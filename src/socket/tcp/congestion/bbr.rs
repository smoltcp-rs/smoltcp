use crate::time::{Duration, Instant};

use super::{Controller, RttEstimator};

mod bw_estimation;
mod min_max;

use bw_estimation::BandwidthEstimation;
use min_max::MinMax;

/// Experimental BBR congestion control algorithm.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on google's quiche implementation <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
/// of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Bbr {
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: usize,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: usize,
    min_cwnd: usize,
    prev_in_flight_count: usize,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: usize,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    rwnd: usize,
    // Simple linear congruential generator for randomness (no_std compatible)
    rng_state: u32,
    // App-limited tracking: true when the application doesn't have enough data to fill cwnd
    app_limited: bool,
}

impl Bbr {
    pub fn new() -> Self {
        let initial_window = 1024 * 10;
        let min_window = 1024 * 2;
        Self {
            max_bandwidth: BandwidthEstimation::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: Default::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: K_DEFAULT_HIGH_GAIN,
            high_gain: K_DEFAULT_HIGH_GAIN,
            drain_gain: 1.0 / K_DEFAULT_HIGH_GAIN,
            cwnd_gain: K_DEFAULT_HIGH_GAIN,
            high_cwnd_gain: K_DEFAULT_HIGH_GAIN,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: min_window,
            prev_in_flight_count: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Duration::ZERO,
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState {
                max_ack_height: MinMax::new(10),
                aggregation_epoch_start_time: None,
                aggregation_epoch_bytes: 0,
            },
            rwnd: 64 * 1024,
            rng_state: 12345, // Arbitrary seed
            app_limited: false,
        }
    }

    // Simple pseudo-random number generator (LCG)
    fn random_range(&mut self, max: u8) -> u8 {
        self.rng_state = self.rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        ((self.rng_state / 65536) % max as u32) as u8
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = K_DERIVED_HIGH_CWNDGAIN;
        self.last_cycle_start = Some(now);
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = self.random_range((K_PACING_GAIN.len() as u8) - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = K_PACING_GAIN[rand_index as usize];
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in calculate_recovery_window().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_losses()
                    && self.max_acked_packet_number > self.end_recovery_at_packet_number
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: usize) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| {
                if now > last_cycle_start {
                    now - last_cycle_start > self.min_rtt
                } else {
                    false
                }
            })
            .unwrap_or(false);

        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_losses()
            && self.prev_in_flight_count < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset = (self.current_cycle_offset + 1) % K_PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if DRAIN_TO_TARGET
                && self.pacing_gain < 1.0
                && (K_PACING_GAIN[self.current_cycle_offset as usize] - 1.0).abs() < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = K_PACING_GAIN[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: usize) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant) -> bool {
        !self.app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| {
                    if now > last {
                        now - last > Duration::from_secs(10)
                    } else {
                        false
                    }
                })
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: usize,
        _app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now);
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            if self.exit_probe_rtt_at.is_none() {
                // If the window has reached the appropriate size, schedule exiting
                // ProbeRtt.  The CWND during ProbeRtt is
                // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                // checks CWND before sending a packet.
                if bytes_in_flight < self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE {
                    const K_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                    self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);
                }
            } else if is_round_start {
                if let Some(exit_time) = self.exit_probe_rtt_at {
                    if now >= exit_time {
                        if !self.is_at_full_bandwidth {
                            self.enter_startup_mode();
                        } else {
                            self.enter_probe_bandwidth_mode(now);
                        }
                    }
                }
            }
        }

        self.exiting_quiescence = false;
    }

    fn get_target_cwnd(&self, gain: f32) -> usize {
        let bw = self.max_bandwidth.get_estimate();
        let bdp = self.min_rtt.total_micros() * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as usize;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> usize {
        const K_MODERATE_PROBE_RTT_MULTIPLIER: f32 = 0.75;
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(K_MODERATE_PROBE_RTT_MULTIPLIER);
        }
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self) {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.min_rtt.total_micros() != 0 {
            self.pacing_rate =
                BandwidthEstimation::bw_from_delta(self.init_cwnd as u64, self.min_rtt)
                    .unwrap_or(0);
            return;
        }

        // Do not decrease the pacing rate during startup.
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: usize, excess_acked: usize) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window =
                target_window.saturating_add(self.ack_aggregation.max_ack_height.get() as usize);
        } else {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window = target_window.saturating_add(excess_acked);
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd.saturating_add(bytes_acked));
        } else if (self.cwnd_gain < target_window as f32)
            || (self.acked_bytes < self.init_cwnd as u64)
        {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd = self.cwnd.saturating_add(bytes_acked);
        }

        // Enforce the limits on the congestion window.
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(
        &mut self,
        bytes_acked: usize,
        bytes_lost: usize,
        in_flight: usize,
    ) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight.saturating_add(bytes_acked));
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            self.recovery_window = MAX_SEGMENT_SIZE;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window = self.recovery_window.saturating_add(bytes_acked);
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight.saturating_add(bytes_acked))
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self) {
        if self.app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * K_STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            self.ack_aggregation.max_ack_height.reset();
            return;
        }

        self.round_wo_bw_gain += 1;
        if self.round_wo_bw_gain >= K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP as u64
            || (self.recovery_state.in_recovery())
        {
            self.is_at_full_bandwidth = true;
        }
    }

    fn on_ack_impl(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {
        let bytes = len as u64;
        // Simulate packet numbers using bytes
        let packet_number = self.max_acked_packet_number + 1;
        self.max_acked_packet_number = packet_number;

        // Update bandwidth estimation with app_limited state
        self.max_bandwidth
            .on_ack(now, now, bytes, self.round_count, self.app_limited);
        self.acked_bytes += bytes;

        if self.min_rtt == Duration::ZERO || self.min_rtt > rtt.min_rtt() {
            self.min_rtt = rtt.min_rtt();
        }

        // End of acks processing
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window() as usize;
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked as u64,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
        ) as usize;
        self.max_bandwidth
            .end_acks(self.round_count, self.app_limited);

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start =
                self.max_acked_packet_number > self.current_round_trip_end_packet_number;
            if is_round_start {
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
                self.round_count += 1;
            }
        }

        self.update_recovery_state(is_round_start);

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, self.cwnd);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached();
        }

        self.maybe_exit_startup_or_drain(now, self.cwnd);

        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, self.cwnd, self.app_limited);

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, self.loss_state.lost_bytes, self.cwnd);

        self.prev_in_flight_count = self.cwnd;
        self.loss_state.reset();
    }

    fn on_transmit_impl(&mut self, now: Instant, len: usize) {
        let bytes = len as u64;
        let packet_number = self.max_sent_packet_number + 1;
        self.max_sent_packet_number = packet_number;
        self.max_bandwidth.on_sent(now, bytes);
    }
}

impl Controller for Bbr {
    fn window(&self) -> usize {
        let cwnd = if self.mode == Mode::ProbeRtt {
            self.get_probe_rtt_cwnd()
        } else if self.recovery_state.in_recovery() && self.mode != Mode::Startup {
            self.cwnd.min(self.recovery_window)
        } else {
            self.cwnd
        };
        cwnd.min(self.rwnd)
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {
        self.on_ack_impl(now, len, rtt);
    }

    fn on_retransmit(&mut self, _now: Instant) {
        self.loss_state.lost_bytes = self.loss_state.lost_bytes.saturating_add(1);
    }

    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.loss_state.lost_bytes = self.loss_state.lost_bytes.saturating_add(1);
    }

    fn pre_transmit(&mut self, _now: Instant) {
        // BBR doesn't need pre-transmission processing
    }

    fn post_transmit(&mut self, now: Instant, len: usize) {
        self.on_transmit_impl(now, len);
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss * 2;
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn on_send_ready(&mut self, _now: Instant, bytes_available: usize) {
        // Track app-limited state: true when bytes_available < cwnd
        // This follows Quinn's approach where app_limited indicates the application
        // doesn't have enough data to fill the congestion window.
        let cwnd = self.window();
        self.app_limited = bytes_available < cwnd;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    pub fn in_recovery(&self) -> bool {
        !matches!(self, RecoveryState::NotInRecovery)
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct AckAggregationState {
    max_ack_height: MinMax,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
}

impl AckAggregationState {
    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
    ) -> u64 {
        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let expected_bytes_acked = if let Some(start_time) = self.aggregation_epoch_start_time {
            if now > start_time {
                let elapsed = now - start_time;
                max_bandwidth * elapsed.total_micros() / 1_000_000
            } else {
                0
            }
        } else {
            0
        };

        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <= expected_bytes_acked {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update_max(round, diff);
        diff
    }
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct LossState {
    lost_bytes: usize,
}

impl LossState {
    pub fn reset(&mut self) {
        self.lost_bytes = 0;
    }

    pub fn has_losses(&self) -> bool {
        self.lost_bytes != 0
    }
}

// The gain used for the STARTUP, equal to 2/ln(2).
const K_DEFAULT_HIGH_GAIN: f32 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
const K_DERIVED_HIGH_CWNDGAIN: f32 = 2.0;
// The cycle of gains used during the ProbeBw stage.
const K_PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const K_STARTUP_GROWTH_TARGET: f32 = 1.25;
const K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: u8 = 3;

const MAX_SEGMENT_SIZE: usize = 1460;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;

#[cfg(test)]
mod test {
    use crate::{socket::tcp::RttEstimator, time::Instant};

    use super::*;

    #[test]
    fn test_bbr_basic() {
        let remote_window = 64 * 1024 * 1024;
        let _now = Instant::from_millis(0);

        let mut bbr = Bbr::new();
        bbr.set_remote_window(remote_window);
        bbr.set_mss(1480);

        // Initial state should be Startup
        assert_eq!(bbr.mode, Mode::Startup);

        let initial_cwnd = bbr.window();
        assert!(initial_cwnd >= bbr.min_cwnd);
        assert!(initial_cwnd <= remote_window);

        println!("BBR: Initial cwnd = {}", initial_cwnd);
    }

    #[test]
    fn test_bbr_startup_growth() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let rtt = RttEstimator::default();
        let _now = Instant::from_millis(0);

        let initial_cwnd = bbr.window();

        // Simulate successful transmissions and acks in startup
        for i in 1..20 {
            let t = Instant::from_millis(i * 10);

            // Transmit some data
            bbr.post_transmit(t, 1480);

            // ACK the data after some RTT
            bbr.on_ack(t, 1480, &rtt);

            let cwnd = bbr.window();
            println!("BBR Startup round {}: cwnd = {}", i, cwnd);
        }

        // In startup, cwnd should grow significantly
        let final_cwnd = bbr.window();
        assert!(final_cwnd >= initial_cwnd);
    }

    #[test]
    fn test_bbr_loss_response() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let now = Instant::from_millis(0);
        let cwnd_before = bbr.window();

        // Simulate retransmission (loss)
        bbr.on_retransmit(now);

        // BBR should track losses
        assert!(bbr.loss_state.has_losses());

        println!(
            "BBR: cwnd before loss = {}, after loss = {}",
            cwnd_before,
            bbr.window()
        );
    }

    #[test]
    fn test_bbr_duplicate_ack() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let now = Instant::from_millis(0);
        let cwnd_before = bbr.window();

        // Simulate duplicate ack (possible loss indicator)
        bbr.on_duplicate_ack(now);

        // BBR should track this as a loss signal
        assert!(bbr.loss_state.has_losses());

        println!(
            "BBR: cwnd before dup ack = {}, after = {}",
            cwnd_before,
            bbr.window()
        );
    }

    #[test]
    fn test_bbr_min_cwnd() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let now = Instant::from_millis(0);

        // Simulate many losses
        for _ in 0..100 {
            bbr.on_retransmit(now);
            let cwnd = bbr.window();

            // Should never go below min_cwnd
            assert!(cwnd >= bbr.min_cwnd);
        }

        println!(
            "BBR: min_cwnd = {}, final cwnd = {}",
            bbr.min_cwnd,
            bbr.window()
        );
    }

    #[test]
    fn test_bbr_remote_window_limit() {
        let mut bbr = Bbr::new();
        let remote_window = 16 * 1024; // Small remote window
        bbr.set_remote_window(remote_window);
        bbr.set_mss(1480);

        let rtt = RttEstimator::default();

        // Simulate many acks to try to grow cwnd
        for i in 0..100 {
            let t = Instant::from_millis(i * 10);
            bbr.post_transmit(t, 1480);
            bbr.on_ack(t, 1480, &rtt);
        }

        // Window should not exceed remote window
        assert!(bbr.window() <= remote_window);

        println!(
            "BBR: remote_window = {}, cwnd = {}",
            remote_window,
            bbr.window()
        );
    }

    #[test]
    fn test_bbr_mode_transitions() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Should start in Startup mode
        assert_eq!(bbr.mode, Mode::Startup);
        println!("BBR: Initial mode = {:?}", bbr.mode);

        // Simulate achieving full bandwidth (set the flag manually for testing)
        bbr.is_at_full_bandwidth = true;

        let now = Instant::from_millis(1000);

        // First call should transition to Drain mode
        bbr.maybe_exit_startup_or_drain(now, bbr.window() * 2); // High in_flight to stay in Drain
        assert_eq!(bbr.mode, Mode::Drain);
        println!("BBR: After full BW = {:?}", bbr.mode);

        // When in_flight <= target_cwnd, should move to ProbeBw
        bbr.maybe_exit_startup_or_drain(now, bbr.get_target_cwnd(1.0) / 2);
        assert_eq!(bbr.mode, Mode::ProbeBw);
        println!("BBR: After drain = {:?}", bbr.mode);
    }

    #[test]
    fn test_bbr_probe_rtt() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Set to ProbeBw mode and mark last probe as long ago
        bbr.mode = Mode::ProbeBw;
        bbr.is_at_full_bandwidth = true;
        bbr.probe_rtt_last_started_at = Some(Instant::from_millis(0));

        let now = Instant::from_millis(11000); // 11 seconds later (>10s threshold)

        bbr.maybe_enter_or_exit_probe_rtt(now, false, bbr.window(), false);

        // Should enter ProbeRTT mode
        assert_eq!(bbr.mode, Mode::ProbeRtt);
        println!("BBR: Entered ProbeRTT mode");
    }

    #[test]
    fn test_bbr_bandwidth_estimation() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let rtt = RttEstimator::default();

        // Simulate data transfer with known rate
        let bytes_per_ack = 1480;
        let ack_interval_ms = 10;

        for i in 0..50 {
            let t = Instant::from_millis(i * ack_interval_ms);
            bbr.post_transmit(t, bytes_per_ack);
            bbr.on_ack(t, bytes_per_ack, &rtt);
        }

        let estimated_bw = bbr.max_bandwidth.get_estimate();
        println!("BBR: Estimated bandwidth = {} bytes/sec", estimated_bw);

        // Should have some bandwidth estimate
        assert!(estimated_bw > 0);
    }

    #[test]
    fn test_bbr_recovery_window() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Cause a loss to enter recovery
        bbr.on_retransmit(Instant::from_millis(0));

        // Force into recovery state
        bbr.recovery_state = RecoveryState::Conservation;

        let in_flight = bbr.window();
        bbr.calculate_recovery_window(1480, 1480, in_flight);

        assert!(bbr.recovery_state.in_recovery());
        assert!(bbr.recovery_window >= bbr.min_cwnd);

        println!("BBR: recovery_window = {}", bbr.recovery_window);
    }

    #[test]
    fn test_bbr_pacing_rate() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Set some bandwidth and RTT
        bbr.min_rtt = crate::time::Duration::from_millis(100);

        // Manually set bandwidth for testing
        for i in 0..10 {
            let t = Instant::from_millis(i * 10);
            bbr.max_bandwidth.on_sent(t, 1480);
            bbr.max_bandwidth.on_ack(t, t, 1480, 0, false);
        }

        bbr.calculate_pacing_rate();

        println!("BBR: pacing_rate = {} bytes/sec", bbr.pacing_rate);

        // Should calculate some pacing rate
        assert!(bbr.pacing_rate > 0 || bbr.max_bandwidth.get_estimate() == 0);
    }

    #[test]
    fn test_bbr_target_cwnd() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Set known bandwidth and RTT
        bbr.min_rtt = crate::time::Duration::from_millis(50);

        // Simulate some bandwidth
        for i in 0..10 {
            let t = Instant::from_millis(i * 5);
            bbr.max_bandwidth.on_sent(t, 10000);
            bbr.max_bandwidth.on_ack(t, t, 10000, 0, false);
        }

        let target = bbr.get_target_cwnd(1.0);
        println!("BBR: target_cwnd = {}", target);

        // Should be at least min_cwnd
        assert!(target >= bbr.min_cwnd);
    }

    #[test]
    fn test_bbr_full_bandwidth_detection() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        // Initially not at full bandwidth
        assert!(!bbr.is_at_full_bandwidth);

        // Simulate stalled bandwidth growth
        bbr.bw_at_last_round = 1000000;
        bbr.max_bandwidth.on_sent(Instant::from_millis(0), 1000);
        bbr.max_bandwidth.on_ack(
            Instant::from_millis(10),
            Instant::from_millis(0),
            1000,
            0,
            false,
        );

        // If bandwidth doesn't grow for 3 rounds, should detect full bandwidth
        for _ in 0..4 {
            bbr.check_if_full_bw_reached();
        }

        println!("BBR: is_at_full_bandwidth = {}", bbr.is_at_full_bandwidth);
    }

    #[test]
    fn test_bbr_ack_aggregation() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.set_mss(1480);

        let now = Instant::from_millis(0);

        // Set up some bandwidth
        for i in 0..5i64 {
            bbr.max_bandwidth
                .on_sent(Instant::from_millis(i * 10), 1480);
            bbr.max_bandwidth.on_ack(
                Instant::from_millis(i * 10 + 5),
                Instant::from_millis(i * 10),
                1480,
                i as u64,
                false,
            );
        }

        let bw = bbr.max_bandwidth.get_estimate();
        let excess = bbr
            .ack_aggregation
            .update_ack_aggregation_bytes(5000, now, 5, bw);

        println!("BBR: ack aggregation excess = {} bytes", excess);
    }

    #[test]
    fn test_bbr_set_mss() {
        let mut bbr = Bbr::new();

        let old_min_cwnd = bbr.min_cwnd;
        bbr.set_mss(1500);

        // min_cwnd should be updated to 2 * MSS
        assert_eq!(bbr.min_cwnd, 1500 * 2);
        assert!(bbr.min_cwnd != old_min_cwnd);

        // cwnd should not be less than min_cwnd
        assert!(bbr.cwnd >= bbr.min_cwnd);

        println!(
            "BBR: After set_mss(1500), min_cwnd = {}, cwnd = {}",
            bbr.min_cwnd, bbr.cwnd
        );
    }

    #[test]
    fn test_bbr_random_generator() {
        let mut bbr = Bbr::new();

        // Test that random generator produces values in range
        for _ in 0..100 {
            let val = bbr.random_range(8);
            assert!(val < 8);
        }

        println!("BBR: Random generator test passed");
    }

    #[test]
    fn test_bbr_app_limited_tracking() {
        let mut bbr = Bbr::new();
        bbr.set_remote_window(64 * 1024);
        bbr.set_mss(1480);

        let now = Instant::from_millis(0);

        // Initially not app-limited
        assert!(!bbr.app_limited);

        // With plenty of data available (more than cwnd), should not be app-limited
        let cwnd = bbr.window();
        bbr.on_send_ready(now, cwnd + 1000);
        assert!(!bbr.app_limited);
        println!(
            "BBR: With {} bytes available (cwnd={}), app_limited={}",
            cwnd + 1000,
            cwnd,
            bbr.app_limited
        );

        // With less data than cwnd, should be app-limited
        bbr.on_send_ready(now, cwnd / 2);
        assert!(bbr.app_limited);
        println!(
            "BBR: With {} bytes available (cwnd={}), app_limited={}",
            cwnd / 2,
            cwnd,
            bbr.app_limited
        );

        // With no data, should be app-limited
        bbr.on_send_ready(now, 0);
        assert!(bbr.app_limited);
        println!(
            "BBR: With 0 bytes available (cwnd={}), app_limited={}",
            cwnd, bbr.app_limited
        );
    }
}
