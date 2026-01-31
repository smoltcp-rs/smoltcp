use crate::time::{Duration, Instant};

use super::{Controller, RttEstimator};

mod bw_estimation;
mod min_max;

use bw_estimation::BandwidthEstimation;

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
    // Idle restart flag: set when restarting after idle period
    // This matches Linux BBR (tcp_bbr.c:101)
    idle_restart: bool,
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
    // Prior cwnd before loss recovery (for restoration after recovery exits)
    prior_cwnd: usize,
    // Packet conservation flag: follow packet conservation principle during first round of recovery
    // This matches Linux BBR (tcp_bbr.c:99)
    packet_conservation: bool,
    // Previous congestion avoidance state for tracking recovery entry/exit
    // This matches Linux BBR (tcp_bbr.c:98) but simplified to bool (in_recovery)
    prev_in_recovery: bool,
    // Round start flag: indicates if we've started a new round trip
    // This matches Linux BBR (tcp_bbr.c:100)
    round_start: bool,
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
            idle_restart: false,
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
                extra_acked: [0, 0],
                extra_acked_win_idx: 0,
                extra_acked_win_rtts: 0,
                ack_epoch_mstamp: None,
                ack_epoch_acked: 0,
            },
            rwnd: 64 * 1024,
            rng_state: 12345, // Arbitrary seed
            app_limited: false,
            prior_cwnd: initial_window,
            packet_conservation: false,
            prev_in_recovery: false,
            round_start: false,
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

    fn save_cwnd(&mut self) {
        // Save current cwnd before entering recovery
        // This matches Linux BBR (tcp_bbr.c:756, 884)
        if self.recovery_state == RecoveryState::NotInRecovery && self.mode != Mode::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        }
    }

    fn restore_cwnd(&mut self) {
        // Restore cwnd when exiting recovery
        // This matches Linux BBR (tcp_bbr.c:785, 903)
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    /// Packet conservation: handle recovery and restoration of cwnd.
    /// Matches Linux BBR bbr_set_cwnd_to_recover_or_restore() (tcp_bbr.c:480-514)
    ///
    /// On the first round of recovery, follow packet conservation principle:
    /// send P packets per P packets acked. After that, slow-start and send
    /// at most 2*P packets per P packets acked.
    fn set_cwnd_to_recover_or_restore(
        &mut self,
        bytes_acked: usize,
        bytes_lost: usize,
        bytes_in_flight: usize,
    ) -> Option<usize> {
        let in_recovery = self.recovery_state.in_recovery();
        let mut cwnd = self.cwnd;

        // An ACK for P pkts should release at most 2*P packets. We do this
        // in two steps. First, here we deduct the number of lost packets.
        // Then, in calculate_cwnd() we slow start up toward the target cwnd.
        // Matches tcp_bbr.c:492-493
        if bytes_lost > 0 {
            cwnd = cwnd.saturating_sub(bytes_lost).max(MAX_SEGMENT_SIZE);
        }

        // Entering recovery: start packet conservation
        // Matches tcp_bbr.c:495-500
        if in_recovery && !self.prev_in_recovery {
            // Starting 1st round of Recovery, so do packet conservation.
            self.packet_conservation = true;
            // Start new round now
            self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            // Cut unused cwnd from app behavior or other factors
            cwnd = bytes_in_flight.saturating_add(bytes_acked);
        }
        // Exiting recovery: restore cwnd
        // Matches tcp_bbr.c:501-504
        else if !in_recovery && self.prev_in_recovery {
            // Exiting loss recovery; restore cwnd saved before recovery.
            cwnd = cwnd.max(self.prior_cwnd);
            self.packet_conservation = false;
        }

        // Update prev state for next time
        self.prev_in_recovery = in_recovery;

        // If using packet conservation, ensure cwnd >= inflight + acked
        // Matches tcp_bbr.c:508-513
        if self.packet_conservation {
            let conserved_cwnd = bytes_in_flight.saturating_add(bytes_acked).max(cwnd);
            Some(conserved_cwnd)
        } else {
            Some(cwnd)
        }
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                // Save cwnd before entering recovery (matches Linux BBR)
                self.save_cwnd();
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
                    // Restore cwnd when exiting recovery (matches Linux BBR)
                    self.restore_cwnd();
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
            #[cfg(feature = "log")]
            log::info!("[BBR MODE] Startup → Drain | pacing_gain={:.2}", self.drain_gain);

            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain {
            let target = self.get_target_cwnd(1.0);
            #[cfg(feature = "log")]
            if self.round_start {
                log::debug!("[BBR DRAIN] in_flight={} | target_cwnd={} | will_exit={}",
                    in_flight, target, in_flight <= target);
            }

            if in_flight <= target {
                #[cfg(feature = "log")]
                log::info!("[BBR MODE] Drain → ProbeBw | in_flight={} | target_cwnd={}",
                    in_flight, target);

                self.enter_probe_bandwidth_mode(now);
            }
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
                .unwrap_or(false)  // Never entered ProbeRtt before -> not expired
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: usize,
        _app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now);
        // Enter ProbeRTT if min_rtt expired, not restarting from idle, and not already in ProbeRTT
        // CRITICAL: Don't enter ProbeRtt during Startup - let BBR probe bandwidth first!
        // Matches tcp_bbr.c:957-962
        if min_rtt_expired && !self.idle_restart && self.mode != Mode::ProbeRtt && self.mode != Mode::Startup {
            // Save cwnd before entering ProbeRTT (matches Linux BBR tcp_bbr.c:960)
            self.save_cwnd();
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);

            // CRITICAL FIX: Actually reduce cwnd when entering ProbeRtt!
            // This is what makes bytes_in_flight drain down
            self.cwnd = self.get_probe_rtt_cwnd();

            #[cfg(feature = "log")]
            log::info!(
                "[BBR ProbeRtt] ENTERED ProbeRtt | old_cwnd saved | new_cwnd={} | bytes_in_flight={} | target={}",
                self.cwnd,
                bytes_in_flight,
                self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE
            );
        }

        if self.mode == Mode::ProbeRtt {
            if self.exit_probe_rtt_at.is_none() {
                // If the window has reached the appropriate size, schedule exiting
                // ProbeRtt.  The CWND during ProbeRtt is
                // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                // checks CWND before sending a packet.

                #[cfg(feature = "log")]
                if bytes_in_flight >= self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE {
                    log::debug!(
                        "[BBR ProbeRtt] WAITING for cwnd drain | bytes_in_flight={} | target={} | cwnd={}",
                        bytes_in_flight,
                        self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE,
                        self.cwnd
                    );
                }

                if bytes_in_flight < self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE {
                    const K_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                    self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);

                    #[cfg(feature = "log")]
                    log::debug!(
                        "[BBR ProbeRtt] SCHEDULED EXIT in 200ms | bytes_in_flight={} | target={}",
                        bytes_in_flight,
                        self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE
                    );
                }
            } else {
                // Check if we can exit ProbeRtt (after 200ms has passed)
                if let Some(exit_time) = self.exit_probe_rtt_at {
                    if now >= exit_time {
                        // Restore cwnd when exiting ProbeRTT (matches Linux BBR tcp_bbr.c:918)
                        self.restore_cwnd();

                        #[cfg(feature = "log")]
                        log::info!(
                            "[BBR ProbeRtt] EXITING ProbeRtt | restored_cwnd={} | is_at_full_bandwidth={} | is_round_start={}",
                            self.cwnd,
                            self.is_at_full_bandwidth,
                            is_round_start
                        );

                        if !self.is_at_full_bandwidth {
                            self.enter_startup_mode();
                        } else {
                            self.enter_probe_bandwidth_mode(now);
                        }
                    }
                }
            }
        }
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

        // If no bandwidth estimate yet, initialize pacing rate from cwnd/RTT
        // Matches Linux BBR bbr_init_pacing_rate_from_rtt (tcp_bbr.c:266-283)
        if bw == 0 {
            // Use measured RTT if available, otherwise use 1ms default (like Linux)
            let rtt_us = if self.min_rtt.total_micros() != 0 {
                self.min_rtt.total_micros()
            } else {
                1000  // 1ms default RTT (USEC_PER_MSEC)
            };

            // Calculate initial bandwidth: init_cwnd / RTT
            let rtt_duration = Duration::from_micros(rtt_us);
            let initial_bw = BandwidthEstimation::bw_from_delta(self.init_cwnd as u64, rtt_duration)
                .unwrap_or(0);

            if initial_bw > 0 {
                // Apply high_gain to initial pacing rate (Startup mode)
                let initial_rate = (initial_bw as f64 * self.pacing_gain as f64) as u64;
                self.pacing_rate = initial_rate;

                #[cfg(feature = "log")]
                log::debug!(
                    "[BBR PACING] Initial pacing rate: cwnd={} / rtt={}us * gain={:.2} = {} B/s ({:.3} Mbps)",
                    self.init_cwnd,
                    rtt_us,
                    self.pacing_gain,
                    self.pacing_rate,
                    (self.pacing_rate as f64 * 8.0) / 1_000_000.0
                );
            }
            return;
        }

        // Calculate target rate with pacing gain
        let mut target_rate = (bw as f64 * self.pacing_gain as f64) as u64;

        // Apply pacing margin: pace at ~1% below estimated bandwidth
        // This matches Linux BBR (tcp_bbr.c:251) to reduce queue buildup at bottleneck
        target_rate = (target_rate * (100 - BBR_PACING_MARGIN_PERCENT as u64)) / 100;

        #[cfg(feature = "log")]
        log::trace!(
            "[BBR PACING] bw_estimate={} B/s ({:.3} Mbps) | pacing_gain={} | target_rate={} B/s ({:.3} Mbps) | mode={:?}",
            bw,
            (bw as f64 * 8.0) / 1_000_000.0,
            self.pacing_gain,
            target_rate,
            (target_rate as f64 * 8.0) / 1_000_000.0,
            self.mode
        );

        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Do not decrease the pacing rate during startup.
        // Matches Linux BBR (tcp_bbr.c:294)
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: usize) {
        if self.mode == Mode::ProbeRtt {
            return;
        }

        // No packet fully ACKed; just apply caps
        // Matches tcp_bbr.c:526-527
        if bytes_acked == 0 {
            // Enforce minimum cwnd
            if self.cwnd < self.min_cwnd {
                self.cwnd = self.min_cwnd;
            }
            return;
        }

        // Handle recovery and restoration with packet conservation
        // Matches tcp_bbr.c:529-530
        if let Some(new_cwnd) = self.set_cwnd_to_recover_or_restore(
            bytes_acked,
            self.loss_state.lost_bytes,
            self.cwnd, // Use current cwnd as bytes_in_flight approximation
        ) {
            self.cwnd = new_cwnd;
            // If packet conservation is active, skip normal cwnd growth
            // and just enforce minimum. Matches tcp_bbr.c:529-530 (goto done)
            if self.packet_conservation {
                if self.cwnd < self.min_cwnd {
                    self.cwnd = self.min_cwnd;
                }
                return;
            }
        }

        // Normal cwnd calculation: compute target cwnd based on BDP
        // Matches tcp_bbr.c:532-538
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);

        // Add ACK aggregation cwnd increment
        // Matches tcp_bbr.c:537
        let bw = self.max_bandwidth.get_estimate();
        target_window = target_window.saturating_add(
            self.ack_aggregation
                .ack_aggregation_cwnd(bw, self.is_at_full_bandwidth),
        );

        // Note: bbr_quantization_budget (tcp_bbr.c:538) is omitted as it's
        // TSO-specific and not applicable to smoltcp

        // Slow start cwnd toward target cwnd
        // Matches tcp_bbr.c:541-545
        if self.is_at_full_bandwidth {
            // Only cut cwnd if we filled the pipe
            self.cwnd = target_window.min(self.cwnd.saturating_add(bytes_acked));
        } else if (self.cwnd < target_window)
            || (self.acked_bytes < self.init_cwnd as u64)
        {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd = self.cwnd.saturating_add(bytes_acked);
        }

        // Enforce the limits on the congestion window.
        // Matches tcp_bbr.c:545
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

        #[cfg(feature = "log")]
        log::info!(
            "[BBR STARTUP] Check full BW: current={} B/s ({:.1} Mbps) | target={} B/s ({:.1} Mbps) | last={} B/s | rounds_wo_gain={} | in_recovery={}",
            bw, (bw as f64 * 8.0) / 1e6,
            target, (target as f64 * 8.0) / 1e6,
            self.bw_at_last_round,
            self.round_wo_bw_gain,
            self.recovery_state.in_recovery()
        );

        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            // Reset ACK aggregation tracking when bandwidth increases
            self.ack_aggregation.extra_acked = [0, 0];
            self.ack_aggregation.extra_acked_win_rtts = 0;

            #[cfg(feature = "log")]
            log::info!("[BBR STARTUP] Bandwidth grew! Resetting counter");
            return;
        }

        self.round_wo_bw_gain += 1;

        #[cfg(feature = "log")]
        log::info!("[BBR STARTUP] No growth, counter now: {}", self.round_wo_bw_gain);

        if self.round_wo_bw_gain >= K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP as u64
            || (self.recovery_state.in_recovery())
        {
            self.is_at_full_bandwidth = true;

            #[cfg(feature = "log")]
            log::info!("[BBR STARTUP] *** EXITING STARTUP *** is_at_full_bandwidth=true");
        }
    }

    fn on_ack_impl(&mut self, now: Instant, len: usize, rtt: &RttEstimator, bytes_in_flight: usize) {
        let bytes = len as u64;
        // Simulate packet numbers using bytes
        let packet_number = self.max_acked_packet_number + 1;
        self.max_acked_packet_number = packet_number;

        // Track round start BEFORE updating bandwidth estimation
        // This ensures bandwidth estimation sees the correct round number
        // Matches tcp_bbr.c:767, 772-777
        self.round_start = false;
        let is_round_start =
            self.max_acked_packet_number > self.current_round_trip_end_packet_number;

        if is_round_start {
            self.round_start = true;
            self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            self.round_count += 1;
            // Reset packet conservation on round start
            // Matches tcp_bbr.c:776
            self.packet_conservation = false;

            #[cfg(feature = "log")]
            log::trace!(
                "[BBR ROUND] round={} | is_round_start={} | max_acked={} | round_end={} | max_sent={} | mode={:?}",
                self.round_count,
                is_round_start,
                self.max_acked_packet_number,
                self.current_round_trip_end_packet_number,
                self.max_sent_packet_number,
                self.mode
            );
        }

        // Update bandwidth estimation with app_limited state
        // Now uses the UPDATED round_count if we just started a new round
        self.max_bandwidth
            .on_ack(now, now, bytes, self.round_count, self.app_limited);
        self.acked_bytes += bytes;

        // Update min_rtt from the RttEstimator's windowed minimum
        // The RttEstimator now properly tracks the minimum RTT over a 10-second window
        // and handles expiration, matching Linux BBR behavior
        let current_min_rtt = rtt.min_rtt();
        if self.min_rtt == Duration::ZERO || self.min_rtt > current_min_rtt {
            self.min_rtt = current_min_rtt;
        }

        // End of acks processing
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window() as usize;
        self.max_bandwidth
            .end_acks(self.round_count, self.app_limited);

        self.update_recovery_state(self.round_start);

        // Update ACK aggregation tracking
        // Matches tcp_bbr.c:1019 (bbr_update_ack_aggregation call in bbr_update_model)
        self.ack_aggregation.update_ack_aggregation(
            bytes_acked as u64,
            now,
            self.round_start,
            self.max_bandwidth.get_estimate(),
            self.cwnd,
        );

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, bytes_in_flight);
        }

        if self.round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached();
        }

        self.maybe_exit_startup_or_drain(now, bytes_in_flight);

        self.maybe_enter_or_exit_probe_rtt(now, self.round_start, bytes_in_flight, self.app_limited);

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked);
        self.calculate_recovery_window(bytes_acked, self.loss_state.lost_bytes, self.cwnd);

        // Reset idle_restart after processing new data delivery
        // Matches tcp_bbr.c:983-984: "Restart after idle ends only once we process a new S/ACK for data"
        if bytes_acked > 0 {
            self.idle_restart = false;
        }

        self.prev_in_flight_count = bytes_in_flight;
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

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator, bytes_in_flight: usize) {
        self.on_ack_impl(now, len, rtt, bytes_in_flight);
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

    fn on_send_ready(&mut self, now: Instant, bytes_available: usize) {
        // Detect idle restart: transmission starting when app_limited
        // Matches tcp_bbr.c:337-348 (CA_EVENT_TX_START)
        if self.app_limited && bytes_available > 0 {
            self.idle_restart = true;
            // Reset ACK aggregation epoch on idle restart
            self.ack_aggregation.ack_epoch_mstamp = Some(now);
            self.ack_aggregation.ack_epoch_acked = 0;
            // Note: Pacing rate adjustment happens in set_pacing_rate() calls
            // which are made during normal cwnd/pacing updates
        }

        // Track app-limited state: true when bytes_available < cwnd
        // This follows Quinn's approach where app_limited indicates the application
        // doesn't have enough data to fill the congestion window.
        let cwnd = self.window();
        self.app_limited = bytes_available < cwnd;
    }

    fn pacing_rate(&self) -> u64 {
        self.pacing_rate
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
    // Windowed max filter for tracking maximum extra acked
    // Matches tcp_bbr.c:123 (extra_acked[2])
    extra_acked: [u64; 2],
    // Current window index for extra_acked array
    // Matches tcp_bbr.c:126 (extra_acked_win_idx)
    extra_acked_win_idx: usize,
    // Age of extra_acked window in round trips
    // Matches tcp_bbr.c:125 (extra_acked_win_rtts)
    extra_acked_win_rtts: u32,
    // Start time of current ACK aggregation epoch
    // Matches tcp_bbr.c:122 (ack_epoch_mstamp)
    ack_epoch_mstamp: Option<Instant>,
    // Packets ACKed in current sampling epoch
    // Matches tcp_bbr.c:124 (ack_epoch_acked)
    ack_epoch_acked: u64,
}

impl AckAggregationState {
    /// Return maximum extra acked in past k-2k round trips, where k = BBR_EXTRA_ACKED_WIN_RTTS
    /// Matches Linux BBR bbr_extra_acked() (tcp_bbr.c:233-238)
    fn extra_acked(&self) -> u64 {
        self.extra_acked[0].max(self.extra_acked[1])
    }

    /// Estimates the windowed max degree of ACK aggregation.
    /// Matches Linux BBR bbr_update_ack_aggregation() (tcp_bbr.c:817-863)
    fn update_ack_aggregation(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round_start: bool,
        max_bandwidth: u64,
        cwnd: usize,
    ) {
        // Check if we should skip (no gain configured or invalid input)
        // Matches tcp_bbr.c:824-826
        if BBR_EXTRA_ACKED_GAIN == 0 || newly_acked_bytes == 0 {
            return;
        }

        // Advance the windowed max filter on round start
        // Matches tcp_bbr.c:828-836
        if round_start {
            self.extra_acked_win_rtts = (self.extra_acked_win_rtts + 1).min(0x1F);
            if self.extra_acked_win_rtts >= BBR_EXTRA_ACKED_WIN_RTTS {
                self.extra_acked_win_rtts = 0;
                self.extra_acked_win_idx = if self.extra_acked_win_idx == 0 { 1 } else { 0 };
                self.extra_acked[self.extra_acked_win_idx] = 0;
            }
        }

        // Compute how many bytes we expected to be delivered over this epoch
        // Matches tcp_bbr.c:839-842
        let expected_acked = if let Some(epoch_start) = self.ack_epoch_mstamp {
            if now > epoch_start {
                let epoch_us = (now - epoch_start).total_micros();
                max_bandwidth * epoch_us / 1_000_000
            } else {
                0
            }
        } else {
            0
        };

        // Reset the aggregation epoch if ACK rate is below expected rate or
        // epoch has become too large (stale)
        // Matches tcp_bbr.c:844-854
        if self.ack_epoch_acked <= expected_acked
            || self.ack_epoch_acked + newly_acked_bytes >= BBR_ACK_EPOCH_ACKED_RESET_THRESH
        {
            self.ack_epoch_acked = 0;
            self.ack_epoch_mstamp = Some(now);
            // expected_acked = 0 after reset (implicitly used below)
            // Matches tcp_bbr.c:853
        }

        // Compute excess data delivered, beyond what was expected
        // Matches tcp_bbr.c:856-862
        self.ack_epoch_acked = (self.ack_epoch_acked + newly_acked_bytes).min(0xFFFFF);

        let extra_acked = if self.ack_epoch_acked > expected_acked {
            self.ack_epoch_acked - expected_acked
        } else {
            0
        };

        // Clamp by cwnd
        let extra_acked = extra_acked.min(cwnd as u64);

        // Update windowed max
        if extra_acked > self.extra_acked[self.extra_acked_win_idx] {
            self.extra_acked[self.extra_acked_win_idx] = extra_acked;
        }
    }

    /// Find the cwnd increment based on estimate of ack aggregation
    /// Matches Linux BBR bbr_ack_aggregation_cwnd() (tcp_bbr.c:457-470)
    fn ack_aggregation_cwnd(&self, bw: u64, is_at_full_bandwidth: bool) -> usize {
        if BBR_EXTRA_ACKED_GAIN == 0 || !is_at_full_bandwidth {
            return 0;
        }

        // max_aggr_cwnd = bw * 100ms
        // Matches tcp_bbr.c:462-463
        let max_aggr_cwnd = (bw * BBR_EXTRA_ACKED_MAX_US / 1_000_000) as usize;

        // aggr_cwnd = (gain * extra_acked) >> BBR_SCALE
        // Matches tcp_bbr.c:464-465
        let extra = self.extra_acked();
        let aggr_cwnd = ((BBR_EXTRA_ACKED_GAIN as u64 * extra) >> BBR_SCALE) as usize;

        // Clamp by max
        // Matches tcp_bbr.c:466
        aggr_cwnd.min(max_aggr_cwnd)
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

// Pacing margin: pace at ~1% below estimated bandwidth to reduce queue buildup
// This matches Linux BBR (tcp_bbr.c:147)
const BBR_PACING_MARGIN_PERCENT: u8 = 1;

// ACK aggregation constants
// Gain factor for adding extra_acked to target cwnd
// Matches tcp_bbr.c:196 (bbr_extra_acked_gain = BBR_UNIT = 256)
const BBR_EXTRA_ACKED_GAIN: u32 = 256;
// Window length of extra_acked window in round trips
// Matches tcp_bbr.c:198
const BBR_EXTRA_ACKED_WIN_RTTS: u32 = 5;
// Max allowed value for ack_epoch_acked, after which sampling epoch is reset
// Matches tcp_bbr.c:200
const BBR_ACK_EPOCH_ACKED_RESET_THRESH: u64 = 1u64 << 20;
// Time period for clamping cwnd increment due to ack aggregation (100ms in microseconds)
// Matches tcp_bbr.c:202
const BBR_EXTRA_ACKED_MAX_US: u64 = 100 * 1000;
// BBR_SCALE for gain calculations
// Matches tcp_bbr.c:77 (BBR_SCALE = 8, BBR_UNIT = 1 << 8 = 256)
const BBR_SCALE: u32 = 8;

const MAX_SEGMENT_SIZE: usize = 1460;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;

