use crate::time::{Duration, Instant};

use super::min_max::MinMax;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
    last_round: u64,  // Track RTT rounds to detect measurement window boundaries
}

impl Default for BandwidthEstimation {
    fn default() -> Self {
        BandwidthEstimation {
            total_acked: 0,
            prev_total_acked: 0,
            acked_time: None,
            prev_acked_time: None,
            total_sent: 0,
            prev_total_sent: 0,
            sent_time: None,
            prev_sent_time: None,
            max_filter: MinMax::new(10),
            acked_at_last_window: 0,
            last_round: 0,
        }
    }
}

impl BandwidthEstimation {
    pub fn on_sent(&mut self, now: Instant, bytes: u64) {
        // Only update prev_* when we haven't sent anything in this window yet
        // This allows accumulating sent bytes over the window
        if self.sent_time.is_none() {
            self.prev_total_sent = self.total_sent;
            self.prev_sent_time = None;
        }

        self.total_sent += bytes;
        self.sent_time = Some(now);
    }

    pub fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        #[cfg(feature = "log")]
        log::trace!(
            "[BBR BW] on_ack called: round={} bytes={} last_round={}",
            round,
            bytes,
            self.last_round
        );

        // Initialize on first ACK
        if self.acked_time.is_none() {
            self.prev_total_acked = 0;
            self.prev_acked_time = Some(now);
            self.total_acked = bytes;
            self.acked_time = Some(now);
            self.last_round = round;
            return;
        }

        // Detect new round - this means we completed the previous round!
        // Calculate bandwidth for the COMPLETED round and update filter ONCE per round
        #[cfg(feature = "log")]
        if round != self.last_round {
            log::trace!(
                "[BBR BW] Round change detected: {} -> {}",
                self.last_round,
                round
            );
        }

        if round != self.last_round {
            // Calculate bandwidth for the completed round using accumulated data
            let completed_round_bw = if let Some(prev_acked_time) = self.prev_acked_time {
                if self.acked_time.unwrap() > prev_acked_time {
                    let delta_bytes = self.total_acked - self.prev_total_acked;
                    let delta_time = self.acked_time.unwrap() - prev_acked_time;
                    BandwidthEstimation::bw_from_delta(delta_bytes, delta_time).unwrap_or(0)
                } else {
                    0
                }
            } else {
                0
            };

            // Update the MinMax filter ONCE per round with the completed round's bandwidth
            if !app_limited && completed_round_bw > 0 {
                let old_max = self.max_filter.get();
                self.max_filter.update_max(self.last_round, completed_round_bw);
                let new_max = self.max_filter.get();

                #[cfg(feature = "log")]
                log::debug!(
                    "[BBR BW] Round {} complete: bw={} B/s ({:.3} Mbps) | old_max={} B/s ({:.3} Mbps) | new_max={} B/s ({:.3} Mbps)",
                    self.last_round,
                    completed_round_bw,
                    (completed_round_bw as f64 * 8.0) / 1_000_000.0,
                    old_max,
                    (old_max as f64 * 8.0) / 1_000_000.0,
                    new_max,
                    (new_max as f64 * 8.0) / 1_000_000.0
                );
            }

            // Now start the new round - reset accumulators
            self.prev_total_acked = self.total_acked;
            self.prev_acked_time = self.acked_time;
            self.last_round = round;

            // Also reset sent tracking for new round
            if self.sent_time.is_some() {
                self.prev_total_sent = self.total_sent;
                self.prev_sent_time = self.sent_time;
            }
        }

        // Accumulate bytes for this ACK
        self.total_acked += bytes;
        self.acked_time = Some(now);

        // Note: MinMax filter is only updated once per round (above when round changes)
        // get_estimate() returns the max bandwidth over the last 10 completed rounds
        // This is correct BBR behavior - don't update filter on every ACK
    }

    pub fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_micros = delta.total_micros();
        if window_duration_micros == 0 {
            return None;
        }
        let bytes_per_second = bytes * 1_000_000 / window_duration_micros;
        Some(bytes_per_second)
    }
}
