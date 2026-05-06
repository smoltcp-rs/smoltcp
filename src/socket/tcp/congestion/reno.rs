use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    min_cwnd: usize,
    ssthresh: usize,
    rwnd: usize,
    recovery_start: Option<Instant>,
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            ssthresh: usize::MAX,
            rwnd: 64 * 1024,
            recovery_start: None,
        }
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _in_flight: usize, _rtt: &RttEstimator) {
        // First new-data-ack exits fast recovery and deflates `cwnd`
        if self.recovery_start.is_some() {
            self.recovery_start = None;
            self.cwnd = self.ssthresh;
            return;
        }

        let inc = if self.cwnd < self.ssthresh {
            // Slow start: increase `cwnd` by 1 MSS per ACK.
            len.min(self.min_cwnd)
        } else {
            // Congestion avoidance: increase by ~1 MSS per RTT.
            (self.min_cwnd * self.min_cwnd / self.cwnd).max(1)
        };

        self.cwnd = self
            .cwnd
            .saturating_add(inc)
            .min(self.rwnd)
            .max(self.min_cwnd);
    }

    fn on_dup_ack(&mut self, _now: Instant, len: usize, _in_flight: usize) {
        if self.recovery_start.is_some() {
            self.cwnd = self
                .cwnd
                .saturating_add(len)
                .min(self.rwnd)
                .max(self.min_cwnd);
        }
    }

    fn on_loss(&mut self, now: Instant, in_flight: usize) {
        // Only cut window size on first entrance to fast recovery.
        if self.recovery_start.is_none() {
            self.ssthresh = (in_flight >> 1).max(2 * self.min_cwnd);
            self.cwnd = self
                .ssthresh
                .saturating_add(3 * self.min_cwnd)
                .min(self.rwnd);

            self.recovery_start = Some(now);
        }
    }

    fn on_rto(&mut self, _now: Instant, in_flight: usize) {
        self.ssthresh = (in_flight >> 1).max(2 * self.min_cwnd);
        self.cwnd = self.min_cwnd;

        // Major loss has occurred, ensure we move from fast recovery (if in it) to slow start.
        self.recovery_start = None
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time::Instant;

    use super::*;

    #[test]
    fn test_reno() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut reno = Reno::new();
                reno.set_mss(1480);

                // Set remote window.
                reno.set_remote_window(remote_window);

                reno.on_ack(now, 4096, reno.window(), &RttEstimator::default());

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                if i & 1 == 0 {
                    reno.on_rto(now, reno.window());
                } else {
                    reno.on_loss(now, reno.window());
                }

                let elapsed = Instant::from_millis(1000);
                reno.on_ack(elapsed, n, reno.window(), &RttEstimator::default());

                let cwnd = reno.window();
                println!("Reno: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= reno.min_cwnd);
                assert!(reno.window() <= remote_window);
            }
        }
    }

    #[test]
    fn reno_min_cwnd() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        let mut reno = Reno::new();
        reno.set_remote_window(remote_window);

        for _ in 0..100 {
            reno.on_rto(now, reno.window());
            assert!(reno.window() >= reno.min_cwnd);
        }
    }

    #[test]
    fn reno_set_rwnd() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 * 1024 * 1024);

        println!("{reno:?}");
    }
}
