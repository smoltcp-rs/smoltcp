use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

const DEFAULT_MSS: usize = 1024;

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
            cwnd: DEFAULT_MSS * 2,
            min_cwnd: DEFAULT_MSS * 2,
            ssthresh: usize::MAX,
            rwnd: 64 * DEFAULT_MSS,
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

    const MSS: usize = 1024;

    fn ack(reno: &mut Reno, len: usize, now: Instant) {
        reno.on_ack(now, len, reno.window().saturating_sub(MSS), &rtte())
    }

    fn rtte() -> RttEstimator {
        RttEstimator::default()
    }

    #[test]
    fn congestion_avoidance_works() {
        let mut reno = Reno::new();
        reno.set_mss(MSS);
        reno.cwnd = MSS * 32;
        reno.ssthresh = MSS * 16;

        // CA should grow at less than 1 MSS per ACK.
        for i in 0..10 {
            let initial_cwnd = reno.window();
            ack(&mut reno, MSS, Instant::from_millis(i));
            assert!(reno.window() < initial_cwnd + MSS);
        }

        // CA should cap at the receive window
        reno.cwnd = reno.rwnd - 1;
        ack(&mut reno, MSS, Instant::from_millis(20));
        assert_eq!(reno.window(), reno.rwnd);
    }

    #[test]
    fn fast_recovery_works() {
        let mut reno = Reno::new();
        reno.set_mss(MSS);
        reno.cwnd = MSS * 32;

        // duplicate ACKs before fast recovery should do nothing
        let initial_cwnd = reno.window();
        for _ in 0..3 {
            reno.on_dup_ack(Instant::from_millis(0), MSS, initial_cwnd);
        }
        assert_eq!(reno.window(), initial_cwnd);

        // we enter fast recovery upon minor loss (three duplicate ACKs)
        // window should become half the in-flight bytes
        // sstresh should be the reduced cwnd, advanced by MSS for the 3 dup ACKs
        let inflight = initial_cwnd / 2;
        reno.on_loss(Instant::from_millis(0), inflight);
        assert_eq!(reno.ssthresh, inflight / 2);
        assert_eq!(reno.cwnd, inflight / 2 + 3 * MSS);

        // in fast recovery, each dup-ACK should increase  the cwnd by 1 MSS
        let initial_cwnd = reno.window();
        for i in 0..3 {
            for _ in 0..3 {
                let initial_cwnd = reno.window();
                reno.on_dup_ack(Instant::from_millis(i), MSS, initial_cwnd);
                assert_eq!(reno.window(), initial_cwnd + MSS);
            }

            // multiple loss events (trip-dup-ack) should not trigger additional fast recovery reductions
            let initial_cwnd = reno.window();
            let initial_ssthresh = reno.ssthresh;
            reno.on_loss(Instant::from_millis(i), initial_cwnd);
            assert_eq!(reno.window(), initial_cwnd);
            assert_eq!(reno.ssthresh, initial_ssthresh);
        }
        assert_eq!(reno.window(), initial_cwnd + MSS * 9);

        // a non-duplicate ACK exits fast recovery and enters congestion avoidance
        ack(&mut reno, MSS, Instant::from_millis(10));
        assert_eq!(reno.window(), reno.ssthresh);

        // CA is slower growth so should be less than 1MSS per ACK
        let initial_cwnd = reno.window();
        ack(&mut reno, MSS, Instant::from_millis(30));
        assert!(reno.window() < initial_cwnd + MSS);
    }

    #[test]
    fn slow_start_works() {
        let mut reno = Reno::new();
        reno.set_mss(MSS);
        reno.cwnd = MSS * 32;
        reno.ssthresh = MSS * 16;

        // we enter recovery upon major loss (an RTO)
        // window should become to 1MSS
        // sstresh should become half the in-flight bytes
        let initial_cwnd = reno.window();
        let inflight = initial_cwnd;
        reno.on_rto(Instant::from_millis(0), initial_cwnd);
        assert_eq!(reno.ssthresh, inflight / 2);
        assert_eq!(reno.window(), MSS);

        // slow start grows by at most the MSS per ack
        let initial_cwnd = reno.window();
        for i in 0..10 {
            let initial_cwnd = reno.window();
            let now = Instant::from_millis(i);
            ack(&mut reno, MSS * 2, now);
            assert_eq!(reno.window(), initial_cwnd + MSS);
        }
        assert_eq!(reno.window(), initial_cwnd + MSS * 10);

        // slow start uses the number of ACKed bytes if they're less than the MSS
        let initial_cwnd = reno.window();
        for i in 0..10 {
            let initial_cwnd = reno.window();
            let now = Instant::from_millis(10 + i);
            ack(&mut reno, MSS / 2, now);
            assert_eq!(reno.window(), initial_cwnd + MSS / 2);
        }
        assert_eq!(reno.window(), initial_cwnd + MSS / 2 * 10);

        // slow start transitions to congestion avoidance at ssthresh
        let initial_cwnd = reno.window();
        reno.ssthresh = initial_cwnd + MSS;
        ack(&mut reno, MSS, Instant::from_millis(30));
        assert_eq!(reno.window(), initial_cwnd + MSS);
        assert_eq!(reno.ssthresh, initial_cwnd + MSS);

        // slow start transitions to congestion avoidance at ssthresh
        // CA is slower growth so should be less than 1MSS per ACK
        let initial_cwnd = reno.window();
        ack(&mut reno, MSS, Instant::from_millis(30));
        assert!(reno.window() < initial_cwnd + MSS);
    }

    #[test]
    fn progress_to_ca_via_rto() {
        let mut reno = Reno::new();
        reno.set_mss(MSS);

        let mut time = 0;

        // slow start from default state
        let initial_cwnd = reno.window();
        for _ in 0..30 {
            time += 1;
            ack(&mut reno, MSS, Instant::from_millis(time));
        }
        assert_eq!(reno.window(), initial_cwnd + MSS * 30);
        assert!(reno.window() < reno.ssthresh);

        // rto: cwnd resets to MSS, ssthresh becomes half in-flight bytes
        let rto_cwnd = reno.window();
        reno.on_rto(Instant::from_millis(time), rto_cwnd);
        assert_eq!(reno.window(), MSS);
        assert_eq!(reno.ssthresh, rto_cwnd / 2);

        // slow start again until cwnd reaches new ssthresh
        while reno.window() < reno.ssthresh {
            time += 1;
            let initial_cwnd = reno.window();
            ack(&mut reno, MSS, Instant::from_millis(time));
            assert_eq!(reno.window(), initial_cwnd + MSS);
        }
        assert_eq!(reno.window(), reno.ssthresh);

        // ca: each ack at or above ssthresh grows by less than MSS
        time += 1;
        let initial_cwnd = reno.window();
        ack(&mut reno, MSS, Instant::from_millis(time));
        assert!(reno.window() > initial_cwnd);
        assert!(reno.window() < initial_cwnd + MSS);
    }

    #[test]
    fn progress_to_ca_via_loss() {
        let mut reno = Reno::new();
        reno.set_mss(MSS);

        let mut time = 0;

        // slow start from default state
        let initial_cwnd = reno.window();
        for _ in 0..30 {
            time += 1;
            ack(&mut reno, MSS, Instant::from_millis(time));
        }
        assert_eq!(reno.window(), initial_cwnd + MSS * 30);
        assert!(reno.window() < reno.ssthresh);

        // dup ACKs: cwnd and sstresh become half in-flight bytes AND cwnd gets advanced for each dup-ack it had received
        time += 1;
        let loss_cwnd = reno.window();
        let expected_ssthresh = loss_cwnd / 2;
        reno.on_loss(Instant::from_millis(time), loss_cwnd);
        assert_eq!(reno.ssthresh, expected_ssthresh);
        assert_eq!(reno.window(), expected_ssthresh + 3 * MSS);
        assert_eq!(reno.recovery_start, Some(Instant::from_millis(time)));

        // inflate cwnd until on each duplicate ACK
        for _ in 0..9 {
            time += 1;
            let initial_cwnd = reno.window();
            reno.on_dup_ack(Instant::from_millis(time), MSS, reno.cwnd);
            assert_eq!(reno.window(), initial_cwnd + MSS);
        }

        // non-duplicate ACK deflates cwnd to ssthresh
        time += 1;
        ack(&mut reno, MSS, Instant::from_millis(time));
        assert_eq!(reno.window(), expected_ssthresh);
        assert_eq!(reno.recovery_start, None);

        // ca: each ack at or above ssthresh grows by less than MSS
        time += 1;
        let initial_cwnd = reno.window();
        ack(&mut reno, MSS, Instant::from_millis(time));
        assert!(reno.window() > initial_cwnd);
        assert!(reno.window() < initial_cwnd + MSS);
    }

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
