use crate::time::Instant;

use super::RttEstimator;

pub(super) mod no_control;

#[cfg(feature = "socket-tcp-cubic")]
pub(super) mod cubic;

#[cfg(feature = "socket-tcp-reno")]
pub(super) mod reno;

#[cfg(feature = "socket-tcp-bbr")]
pub(super) mod bbr;

#[allow(unused_variables)]
pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {}

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator, bytes_in_flight: usize) {}

    fn on_retransmit(&mut self, now: Instant) {}

    fn on_duplicate_ack(&mut self, now: Instant) {}

    fn pre_transmit(&mut self, now: Instant) {}

    fn post_transmit(&mut self, now: Instant, len: usize) {}

    /// Set the maximum segment size.
    fn set_mss(&mut self, mss: usize) {}

    /// Called when the socket is about to send data.
    /// `bytes_available` indicates how many bytes are waiting in the send buffer.
    /// This allows the congestion controller to track whether the application
    /// is app-limited (not enough data to send) or cwnd-limited.
    fn on_send_ready(&mut self, now: Instant, bytes_available: usize) {}

    /// Returns the pacing rate in bytes per second.
    /// Returns 0 if pacing is not supported or not active.
    fn pacing_rate(&self) -> u64 {
        0
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub(super) enum AnyController {
    None(no_control::NoControl),

    #[cfg(feature = "socket-tcp-reno")]
    Reno(reno::Reno),

    #[cfg(feature = "socket-tcp-cubic")]
    Cubic(cubic::Cubic),

    #[cfg(feature = "socket-tcp-bbr")]
    Bbr(bbr::Bbr),
}

impl AnyController {
    /// Create a new congestion controller.
    /// `AnyController::new()` selects the best congestion controller based on the features.
    ///
    /// - If `socket-tcp-bbr` feature is enabled, it will use `Bbr`.
    /// - If `socket-tcp-cubic` feature is enabled, it will use `Cubic`.
    /// - If `socket-tcp-reno` feature is enabled, it will use `Reno`.
    /// - Priority: BBR > Cubic > Reno > NoControl
    ///    - `BBR` is optimized for high bandwidth-delay product networks.
    ///    - `Cubic` is more efficient regarding throughput.
    ///    - `Reno` is more conservative and is suitable for low-power devices.
    /// - If no congestion controller is available, it will use `NoControl`.
    ///
    /// Users can also select a congestion controller manually by [`super::Socket::set_congestion_control()`]
    /// method at run-time.
    #[allow(unreachable_code)]
    #[inline]
    pub fn new() -> Self {
        #[cfg(feature = "socket-tcp-bbr")]
        {
            return AnyController::Bbr(bbr::Bbr::new());
        }

        #[cfg(feature = "socket-tcp-cubic")]
        {
            return AnyController::Cubic(cubic::Cubic::new());
        }

        #[cfg(feature = "socket-tcp-reno")]
        {
            return AnyController::Reno(reno::Reno::new());
        }

        AnyController::None(no_control::NoControl)
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn Controller {
        match self {
            AnyController::None(n) => n,

            #[cfg(feature = "socket-tcp-reno")]
            AnyController::Reno(r) => r,

            #[cfg(feature = "socket-tcp-cubic")]
            AnyController::Cubic(c) => c,

            #[cfg(feature = "socket-tcp-bbr")]
            AnyController::Bbr(b) => b,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn Controller {
        match self {
            AnyController::None(n) => n,

            #[cfg(feature = "socket-tcp-reno")]
            AnyController::Reno(r) => r,

            #[cfg(feature = "socket-tcp-cubic")]
            AnyController::Cubic(c) => c,

            #[cfg(feature = "socket-tcp-bbr")]
            AnyController::Bbr(b) => b,
        }
    }
}
