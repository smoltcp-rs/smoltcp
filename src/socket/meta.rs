use wire::IpAddress;
use super::{SocketHandle, PollAt};
use time::{Duration, Instant};

/// Neighbor dependency.
///
/// This enum tracks whether the socket should be polled based on the neighbor it is
/// going to send packets to.
#[derive(Debug)]
enum NeighborState {
    /// Socket can be polled immediately.
    Active,
    /// Socket should not be polled until either `silent_until` passes or `neighbor` appears
    /// in the neighbor cache.
    Waiting {
        neighbor: IpAddress,
        silent_until: Instant,
    }
}

impl Default for NeighborState {
    fn default() -> Self {
        NeighborState::Active
    }
}

/// Network socket metadata.
///
/// This includes things that only external (to the socket, that is) code
/// is interested in, but which are more conveniently stored inside the socket itself.
#[derive(Debug, Default)]
pub struct Meta {
    /// Handle of this socket within its enclosing `SocketSet`.
    /// Mainly useful for debug output.
    pub(crate) handle: SocketHandle,
    /// See [NeighborState](struct.NeighborState.html).
    neighbor_state:    NeighborState,
}

impl Meta {
    /// Minimum delay between neighbor discovery requests for this particular socket,
    /// in milliseconds.
    ///
    /// See also `iface::NeighborCache::SILENT_TIME`.
    pub(crate) const DISCOVERY_SILENT_TIME: Duration = Duration { millis: 3_000 };

    pub(crate) fn poll_at<F>(&self, socket_poll_at: PollAt, has_neighbor: F) -> PollAt 
        where F: Fn(IpAddress) -> bool
    {
        match self.neighbor_state {
            NeighborState::Active =>
                socket_poll_at,
            NeighborState::Waiting { neighbor, .. }
                    if has_neighbor(neighbor) =>
                socket_poll_at,
            NeighborState::Waiting { silent_until, .. } =>
                PollAt::Time(silent_until)
        }
    }

    pub(crate) fn egress_permitted<F>(&mut self, timestamp: Instant, has_neighbor: F) -> bool
        where F: Fn(IpAddress) -> bool
    {
        match self.neighbor_state {
            NeighborState::Active =>
                true,
            NeighborState::Waiting { neighbor, silent_until } => {
                if has_neighbor(neighbor) {
                    net_trace!("{}: neighbor {} discovered, unsilencing",
                               self.handle, neighbor);
                    self.neighbor_state = NeighborState::Active;
                    true
                } else if timestamp >= silent_until {
                    net_trace!("{}: neighbor {} silence timer expired, rediscovering", self.handle, neighbor);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub(crate) fn neighbor_missing(&mut self, timestamp: Instant, neighbor: IpAddress) {
        net_trace!("{}: neighbor {} missing, silencing until t+{}",
                   self.handle, neighbor, Self::DISCOVERY_SILENT_TIME);
        self.neighbor_state = NeighborState::Waiting {
            neighbor, silent_until: timestamp + Self::DISCOVERY_SILENT_TIME
        };
    }
}
