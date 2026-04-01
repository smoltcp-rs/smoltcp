use super::ListenError;
use crate::iface::Context;
use crate::socket::PollAt;
use crate::time::Instant;
use crate::wire::*;
use managed::ManagedSlice;

/// Timeout for queued SYN entries, in milliseconds.
///
/// Entries older than this are silently evicted when a fresh SYN needs a
/// slot.
const SYN_TIMEOUT_MS: i64 = 75_000;

/// A single slot in the listener backlog.
///
/// Each entry stores a queued SYN waiting for userspace `accept()`.
#[derive(Debug, Clone, Copy)]
pub struct BacklogEntry {
    local: IpEndpoint,
    remote: IpEndpoint,
    /// ISN to use once a `tcp::Socket` accepts this connection.
    local_seq_no: TcpSeqNumber,
    /// Remote ISN + 1.
    remote_seq_no: TcpSeqNumber,
    remote_mss: u16,
    remote_win_scale: Option<u8>,
    remote_has_sack: bool,
    /// Creation timestamp (for expiry).
    created_at: Instant,
}

/// Information about a queued TCP SYN, ready to be accepted.
///
/// Obtained from [`Listener::accept`] and passed to
/// [`tcp::Socket::accept`](super::Socket::accept) to initialise a
/// full TCP socket in the SYN-RECEIVED state.
#[derive(Debug, Clone, Copy)]
pub struct PendingConnection {
    /// Local endpoint of the connection.
    pub local: IpEndpoint,
    /// Remote endpoint of the connection.
    pub remote: IpEndpoint,
    pub(crate) local_seq_no: TcpSeqNumber,
    pub(crate) remote_seq_no: TcpSeqNumber,
    pub(crate) remote_mss: usize,
    pub(crate) remote_win_scale: Option<u8>,
    pub(crate) remote_has_sack: bool,
}

/// A TCP listening socket with a backlog of queued SYNs.
///
/// Unlike [`tcp::Socket`](super::Socket), this socket does not run the
/// handshake state machine. Incoming SYN packets create lightweight queued
/// entries in the backlog; once userspace calls [`accept`](Listener::accept),
/// the resulting [`PendingConnection`] is transferred into a full
/// [`tcp::Socket`](super::Socket), which continues the handshake in
/// SYN-RECEIVED.
///
/// # Usage
///
/// ```no_run
/// # #[cfg(all(
/// #     feature = "proto-ipv4",
/// #     feature = "socket-tcp",
/// # ))]
/// # {
/// # use smoltcp::socket::tcp;
/// # use smoltcp::socket::tcp::listener::Listener;
/// #
/// let mut backlog_buf = [None; 16];
/// let mut listen = Listener::new(&mut backlog_buf[..]);
/// listen.listen(4243).unwrap();
///
/// // In your poll loop, after iface.poll():
/// if let Some(pending) = listen.accept() {
///     let mut tcp = tcp::Socket::new(
///         tcp::SocketBuffer::new(vec![0; 1024]),
///         tcp::SocketBuffer::new(vec![0; 1024]),
///     );
///     tcp.accept(pending).unwrap();
///     // add `tcp` to your socket set, then poll to send SYN|ACK
/// }
/// # }
/// ```
pub struct Listener<'a> {
    listen_endpoint: IpListenEndpoint,
    /// Backlog of queued SYNs.
    backlog: ManagedSlice<'a, Option<BacklogEntry>>,
    #[cfg(feature = "async")]
    waker: crate::socket::WakerRegistration,
}

impl<'a> Listener<'a> {
    /// Create a new TCP listen socket.
    ///
    /// * `backlog` – storage for queued SYNs waiting to be accepted.
    ///   Its length limits the total number of pending connection attempts.
    pub fn new<S>(backlog: S) -> Self
    where
        S: Into<ManagedSlice<'a, Option<BacklogEntry>>>,
    {
        Self {
            listen_endpoint: IpListenEndpoint::default(),
            backlog: backlog.into(),
            #[cfg(feature = "async")]
            waker: crate::socket::WakerRegistration::new(),
        }
    }

    /// Start listening on the given endpoint.
    pub fn listen<T: Into<IpListenEndpoint>>(
        &mut self,
        local_endpoint: T,
    ) -> core::result::Result<(), ListenError> {
        let local_endpoint = local_endpoint.into();
        if local_endpoint.port == 0 {
            return Err(ListenError::Unaddressable);
        }
        if self.is_listening() {
            if self.listen_endpoint == local_endpoint {
                return Ok(());
            } else {
                return Err(ListenError::InvalidState);
            }
        }
        for slot in self.backlog.iter_mut() {
            *slot = None;
        }
        self.listen_endpoint = local_endpoint;
        Ok(())
    }

    /// Return the listen endpoint.
    pub fn listen_endpoint(&self) -> IpListenEndpoint {
        self.listen_endpoint
    }

    /// Return whether this socket is actively listening.
    pub fn is_listening(&self) -> bool {
        self.listen_endpoint.port != 0
    }

    /// Stop listening and clear the backlog.
    pub fn close(&mut self) {
        self.listen_endpoint = IpListenEndpoint::default();
        for slot in self.backlog.iter_mut() {
            *slot = None;
        }
    }

    /// Pop a queued SYN from the backlog.
    pub fn accept(&mut self) -> Option<PendingConnection> {
        for slot in self.backlog.iter_mut() {
            if let Some(BacklogEntry {
                local,
                remote,
                local_seq_no,
                remote_seq_no,
                remote_mss,
                remote_win_scale,
                remote_has_sack,
                ..
            }) = slot
            {
                let pc = PendingConnection {
                    local: *local,
                    remote: *remote,
                    local_seq_no: *local_seq_no,
                    remote_seq_no: *remote_seq_no,
                    remote_mss: *remote_mss as usize,
                    remote_win_scale: *remote_win_scale,
                    remote_has_sack: *remote_has_sack,
                };
                *slot = None;
                return Some(pc);
            }
        }
        None
    }

    /// Return whether there is at least one queued SYN ready.
    pub fn can_accept(&self) -> bool {
        self.backlog.iter().any(Option::is_some)
    }

    /// Register a waker for async accept notification.
    #[cfg(feature = "async")]
    pub fn register_accept_waker(&mut self, waker: &core::task::Waker) {
        self.waker.register(waker);
    }

    // ── internal helpers ──────────────────────────────────────────

    /// Find a queued SYN matching the given 4-tuple.
    fn find_pending(&self, local: &IpEndpoint, remote: &IpEndpoint) -> Option<usize> {
        self.backlog.iter().position(|s| {
            matches!(s, Some(BacklogEntry { local: l, remote: r, .. }) if l == local && r == remote)
        })
    }

    /// Check whether the backlog has a free slot or an expired queued SYN entry
    /// that can be recycled.
    fn has_available_slot(&self, now: Instant) -> bool {
        self.backlog.iter().any(|s| match s {
            None => true,
            Some(BacklogEntry { created_at, .. }) => {
                now.total_millis() - created_at.total_millis() >= SYN_TIMEOUT_MS
            }
        })
    }

    /// Allocate a backlog slot, preferring empty ones, then expired
    /// queued SYN entries.
    fn alloc_slot(&mut self, now: Instant) -> Option<&mut Option<BacklogEntry>> {
        let idx = self.backlog.iter().position(|s| s.is_none());
        if let Some(i) = idx {
            return Some(&mut self.backlog[i]);
        }
        let idx = self.backlog.iter().position(|s| {
            matches!(
                s,
                Some(BacklogEntry { created_at, .. })
                    if now.total_millis() - created_at.total_millis() >= SYN_TIMEOUT_MS
            )
        });
        if let Some(i) = idx {
            return Some(&mut self.backlog[i]);
        }
        None
    }

    fn prune_expired(&mut self, now: Instant) {
        for slot in self.backlog.iter_mut() {
            if matches!(
                slot,
                Some(BacklogEntry { created_at, .. })
                    if now.total_millis() - created_at.total_millis() >= SYN_TIMEOUT_MS
            ) {
                *slot = None;
            }
        }
    }

    // ── methods called by Interface ──────────────────────────────

    pub(crate) fn ingress_action(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> IngressAction {
        self.prune_expired(cx.now());

        if !self.is_listening() {
            return IngressAction::Ignore;
        }
        let addr_ok = match self.listen_endpoint.addr {
            Some(addr) => ip_repr.dst_addr() == addr,
            None => true,
        };
        if !addr_ok || repr.dst_port != self.listen_endpoint.port {
            return IngressAction::Ignore;
        }

        let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
        let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);

        // SYN (new connection attempt)
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            return if self.find_pending(&local, &remote).is_some()
                || self.has_available_slot(cx.now())
            {
                IngressAction::Handle
            } else {
                IngressAction::Drop
            };
        }

        // While a SYN is queued but not yet accepted, suppress fallback RSTs for
        // later packets on the same tuple. Once a full TCP socket is accepted,
        // it will be checked before the listener and take over processing.
        if repr.control != TcpControl::Rst && self.find_pending(&local, &remote).is_some() {
            return IngressAction::Drop;
        }

        IngressAction::Ignore
    }

    /// Process an incoming TCP packet.
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            return self.process_syn(cx, ip_repr, repr);
        }

        None
    }

    fn process_syn(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
        let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);
        let now = cx.now();

        // Already queued? Refresh duplicate SYNs or replace a fresh attempt.
        if let Some(idx) = self.find_pending(&local, &remote) {
            let remote_mss = repr.max_seg_size.unwrap_or(536);
            if remote_mss == 0 {
                return None;
            }
            let local_seq_no = match self.backlog[idx] {
                Some(BacklogEntry {
                    local_seq_no,
                    remote_seq_no,
                    ..
                }) if repr.seq_number + 1 == remote_seq_no => local_seq_no,
                _ => TcpSeqNumber(cx.rand().rand_u32() as i32),
            };
            self.backlog[idx] = Some(BacklogEntry {
                local,
                remote,
                local_seq_no,
                remote_seq_no: repr.seq_number + 1,
                remote_mss,
                remote_win_scale: repr.window_scale,
                remote_has_sack: repr.sack_permitted,
                created_at: now,
            });
            #[cfg(feature = "async")]
            self.waker.wake();
            return None;
        }

        // Brand-new SYN → allocate a slot.
        let remote_mss = repr.max_seg_size.unwrap_or(536);
        if remote_mss == 0 {
            return None;
        }
        let local_seq = TcpSeqNumber(cx.rand().rand_u32() as i32);

        let slot = self.alloc_slot(now)?;
        *slot = Some(BacklogEntry {
            local,
            remote,
            local_seq_no: local_seq,
            remote_seq_no: repr.seq_number + 1,
            remote_mss,
            remote_win_scale: repr.window_scale,
            remote_has_sack: repr.sack_permitted,
            created_at: now,
        });
        #[cfg(feature = "async")]
        self.waker.wake();
        None
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        _cx: &mut Context,
        _emit: F,
    ) -> core::result::Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, TcpRepr<'static>)) -> core::result::Result<(), E>,
    {
        Ok(())
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        PollAt::Ingress
    }
}

pub(crate) enum IngressAction {
    Ignore,
    Handle,
    Drop,
}

impl core::fmt::Debug for Listener<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tcp::Listener")
            .field("listen_endpoint", &self.listen_endpoint)
            .field(
                "pending_count",
                &self.backlog.iter().filter(|s| s.is_some()).count(),
            )
            .finish()
    }
}
