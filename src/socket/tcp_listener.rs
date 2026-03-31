use crate::iface::Context;
use crate::socket::PollAt;
use crate::time::{Duration, Instant};
use crate::wire::*;

/// Timeout for half-open (SYN_RECEIVED) entries, in milliseconds.
///
/// Entries older than this are silently evicted when a fresh SYN needs a
/// slot.
const SYN_TIMEOUT_MS: i64 = 75_000;
const SYN_RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);

/// Lightweight state for a half-open (SYN_RECEIVED) connection.
///
/// Users never need to inspect or construct this type directly.  Create
/// arrays of `Option<HalfOpen>` initialised to `None` and pass them to
/// [`Socket::new`]:
///
/// ```rust,ignore
/// let mut syn_buf: [Option<tcp_listener::HalfOpen>; 16] = [None; 16];
/// ```
#[derive(Debug, Clone, Copy)]
pub struct HalfOpen {
    local: IpEndpoint,
    remote: IpEndpoint,
    /// Our ISN (the `seq_number` we put in the SYN-ACK).
    local_seq_no: TcpSeqNumber,
    /// Remote ISN + 1 (the `ack_number` we put in the SYN-ACK).
    remote_seq_no: TcpSeqNumber,
    remote_mss: u16,
    remote_win_scale: Option<u8>,
    remote_win_len: u16,
    remote_has_sack: bool,
    /// MSS we advertised in our SYN-ACK (cached for retransmit on
    /// duplicate SYN).
    our_mss: u16,
    /// Creation timestamp (for expiry).
    created_at: Instant,
    /// When to retransmit the SYN-ACK if the handshake is still incomplete.
    retransmit_at: Instant,
    /// The final ACK of the three-way handshake has been received, but the
    /// accept queue was full at that moment.  Stop retransmitting SYN-ACK and
    /// wait for userspace to drain the accept queue; promote without needing
    /// another client ACK.
    ack_received: bool,
}

/// Information about a completed TCP connection, ready to be accepted.
///
/// Obtained from [`Socket::accept`] and passed to
/// [`tcp::Socket::accept`](super::tcp::Socket::accept) to initialise a
/// full TCP socket in the ESTABLISHED state.
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
    pub(crate) remote_win_len: usize,
    pub(crate) remote_has_sack: bool,
}

/// Re-export for convenience.
pub use super::tcp::ListenError;

/// A TCP listening socket with a lightweight SYN queue.
///
/// Unlike [`tcp::Socket`](super::tcp::Socket), this socket only handles the
/// listening phase of TCP.  Incoming SYN packets create lightweight
/// [`HalfOpen`] entries in a fixed-size SYN queue; when the three-way
/// handshake completes the connection is promoted to the accept queue as
/// a [`PendingConnection`].
///
/// # Usage
///
/// ```rust,ignore
/// let mut syn_buf = [None; 16];   // room for 16 half-open connections
/// let mut accept_buf = [None; 4]; // room for 4 completed connections
/// let mut listen = tcp_listener::Socket::new(&mut syn_buf[..], &mut accept_buf[..]);
/// listen.listen(4243).unwrap();
///
/// // In your poll loop, after iface.poll():
/// if let Some(pending) = listen.accept() {
///     let mut tcp = tcp::Socket::new(
///         tcp::SocketBuffer::new(vec![0; 1024]),
///         tcp::SocketBuffer::new(vec![0; 1024]),
///     );
///     tcp.accept(pending).unwrap();
///     // tcp is now ESTABLISHED
/// }
/// ```
pub struct Socket<'a> {
    listen_endpoint: IpListenEndpoint,
    /// Queue of half-open (SYN_RECEIVED) connections.
    syn_queue: &'a mut [Option<HalfOpen>],
    /// Queue of completed connections waiting to be accepted.
    accept_queue: &'a mut [Option<PendingConnection>],
    #[cfg(feature = "async")]
    waker: crate::socket::WakerRegistration,
}

impl<'a> Socket<'a> {
    /// Create a new TCP listen socket.
    ///
    /// * `syn_queue` – storage for half-open connections (SYN_RECEIVED).
    ///   Its length limits the number of concurrent in-progress handshakes.
    /// * `accept_queue` – storage for completed connections waiting to be
    ///   accepted.  Its length is the backlog.
    pub fn new(
        syn_queue: &'a mut [Option<HalfOpen>],
        accept_queue: &'a mut [Option<PendingConnection>],
    ) -> Self {
        Self {
            listen_endpoint: IpListenEndpoint::default(),
            syn_queue,
            accept_queue,
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
        // Already listening on the same endpoint? Nothing to do.
        if self.is_listening() {
            if self.listen_endpoint == local_endpoint {
                return Ok(());
            } else {
                return Err(ListenError::InvalidState);
            }
        }
        // Clear any stale state from a previous listen session.
        for slot in self.syn_queue.iter_mut() {
            *slot = None;
        }
        for slot in self.accept_queue.iter_mut() {
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

    /// Pop a completed connection from the accept queue.
    pub fn accept(&mut self) -> Option<PendingConnection> {
        for slot in self.accept_queue.iter_mut() {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// Return whether there is at least one completed connection ready.
    pub fn can_accept(&self) -> bool {
        self.accept_queue.iter().any(|s| s.is_some())
    }

    /// Register a waker for async accept notification.
    #[cfg(feature = "async")]
    pub fn register_accept_waker(&mut self, waker: &core::task::Waker) {
        self.waker.register(waker);
    }

    // ── internal helpers ──────────────────────────────────────────

    /// Find a half-open entry matching the given 4-tuple.
    fn find_syn(&self, local: &IpEndpoint, remote: &IpEndpoint) -> Option<usize> {
        self.syn_queue.iter().position(|s| {
            matches!(s, Some(ho) if ho.local == *local && ho.remote == *remote)
        })
    }

    /// Check whether a completed connection with these endpoints exists.
    fn has_pending(&self, local: &IpEndpoint, remote: &IpEndpoint) -> bool {
        self.accept_queue.iter().any(|entry| {
            matches!(entry, Some(pc) if pc.local == *local && pc.remote == *remote)
        })
    }

    /// Check whether the SYN queue has a free or expired slot.
    fn syn_queue_available(&self, now: Instant) -> bool {
        self.syn_queue.iter().any(|s| match s {
            None => true,
            Some(ho) => now.total_millis() - ho.created_at.total_millis() >= SYN_TIMEOUT_MS,
        })
    }

    /// Check whether the accept queue has at least one free slot.
    fn has_free_accept_slot(&self) -> bool {
        self.accept_queue.iter().any(|s| s.is_none())
    }

    /// Allocate a SYN queue slot, preferring empty ones, then expired ones.
    fn alloc_syn_slot(&mut self, now: Instant) -> Option<&mut Option<HalfOpen>> {
        // Prefer genuinely empty slots.
        let idx = self.syn_queue.iter().position(|s| s.is_none());
        if let Some(i) = idx {
            return Some(&mut self.syn_queue[i]);
        }
        // Fall back to the oldest expired entry.
        let idx = self.syn_queue.iter().position(|s| {
            matches!(s, Some(ho) if now.total_millis() - ho.created_at.total_millis() >= SYN_TIMEOUT_MS)
        });
        if let Some(i) = idx {
            return Some(&mut self.syn_queue[i]);
        }
        None
    }

    fn prune_expired(&mut self, now: Instant) {
        for slot in self.syn_queue.iter_mut() {
            if matches!(
                slot,
                Some(ho) if now.total_millis() - ho.created_at.total_millis() >= SYN_TIMEOUT_MS
            ) {
                *slot = None;
            }
        }
    }

    /// Build a SYN-ACK reply from a half-open entry.
    fn make_syn_ack(ho: &HalfOpen) -> (IpRepr, TcpRepr<'static>) {
        let reply = TcpRepr {
            src_port: ho.local.port,
            dst_port: ho.remote.port,
            control: TcpControl::Syn,
            seq_number: ho.local_seq_no,
            ack_number: Some(ho.remote_seq_no),
            // Advertise a large window; the accepting TcpSocket will
            // correct it once it has an actual rx buffer.
            window_len: u16::MAX,
            // We don't know the rx buffer size yet, so don't offer scaling.
            window_scale: Some(0),
            max_seg_size: Some(ho.our_mss),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_reply = IpRepr::new(
            ho.local.addr,
            ho.remote.addr,
            IpProtocol::Tcp,
            reply.buffer_len(),
            64,
        );
        (ip_reply, reply)
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
            return if self.find_syn(&local, &remote).is_some()
                || self.has_pending(&local, &remote)
                || self.syn_queue_available(cx.now())
            {
                IngressAction::Handle
            } else {
                // Listener exists, but its lightweight backlog is full.
                IngressAction::Drop
            };
        }

        // Non-RST packet with ACK: might complete a handshake or belong
        // to an already-completed connection.
        if repr.control != TcpControl::Rst && repr.ack_number.is_some() {
            // Already completed? Absorb to suppress an RST.
            if self.has_pending(&local, &remote) {
                return IngressAction::Handle;
            }
            // Matching half-open – hold the ACK until userspace drains the
            // accept queue instead of actively rejecting it with an RST.
            if self.find_syn(&local, &remote).is_some() {
                return if self.has_free_accept_slot() {
                    IngressAction::Handle
                } else {
                    net_debug!("tcp listen: accept queue full, deferring completion");
                    IngressAction::Drop
                };
            }
        }

        IngressAction::Ignore
    }

    /// Process an incoming TCP packet.
    ///
    /// Returns a SYN-ACK for new SYN packets.  ACKs completing the
    /// three-way handshake are silently enqueued into the accept queue.
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            return self.process_syn(cx, ip_repr, repr);
        }

        if repr.ack_number.is_some() {
            self.process_ack(ip_repr, repr);
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

        // Already in accept_queue? Absorb silently.
        if self.has_pending(&local, &remote) {
            return None;
        }

        // Already in syn_queue? Handle duplicate / new SYN.
        if let Some(idx) = self.find_syn(&local, &remote) {
            let ho = self.syn_queue[idx].as_mut().unwrap();
            if repr.seq_number + 1 == ho.remote_seq_no {
                // Duplicate SYN (same ISN) → resend SYN-ACK unchanged.
                return Some(Self::make_syn_ack(ho));
            }
            // Different ISN → treat as a fresh connection on the same
            // 4-tuple (e.g. client rebooted).  Regenerate our ISN.
            let remote_mss = repr.max_seg_size.unwrap_or(536);
            if remote_mss == 0 {
                return None;
            }
            let ip_tmp = IpRepr::new(
                ip_repr.dst_addr(), ip_repr.src_addr(), IpProtocol::Tcp, 0, 64,
            );
            let our_mss =
                (cx.ip_mtu() - ip_tmp.header_len() - TCP_HEADER_LEN) as u16;
            *ho = HalfOpen {
                local,
                remote,
                local_seq_no: TcpSeqNumber(cx.rand().rand_u32() as i32),
                remote_seq_no: repr.seq_number + 1,
                remote_mss,
                remote_win_scale: repr.window_scale,
                remote_win_len: repr.window_len,
                remote_has_sack: repr.sack_permitted,
                our_mss,
                created_at: now,
                retransmit_at: now + SYN_RETRANSMIT_DELAY,
                ack_received: false,
            };
            return Some(Self::make_syn_ack(ho));
        }

        // Brand-new SYN → allocate a slot.
        let remote_mss = repr.max_seg_size.unwrap_or(536);
        if remote_mss == 0 {
            return None;
        }
        let ip_tmp = IpRepr::new(
            ip_repr.dst_addr(), ip_repr.src_addr(), IpProtocol::Tcp, 0, 64,
        );
        let our_mss =
            (cx.ip_mtu() - ip_tmp.header_len() - TCP_HEADER_LEN) as u16;
        let local_seq = TcpSeqNumber(cx.rand().rand_u32() as i32);

        let slot = self.alloc_syn_slot(now)?;
        *slot = Some(HalfOpen {
            local,
            remote,
            local_seq_no: local_seq,
            remote_seq_no: repr.seq_number + 1,
            remote_mss,
            remote_win_scale: repr.window_scale,
            remote_win_len: repr.window_len,
            remote_has_sack: repr.sack_permitted,
            our_mss,
            created_at: now,
            retransmit_at: now + SYN_RETRANSMIT_DELAY,
            ack_received: false,
        });
        Some(Self::make_syn_ack(slot.as_ref().unwrap()))
    }

    fn process_ack(
        &mut self,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) {
        let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
        let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);

        // Already completed? Nothing more to do.
        if self.has_pending(&local, &remote) {
            return;
        }

        // Look up the matching half-open entry.
        let Some(idx) = self.find_syn(&local, &remote) else {
            return;
        };
        let ho = self.syn_queue[idx].as_ref().unwrap();

        // Verify the client is ACK-ing our ISN + 1, and that its
        // sequence number matches what we expect (their ISN + 1).
        let expected_ack = ho.local_seq_no + 1;
        if repr.ack_number != Some(expected_ack) || repr.seq_number != ho.remote_seq_no {
            return;
        }

        // Promote to accept_queue.
        let Some(accept_slot) = self.accept_queue.iter_mut().find(|s| s.is_none())
        else {
            // accept_queue is full right now.  Mark the half-open entry so we
            // stop retransmitting SYN-ACK (the client already did its part) and
            // promote it once userspace drains the queue.
            net_debug!("tcp listen: accept queue full, parking completed handshake");
            self.syn_queue[idx].as_mut().unwrap().ack_received = true;
            return;
        };

        *accept_slot = Some(PendingConnection {
            local: ho.local,
            remote: ho.remote,
            local_seq_no: expected_ack,            // next seq we send
            remote_seq_no: ho.remote_seq_no,       // next seq we expect
            remote_mss: ho.remote_mss as usize,
            remote_win_scale: ho.remote_win_scale,
            remote_win_len: ho.remote_win_len as usize,
            remote_has_sack: ho.remote_has_sack,
        });

        // Remove from syn_queue.
        self.syn_queue[idx] = None;

        #[cfg(feature = "async")]
        self.waker.wake();
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        cx: &mut Context,
        emit: F,
    ) -> core::result::Result<(), E>
    where
        F: FnOnce(
            &mut Context,
            (IpRepr, TcpRepr<'static>),
        ) -> core::result::Result<(), E>,
    {
        self.prune_expired(cx.now());

        // Promote any parked entries whose ACK already arrived but the accept
        // queue was full at the time.
        for slot in self.syn_queue.iter_mut() {
            let promote = matches!(slot, Some(ho) if ho.ack_received);
            if promote {
                let Some(accept_slot) = self.accept_queue.iter_mut().find(|s| s.is_none())
                else {
                    break; // still full
                };
                let ho = slot.take().unwrap();
                let expected_ack = ho.local_seq_no + 1;
                *accept_slot = Some(PendingConnection {
                    local: ho.local,
                    remote: ho.remote,
                    local_seq_no: expected_ack,
                    remote_seq_no: ho.remote_seq_no,
                    remote_mss: ho.remote_mss as usize,
                    remote_win_scale: ho.remote_win_scale,
                    remote_win_len: ho.remote_win_len as usize,
                    remote_has_sack: ho.remote_has_sack,
                });
                #[cfg(feature = "async")]
                self.waker.wake();
            }
        }

        let Some(half_open) = self
            .syn_queue
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|ho| !ho.ack_received && ho.retransmit_at <= cx.now())
        else {
            return Ok(());
        };

        let packet = Self::make_syn_ack(half_open);
        emit(cx, packet)?;
        half_open.retransmit_at = cx.now() + SYN_RETRANSMIT_DELAY;
        Ok(())
    }

    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        let now = cx.now();

        self.syn_queue
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|ho| {
                let expires_at = ho.created_at + Duration::from_millis(SYN_TIMEOUT_MS as u64);
                let wake_at = ho.retransmit_at.min(expires_at);
                if wake_at <= now {
                    PollAt::Now
                } else {
                    PollAt::Time(wake_at)
                }
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

pub(crate) enum IngressAction {
    Ignore,
    Handle,
    Drop,
}

impl core::fmt::Debug for Socket<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tcp_listener::Socket")
            .field("listen_endpoint", &self.listen_endpoint)
            .field(
                "syn_queue_len",
                &self.syn_queue.iter().filter(|s| s.is_some()).count(),
            )
            .field(
                "accept_queue_len",
                &self.accept_queue.iter().filter(|s| s.is_some()).count(),
            )
            .finish()
    }
}
