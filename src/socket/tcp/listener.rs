use crate::iface::Context;
use crate::socket::PollAt;
use crate::time::{Duration, Instant};
use crate::wire::*;
use managed::ManagedSlice;
use super::ListenError;

/// Timeout for half-open (SYN_RECEIVED) entries, in milliseconds.
///
/// Entries older than this are silently evicted when a fresh SYN needs a
/// slot.
const SYN_TIMEOUT_MS: i64 = 75_000;
const SYN_RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);

/// A single slot in the listener backlog.
///
/// Each entry is either a half-open connection (SYN_RECEIVED, still
/// completing the three-way handshake) or a completed connection waiting
/// to be accepted by userspace.
#[derive(Debug, Clone, Copy)]
pub enum BacklogEntry {
    /// SYN received, SYN-ACK sent, waiting for the final ACK.
    HalfOpen {
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
        /// MSS we advertised in our SYN-ACK.
        our_mss: u16,
        /// Creation timestamp (for expiry).
        created_at: Instant,
        /// When to retransmit the SYN-ACK.
        retransmit_at: Instant,
    },
    /// Three-way handshake completed; waiting for userspace `accept()`.
    Completed {
        local: IpEndpoint,
        remote: IpEndpoint,
        local_seq_no: TcpSeqNumber,
        remote_seq_no: TcpSeqNumber,
        remote_mss: u16,
        remote_win_scale: Option<u8>,
        remote_win_len: u16,
        remote_has_sack: bool,
    },
}

/// Information about a completed TCP connection, ready to be accepted.
///
/// Obtained from [`Listener::accept`] and passed to
/// [`tcp::Socket::accept`](super::Socket::accept) to initialise a
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

/// A TCP listening socket with a unified backlog.
///
/// Unlike [`tcp::Socket`](super::Socket), this socket only handles the
/// listening phase of TCP.  Incoming SYN packets create lightweight
/// half-open entries in the backlog; when the three-way handshake
/// completes the entry is promoted to *completed* and can be retrieved
/// via [`accept`](Listener::accept).
///
/// # Usage
///
/// ```rust,ignore
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
///     // tcp is now ESTABLISHED
/// }
/// ```
pub struct Listener<'a> {
    listen_endpoint: IpListenEndpoint,
    /// Unified backlog of half-open and completed connections.
    backlog: ManagedSlice<'a, Option<BacklogEntry>>,
    #[cfg(feature = "async")]
    waker: crate::socket::WakerRegistration,
}

impl<'a> Listener<'a> {
    /// Create a new TCP listen socket.
    ///
    /// * `backlog` – storage for both half-open (SYN_RECEIVED) and
    ///   completed connections.  Its length limits the total number of
    ///   in-progress handshakes plus completed connections waiting to be
    ///   accepted.
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

    /// Pop a completed connection from the backlog.
    pub fn accept(&mut self) -> Option<PendingConnection> {
        for slot in self.backlog.iter_mut() {
            if let Some(BacklogEntry::Completed {
                local,
                remote,
                local_seq_no,
                remote_seq_no,
                remote_mss,
                remote_win_scale,
                remote_win_len,
                remote_has_sack,
            }) = slot
            {
                let pc = PendingConnection {
                    local: *local,
                    remote: *remote,
                    local_seq_no: *local_seq_no,
                    remote_seq_no: *remote_seq_no,
                    remote_mss: *remote_mss as usize,
                    remote_win_scale: *remote_win_scale,
                    remote_win_len: *remote_win_len as usize,
                    remote_has_sack: *remote_has_sack,
                };
                *slot = None;
                return Some(pc);
            }
        }
        None
    }

    /// Return whether there is at least one completed connection ready.
    pub fn can_accept(&self) -> bool {
        self.backlog
            .iter()
            .any(|s| matches!(s, Some(BacklogEntry::Completed { .. })))
    }

    /// Register a waker for async accept notification.
    #[cfg(feature = "async")]
    pub fn register_accept_waker(&mut self, waker: &core::task::Waker) {
        self.waker.register(waker);
    }

    // ── internal helpers ──────────────────────────────────────────

    /// Find a half-open entry matching the given 4-tuple.
    fn find_half_open(&self, local: &IpEndpoint, remote: &IpEndpoint) -> Option<usize> {
        self.backlog.iter().position(|s| {
            matches!(s, Some(BacklogEntry::HalfOpen { local: l, remote: r, .. }) if l == local && r == remote)
        })
    }

    /// Check whether a completed connection with these endpoints exists.
    fn has_completed(&self, local: &IpEndpoint, remote: &IpEndpoint) -> bool {
        self.backlog.iter().any(|s| {
            matches!(s, Some(BacklogEntry::Completed { local: l, remote: r, .. }) if l == local && r == remote)
        })
    }

    /// Check whether the backlog has a free slot or an expired half-open
    /// entry that can be recycled.
    fn has_available_slot(&self, now: Instant) -> bool {
        self.backlog.iter().any(|s| match s {
            None => true,
            Some(BacklogEntry::HalfOpen { created_at, .. }) => {
                now.total_millis() - created_at.total_millis() >= SYN_TIMEOUT_MS
            }
            _ => false,
        })
    }

    /// Allocate a backlog slot, preferring empty ones, then expired
    /// half-open entries.
    fn alloc_slot(&mut self, now: Instant) -> Option<&mut Option<BacklogEntry>> {
        let idx = self.backlog.iter().position(|s| s.is_none());
        if let Some(i) = idx {
            return Some(&mut self.backlog[i]);
        }
        let idx = self.backlog.iter().position(|s| {
            matches!(
                s,
                Some(BacklogEntry::HalfOpen { created_at, .. })
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
                Some(BacklogEntry::HalfOpen { created_at, .. })
                    if now.total_millis() - created_at.total_millis() >= SYN_TIMEOUT_MS
            ) {
                *slot = None;
            }
        }
    }

    /// Build a SYN-ACK reply from a half-open entry.
    fn make_syn_ack(entry: &BacklogEntry) -> (IpRepr, TcpRepr<'static>) {
        let (local, remote, local_seq_no, remote_seq_no, our_mss) = match entry {
            BacklogEntry::HalfOpen {
                local,
                remote,
                local_seq_no,
                remote_seq_no,
                our_mss,
                ..
            } => (local, remote, local_seq_no, remote_seq_no, our_mss),
            _ => unreachable!(),
        };
        let reply = TcpRepr {
            src_port: local.port,
            dst_port: remote.port,
            control: TcpControl::Syn,
            seq_number: *local_seq_no,
            ack_number: Some(*remote_seq_no),
            window_len: u16::MAX,
            window_scale: Some(0),
            max_seg_size: Some(*our_mss),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_reply = IpRepr::new(
            local.addr,
            remote.addr,
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
            return if self.find_half_open(&local, &remote).is_some()
                || self.has_completed(&local, &remote)
                || self.has_available_slot(cx.now())
            {
                IngressAction::Handle
            } else {
                IngressAction::Drop
            };
        }

        // Non-RST packet with ACK
        if repr.control != TcpControl::Rst && repr.ack_number.is_some() {
            if self.has_completed(&local, &remote) {
                return IngressAction::Handle;
            }
            if self.find_half_open(&local, &remote).is_some() {
                return IngressAction::Handle;
            }
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

        if repr.ack_number.is_some() {
            self.process_ack(cx, ip_repr, repr);
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

        // Already completed? Absorb silently.
        if self.has_completed(&local, &remote) {
            return None;
        }

        // Already half-open? Handle duplicate / new SYN.
        if let Some(idx) = self.find_half_open(&local, &remote) {
            if let Some(BacklogEntry::HalfOpen {
                remote_seq_no: ref rsn,
                ..
            }) = self.backlog[idx]
            {
                if repr.seq_number + 1 == *rsn {
                    return Some(Self::make_syn_ack(self.backlog[idx].as_ref().unwrap()));
                }
            }
            // Different ISN → fresh connection on same 4-tuple.
            let remote_mss = repr.max_seg_size.unwrap_or(536);
            if remote_mss == 0 {
                return None;
            }
            let ip_tmp = IpRepr::new(
                ip_repr.dst_addr(),
                ip_repr.src_addr(),
                IpProtocol::Tcp,
                0,
                64,
            );
            let our_mss = (cx.ip_mtu() - ip_tmp.header_len() - TCP_HEADER_LEN) as u16;
            self.backlog[idx] = Some(BacklogEntry::HalfOpen {
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
            });
            return Some(Self::make_syn_ack(self.backlog[idx].as_ref().unwrap()));
        }

        // Brand-new SYN → allocate a slot.
        let remote_mss = repr.max_seg_size.unwrap_or(536);
        if remote_mss == 0 {
            return None;
        }
        let ip_tmp = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            0,
            64,
        );
        let our_mss = (cx.ip_mtu() - ip_tmp.header_len() - TCP_HEADER_LEN) as u16;
        let local_seq = TcpSeqNumber(cx.rand().rand_u32() as i32);

        let slot = self.alloc_slot(now)?;
        *slot = Some(BacklogEntry::HalfOpen {
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
        });
        Some(Self::make_syn_ack(slot.as_ref().unwrap()))
    }

    fn process_ack(&mut self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) {
        let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
        let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);

        // Already completed? Nothing more to do.
        if self.has_completed(&local, &remote) {
            return;
        }

        let Some(idx) = self.find_half_open(&local, &remote) else {
            return;
        };

        let (local_seq_no, remote_seq_no, remote_mss, remote_win_scale, remote_win_len, remote_has_sack) =
            match self.backlog[idx] {
                Some(BacklogEntry::HalfOpen {
                    local_seq_no,
                    remote_seq_no,
                    remote_mss,
                    remote_win_scale,
                    remote_win_len,
                    remote_has_sack,
                    ..
                }) => (local_seq_no, remote_seq_no, remote_mss, remote_win_scale, remote_win_len, remote_has_sack),
                _ => return,
            };

        let expected_ack = local_seq_no + 1;
        if repr.ack_number != Some(expected_ack) || repr.seq_number != remote_seq_no {
            return;
        }

        // Promote to Completed in-place.
        self.backlog[idx] = Some(BacklogEntry::Completed {
            local,
            remote,
            local_seq_no: expected_ack,
            remote_seq_no,
            remote_mss,
            remote_win_scale,
            remote_win_len,
            remote_has_sack,
        });

        #[cfg(feature = "async")]
        self.waker.wake();
    }

    pub(crate) fn dispatch<F, E>(
        &mut self,
        cx: &mut Context,
        emit: F,
    ) -> core::result::Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, TcpRepr<'static>)) -> core::result::Result<(), E>,
    {
        self.prune_expired(cx.now());

        // Find the first half-open entry that needs a SYN-ACK retransmit.
        let Some(entry) = self
            .backlog
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|e| {
                matches!(
                    e,
                    BacklogEntry::HalfOpen {
                                retransmit_at,
                        ..
                    } if *retransmit_at <= cx.now()
                )
            })
        else {
            return Ok(());
        };

        let packet = Self::make_syn_ack(entry);
        emit(cx, packet)?;
        if let BacklogEntry::HalfOpen {
            retransmit_at,
            ..
        } = entry
        {
            *retransmit_at = cx.now() + SYN_RETRANSMIT_DELAY;
        }
        Ok(())
    }

    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        let now = cx.now();

        self.backlog
            .iter()
            .filter_map(|slot| match slot {
                Some(BacklogEntry::HalfOpen {
                    created_at,
                    retransmit_at,
                    ..
                }) => {
                    let expires_at =
                        *created_at + Duration::from_millis(SYN_TIMEOUT_MS as u64);
                    let wake_at = (*retransmit_at).min(expires_at);
                    if wake_at <= now {
                        Some(PollAt::Now)
                    } else {
                        Some(PollAt::Time(wake_at))
                    }
                }
                _ => None,
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

impl core::fmt::Debug for Listener<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tcp::Listener")
            .field("listen_endpoint", &self.listen_endpoint)
            .field(
                "half_open_count",
                &self
                    .backlog
                    .iter()
                    .filter(|s| matches!(s, Some(BacklogEntry::HalfOpen { .. })))
                    .count(),
            )
            .field(
                "completed_count",
                &self
                    .backlog
                    .iter()
                    .filter(|s| matches!(s, Some(BacklogEntry::Completed { .. })))
                    .count(),
            )
            .finish()
    }
}
