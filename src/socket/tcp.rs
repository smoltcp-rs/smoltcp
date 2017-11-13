// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP. Consult RFC 7414 when implementing
// a new feature.

use core::{cmp, fmt};

use {Error, Result};
use phy::DeviceCapabilities;
use wire::{IpProtocol, IpRepr, IpAddress, IpEndpoint, TcpSeqNumber, TcpRepr, TcpControl};
use socket::{Socket, SocketHandle};
use storage::{Assembler, RingBuffer};

pub type SocketBuffer<'a> = RingBuffer<'a, u8>;

/// The state of a TCP socket, according to [RFC 793][rfc793].
/// [rfc793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &State::Closed      => write!(f, "CLOSED"),
            &State::Listen      => write!(f, "LISTEN"),
            &State::SynSent     => write!(f, "SYN-SENT"),
            &State::SynReceived => write!(f, "SYN-RECEIVED"),
            &State::Established => write!(f, "ESTABLISHED"),
            &State::FinWait1    => write!(f, "FIN-WAIT-1"),
            &State::FinWait2    => write!(f, "FIN-WAIT-2"),
            &State::CloseWait   => write!(f, "CLOSE-WAIT"),
            &State::Closing     => write!(f, "CLOSING"),
            &State::LastAck     => write!(f, "LAST-ACK"),
            &State::TimeWait    => write!(f, "TIME-WAIT")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Timer {
    Idle {
        keep_alive_at: Option<u64>,
    },
    Retransmit {
        expires_at: u64,
        delay:      u64
    },
    Close {
        expires_at: u64
    }
}

const RETRANSMIT_DELAY: u64 = 100;
const CLOSE_DELAY:      u64 = 10_000;

impl Default for Timer {
    fn default() -> Timer {
        Timer::Idle { keep_alive_at: None }
    }
}

impl Timer {
    fn should_keep_alive(&self, timestamp: u64) -> bool {
        match *self {
            Timer::Idle { keep_alive_at: Some(keep_alive_at) }
                    if timestamp >= keep_alive_at => {
                true
            }
            _ => false
        }
    }

    fn should_retransmit(&self, timestamp: u64) -> Option<u64> {
        match *self {
            Timer::Retransmit { expires_at, delay }
                    if timestamp >= expires_at => {
                Some(timestamp - expires_at + delay)
            }
            _ => None
        }
    }

    fn should_close(&self, timestamp: u64) -> bool {
        match *self {
            Timer::Close { expires_at }
                    if timestamp >= expires_at => {
                true
            }
            _ => false
        }
    }

    fn poll_at(&self) -> Option<u64> {
        match *self {
            Timer::Idle { keep_alive_at } => keep_alive_at,
            Timer::Retransmit { expires_at, .. } => Some(expires_at),
            Timer::Close { expires_at } => Some(expires_at),
        }
    }

    fn set_for_idle(&mut self, timestamp: u64, interval: Option<u64>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval)
        }
    }

    fn set_keep_alive(&mut self) {
        match *self {
            Timer::Idle { ref mut keep_alive_at }
                    if keep_alive_at.is_none() => {
                *keep_alive_at = Some(0)
            }
            _ => ()
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: u64, interval: Option<u64>) {
        match self {
            &mut Timer::Idle { ref mut keep_alive_at } => {
                *keep_alive_at = interval.map(|interval| timestamp + interval)
            }
            _ => ()
        }
    }

    fn set_for_retransmit(&mut self, timestamp: u64) {
        match *self {
            Timer::Idle { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + RETRANSMIT_DELAY,
                    delay:      RETRANSMIT_DELAY,
                }
            }
            Timer::Retransmit { expires_at, delay }
                    if timestamp >= expires_at => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                    delay:      delay * 2
                }
            }
            Timer::Retransmit { .. } => (),
            Timer::Close { .. } => ()
        }
    }

    fn set_for_close(&mut self, timestamp: u64) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY
        }
    }

    fn is_retransmit(&self) -> bool {
        match *self {
            Timer::Retransmit {..} => true,
            _ => false,
        }
    }
}

/// A Transmission Control Protocol socket.
///
/// A TCP socket may passively listen for connections or actively connect to another endpoint.
/// Note that, for listening sockets, there is no "backlog"; to be able to simultaneously
/// accept several connections, as many sockets must be allocated, or any new connection
/// attempts will be reset.
#[derive(Debug)]
pub struct TcpSocket<'a> {
    handle:          SocketHandle,
    state:           State,
    timer:           Timer,
    assembler:       Assembler,
    rx_buffer:       SocketBuffer<'a>,
    tx_buffer:       SocketBuffer<'a>,
    /// Interval after which, if no inbound packets are received, the connection is aborted.
    timeout:         Option<u64>,
    /// Interval at which keep-alive packets will be sent.
    keep_alive:      Option<u64>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ttl:             Option<u8>,
    /// Address passed to listen(). Listen address is set when listen() is called and
    /// used every time the socket is reset back to the LISTEN state.
    listen_address:  IpAddress,
    /// Current local endpoint. This is used for both filtering the incoming packets and
    /// setting the source address. When listening or initiating connection on/from
    /// an unspecified address, this field is updated with the chosen source address before
    /// any packets are sent.
    local_endpoint:  IpEndpoint,
    /// Current remote endpoint. This is used for both filtering the incoming packets and
    /// setting the destination address. If the remote endpoint is unspecified, it means that
    /// aborting the connection will not send an RST, and, in TIME-WAIT state, will not
    /// send an ACK.
    remote_endpoint: IpEndpoint,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no:    TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no:   TcpSeqNumber,
    /// The last sequence number sent.
    /// I.e. in an idle socket, local_seq_no+tx_buffer.len().
    remote_last_seq: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx_buffer.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last window length sent.
    remote_last_win: u16,
    /// The speculative remote window size.
    /// I.e. the actual remote window size minus the count of in-flight octets.
    remote_win_len:  usize,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss:      usize,
    /// The timestamp of the last packet received.
    remote_last_ts:  Option<u64>,
}

const DEFAULT_MSS: usize = 536;

impl<'a> TcpSocket<'a> {
    /// Create a socket using the given buffers.
    pub fn new<T>(rx_buffer: T, tx_buffer: T) -> Socket<'a, 'static>
            where T: Into<SocketBuffer<'a>> {
        let (rx_buffer, tx_buffer) = (rx_buffer.into(), tx_buffer.into());
        if rx_buffer.capacity() > <u16>::max_value() as usize {
            panic!("buffers larger than {} require window scaling, which is not implemented",
                   <u16>::max_value())
        }

        Socket::Tcp(TcpSocket {
            handle:          SocketHandle::EMPTY,
            state:           State::Closed,
            timer:           Timer::default(),
            assembler:       Assembler::new(rx_buffer.capacity()),
            tx_buffer:       tx_buffer,
            rx_buffer:       rx_buffer,
            timeout:         None,
            keep_alive:      None,
            ttl:             None,
            listen_address:  IpAddress::default(),
            local_endpoint:  IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            local_seq_no:    TcpSeqNumber::default(),
            remote_seq_no:   TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win: 0,
            remote_win_len:  0,
            remote_mss:      DEFAULT_MSS,
            remote_last_ts:  None,
        })
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.handle
    }

    /// Set the socket handle.
    pub(in super) fn set_handle(&mut self, handle: SocketHandle) {
        self.handle = handle;
    }

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<u64>) {
        self.timeout = duration
    }

    /// Return the keep-alive interval.
    ///
    /// See also the [set_keep_alive](#method.set_keep_alive) method.
    pub fn keep_alive(&self) -> Option<u64> {
        self.keep_alive
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "challenge ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<u64>) {
        self.keep_alive = interval;
        if self.keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.timer.set_keep_alive();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_ttl](#method.set_ttl) method
    pub fn ttl(&self) -> Option<u8> {
        self.ttl
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set TTL value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a TTL value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_ttl(&mut self, ttl: Option<u8>) {
        // A host MUST NOT send a datagram with a Time-to-Live (TTL) value of 0
        if let Some(0) = ttl {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.ttl = ttl
    }

    /// Return the local endpoint.
    #[inline]
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    /// Return the remote endpoint.
    #[inline]
    pub fn remote_endpoint(&self) -> IpEndpoint {
        self.remote_endpoint
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    fn reset(&mut self) {
        self.state           = State::Closed;
        self.timer           = Timer::default();
        self.assembler       = Assembler::new(self.rx_buffer.capacity());
        self.tx_buffer.clear();
        self.rx_buffer.clear();
        self.keep_alive      = None;
        self.timeout         = None;
        self.ttl             = None;
        self.listen_address  = IpAddress::default();
        self.local_endpoint  = IpEndpoint::default();
        self.remote_endpoint = IpEndpoint::default();
        self.local_seq_no    = TcpSeqNumber::default();
        self.remote_seq_no   = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win = 0;
        self.remote_win_len  = 0;
        self.remote_mss      = DEFAULT_MSS;
        self.remote_last_ts  = None;
    }

    /// Start listening on the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was already open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<()>
            where T: Into<IpEndpoint> {
        let local_endpoint = local_endpoint.into();
        if local_endpoint.port == 0 { return Err(Error::Unaddressable) }

        if self.is_open() { return Err(Error::Illegal) }

        self.reset();
        self.listen_address  = local_endpoint.addr;
        self.local_endpoint  = local_endpoint;
        self.remote_endpoint = IpEndpoint::default();
        self.set_state(State::Listen);
        Ok(())
    }

    /// Connect to a given endpoint.
    ///
    /// The local port must be provided explicitly. Assuming `fn get_ephemeral_port() -> u16`
    /// allocates a port between 49152 and 65535, a connection may be established as follows:
    ///
    /// ```rust,ignore
    /// socket.connect((IpAddress::v4(10, 0, 0, 1), 80), get_ephemeral_port())
    /// ```
    ///
    /// The local address may optionally be provided.
    ///
    /// This function returns an error if the socket was open; see [is_open](#method.is_open).
    /// It also returns an error if the local or remote port is zero, or if the remote address
    /// is unspecified.
    pub fn connect<T, U>(&mut self, remote_endpoint: T, local_endpoint: U) -> Result<()>
            where T: Into<IpEndpoint>, U: Into<IpEndpoint> {
        let remote_endpoint = remote_endpoint.into();
        let local_endpoint  = local_endpoint.into();

        if self.is_open() { return Err(Error::Illegal) }
        if !remote_endpoint.is_specified() { return Err(Error::Unaddressable) }
        if local_endpoint.port == 0 { return Err(Error::Unaddressable) }

        // If local address is not provided, use an unspecified address but a specified protocol.
        // This lets us lower IpRepr later to determine IP header size and calculate MSS,
        // but without committing to a specific address right away.
        let local_addr = match remote_endpoint.addr {
            IpAddress::Unspecified => return Err(Error::Unaddressable),
            _ => remote_endpoint.addr.to_unspecified(),
        };
        let local_endpoint = IpEndpoint { addr: local_addr, ..local_endpoint };

        // Carry over the local sequence number.
        let local_seq_no = self.local_seq_no;

        self.reset();
        self.local_endpoint  = local_endpoint;
        self.remote_endpoint = remote_endpoint;
        self.local_seq_no    = local_seq_no;
        self.remote_last_seq = local_seq_no;
        self.set_state(State::SynSent);
        Ok(())
    }

    /// Close the transmit half of the full-duplex connection.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.state {
            // In the LISTEN state there is no established connection.
            State::Listen =>
                self.set_state(State::Closed),
            // In the SYN-SENT state the remote endpoint is not yet synchronized and, upon
            // receiving an RST, will abort the connection.
            State::SynSent =>
                self.set_state(State::Closed),
            // In the SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            State::SynReceived | State::Established =>
                self.set_state(State::FinWait1),
            State::CloseWait =>
                self.set_state(State::LastAck),
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1 | State::FinWait2 | State::Closing |
            State::TimeWait | State::LastAck | State::Closed => ()
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.set_state(State::Closed);
    }

    /// Return whether the socket is passively listening for incoming connections.
    ///
    /// In terms of the TCP state machine, the socket must be in the `LISTEN` state.
    #[inline]
    pub fn is_listening(&self) -> bool {
        match self.state {
            State::Listen => true,
            _ => false
        }
    }

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` states.
    #[inline]
    pub fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true
        }
    }

    /// Return whether a connection is active.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    ///
    /// In terms of the TCP state machine, the socket must be in the `CLOSED`, `TIME-WAIT`,
    /// or `LISTEN` state.
    #[inline]
    pub fn is_active(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            State::Listen => false,
            _ => true
        }
    }

    /// Return whether the transmit half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to send data and have it arrive
    /// to the remote endpoint. However, it does not make any guarantees about the state
    /// of the transmit buffer, and even if it returns true, [send](#method.send) may
    /// not be able to enqueue any octets.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED` or
    /// `CLOSE-WAIT` state.
    #[inline]
    pub fn may_send(&self) -> bool {
        match self.state {
            State::Established => true,
            // In CLOSE-WAIT, the remote endpoint has closed our receive half of the connection
            // but we still can transmit indefinitely.
            State::CloseWait => true,
            _ => false
        }
    }

    /// Return whether the receive half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to receive data from the remote endpoint.
    /// It will return true while there is data in the receive buffer, and if there isn't,
    /// as long as the remote endpoint has not closed the connection.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED`,
    /// `FIN-WAIT-1`, or `FIN-WAIT-2` state, or have data in the receive buffer instead.
    #[inline]
    pub fn may_recv(&self) -> bool {
        match self.state {
            State::Established => true,
            // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
            // we still can receive indefinitely.
            State::FinWait1 | State::FinWait2 => true,
            // If we have something in the receive buffer, we can receive that.
            _ if self.rx_buffer.len() > 0 => true,
            _ => false
        }
    }

    /// Check whether the transmit half of the full-duplex connection is open
    /// (see [may_send](#method.may_send), and the transmit buffer is not full.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.may_send() { return false }

        !self.tx_buffer.is_full()
    }

    /// Check whether the receive half of the full-duplex connection buffer is open
    /// (see [may_recv](#method.may_recv), and the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        if !self.may_recv() { return false }

        !self.rx_buffer.is_empty()
    }

    fn send_impl<'b, F, R>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R) {
        if !self.may_send() { return Err(Error::Illegal) }

        // The connection might have been idle for a long time, and so remote_last_ts
        // would be far in the past. Unless we clear it here, we'll abort the connection
        // down over in dispatch() by erroneously detecting it as timed out.
        if self.tx_buffer.is_empty() { self.remote_last_ts = None }

        let _old_length = self.tx_buffer.len();
        let (size, result) = f(&mut self.tx_buffer);
        if size > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!("{}:{}:{}: tx buffer: enqueueing {} octets (now {})",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       size, _old_length + size);
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the transmit buffer,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(Error::Illegal) if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send<'b, F, R>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut [u8]) -> (usize, R) {
        self.send_impl(|tx_buffer| {
            tx_buffer.enqueue_many_with(f)
        })
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of bytes actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        self.send_impl(|tx_buffer| {
            let size = tx_buffer.enqueue_slice(data);
            (size, size)
        })
    }

    pub fn recv_impl<'b, F, R>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R) {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN. (We do not support TCP Fast Open.)
        if !self.may_recv() { return Err(Error::Illegal) }

        let _old_length = self.rx_buffer.len();
        let (size, result) = f(&mut self.rx_buffer);
        self.remote_seq_no += size;
        if size > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!("{}:{}:{}: rx buffer: dequeueing {} octets (now {})",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       size, _old_length - size);
        }
        Ok(result)
    }


    /// Call `f` with the largest contiguous slice of octets in the receive buffer,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(Error::Illegal) if the receive half of
    /// the connection is not open; see [may_recv](#method.may_recv).
    pub fn recv<'b, F, R>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut [u8]) -> (usize, R) {
        self.recv_impl(|rx_buffer| {
            rx_buffer.dequeue_many_with(f)
        })
    }

    /// Dequeue a sequence of received octets, and fill a slice from it.
    ///
    /// This function returns the amount of bytes actually dequeued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        self.recv_impl(|rx_buffer| {
            let size = rx_buffer.dequeue_slice(data);
            (size, size)
        })
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and return a pointer to it.
    ///
    /// This function otherwise behaves identically to [recv](#method.recv).
    pub fn peek(&mut self, size: usize) -> Result<&[u8]> {
        // See recv() above.
        if !self.may_recv() { return Err(Error::Illegal) }

        let buffer = self.rx_buffer.get_allocated(0, size);
        if buffer.len() > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!("{}:{}:{}: rx buffer: peeking at {} octets",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       buffer.len());
        }
        Ok(buffer)
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and fill a slice from it.
    ///
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.peek(data.len())?;
        let data = &mut data[..buffer.len()];
        data.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Return the amount of octets queued in the receive buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.len()
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            if self.remote_endpoint.addr.is_unspecified() {
                net_trace!("{}:{}: state={}=>{}",
                           self.handle, self.local_endpoint,
                           self.state, state);
            } else {
                net_trace!("{}:{}:{}: state={}=>{}",
                           self.handle, self.local_endpoint, self.remote_endpoint,
                           self.state, state);
            }
        }
        self.state = state
    }

    pub(crate) fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port:     repr.dst_port,
            dst_port:     repr.src_port,
            control:      TcpControl::None,
            seq_number:   TcpSeqNumber(0),
            ack_number:   None,
            window_len:   0,
            max_seg_size: None,
            payload:      &[]
        };
        let ip_reply_repr = IpRepr::Unspecified {
            src_addr:    ip_repr.dst_addr(),
            dst_addr:    ip_repr.src_addr(),
            protocol:    IpProtocol::Tcp,
            payload_len: reply_repr.buffer_len(),
            ttl:         64
        };
        (ip_reply_repr, reply_repr)
    }

    pub(crate) fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        debug_assert!(repr.control != TcpControl::Rst);

        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // See https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for explanation
        // of why we sometimes send an RST and sometimes an RST|ACK
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn ack_reply(&self, ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.remote_last_seq;
        reply_repr.ack_number = self.remote_last_ack;
        reply_repr.window_len = self.rx_buffer.window() as u16;

        (ip_reply_repr, reply_repr)
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state == State::Closed { return false }

        // If we're still listening for SYNs and the packet has an ACK, it cannot
        // be destined to this socket, but another one may well listen on the same
        // local endpoint.
        if self.state == State::Listen && repr.ack_number.is_some() { return false }

        // Reject packets with a wrong destination.
        if self.local_endpoint.port != repr.dst_port { return false }
        if !self.local_endpoint.addr.is_unspecified() &&
            self.local_endpoint.addr != ip_repr.dst_addr() { return false }

        // Reject packets from a source to which we aren't connected.
        if self.remote_endpoint.port != 0 &&
            self.remote_endpoint.port != repr.src_port { return false }
        if !self.remote_endpoint.addr.is_unspecified() &&
            self.remote_endpoint.addr != ip_repr.src_addr() { return false }

        true
    }

    pub(crate) fn process(&mut self, timestamp: u64, ip_repr: &IpRepr, repr: &TcpRepr) ->
                         Result<Option<(IpRepr, TcpRepr<'static>)>> {
        debug_assert!(self.accepts(ip_repr, repr));

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state {
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgemetns for
            // all of the control flags we sent.
            _ => (false, false)
        };
        let control_len = (sent_syn as usize) + (sent_fin as usize);

        // Reject unacceptable acknowledgements.
        match (self.state, repr) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, &TcpRepr {
                control: TcpControl::Rst, ack_number: None, ..
            }) => {
                net_debug!("{}:{}:{}: unacceptable RST (expecting RST|ACK) \
                            in response to initial SYN",
                           self.handle, self.local_endpoint, self.remote_endpoint);
                return Err(Error::Dropped)
            }
            (State::SynSent, &TcpRepr {
                control: TcpControl::Rst, ack_number: Some(ack_number), ..
            }) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!("{}:{}:{}: unacceptable RST|ACK in response to initial SYN",
                               self.handle, self.local_endpoint, self.remote_endpoint);
                    return Err(Error::Dropped)
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, &TcpRepr { control: TcpControl::Rst, .. }) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, &TcpRepr { ack_number: None, .. }) => (),
            // This case is handled above.
            (State::Listen, &TcpRepr { ack_number: Some(_), .. }) => unreachable!(),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, &TcpRepr { ack_number: None, .. }) => {
                net_debug!("{}:{}:{}: expecting an ACK",
                           self.handle, self.local_endpoint, self.remote_endpoint);
                return Err(Error::Dropped)
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, &TcpRepr { ack_number: Some(ack_number), .. }) => {
                let unacknowledged = self.tx_buffer.len() + control_len;

                if ack_number < self.local_seq_no {
                    net_debug!("{}:{}:{}: duplicate ACK ({} not in {}...{})",
                               self.handle, self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    // FIXME: implement fast retransmit
                    return Err(Error::Dropped)
                }

                if ack_number > self.local_seq_no + unacknowledged {
                    net_debug!("{}:{}:{}: unacceptable ACK ({} not in {}...{})",
                               self.handle, self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    return Ok(Some(self.ack_reply(ip_repr, &repr)))
                }
            }
        }

        let payload_offset;
        match self.state {
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            State::Listen | State::SynSent =>
                payload_offset = 0,
            // In all other states, segments must occupy a valid portion of the receive window.
            _ => {
                let mut segment_in_window = true;

                let window_start  = self.remote_seq_no + self.rx_buffer.len();
                let window_end    = self.remote_seq_no + self.rx_buffer.capacity();
                let segment_start = repr.seq_number;
                let segment_end   = repr.seq_number + repr.segment_len();

                if window_start == window_end && segment_start != segment_end {
                    net_debug!("{}:{}:{}: non-zero-length segment with zero receive window, \
                                will only send an ACK",
                               self.handle, self.local_endpoint, self.remote_endpoint);
                    segment_in_window = false;
                }

                if !((window_start <= segment_start && segment_start <= window_end) &&
                     (window_start <= segment_end   && segment_end <= window_end)) {
                    net_debug!("{}:{}:{}: segment not in receive window \
                                ({}..{} not intersecting {}..{}), will send challenge ACK",
                               self.handle, self.local_endpoint, self.remote_endpoint,
                               segment_start, segment_end, window_start, window_end);
                    segment_in_window = false;
                }

                if segment_in_window {
                    // We've checked that segment_start >= window_start above.
                    payload_offset = (segment_start - window_start) as usize;
                } else {
                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not have realized we've closed the connection.
                    if self.state == State::TimeWait {
                        self.timer.set_for_close(timestamp);
                    }

                    return Ok(Some(self.ack_reply(ip_repr, &repr)))
                }
            }
        }

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        if repr.control != TcpControl::Rst {
            if let Some(ack_number) = repr.ack_number {
                ack_len = ack_number - self.local_seq_no;
                // There could have been no data sent before the SYN, so we always remove it
                // from the sequence space.
                if sent_syn {
                    ack_len -= 1
                }
                // We could've sent data before the FIN, so only remove FIN from the sequence
                // space if all of that data is acknowledged.
                if sent_fin && self.tx_buffer.len() + 1 == ack_len {
                    ack_len -= 1;
                    net_trace!("{}:{}:{}: received ACK of FIN",
                               self.handle, self.local_endpoint, self.remote_endpoint);
                    ack_of_fin = true;
                }
            }
        }

        // Validate and update the state.
        match (self.state, repr.control.quash_psh()) {
            // RSTs are not accepted in the LISTEN state.
            (State::Listen, TcpControl::Rst) =>
                return Err(Error::Dropped),

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            (State::SynReceived, TcpControl::Rst) => {
                net_trace!("{}:{}:{}: received RST",
                           self.handle, self.local_endpoint, self.remote_endpoint);
                self.local_endpoint.addr = self.listen_address;
                self.remote_endpoint     = IpEndpoint::default();
                self.set_state(State::Listen);
                return Ok(None)
            }

            // RSTs in any other state close the socket.
            (_, TcpControl::Rst) => {
                net_trace!("{}:{}:{}: received RST",
                           self.handle, self.local_endpoint, self.remote_endpoint);
                self.set_state(State::Closed);
                self.local_endpoint  = IpEndpoint::default();
                self.remote_endpoint = IpEndpoint::default();
                return Ok(None)
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpControl::Syn) => {
                net_trace!("{}:{}: received SYN",
                           self.handle, self.local_endpoint);
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                self.remote_endpoint = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);
                // FIXME: use something more secure here
                self.local_seq_no    = TcpSeqNumber(-repr.seq_number.0);
                self.remote_seq_no   = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no;
                if let Some(max_seg_size) = repr.max_seg_size {
                    self.remote_mss = max_seg_size as usize
                }
                self.set_state(State::SynReceived);
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.set_state(State::Established);
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpControl::Fin) => {
                self.remote_seq_no  += 1;
                self.set_state(State::CloseWait);
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            (State::SynSent, TcpControl::Syn) => {
                net_trace!("{}:{}:{}: received SYN|ACK",
                           self.handle, self.local_endpoint, self.remote_endpoint);
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                self.remote_seq_no   = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_last_ack = Some(repr.seq_number);
                if let Some(max_seg_size) = repr.max_seg_size {
                    self.remote_mss = max_seg_size as usize;
                }
                self.set_state(State::Established);
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // ACK packets in ESTABLISHED state reset the retransmit timer,
            // except for duplicate ACK packets which preserve it.
            (State::Established, TcpControl::None) => {
                if !self.timer.is_retransmit() || ack_len != 0 {
                    self.timer.set_for_idle(timestamp, self.keep_alive);
                }
            },

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpControl::Fin) => {
                self.remote_seq_no  += 1;
                self.set_state(State::CloseWait);
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                }
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpControl::Fin) => {
                self.remote_seq_no  += 1;
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(timestamp);
                } else {
                    self.set_state(State::Closing);
                    self.timer.set_for_idle(timestamp, self.keep_alive);
                }
            }

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpControl::Fin) => {
                self.remote_seq_no  += 1;
                self.set_state(State::TimeWait);
                self.timer.set_for_close(timestamp);
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(timestamp);
                } else {
                    self.timer.set_for_idle(timestamp, self.keep_alive);
                }
            }

            // ACK packets in CLOSE-WAIT state reset the retransmit timer.
            (State::CloseWait, TcpControl::None) => {
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                // Clear the remote endpoint, or we'll send an RST there.
                self.set_state(State::Closed);
                self.local_endpoint  = IpEndpoint::default();
                self.remote_endpoint = IpEndpoint::default();
            }

            _ => {
                net_debug!("{}:{}:{}: unexpected packet {}",
                           self.handle, self.local_endpoint, self.remote_endpoint, repr);
                return Err(Error::Dropped)
            }
        }

        // Update remote state.
        self.remote_last_ts = Some(timestamp);
        self.remote_win_len = repr.window_len as usize;

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx_buffer.len() >= ack_len);
            net_trace!("{}:{}:{}: tx buffer: dequeueing {} octets (now {})",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       ack_len, self.tx_buffer.len() - ack_len);
            self.tx_buffer.dequeue_allocated(ack_len);
        }

        if let Some(ack_number) = repr.ack_number {
            // We've processed everything in the incoming segment, so advance the local
            // sequence number past it.
            self.local_seq_no = ack_number;
        }

        let payload_len = repr.payload.len();
        if payload_len == 0 { return Ok(None) }

        let assembler_was_empty = self.assembler.is_empty();

        // Try adding payload octets to the assembler.
        match self.assembler.add(payload_offset, payload_len) {
            Ok(()) => {
                debug_assert!(self.assembler.total_size() == self.rx_buffer.capacity());
                // Place payload octets into the buffer.
                net_trace!("{}:{}:{}: rx buffer: receiving {} octets at offset {}",
                           self.handle, self.local_endpoint, self.remote_endpoint,
                           payload_len, payload_offset);
                self.rx_buffer.write_unallocated(payload_offset, repr.payload);
            }
            Err(()) => {
                net_debug!("{}:{}:{}: assembler: too many holes to add {} octets at offset {}",
                           self.handle, self.local_endpoint, self.remote_endpoint,
                           payload_len, payload_offset);
                return Err(Error::Dropped)
            }
        }

        if let Some(contig_len) = self.assembler.remove_front() {
            debug_assert!(self.assembler.total_size() == self.rx_buffer.capacity());
            // Enqueue the contiguous data octets in front of the buffer.
            net_trace!("{}:{}:{}: rx buffer: enqueueing {} octets (now {})",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       contig_len, self.rx_buffer.len() + contig_len);
            self.rx_buffer.enqueue_unallocated(contig_len);
        }

        if !self.assembler.is_empty() {
            // Print the ranges recorded in the assembler.
            net_trace!("{}:{}:{}: assembler: {}",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       self.assembler);
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because smoltcp assumes that it can always transmit zero or one
            // packets for every packet it receives.
            self.remote_last_ack = Some(self.remote_seq_no + self.rx_buffer.len());
            Ok(Some(self.ack_reply(ip_repr, &repr)))
        } else {
            Ok(None)
        }
    }

    fn timed_out(&self, timestamp: u64) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) =>
                timestamp >= remote_last_ts + timeout,
            (_, _) =>
                false
        }
    }

    fn seq_to_transmit(&self) -> bool {
        let control;
        match self.state {
            State::SynSent  | State::SynReceived =>
                control = TcpControl::Syn,
            State::FinWait1 | State::LastAck =>
                control = TcpControl::Fin,
            _ => control = TcpControl::None
        }

        if self.remote_win_len > 0 {
            self.remote_last_seq < self.local_seq_no + self.tx_buffer.len() + control.len()
        } else {
            false
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    fn window_to_update(&self) -> bool {
        self.rx_buffer.window() as u16 > self.remote_last_win
    }

    pub(crate) fn dispatch<F>(&mut self, timestamp: u64, caps: &DeviceCapabilities,
                              emit: F) -> Result<()>
            where F: FnOnce((IpRepr, TcpRepr)) -> Result<()> {
        if !self.remote_endpoint.is_specified() { return Err(Error::Exhausted) }

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(timestamp);
        }

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(timestamp) {
            // If a timeout expires, we should abort the connection.
            net_debug!("{}:{}:{}: timeout exceeded",
                       self.handle, self.local_endpoint, self.remote_endpoint);
            self.set_state(State::Closed);
        } else if !self.seq_to_transmit() {
            if let Some(retransmit_delta) = self.timer.should_retransmit(timestamp) {
                // If a retransmit timer expired, we should resend data starting at the last ACK.
                net_debug!("{}:{}:{}: retransmitting at t+{}ms",
                           self.handle, self.local_endpoint, self.remote_endpoint,
                           retransmit_delta);
                self.remote_last_seq = self.local_seq_no;
            }
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit() {
            // If we have data to transmit and it fits into partner's window, do it.
        } else if self.ack_to_transmit() {
            // If we have data to acknowledge, do it.
        } else if self.window_to_update() {
            // If we have window length increase to advertise, do it.
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
        } else if self.timer.should_retransmit(timestamp).is_some() {
            // If we have packets to retransmit, do it.
        } else if self.timer.should_keep_alive(timestamp) {
            // If we need to transmit a keep-alive packet, do it.
        } else if self.timer.should_close(timestamp) {
            // If we have spent enough time in the TIME-WAIT state, close the socket.
        } else {
            return Err(Error::Exhausted)
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::Unspecified {
            src_addr:     self.local_endpoint.addr,
            dst_addr:     self.remote_endpoint.addr,
            protocol:     IpProtocol::Tcp,
            ttl:          self.ttl.unwrap_or(64),
            payload_len:  0
        }.lower(&[])?;

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port:     self.local_endpoint.port,
            dst_port:     self.remote_endpoint.port,
            control:      TcpControl::None,
            seq_number:   self.remote_last_seq,
            ack_number:   Some(self.remote_seq_no + self.rx_buffer.len()),
            window_len:   self.rx_buffer.window() as u16,
            max_seg_size: None,
            payload:      &[]
        };

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Err(Error::Exhausted),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                if self.state == State::SynSent {
                    repr.ack_number = None;
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open:
            // the ESTABLISHED, FIN-WAIT-1, CLOSE-WAIT and LAST-ACK states.
            State::Established | State::FinWait1 | State::CloseWait | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.
                let offset = self.remote_last_seq - self.local_seq_no;
                let size = cmp::min(self.remote_win_len, self.remote_mss);
                repr.payload = self.tx_buffer.get_allocated(offset, size);
                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck =>
                            repr.control = TcpControl::Fin,
                        State::Established | State::CloseWait if repr.payload.len() > 0 =>
                            repr.control = TcpControl::Psh,
                        _ => ()
                    }
                }
            }

            // We do not transmit anything in the FIN-WAIT-2 state.
            State::FinWait2 => return Err(Error::Exhausted),

            // We do not transmit data or control flags in the CLOSING state, but we may
            // retransmit an ACK.
            State::Closing => (),

            // Handling of the TIME-WAIT state is the same as for the CLOSING state, but also
            // we wait for the timer to expire.
            State::TimeWait => {
                if self.timer.should_close(timestamp) {
                    net_trace!("{}:{}:{}: TIME-WAIT timeout",
                               self.handle, self.local_endpoint, self.remote_endpoint);
                    self.reset();
                    return Err(Error::Exhausted)
                }
            }
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.
        let is_keep_alive;
        if self.timer.should_keep_alive(timestamp) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            repr.payload    = b"\x00"; // RFC 1122 says we should do this
            is_keep_alive = true;
        } else {
            is_keep_alive = false;
        }

        // Trace a summary of what will be sent.
        if is_keep_alive {
            net_trace!("{}:{}:{}: sending a keep-alive",
                       self.handle, self.local_endpoint, self.remote_endpoint);
        } else if repr.payload.len() > 0 {
            net_trace!("{}:{}:{}: tx buffer: sending {} octets at offset {}",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       repr.payload.len(), self.remote_last_seq - self.local_seq_no);
        }
        if repr.control != TcpControl::None || repr.payload.len() == 0 {
            let flags =
                match (repr.control, repr.ack_number) {
                    (TcpControl::Syn,  None)    => "SYN",
                    (TcpControl::Syn,  Some(_)) => "SYN|ACK",
                    (TcpControl::Fin,  Some(_)) => "FIN|ACK",
                    (TcpControl::Rst,  Some(_)) => "RST|ACK",
                    (TcpControl::Psh,  Some(_)) => "PSH|ACK",
                    (TcpControl::None, Some(_)) => "ACK",
                    _ => "<unreachable>"
                };
            net_trace!("{}:{}:{}: sending {}",
                       self.handle, self.local_endpoint, self.remote_endpoint,
                       flags);
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let mut max_segment_size = caps.max_transmission_unit;
            max_segment_size -= ip_repr.buffer_len();
            max_segment_size -= repr.header_len();
            repr.max_seg_size = Some(max_segment_size as u16);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        ip_repr.set_payload_len(repr.buffer_len());
        emit((ip_repr, repr))?;

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(timestamp, self.keep_alive);

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive { return Ok(()) }

        // We've sent a packet successfully, so we can update the internal state now.
        self.remote_last_seq = repr.seq_number + repr.segment_len();
        self.remote_last_ack = repr.ack_number;
        self.remote_last_win = repr.window_len;

        if !self.seq_to_transmit() && repr.segment_len() > 0 {
            // If we've transmitted all data we could (and there was something at all,
            // data or flag, to transmit, not just an ACK), wind up the retransmit timer.
            self.timer.set_for_retransmit(timestamp);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.local_endpoint  = IpEndpoint::default();
            self.remote_endpoint = IpEndpoint::default();
        }

        Ok(())
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        // The logic here mirrors the beginning of dispatch() closely.
        if !self.remote_endpoint.is_specified() {
            // No one to talk to, nothing to transmit.
            None
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            Some(0)
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            Some(0)
        } else if self.seq_to_transmit() || self.ack_to_transmit() || self.window_to_update() {
            // We have a data or flag packet to transmit.
            Some(0)
        } else {
            let timeout_poll_at;
            match (self.remote_last_ts, self.timeout) {
                // If we're transmitting or retransmitting data, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) =>
                    timeout_poll_at = Some(remote_last_ts + timeout),
                // Otherwise we have no timeout.
                (_, _) =>
                    timeout_poll_at = None
            }

            // We wait for the earliest of our timers to fire.
            [self.timer.poll_at(), timeout_poll_at]
                .iter()
                .filter_map(|x| *x)
                .min()
        }
    }
}

impl<'a> fmt::Write for TcpSocket<'a> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod test {
    use core::i32;
    use wire::{IpAddress, IpRepr};
    use wire::{Ipv4Address, IpCidr, Ipv4Repr};
    use super::*;

    #[test]
    fn test_timer_retransmit() {
        let mut r = Timer::default();
        assert_eq!(r.should_retransmit(1000), None);
        r.set_for_retransmit(1000);
        assert_eq!(r.should_retransmit(1000), None);
        assert_eq!(r.should_retransmit(1050), None);
        assert_eq!(r.should_retransmit(1101), Some(101));
        r.set_for_retransmit(1101);
        assert_eq!(r.should_retransmit(1101), None);
        assert_eq!(r.should_retransmit(1150), None);
        assert_eq!(r.should_retransmit(1200), None);
        assert_eq!(r.should_retransmit(1301), Some(300));
        r.set_for_idle(1301, None);
        assert_eq!(r.should_retransmit(1350), None);
    }

    const LOCAL_IP:     IpAddress    = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1]));
    const REMOTE_IP:    IpAddress    = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 2]));
    const OTHER_IP:     IpAddress    = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 3]));
    const LOCAL_PORT:   u16          = 80;
    const REMOTE_PORT:  u16          = 49500;
    const LOCAL_END:    IpEndpoint   = IpEndpoint { addr: LOCAL_IP,  port: LOCAL_PORT  };
    const REMOTE_END:   IpEndpoint   = IpEndpoint { addr: REMOTE_IP, port: REMOTE_PORT };
    const LOCAL_SEQ:    TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ:   TcpSeqNumber = TcpSeqNumber(-10000);

    const SEND_IP_TEMPL: IpRepr = IpRepr::Unspecified {
        src_addr: LOCAL_IP, dst_addr: REMOTE_IP,
        protocol: IpProtocol::Tcp, payload_len: 20,
        ttl: 64
    };
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT, dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 256, max_seg_size: None,
        payload: &[]
    };
    const _RECV_IP_TEMPL: IpRepr = IpRepr::Unspecified {
        src_addr: REMOTE_IP, dst_addr: LOCAL_IP,
        protocol: IpProtocol::Tcp, payload_len: 20,
        ttl: 64
    };
    const RECV_TEMPL:  TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT, dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 64, max_seg_size: None,
        payload: &[]
    };

    fn send(socket: &mut TcpSocket, timestamp: u64, repr: &TcpRepr) ->
           Result<Option<TcpRepr<'static>>> {
        let ip_repr = IpRepr::Unspecified {
            src_addr:    REMOTE_IP,
            dst_addr:    LOCAL_IP,
            protocol:    IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            ttl:         64
        };
        trace!("send: {}", repr);

        assert!(socket.accepts(&ip_repr, repr));
        match socket.process(timestamp, &ip_repr, repr) {
            Ok(Some((_ip_repr, repr))) => {
                trace!("recv: {}", repr);
                Ok(Some(repr))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err)
        }
    }

    fn recv<F>(socket: &mut TcpSocket, timestamp: u64, mut f: F)
            where F: FnMut(Result<TcpRepr>) {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1520;
        let result = socket.dispatch(timestamp, &caps, |(ip_repr, tcp_repr)| {
            let ip_repr = ip_repr.lower(&[IpCidr::new(LOCAL_END.addr, 24)]).unwrap();

            assert_eq!(ip_repr.protocol(), IpProtocol::Tcp);
            assert_eq!(ip_repr.src_addr(), LOCAL_IP);
            assert_eq!(ip_repr.dst_addr(), REMOTE_IP);
            assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

            trace!("recv: {}", tcp_repr);
            Ok(f(Ok(tcp_repr)))
        });
        match result {
            Ok(()) => (),
            Err(e) => f(Err(e))
        }
    }

    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, Ok(None)));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, $time, &$repr), $result));
    }

    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv!($socket, Err(Error::Exhausted))
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, $time, |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, $time, |repr| assert_eq!(repr, $result)));
    }

    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => ({
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state,            s2.state,           "state");
            assert_eq!(s1.listen_address,   s2.listen_address,  "listen_address");
            assert_eq!(s1.local_endpoint,   s2.local_endpoint,  "local_endpoint");
            assert_eq!(s1.remote_endpoint,  s2.remote_endpoint, "remote_endpoint");
            assert_eq!(s1.local_seq_no,     s2.local_seq_no,    "local_seq_no");
            assert_eq!(s1.remote_seq_no,    s2.remote_seq_no,   "remote_seq_no");
            assert_eq!(s1.remote_last_seq,  s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack,  s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win,  s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len,   s2.remote_win_len,  "remote_win_len");
            assert_eq!(s1.timer,            s2.timer,           "timer");
        })
    }

    fn init_logger() {
        extern crate log;
        use std::boxed::Box;

        struct Logger(());

        impl log::Log for Logger {
            fn enabled(&self, _metadata: &log::LogMetadata) -> bool {
                true
            }

            fn log(&self, record: &log::LogRecord) {
                println!("{}", record.args());
            }
        }

        let _ = log::set_logger(|max_level| {
            max_level.set(log::LogLevelFilter::Trace);
            Box::new(Logger(()))
        });

        println!("");
    }

    fn socket() -> TcpSocket<'static> {
        init_logger();

        let rx_buffer = SocketBuffer::new(vec![0; 64]);
        let tx_buffer = SocketBuffer::new(vec![0; 64]);
        match TcpSocket::new(rx_buffer, tx_buffer) {
            Socket::Tcp(socket) => socket,
            _ => unreachable!()
        }
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.accepts(&SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.accepts(&SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TcpSocket<'static> {
        let mut s = socket();
        s.state           = State::Listen;
        s.local_endpoint  = IpEndpoint::new(IpAddress::default(), LOCAL_PORT);
        s
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(Error::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        assert_eq!(s.listen(80), Err(Error::Illegal));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control:    TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        });
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.accepts(&SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }, Err(Error::Dropped));
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//
    fn socket_syn_received() -> TcpSocket<'static> {
        let mut s = socket();
        s.state           = State::SynReceived;
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ;
        s.remote_seq_no   = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_win_len  = 256;
        s
    }

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
            window_len: 58,
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, TcpSocket {
            remote_last_ack: Some(REMOTE_SEQ + 1 + 6 + 1),
            remote_last_win: 58,
            ..socket_close_wait()
        });
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Listen);
        assert_eq!(s.local_endpoint, IpEndpoint::new(IpAddress::Unspecified, LOCAL_END.port));
        assert_eq!(s.remote_endpoint, IpEndpoint::default());
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//
    fn socket_syn_sent() -> TcpSocket<'static> {
        let mut s = socket();
        s.state           = State::SynSent;
        s.local_endpoint  = IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), LOCAL_PORT);
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(s.connect((IpAddress::v4(0, 0, 0, 0), 80), LOCAL_END),
                   Err(Error::Unaddressable));
        assert_eq!(s.connect(REMOTE_END, (IpAddress::v4(10, 0, 0, 0), 0)),
                   Err(Error::Unaddressable));
        assert_eq!(s.connect((IpAddress::v4(10, 0, 0, 0), 0), LOCAL_END),
                   Err(Error::Unaddressable));
        assert_eq!(s.connect((IpAddress::Unspecified, 80), LOCAL_END),
                   Err(Error::Unaddressable));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.connect(REMOTE_END, LOCAL_END.port).unwrap();
        assert_eq!(s.local_endpoint, IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), LOCAL_END.port));
        recv!(s, [TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control:    TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(1400),
            ..SEND_TEMPL
        });
        assert_eq!(s.local_endpoint, LOCAL_END);
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.connect(REMOTE_END, (IpAddress::v4(0, 0, 0, 0), 80)),
                   Ok(()));
        s.abort();
        assert_eq!(s.connect(REMOTE_END, (IpAddress::Unspecified, 80)),
                   Ok(()));
        s.abort();
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(s.connect(REMOTE_END, (IpAddress::v4(10, 0, 0, 2), 80)),
                   Ok(()));
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.connect(REMOTE_END, (IpAddress::Unspecified, 80)),
                   Ok(()));
        assert_eq!(s.connect(REMOTE_END, (IpAddress::Unspecified, 80)),
                   Err(Error::Illegal));
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no    = LOCAL_SEQ;
        s.connect(REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(s, [TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control:    TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(1400),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        recv!(s, time 1000, Err(Error::Exhausted));
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }, Err(Error::Dropped));
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(TcpSeqNumber(1234)),
            ..SEND_TEMPL
        }, Err(Error::Dropped));
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//
    fn socket_established() -> TcpSocket<'static> {
        let mut s = socket_syn_received();
        s.state           = State::Established;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = 64;
        s
    }

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]);
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        assert_eq!(s.tx_buffer.len(), 6);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        });
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        });
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        s.send_slice(b"foobar").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[0..16],
            ..RECV_TEMPL
        }, TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 16,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[16..32],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }, Err(Error::Dropped));
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
            ..SEND_TEMPL
        }, Err(Error::Dropped));
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 10),
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })));
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })));
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//
    fn socket_fin_wait_1() -> TcpSocket<'static> {
        let mut s = socket_established();
        s.state           = State::FinWait1;
        s
    }

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//
    fn socket_fin_wait_2() -> TcpSocket<'static> {
        let mut s = socket_fin_wait_1();
        s.state           = State::FinWait2;
        s.local_seq_no    = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//
    fn socket_closing() -> TcpSocket<'static> {
        let mut s = socket_fin_wait_1();
        s.state           = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1 + 1;
        s
    }

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//
    fn socket_time_wait(from_closing: bool) -> TcpSocket<'static> {
        let mut s = socket_fin_wait_2();
        s.state           = State::TimeWait;
        s.remote_seq_no   = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer           = Timer::Close { expires_at: 1_000 + CLOSE_DELAY };
        s
    }

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        })));
        assert_eq!(s.timer, Timer::Close { expires_at: 5_000 + CLOSE_DELAY });
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
        recv!(s, time 60_000, Err(Error::Exhausted));
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//
    fn socket_close_wait() -> TcpSocket<'static> {
        let mut s = socket_established();
        s.state           = State::CloseWait;
        s.remote_seq_no   = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    fn socket_last_ack() -> TcpSocket<'static> {
        let mut s = socket_close_wait();
        s.state           = State::LastAck;
        s
    }

    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::LastAck);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//
    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(IpEndpoint::new(IpAddress::default(), LOCAL_PORT)).unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::CloseWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::FinWait2);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(s, [TcpRepr { // due to reordering, this is logically located...
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::Closing);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        // ... at this point
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(s, [TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }])
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::FinWait2);
        send!(s, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//
    fn socket_recved() -> TcpSocket<'static> {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]);
        s
    }

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        })));
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Err(Error::Exhausted));
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        s.remote_win_len = 6;
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        s.remote_win_len = 6;
        recv!(s, time 0, Err(Error::Exhausted));

        recv!(s, time 50, Err(Error::Exhausted));

        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        s.remote_win_len = 6;
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        s.remote_win_len = 6;
        recv!(s, time 200, Err(Error::Exhausted));
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }));
        recv!(s, time 150, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }));
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }])
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(1000),
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 32767,
            ..SEND_TEMPL
        });
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; 1000][..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            control:    TcpControl::Psh,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]);
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"123456"[..],
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        })));
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        });
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]);
        recv!(s, time 0, Err(Error::Exhausted));
        s.recv(|buffer| {
            assert_eq!(&buffer[..3], b"abc");
            (3, ())
        }).unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Err(Error::Exhausted));
        s.recv(|buffer| {
            assert_eq!(buffer, b"def");
            (buffer.len(), ())
        }).unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }, TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }, TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"!@#$%^"[..],
            ..RECV_TEMPL
        }]);
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(100));
        assert_eq!(s.poll_at(), None);
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.connect(REMOTE_END, LOCAL_END.port).unwrap();
        s.set_timeout(Some(100));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(1480),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(s.poll_at(), Some(250));
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(200));
        recv!(s, time 250, Err(Error::Exhausted));
        assert_eq!(s.poll_at(), Some(450));
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.poll_at(), Some(0));
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(s.poll_at(), Some(355));
        recv!(s, time 355, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(s.poll_at(), Some(455));
        recv!(s, time 500, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(50));
        s.set_timeout(Some(100));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv!(s, time 100, Err(Error::Exhausted));
        assert_eq!(s.poll_at(), Some(150));
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.poll_at(), Some(155));
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv!(s, time 155, Err(Error::Exhausted));
        assert_eq!(s.poll_at(), Some(205));
        recv!(s, time 200, Err(Error::Exhausted));
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 205, Err(Error::Exhausted));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(200));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.poll_at(), Some(200));
        recv!(s, time 400, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(200));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.poll_at(), Some(200));
        recv!(s, time 400, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(200));
        s.remote_last_ts = Some(100);
        s.abort();
        assert_eq!(s.poll_at(), Some(0));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.poll_at(), None);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })));
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(100));

        // drain the forced keep-alive packet
        assert_eq!(s.poll_at(), Some(0));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(s.poll_at(), Some(100));
        recv!(s, time 95, Err(Error::Exhausted));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(s.poll_at(), Some(200));
        recv!(s, time 195, Err(Error::Exhausted));
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.poll_at(), Some(350));
        recv!(s, time 345, Err(Error::Exhausted));
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_ttl() {
        let mut s = socket_syn_received();
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1520;

        s.set_ttl(Some(0x2a));
        assert_eq!(s.dispatch(0, &caps, |(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address([10, 0, 0, 1]),
                dst_addr: Ipv4Address([10, 0, 0, 2]),
                protocol: IpProtocol::Tcp,
                payload_len: 24,
                ttl: 0x2a,
            }));
            Ok(())
        }), Ok(()));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_ttl_zero() {
        let mut s = socket_syn_received();
        s.set_ttl(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"def"[..],
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })));
        s.recv(|buffer| {
            assert_eq!(buffer, b"");
            (buffer.len(), ())
        }).unwrap();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        })));
        s.recv(|buffer| {
            assert_eq!(buffer, b"abcdef");
            (buffer.len(), ())
        }).unwrap();
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abc"[..],
            ..SEND_TEMPL
        });
        s.recv(|buffer| {
            assert_eq!(buffer, b"abc");
            (buffer.len(), ())
        }).unwrap();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"defghi"[..],
            ..SEND_TEMPL
        });
        let mut data = [0; 6];
        assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();
        s.tx_buffer = SocketBuffer::new(vec![0; 6]);
        assert_eq!(s.send_slice(b"abc"), Ok(3));
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 3),
            ..SEND_TEMPL
        });
        assert_eq!(s.send_slice(b"defghi"), Ok(6));
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"def"[..],
            ..RECV_TEMPL
        }));
        // "defghi" not contiguous in tx buffer
        recv!(s, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ghi"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port:   LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.accepts(&SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port:   REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.accepts(&SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpRepr::Unspecified {
            src_addr:    REMOTE_IP,
            dst_addr:    LOCAL_IP,
            protocol:    IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            ttl:         64
        };
        assert!(s.accepts(&ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpRepr::Unspecified {
            src_addr:    OTHER_IP,
            dst_addr:    LOCAL_IP,
            protocol:    IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            ttl:         64
        };
        assert!(!s.accepts(&ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpRepr::Unspecified {
            src_addr:    REMOTE_IP,
            dst_addr:    OTHER_IP,
            protocol:    IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            ttl:         64
        };
        assert!(!s.accepts(&ip_repr_wrong_dst, &tcp_repr));
    }
}
