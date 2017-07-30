// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP.

use core::fmt;
use managed::Managed;

use {Error, Result};
use phy::DeviceLimits;
use wire::{IpProtocol, IpAddress, IpEndpoint};
use wire::{TcpSeqNumber, TcpPacket, TcpRepr, TcpControl};
use socket::{Socket, IpRepr, IpPayload};

/// A TCP stream ring buffer.
#[derive(Debug)]
pub struct SocketBuffer<'a> {
    storage: Managed<'a, [u8]>,
    read_at: usize,
    length:  usize
}

impl<'a> SocketBuffer<'a> {
    /// Create a packet buffer with the given storage.
    pub fn new<T>(storage: T) -> SocketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        SocketBuffer {
            storage: storage.into(),
            read_at: 0,
            length:  0
        }
    }

    fn clear(&mut self) {
        self.read_at = 0;
        self.length = 0;
    }

    fn capacity(&self) -> usize {
        self.storage.len()
    }

    fn len(&self) -> usize {
        self.length
    }

    fn window(&self) -> usize {
        self.capacity() - self.len()
    }

    fn empty(&self) -> bool {
        self.len() == 0
    }

    fn full(&self) -> bool {
        self.window() == 0
    }

    fn clamp_writer(&self, mut size: usize) -> (usize, usize) {
        let write_at = (self.read_at + self.length) % self.storage.len();
        // We can't enqueue more than there is free space.
        let free = self.storage.len() - self.length;
        if size > free { size = free }
        // We can't contiguously enqueue past the beginning of the storage.
        let until_end = self.storage.len() - write_at;
        if size > until_end { size = until_end }

        (write_at, size)
    }

    fn enqueue(&mut self, size: usize) -> &mut [u8] {
        let (write_at, size) = self.clamp_writer(size);
        self.length += size;
        &mut self.storage[write_at..write_at + size]
    }

    fn enqueue_slice(&mut self, data: &[u8]) {
        let data = {
            let mut dest = self.enqueue(data.len());
            let (data, rest) = data.split_at(dest.len());
            dest.copy_from_slice(data);
            rest
        };
        // Retry, in case we had a wraparound.
        let mut dest = self.enqueue(data.len());
        let (data, _) = data.split_at(dest.len());
        dest.copy_from_slice(data);
    }

    fn clamp_reader(&self, offset: usize, mut size: usize) -> (usize, usize) {
        let read_at = (self.read_at + offset) % self.storage.len();
        // We can't read past the end of the queued data.
        if offset > self.length { return (read_at, 0) }
        // We can't dequeue more than was queued.
        let clamped_length = self.length - offset;
        if size > clamped_length { size = clamped_length }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.storage.len() - read_at;
        if size > until_end { size = until_end }

        (read_at, size)
    }

    fn dequeue(&mut self, size: usize) -> &[u8] {
        let (read_at, size) = self.clamp_reader(0, size);
        self.read_at = (self.read_at + size) % self.storage.len();
        self.length -= size;
        &self.storage[read_at..read_at + size]
    }

    fn peek(&self, offset: usize, size: usize) -> &[u8] {
        let (read_at, size) = self.clamp_reader(offset, size);
        &self.storage[read_at..read_at + size]
    }

    fn advance(&mut self, size: usize) {
        if size > self.length {
            panic!("advancing {} octets into free space", size - self.length)
        }
        self.read_at = (self.read_at + size) % self.storage.len();
        self.length -= size;
    }
}

impl<'a> Into<SocketBuffer<'a>> for Managed<'a, [u8]> {
    fn into(self) -> SocketBuffer<'a> {
        SocketBuffer::new(self)
    }
}

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

#[derive(Debug, PartialEq)]
struct Retransmit {
    resend_at: u64,
    delay:     u64
}

impl Retransmit {
    fn new() -> Retransmit {
        Retransmit { resend_at: 0, delay: 0 }
    }

    fn reset(&mut self) {
        self.resend_at = 0;
        self.delay     = 0;
    }

    fn may_send_old(&mut self, timestamp: u64) -> bool {
        if self.delay == 0 {
            // We haven't transmitted anything yet.
            false
        } else if timestamp < self.resend_at {
            // We may not retransmit yet.
            false
        } else {
            // We may retransmit!
            true
        }
    }

    fn may_send_new(&mut self, timestamp: u64) -> bool {
        if self.delay == 0 {
            // We've something new to transmit, do it unconditionally.
            self.delay      = 100; // ms
            self.resend_at  = timestamp + self.delay;
            true
        } else {
            false
        }
    }

    fn commit(&mut self, timestamp: u64) -> Option<u64> {
        if self.delay == 0 {
            self.delay      = 100; // ms
            self.resend_at  = timestamp + self.delay;
            None
        } else if timestamp >= self.resend_at {
            let actual_delay = (timestamp - self.resend_at) + self.delay;
            self.resend_at  = timestamp + self.delay;
            self.delay     *= 2;
            Some(actual_delay)
        } else {
            None
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
    debug_id:        usize,
    /// State of the socket.
    state:           State,
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
    remote_last_ack: TcpSeqNumber,
    /// The speculative remote window size.
    /// I.e. the actual remote window size minus the count of in-flight octets.
    remote_win_len:  usize,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss:      usize,
    /// The retransmit timeout.
    retransmit:      Retransmit,
    /// The TIME-WAIT timeout.
    time_wait_since: u64,
    rx_buffer:       SocketBuffer<'a>,
    tx_buffer:       SocketBuffer<'a>,
}

const DEFAULT_MSS: usize = 536;
const TIME_WAIT_TIMEOUT: u64 = 10_000;

impl<'a> TcpSocket<'a> {
    /// Create a socket using the given buffers.
    pub fn new<T>(rx_buffer: T, tx_buffer: T) -> Socket<'a, 'static>
            where T: Into<SocketBuffer<'a>> {
        let rx_buffer = rx_buffer.into();
        if rx_buffer.capacity() > <u16>::max_value() as usize {
            panic!("buffers larger than {} require window scaling, which is not implemented",
                   <u16>::max_value())
        }

        Socket::Tcp(TcpSocket {
            debug_id:        0,
            state:           State::Closed,
            listen_address:  IpAddress::default(),
            local_endpoint:  IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            local_seq_no:    TcpSeqNumber(0),
            remote_seq_no:   TcpSeqNumber(0),
            remote_last_seq: TcpSeqNumber(0),
            remote_last_ack: TcpSeqNumber(0),
            remote_win_len:  0,
            remote_mss:      DEFAULT_MSS,
            retransmit:      Retransmit::new(),
            time_wait_since: 0,
            tx_buffer:       tx_buffer.into(),
            rx_buffer:       rx_buffer.into(),
        })
    }

    /// Return the debug identifier.
    #[inline]
    pub fn debug_id(&self) -> usize {
        self.debug_id
    }

    /// Set the debug identifier.
    ///
    /// The debug identifier is a number printed in socket trace messages.
    /// It could as well be used by the user code.
    pub fn set_debug_id(&mut self, id: usize) {
        self.debug_id = id
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
        self.listen_address  = IpAddress::default();
        self.local_endpoint  = IpEndpoint::default();
        self.remote_endpoint = IpEndpoint::default();
        self.local_seq_no    = TcpSeqNumber(0);
        self.remote_seq_no   = TcpSeqNumber(0);
        self.remote_last_seq = TcpSeqNumber(0);
        self.remote_last_ack = TcpSeqNumber(0);
        self.remote_win_len  = 0;
        self.remote_mss      = DEFAULT_MSS;
        self.retransmit.reset();
        self.tx_buffer.clear();
        self.rx_buffer.clear();
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
            State::SynReceived | State::Established => {
                self.retransmit.reset();
                self.set_state(State::FinWait1);
            }
            State::CloseWait => {
                self.retransmit.reset();
                self.set_state(State::LastAck);
            }
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
    /// In terms of the TCP state machine, the socket must be in the `CLOSED` or `TIME-WAIT` state.
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

        !self.tx_buffer.full()
    }

    /// Check whether the receive half of the full-duplex connection buffer is open
    /// (see [may_recv](#method.may_recv), and the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        if !self.may_recv() { return false }

        !self.rx_buffer.empty()
    }

    /// Enqueue a sequence of octets to be sent, and return a pointer to it.
    ///
    /// This function may return a slice smaller than the requested size in case
    /// there is not enough contiguous free space in the transmit buffer, down to
    /// an empty slice.
    ///
    /// This function returns `Err(Error::Illegal) if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send(&mut self, size: usize) -> Result<&mut [u8]> {
        if !self.may_send() { return Err(Error::Illegal) }

        #[cfg(any(test, feature = "verbose"))]
        let old_length = self.tx_buffer.len();
        let buffer = self.tx_buffer.enqueue(size);
        if buffer.len() > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!("[{}]{}:{}: tx buffer: enqueueing {} octets (now {})",
                       self.debug_id, self.local_endpoint, self.remote_endpoint,
                       buffer.len(), old_length + buffer.len());
            self.retransmit.reset();
        }
        Ok(buffer)
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of bytes actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        let buffer = self.send(data.len())?;
        let data = &data[..buffer.len()];
        buffer.copy_from_slice(data);
        Ok(buffer.len())
    }

    /// Dequeue a sequence of received octets, and return a pointer to it.
    ///
    /// This function may return a slice smaller than the requested size in case
    /// there are not enough octets queued in the receive buffer, down to
    /// an empty slice.
    ///
    /// This function returns `Err(Error::Illegal) if the receive half of
    /// the connection is not open; see [may_recv](#method.may_recv).
    pub fn recv(&mut self, size: usize) -> Result<&[u8]> {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN.
        if !self.may_recv() { return Err(Error::Illegal) }

        #[cfg(any(test, feature = "verbose"))]
        let old_length = self.rx_buffer.len();
        let buffer = self.rx_buffer.dequeue(size);
        self.remote_seq_no += buffer.len();
        if buffer.len() > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!("[{}]{}:{}: rx buffer: dequeueing {} octets (now {})",
                       self.debug_id, self.local_endpoint, self.remote_endpoint,
                       buffer.len(), old_length - buffer.len());
        }
        Ok(buffer)
    }

    /// Dequeue a sequence of received octets, and fill a slice from it.
    ///
    /// This function returns the amount of bytes actually dequeued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.recv(data.len())?;
        let data = &mut data[..buffer.len()];
        data.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            if self.remote_endpoint.addr.is_unspecified() {
                net_trace!("[{}]{}: state={}=>{}",
                           self.debug_id, self.local_endpoint,
                           self.state, state);
            } else {
                net_trace!("[{}]{}:{}: state={}=>{}",
                           self.debug_id, self.local_endpoint, self.remote_endpoint,
                           self.state, state);
            }
        }
        self.state = state
    }

    pub(crate) fn process(&mut self, timestamp: u64, ip_repr: &IpRepr,
                          payload: &[u8]) -> Result<()> {
        debug_assert!(ip_repr.protocol() == IpProtocol::Tcp);

        if self.state == State::Closed { return Err(Error::Rejected) }

        let packet = TcpPacket::new_checked(&payload[..ip_repr.payload_len()])?;
        let repr = TcpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        // Reject packets with a wrong destination.
        if self.local_endpoint.port != repr.dst_port { return Err(Error::Rejected) }
        if !self.local_endpoint.addr.is_unspecified() &&
           self.local_endpoint.addr != ip_repr.dst_addr() { return Err(Error::Rejected) }

        // Reject packets from a source to which we aren't connected.
        if self.remote_endpoint.port != 0 &&
           self.remote_endpoint.port != repr.src_port { return Err(Error::Rejected) }
        if !self.remote_endpoint.addr.is_unspecified() &&
           self.remote_endpoint.addr != ip_repr.src_addr() { return Err(Error::Rejected) }

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
            // The initial SYN (or whatever) cannot contain an acknowledgement.
            // It may be destined to another socket though.
            (State::Listen, TcpRepr { ack_number: Some(_), .. }) => {
                return Err(Error::Rejected)
            }
            (State::Listen, TcpRepr { ack_number: None, .. }) => (),
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpRepr { control: TcpControl::Rst, ack_number: None, .. }) => {
                net_trace!("[{}]{}:{}: unacceptable RST (expecting RST|ACK) \
                            in response to initial SYN",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            (State::SynSent, TcpRepr {
                control: TcpControl::Rst, ack_number: Some(ack_number), ..
            }) => {
                if ack_number != self.local_seq_no + 1 {
                    net_trace!("[{}]{}:{}: unacceptable RST|ACK in response to initial SYN",
                               self.debug_id, self.local_endpoint, self.remote_endpoint);
                    return Err(Error::Malformed)
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpRepr { control: TcpControl::Rst, .. }) => (),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, TcpRepr { ack_number: None, .. }) => {
                net_trace!("[{}]{}:{}: expecting an ACK",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, TcpRepr { ack_number: Some(ack_number), .. }) => {
                let unacknowledged = self.tx_buffer.len() + control_len;
                if ack_number < self.local_seq_no {
                    net_trace!("[{}]{}:{}: duplicate ACK ({} not in {}...{})",
                               self.debug_id, self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    // FIXME: instead of waiting for the retransmit timer to kick in,
                    // reset it here.
                    return Err(Error::Dropped)
                }
                if ack_number > self.local_seq_no + unacknowledged {
                    net_trace!("[{}]{}:{}: unacceptable ACK ({} not in {}...{})",
                               self.debug_id, self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    return Err(Error::Dropped)
                }
            }
        }

        match (self.state, repr) {
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            (State::Listen, _)  => (),
            (State::SynSent, _) => (),
            // In all other states, segments must occupy a valid portion of the receive window.
            // For now, do not try to reassemble out-of-order segments.
            (_, TcpRepr { seq_number, .. }) => {
                let next_remote_seq = self.remote_seq_no + self.rx_buffer.len();
                let mut send_ack_again = false;
                if seq_number > next_remote_seq {
                    net_trace!("[{}]{}:{}: unacceptable SEQ ({} not in {}..), \
                                will send duplicate ACK",
                               self.debug_id, self.local_endpoint, self.remote_endpoint,
                               seq_number, next_remote_seq);
                    // Some segments between what we have last received and this segment
                    // went missing. Send a duplicate ACK; RFC 793 does not specify the behavior
                    // required when receiving a duplicate ACK, but in practice (see RFC 1122
                    // section 4.2.2.21) most congestion control algorithms implement what's called
                    // a "fast retransmit", where a threshold amount of duplicate ACKs triggers
                    // retransmission.
                    send_ack_again = true;
                } else if seq_number != next_remote_seq {
                    net_trace!("[{}]{}:{}: duplicate SEQ ({} in ..{}), \
                                will re-send ACK",
                               self.debug_id, self.local_endpoint, self.remote_endpoint,
                               seq_number, next_remote_seq);
                    // If we've seen this sequence number already but the remote end is not aware
                    // of that, make sure we send the acknowledgement again.
                    send_ack_again = true;
                }

                if send_ack_again {
                    self.remote_last_ack = next_remote_seq - 1;
                    self.retransmit.reset();
                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not realize we've closed the connection.
                    if self.state == State::TimeWait {
                        self.time_wait_since = timestamp;
                    }
                    return Err(Error::Dropped)
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
                    net_trace!("[{}]{}:{}: received ACK of FIN",
                               self.debug_id, self.local_endpoint, self.remote_endpoint);
                    ack_of_fin = true;
                }
            }
        }

        // Validate and update the state.
        match (self.state, repr) {
            // RSTs are ignored in the LISTEN state.
            (State::Listen, TcpRepr { control: TcpControl::Rst, .. }) =>
                return Err(Error::Rejected),

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            (State::SynReceived, TcpRepr { control: TcpControl::Rst, .. }) => {
                net_trace!("[{}]{}:{}: received RST",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                self.local_endpoint.addr = self.listen_address;
                self.remote_endpoint     = IpEndpoint::default();
                self.set_state(State::Listen);
                return Ok(())
            }

            // RSTs in any other state close the socket.
            (_, TcpRepr { control: TcpControl::Rst, .. }) => {
                net_trace!("[{}]{}:{}: received RST",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                self.set_state(State::Closed);
                self.local_endpoint  = IpEndpoint::default();
                self.remote_endpoint = IpEndpoint::default();
                return Ok(())
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpRepr {
                src_port, dst_port, control: TcpControl::Syn, seq_number, ack_number: None,
                max_seg_size, ..
            }) => {
                net_trace!("[{}]{}: received SYN",
                           self.debug_id, self.local_endpoint);
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), dst_port);
                self.remote_endpoint = IpEndpoint::new(ip_repr.src_addr(), src_port);
                // FIXME: use something more secure here
                self.local_seq_no    = TcpSeqNumber(-seq_number.0);
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_seq_no   = seq_number + 1;
                if let Some(max_seg_size) = max_seg_size {
                    self.remote_mss = max_seg_size as usize
                }
                self.set_state(State::SynReceived);
                self.retransmit.reset();
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpRepr { control: TcpControl::None, .. }) => {
                self.set_state(State::Established);
                self.retransmit.reset();
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.set_state(State::CloseWait);
                self.retransmit.reset();
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            (State::SynSent, TcpRepr {
                control: TcpControl::Syn, seq_number, ack_number: Some(_),
                max_seg_size, ..
            }) => {
                net_trace!("[{}]{}:{}: received SYN|ACK",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_seq_no   = seq_number + 1;
                self.remote_last_ack = seq_number;
                if let Some(max_seg_size) = max_seg_size {
                    self.remote_mss = max_seg_size as usize;
                }
                self.set_state(State::Established);
                self.retransmit.reset();
            }

            // ACK packets in ESTABLISHED state reset the retransmit timer.
            (State::Established, TcpRepr { control: TcpControl::None, .. }) => {
                self.retransmit.reset()
            },

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.set_state(State::CloseWait);
                self.retransmit.reset();
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpRepr { control: TcpControl::None, .. }) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                } else {
                    self.retransmit.reset();
                }
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                if ack_of_fin {
                    self.time_wait_since = timestamp;
                    self.set_state(State::TimeWait);
                } else {
                    self.set_state(State::Closing);
                }
                self.retransmit.reset();
            }

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.time_wait_since = timestamp;
                self.set_state(State::TimeWait);
                self.retransmit.reset();
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpRepr { control: TcpControl::None, .. }) => {
                if ack_of_fin {
                    self.time_wait_since = timestamp;
                    self.set_state(State::TimeWait);
                } else {
                    self.retransmit.reset();
                }
            }

            // ACK packets in CLOSE-WAIT state reset the retransmit timer.
            (State::CloseWait, TcpRepr { control: TcpControl::None, .. }) => {
                self.retransmit.reset();
            }

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpRepr { control: TcpControl::None, .. }) => {
                // Clear the remote endpoint, or we'll send an RST there.
                self.set_state(State::Closed);
                self.remote_endpoint = IpEndpoint::default();
            }

            _ => {
                net_trace!("[{}]{}:{}: unexpected packet {}",
                           self.debug_id, self.local_endpoint, self.remote_endpoint, repr);
                return Err(Error::Malformed)
            }
        }

        // Dequeue acknowledged octets.
        if ack_len > 0 {
            net_trace!("[{}]{}:{}: tx buffer: dequeueing {} octets (now {})",
                       self.debug_id, self.local_endpoint, self.remote_endpoint,
                       ack_len, self.tx_buffer.len() - ack_len);
            self.tx_buffer.advance(ack_len);
        }

        // We've processed everything in the incoming segment, so advance the local
        // sequence number past it.
        if let Some(ack_number) = repr.ack_number {
            self.local_seq_no = ack_number;
        }

        // Enqueue payload octets, which is guaranteed to be in order, unless we already did.
        if repr.payload.len() > 0 {
            net_trace!("[{}]{}:{}: rx buffer: enqueueing {} octets (now {})",
                       self.debug_id, self.local_endpoint, self.remote_endpoint,
                       repr.payload.len(), self.rx_buffer.len() + repr.payload.len());
            self.rx_buffer.enqueue_slice(repr.payload)
        }

        // Update window length.
        self.remote_win_len = repr.window_len as usize;

        Ok(())
    }

    pub(crate) fn dispatch<F, R>(&mut self, timestamp: u64, limits: &DeviceLimits,
                                 emit: &mut F) -> Result<R>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R> {
        if !self.remote_endpoint.is_specified() { return Err(Error::Exhausted) }

        let mut repr = TcpRepr {
            src_port:     self.local_endpoint.port,
            dst_port:     self.remote_endpoint.port,
            control:      TcpControl::None,
            push:         false,
            seq_number:   self.local_seq_no,
            ack_number:   None,
            window_len:   self.rx_buffer.window() as u16,
            max_seg_size: None,
            payload:      &[]
        };

        if self.state == State::Closed {
            // If we have a specified local and remote endpoint, but are in the CLOSED state,
            // we've ended up here after aborting a connection. Send exactly one RST packet.
            net_trace!("[{}]{}:{}: sending RST",
                       self.debug_id, self.local_endpoint, self.remote_endpoint);

            repr.control    = TcpControl::Rst;
            repr.ack_number = Some(self.remote_seq_no);
            let ip_repr = IpRepr::Unspecified {
                src_addr:    self.local_endpoint.addr,
                dst_addr:    self.remote_endpoint.addr,
                protocol:    IpProtocol::Tcp,
                payload_len: repr.buffer_len()
            };
            let result = emit(&ip_repr, &repr);

            self.local_endpoint  = IpEndpoint::default();
            self.remote_endpoint = IpEndpoint::default();
            return result
        }

        if self.state == State::TimeWait {
            if timestamp >= self.time_wait_since + TIME_WAIT_TIMEOUT {
                net_trace!("[{}]{}:{}: TIME-WAIT timeout",
                           self.debug_id, self.local_endpoint, self.remote_endpoint);
                self.reset();
                return Err(Error::Exhausted)
            }
        }

        if self.retransmit.may_send_old(timestamp) {
            // The retransmit timer has expired, so assume all in-flight data that
            // has not been acknowledged is lost.
            match self.state {
                // Retransmission of SYN is handled elsewhere.
                State::SynReceived => (),
                _ => self.remote_last_seq = self.local_seq_no
            }
        } else if self.retransmit.may_send_new(timestamp) {
            // The retransmit timer has been reset, and we can send something new.
        } else {
            // We don't have anything to send at this time.
            return Err(Error::Exhausted)
        }

        let mut should_send = false;
        match self.state {
            // We never transmit anything in the CLOSED, LISTEN, or FIN-WAIT-2 states.
            State::Closed | State::Listen | State::FinWait2 => {
                return Err(Error::Exhausted)
            }

            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            // We transmit a SYN in the SYN-SENT state.
            State::SynReceived | State::SynSent => {
                repr.control = TcpControl::Syn;
                net_trace!("[{}]{}:{}: sending SYN{}",
                           self.debug_id, self.local_endpoint, self.remote_endpoint,
                           if self.state == State::SynReceived { "|ACK" } else { "" });
                should_send = true;
            }

            // We transmit data in the ESTABLISHED state,
            // ACK in CLOSE-WAIT, CLOSING, and TIME-WAIT states,
            // FIN in FIN-WAIT-1 and LAST-ACK states,
            // but only if the receiver has a nonzero window.
            State::Established |
            State::CloseWait   | State::Closing | State::TimeWait |
            State::FinWait1    | State::LastAck
                    if self.remote_win_len > 0 => {
                // We can send something, so let's try doing that.
                let mut size = self.tx_buffer.len();
                // Clamp to remote window length.
                if size > self.remote_win_len { size = self.remote_win_len }
                // Clamp to MSS.
                if size > self.remote_mss { size = self.remote_mss }
                // Extract data from the buffer. This may return less than what we want,
                // in case it's not possible to extract a contiguous slice.
                let offset = self.remote_last_seq - self.local_seq_no;
                let data = self.tx_buffer.peek(offset, size);
                if data.len() > 0 {
                    // Send the extracted data.
                    net_trace!("[{}]{}:{}: tx buffer: peeking at {} octets (from {})",
                               self.debug_id, self.local_endpoint, self.remote_endpoint,
                               data.len(), offset);
                    repr.seq_number += offset;
                    repr.payload = data;
                    // If that was the last data we had buffered, set the PSH flag.
                    if offset + data.len() == self.tx_buffer.len() {
                        repr.push = true;
                    }
                    // Speculatively shrink the remote window. This will get updated
                    // the next time we receive a packet.
                    self.remote_win_len  -= data.len();
                    // Advance the in-flight sequence number.
                    self.remote_last_seq += data.len();
                    should_send = true;
                }
                // The FIN control flag occupies the place in the sequence space after
                // the data in the current segment. If we still have some data left for the next
                // segment (e.g. the receiver window is too small), then don't send FIN just yet.
                let all_data_sent = self.tx_buffer.len() == offset + data.len();
                match self.state {
                    State::FinWait1 | State::LastAck if all_data_sent => {
                        // We should notify the other side that we've closed the transmit half
                        // of the connection.
                        net_trace!("[{}]{}:{}: sending FIN|ACK",
                                   self.debug_id, self.local_endpoint, self.remote_endpoint);
                        repr.control = TcpControl::Fin;
                        self.remote_last_seq += 1;
                        should_send = true;
                    }
                    _ => ()
                }
            }

            // We don't transmit anything (except ACKs) if the receiver has a zero window.
            State::Established |
            State::CloseWait   | State::Closing | State::TimeWait |
            State::FinWait1    | State::LastAck => ()
        }

        let ack_number = self.remote_seq_no + self.rx_buffer.len();
        if !should_send && self.remote_last_ack != ack_number {
            // Acknowledge all data we have received, since it is all in order.
            net_trace!("[{}]{}:{}: sending ACK",
                       self.debug_id, self.local_endpoint, self.remote_endpoint);
            should_send = true;
        }

        if should_send {
            if let Some(actual_delay) = self.retransmit.commit(timestamp) {
                net_trace!("[{}]{}:{}: retransmitting at t+{}ms ",
                           self.debug_id, self.local_endpoint, self.remote_endpoint,
                           actual_delay);
            }

            if self.state != State::SynSent {
                repr.ack_number = Some(ack_number);
                self.remote_last_ack = ack_number;
            }

            // Remember the header length before enabling the MSS option, since that option
            // only affects SYN packets.
            let header_len = repr.header_len();

            if repr.control == TcpControl::Syn {
                // First enable the option, without assigning any value, to get a correct
                // result for the payload_len field of ip_repr below.
                repr.max_seg_size = Some(0);
            }

            let ip_repr = IpRepr::Unspecified {
                src_addr:     self.local_endpoint.addr,
                dst_addr:     self.remote_endpoint.addr,
                protocol:     IpProtocol::Tcp,
                payload_len:  repr.buffer_len()
            };
            let ip_repr = ip_repr.lower(&[])?;

            let mut max_segment_size = limits.max_transmission_unit;
            max_segment_size -= header_len;
            max_segment_size -= ip_repr.buffer_len();

            if repr.control == TcpControl::Syn {
                repr.max_seg_size = Some(max_segment_size as u16);
            }

            if let Some(max_burst_size) = limits.max_burst_size {
                let max_window_size = max_burst_size * max_segment_size;
                if repr.window_len as usize > max_window_size {
                    repr.window_len = max_window_size as u16;
                }
            }

            emit(&ip_repr, &repr)
        } else {
            Err(Error::Exhausted)
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

impl<'a> IpPayload for TcpRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.buffer_len()
    }

    fn emit(&self, ip_repr: &IpRepr, payload: &mut [u8]) {
        let mut packet = TcpPacket::new(payload);
        self.emit(&mut packet, &ip_repr.src_addr(), &ip_repr.dst_addr())
    }
}

#[cfg(test)]
mod test {
    use wire::{IpAddress, Ipv4Address};
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = SocketBuffer::new(vec![0; 8]); // ........
        buffer.enqueue(6).copy_from_slice(b"foobar");   // foobar..
        assert_eq!(buffer.dequeue(3), b"foo");          // ...bar..
        buffer.enqueue(6).copy_from_slice(b"ba");       // ...barba
        buffer.enqueue(4).copy_from_slice(b"zho");      // zhobarba
        assert_eq!(buffer.dequeue(6), b"barba");        // zho.....
        assert_eq!(buffer.dequeue(8), b"zho");          // ........
        buffer.enqueue(8).copy_from_slice(b"gefug");    // ...gefug
    }

    #[test]
    fn test_buffer_wraparound() {
        let mut buffer = SocketBuffer::new(vec![0; 8]); // ........
        buffer.enqueue_slice(&b"foobar"[..]);           // foobar..
        assert_eq!(buffer.dequeue(3), b"foo");          // ...bar..
        buffer.enqueue_slice(&b"bazhoge"[..]);          // zhobarba
    }

    #[test]
    fn test_buffer_peek() {
        let mut buffer = SocketBuffer::new(vec![0; 8]); // ........
        buffer.enqueue_slice(&b"foobar"[..]);           // foobar..
        assert_eq!(buffer.peek(0, 8), &b"foobar"[..]);
        assert_eq!(buffer.peek(3, 8), &b"bar"[..]);
    }

    #[test]
    fn test_retransmit_may_send() {
        fn may_send(r: &mut Retransmit, t: u64) -> (bool, bool) {
            (r.may_send_old(t), r.may_send_new(t))
        }

        let mut r = Retransmit::new();
        assert_eq!(may_send(&mut r, 1000), (false, true));
        r.commit(1000);
        assert_eq!(may_send(&mut r, 1000), (false, false));
        assert_eq!(may_send(&mut r, 1050), (false, false));
        assert_eq!(may_send(&mut r, 1101), (true,  false));
        r.commit(1101);
        assert_eq!(may_send(&mut r, 1150), (false, false));
        assert_eq!(may_send(&mut r, 1200), (false, false));
        assert_eq!(may_send(&mut r, 1301), (true,  false));
        r.reset();
        assert_eq!(may_send(&mut r, 1350), (false, true));
    }

    const LOCAL_IP:     IpAddress    = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1]));
    const REMOTE_IP:    IpAddress    = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 2]));
    const LOCAL_PORT:   u16          = 80;
    const REMOTE_PORT:  u16          = 49500;
    const LOCAL_END:    IpEndpoint   = IpEndpoint { addr: LOCAL_IP,  port: LOCAL_PORT  };
    const REMOTE_END:   IpEndpoint   = IpEndpoint { addr: REMOTE_IP, port: REMOTE_PORT };
    const LOCAL_SEQ:    TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ:   TcpSeqNumber = TcpSeqNumber(-10000);

    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT, dst_port: LOCAL_PORT,
        control: TcpControl::None, push: false,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 256, max_seg_size: None,
        payload: &[]
    };
    const RECV_TEMPL:  TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT, dst_port: REMOTE_PORT,
        control: TcpControl::None, push: false,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 64, max_seg_size: None,
        payload: &[]
    };

    fn send(socket: &mut TcpSocket, timestamp: u64, repr: &TcpRepr) -> Result<()> {
        trace!("send: {}", repr);
        let mut buffer = vec![0; repr.buffer_len()];
        let mut packet = TcpPacket::new(&mut buffer);
        repr.emit(&mut packet, &REMOTE_IP, &LOCAL_IP);
        let ip_repr = IpRepr::Unspecified {
            src_addr:    REMOTE_IP,
            dst_addr:    LOCAL_IP,
            protocol:    IpProtocol::Tcp,
            payload_len: repr.buffer_len()
        };
        socket.process(timestamp, &ip_repr, &packet.into_inner()[..])
    }

    fn recv<F>(socket: &mut TcpSocket, timestamp: u64, mut f: F)
            where F: FnMut(Result<TcpRepr>) {
        let mut buffer = vec![];
        let mut limits = DeviceLimits::default();
        limits.max_transmission_unit = 1520;
        let result = socket.dispatch(timestamp, &limits, &mut |ip_repr, payload| {
            let ip_repr = ip_repr.lower(&[LOCAL_END.addr.into()]).unwrap();

            assert_eq!(ip_repr.protocol(), IpProtocol::Tcp);
            assert_eq!(ip_repr.src_addr(), LOCAL_IP);
            assert_eq!(ip_repr.dst_addr(), REMOTE_IP);

            buffer.resize(payload.buffer_len(), 0);
            payload.emit(&ip_repr, &mut buffer[..]);
            let packet = TcpPacket::new(&buffer[..]);
            let repr = TcpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr())?;
            trace!("recv: {}", repr);
            Ok(f(Ok(repr)))
        });
        // Appease borrow checker.
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
            (send!($socket, time $time, $repr, Ok(())));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, $time, &$repr), $result));
    }

    macro_rules! recv {
        ($socket:ident, [$( $repr:expr )*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv!($socket, Err(Error::Exhausted))
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, $time, |repr| {
                // Most of the time we don't care about the PSH flag.
                let repr = repr.map(|r| TcpRepr { push: false, ..r });
                assert_eq!(repr, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, $time, |repr| assert_eq!(repr, $result)));
    }

    macro_rules! sanity {
        ($socket1:expr, $socket2:expr, retransmit: $retransmit:expr) => ({
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state,            s2.state,           "state");
            assert_eq!(s1.listen_address,   s2.listen_address,  "listen_address");
            assert_eq!(s1.local_endpoint,   s2.local_endpoint,  "local_endpoint");
            assert_eq!(s1.remote_endpoint,  s2.remote_endpoint, "remote_endpoint");
            assert_eq!(s1.local_seq_no,     s2.local_seq_no,    "local_seq_no");
            assert_eq!(s1.remote_seq_no,    s2.remote_seq_no,   "remote_seq_no");
            assert_eq!(s1.remote_last_seq,  s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack,  s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_win_len,   s2.remote_win_len,  "remote_win_len");
            assert_eq!(s1.time_wait_since,  s2.time_wait_since, "time_wait_since");
            if $retransmit {
                assert_eq!(s1.retransmit,   s2.retransmit,      "retransmit");
            } else {
                let retransmit = Retransmit { resend_at: 100, delay: 100 };
                assert_eq!(s1.retransmit,      retransmit,      "retransmit (delaying)");
            }
        });
        ($socket1:expr, $socket2:expr) =>
            (sanity!($socket1, $socket2, retransmit: true))
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
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        send!(s, TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        }, Err(Error::Rejected));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        send!(s, TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        }, Err(Error::Rejected));
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
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }, Err(Error::Rejected));
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
        }, Err(Error::Rejected));
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
        s.remote_last_seq = LOCAL_SEQ + 1;
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
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, TcpSocket {
            remote_last_ack: REMOTE_SEQ + 1,
            ..socket_close_wait()
        });
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
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
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established(), retransmit: false);
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
        }, Err(Error::Malformed));
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
        }, Err(Error::Malformed));
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
        s.remote_last_ack = REMOTE_SEQ + 1;
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
        assert_eq!(s.rx_buffer.dequeue(6), &b"abcdef"[..]);
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
        let mut s = socket_established();
        s.remote_win_len = 16;
        // First roundtrip after establishing.
        s.send_slice(&[0; 32][..]).unwrap();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; 16][..],
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }, Err(Error::Malformed));
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
        }, Err(Error::Dropped));
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
        }, Err(Error::Dropped));
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
        sanity!(s, socket_close_wait(), retransmit: false);
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
        sanity!(s, TcpSocket {
            remote_last_seq: LOCAL_SEQ + 1 + 1,
            ..socket_fin_wait_2()
        }, retransmit: false);
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
        sanity!(s, TcpSocket {
            remote_last_seq: LOCAL_SEQ + 1 + 1,
            ..socket_closing()
        });
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
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
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1 + 1;
        s
    }

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true), retransmit: false);
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
            s.remote_last_ack = REMOTE_SEQ + 1 + 1;
        }
        s.time_wait_since = 1_000;
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
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Err(Error::Dropped));
        assert_eq!(s.time_wait_since, 5_000);
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
        s.remote_last_ack = REMOTE_SEQ + 1 + 1;
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
        recv!(s, [TcpRepr { // this is logically located...
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
            seq_number: LOCAL_SEQ + 1,
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
        }, Err(Error::Dropped));
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_missing_segment() {
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
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload:    &b"mnopqr"[..],
            ..SEND_TEMPL
        }, Err(Error::Dropped));
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]);
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
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; 1000][..],
            ..RECV_TEMPL
        }])
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_window_size_clamp() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 32767]);

        let mut limits = DeviceLimits::default();
        limits.max_transmission_unit = 1520;

        limits.max_burst_size = None;
        s.send_slice(b"abcdef").unwrap();
        s.dispatch(0, &limits, &mut |ip_repr, payload| {
            let mut buffer = vec![0; payload.buffer_len()];
            payload.emit(&ip_repr, &mut buffer[..]);
            let packet = TcpPacket::new(&buffer[..]);
            assert_eq!(packet.window_len(), 32767);
            Ok(())
        }).unwrap();

        limits.max_burst_size = Some(4);
        s.send_slice(b"abcdef").unwrap();
        s.dispatch(0, &limits, &mut |ip_repr, payload| {
            let mut buffer = vec![0; payload.buffer_len()];
            payload.emit(&ip_repr, &mut buffer[..]);
            let packet = TcpPacket::new(&buffer[..]);
            assert_eq!(packet.window_len(), 5920);
            Ok(())
        }).unwrap();
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            push:       false,
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            push:       true,
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }
}
