use core::fmt;

use Error;
use Managed;
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

    fn capacity(&self) -> usize {
        self.storage.len()
    }

    fn len(&self) -> usize {
        self.length
    }

    fn window(&self) -> usize {
        self.capacity() - self.len()
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

#[derive(Debug)]
struct Retransmit {
    sent: bool // FIXME
}

impl Retransmit {
    fn new() -> Retransmit {
        Retransmit { sent: false }
    }

    fn reset(&mut self) {
        self.sent = false
    }

    fn check(&mut self) -> bool {
        let result = !self.sent;
        self.sent = true;
        result
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
    retransmit:      Retransmit,
    rx_buffer:       SocketBuffer<'a>,
    tx_buffer:       SocketBuffer<'a>
}

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
            state:           State::Closed,
            listen_address:  IpAddress::default(),
            local_endpoint:  IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            local_seq_no:    TcpSeqNumber(0),
            remote_seq_no:   TcpSeqNumber(0),
            remote_last_seq: TcpSeqNumber(0),
            remote_last_ack: TcpSeqNumber(0),
            remote_win_len:  0,
            retransmit:      Retransmit::new(),
            tx_buffer:       tx_buffer.into(),
            rx_buffer:       rx_buffer.into()
        })
    }

    /// Return the local endpoint.
    #[inline(always)]
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    /// Return the remote endpoint.
    #[inline(always)]
    pub fn remote_endpoint(&self) -> IpEndpoint {
        self.remote_endpoint
    }

    /// Start listening on the given endpoint.
    ///
    /// This function returns an error if the socket was open; see [is_open](#method.is_open).
    pub fn listen<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<(), ()> {
        if self.is_open() { return Err(()) }

        let endpoint = endpoint.into();
        self.listen_address  = endpoint.addr;
        self.local_endpoint  = endpoint;
        self.remote_endpoint = IpEndpoint::default();
        self.set_state(State::Listen);
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

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    pub fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true
        }
    }

    /// Return whether a connection is established.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    pub fn is_connected(&self) -> bool {
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
    pub fn can_send(&self) -> bool {
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
    pub fn can_recv(&self) -> bool {
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

    /// Enqueue a sequence of octets to be sent, and return a pointer to it.
    ///
    /// This function may return a slice smaller than the requested size in case
    /// there is not enough contiguous free space in the transmit buffer, down to
    /// an empty slice.
    ///
    /// This function returns an error if the transmit half of the connection is not open;
    /// see [can_send](#method.can_send).
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], ()> {
        if !self.can_send() { return Err(()) }

        let old_length = self.tx_buffer.len();
        let buffer = self.tx_buffer.enqueue(size);
        if buffer.len() > 0 {
            net_trace!("tcp:{}:{}: tx buffer: enqueueing {} octets (now {})",
                       self.local_endpoint, self.remote_endpoint,
                       buffer.len(), old_length + buffer.len());
        }
        Ok(buffer)
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of bytes actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, ()> {
        let buffer = try!(self.send(data.len()));
        let data = &data[..buffer.len()];
        buffer.copy_from_slice(data);
        Ok(buffer.len())
    }

    /// Dequeue a sequence of received octets, and return a pointer to it.
    ///
    /// This function may return a slice smaller than the requested size in case
    /// there are not enough octets queued in the receive buffer, down to
    /// an empty slice.
    pub fn recv(&mut self, size: usize) -> Result<&[u8], ()> {
        // We may have received some data inside the initial SYN ("TCP Fast Open"),
        // but until the connection is fully open we refuse to dequeue any data.
        if !self.can_recv() { return Err(()) }

        let old_length = self.rx_buffer.len();
        let buffer = self.rx_buffer.dequeue(size);
        self.remote_seq_no += buffer.len();
        if buffer.len() > 0 {
            net_trace!("tcp:{}:{}: rx buffer: dequeueing {} octets (now {})",
                       self.local_endpoint, self.remote_endpoint,
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
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, ()> {
        let buffer = try!(self.recv(data.len()));
        let data = &mut data[..buffer.len()];
        data.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Return the connection state.
    ///
    /// This function is provided for debugging.
    pub fn state(&self) -> State {
        self.state
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            if self.remote_endpoint.addr.is_unspecified() {
                net_trace!("tcp:{}: state={}→{}",
                           self.local_endpoint, self.state, state);
            } else {
                net_trace!("tcp:{}:{}: state={}→{}",
                           self.local_endpoint, self.remote_endpoint, self.state, state);
            }
        }
        self.state = state
    }

    /// See [Socket::process](enum.Socket.html#method.process).
    pub fn process(&mut self, ip_repr: &IpRepr, payload: &[u8]) -> Result<(), Error> {
        if ip_repr.protocol() != IpProtocol::Tcp { return Err(Error::Rejected) }

        let packet = try!(TcpPacket::new(payload));
        let repr = try!(TcpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr()));

        // Reject packets with a wrong destination.
        if self.local_endpoint.port != repr.dst_port { return Err(Error::Rejected) }
        if !self.local_endpoint.addr.is_unspecified() &&
           self.local_endpoint.addr != ip_repr.dst_addr() { return Err(Error::Rejected) }

        // Reject packets from a source to which we aren't connected.
        if self.remote_endpoint.port != 0 &&
           self.remote_endpoint.port != repr.src_port { return Err(Error::Rejected) }
        if !self.remote_endpoint.addr.is_unspecified() &&
           self.remote_endpoint.addr != ip_repr.src_addr() { return Err(Error::Rejected) }

        // Reject packets addressed to a closed socket.
        if self.state == State::Closed {
            net_trace!("tcp:{}:{}:{}: packet received by a closed socket",
                       self.local_endpoint, ip_repr.src_addr(), repr.src_port);
            return Err(Error::Malformed)
        }

        // Reject unacceptable acknowledgements.
        match (self.state, repr) {
            // The initial SYN (or whatever) cannot contain an acknowledgement.
            (State::Listen, TcpRepr { ack_number: Some(_), .. }) => {
                net_trace!("tcp:{}:{}: ACK received by a socket in LISTEN state",
                           self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            (State::Listen, TcpRepr { ack_number: None, .. }) => (),
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpRepr { control: TcpControl::Rst, ack_number: None, .. }) => {
                net_trace!("tcp:{}:{}: unacceptable RST (expecting RST|ACK) \
                            in response to initial SYN",
                           self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            (State::SynSent, TcpRepr {
                control: TcpControl::Rst, ack_number: Some(ack_number), ..
            }) => {
                if ack_number != self.local_seq_no {
                    net_trace!("tcp:{}:{}: unacceptable RST|ACK in response to initial SYN",
                               self.local_endpoint, self.remote_endpoint);
                    return Err(Error::Malformed)
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpRepr { control: TcpControl::Rst, .. }) => (),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, TcpRepr { ack_number: None, .. }) => {
                net_trace!("tcp:{}:{}: expecting an ACK",
                           self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (state, TcpRepr { ack_number: Some(ack_number), .. }) => {
                let control_len = match state {
                    // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
                    State::SynSent | State::SynReceived => 1,
                    // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
                    State::FinWait1 | State::LastAck | State::Closing => 1,
                    // In all other states we've already got acknowledgemetns for
                    // all of the control flags we sent.
                    _ => 0
                };
                let unacknowledged = self.tx_buffer.len() + control_len;
                if !(ack_number >= self.local_seq_no &&
                     ack_number <= (self.local_seq_no + unacknowledged)) {
                    net_trace!("tcp:{}:{}: unacceptable ACK ({} not in {}...{})",
                               self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    return Err(Error::Malformed)
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
                if seq_number > next_remote_seq {
                    net_trace!("tcp:{}:{}: unacceptable SEQ ({} not in {}..)",
                               self.local_endpoint, self.remote_endpoint,
                               seq_number, next_remote_seq);
                    return Err(Error::Malformed)
                } else if seq_number != next_remote_seq {
                    net_trace!("tcp:{}:{}: duplicate SEQ ({} in ..{})",
                               self.local_endpoint, self.remote_endpoint,
                               seq_number, next_remote_seq);
                    return Ok(())
                }
            }
        }

        // Validate and update the state.
        match (self.state, repr) {
            // RSTs are ignored in the LISTEN state.
            (State::Listen, TcpRepr { control: TcpControl::Rst, .. }) =>
                return Ok(()),

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            (State::SynReceived, TcpRepr { control: TcpControl::Rst, .. }) => {
                net_trace!("tcp:{}:{}: received RST",
                           self.local_endpoint, self.remote_endpoint);
                self.local_endpoint.addr = self.listen_address;
                self.remote_endpoint     = IpEndpoint::default();
                self.set_state(State::Listen);
                return Ok(())
            }

            // RSTs in any other state close the socket.
            (_, TcpRepr { control: TcpControl::Rst, .. }) => {
                net_trace!("tcp:{}:{}: received RST",
                           self.local_endpoint, self.remote_endpoint);
                self.local_endpoint  = IpEndpoint::default();
                self.remote_endpoint = IpEndpoint::default();
                self.set_state(State::Closed);
                return Ok(())
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpRepr {
                src_port, dst_port, control: TcpControl::Syn, seq_number, ack_number: None, ..
            }) => {
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), dst_port);
                self.remote_endpoint = IpEndpoint::new(ip_repr.src_addr(), src_port);
                // FIXME: use something more secure here
                self.local_seq_no    = TcpSeqNumber(-seq_number.0);
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_seq_no   = seq_number + 1;
                self.set_state(State::SynReceived);
                self.retransmit.reset();
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpRepr { control: TcpControl::None, .. }) => {
                self.local_seq_no   += 1;
                self.set_state(State::Established);
                self.retransmit.reset();
            }

            // ACK packets in ESTABLISHED state do nothing.
            (State::Established, TcpRepr { control: TcpControl::None, .. }) => (),

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.set_state(State::CloseWait);
                self.retransmit.reset();
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2.
            (State::FinWait1, TcpRepr { control: TcpControl::None, .. }) => {
                self.local_seq_no   += 1;
                self.set_state(State::FinWait2);
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING.
            (State::FinWait1, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.set_state(State::Closing);
                self.retransmit.reset();
            }

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpRepr { control: TcpControl::Fin, .. }) => {
                self.remote_seq_no  += 1;
                self.set_state(State::TimeWait);
                self.retransmit.reset();
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpRepr { control: TcpControl::None, .. }) => {
                self.local_seq_no   += 1;
                self.set_state(State::TimeWait);
                self.retransmit.reset();
            }

            // ACK packets in CLOSE-WAIT state do nothing.
            (State::CloseWait, TcpRepr { control: TcpControl::None, .. }) => (),

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpRepr { control: TcpControl::None, .. }) => {
                // Clear the remote endpoint, or we'll send an RST there.
                self.remote_endpoint = IpEndpoint::default();
                self.local_seq_no   += 1;
                self.set_state(State::Closed);
            }

            _ => {
                net_trace!("tcp:{}:{}: unexpected packet {}",
                           self.local_endpoint, self.remote_endpoint, repr);
                return Err(Error::Malformed)
            }
        }

        // Dequeue acknowledged octets.
        if let Some(ack_number) = repr.ack_number {
            let ack_length = ack_number - self.local_seq_no;
            if ack_length > 0 {
                net_trace!("tcp:{}:{}: tx buffer: dequeueing {} octets (now {})",
                           self.local_endpoint, self.remote_endpoint,
                           ack_length, self.tx_buffer.len() - ack_length);
            }
            self.tx_buffer.advance(ack_length);
            self.local_seq_no = ack_number;
        }

        // Enqueue payload octets, which is guaranteed to be in order, unless we already did.
        if repr.payload.len() > 0 {
            net_trace!("tcp:{}:{}: rx buffer: enqueueing {} octets (now {})",
                       self.local_endpoint, self.remote_endpoint,
                       repr.payload.len(), self.rx_buffer.len() + repr.payload.len());
            self.rx_buffer.enqueue_slice(repr.payload)
        }

        // Update window length.
        self.remote_win_len = repr.window_len as usize;

        Ok(())
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F, R>(&mut self, emit: &mut F) -> Result<R, Error>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R, Error> {
        if self.remote_endpoint.is_unspecified() { return Err(Error::Exhausted) }

        let ip_repr = IpRepr::Unspecified {
            src_addr: self.local_endpoint.addr,
            dst_addr: self.remote_endpoint.addr,
            protocol: IpProtocol::Tcp,
        };
        let mut repr = TcpRepr {
            src_port:   self.local_endpoint.port,
            dst_port:   self.remote_endpoint.port,
            control:    TcpControl::None,
            seq_number: self.local_seq_no,
            ack_number: None,
            window_len: self.rx_buffer.window() as u16,
            payload:    &[]
        };

        let mut should_send = false;
        match self.state {
            // We never transmit anything in the CLOSED, LISTEN, or FIN-WAIT-2 states.
            State::Closed | State::Listen | State::FinWait2 => {
                return Err(Error::Exhausted)
            }

            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynReceived => {
                if !self.retransmit.check() { return Err(Error::Exhausted) }

                repr.control = TcpControl::Syn;
                net_trace!("tcp:{}:{}: sending SYN|ACK",
                           self.local_endpoint, self.remote_endpoint);
                should_send = true;
            }

            // We transmit a SYN in the SYN-SENT state.
            State::SynSent => {
                if !self.retransmit.check() { return Err(Error::Exhausted) }

                repr.control = TcpControl::Syn;
                repr.ack_number = None;
                net_trace!("tcp:{}:{}: sending SYN",
                           self.local_endpoint, self.remote_endpoint);
                should_send = true;
            }

            // We transmit data in the ESTABLISHED state,
            // ACK in CLOSE-WAIT, CLOSING, and TIME-WAIT states,
            // FIN in FIN-WAIT-1 and LAST-ACK states.
            State::Established |
            State::CloseWait   | State::Closing | State::TimeWait |
            State::FinWait1    | State::LastAck => {
                // See if we should send data to the remote end because:
                let mut may_send = false;
                //   1. the retransmit timer has expired or was reset, or...
                if self.retransmit.check() { may_send = true }
                //   2. we've got new data in the transmit buffer.
                let remote_next_seq = self.local_seq_no + self.tx_buffer.len();
                if self.remote_last_seq != remote_next_seq { may_send = true }

                if self.tx_buffer.len() > 0 && self.remote_win_len > 0 && may_send {
                    // We can send something, so let's do that.
                    let mut size = self.tx_buffer.len();
                    // Clamp to remote window length.
                    if size > self.remote_win_len { size = self.remote_win_len }
                    // Clamp to MSS. Currently we only support the default MSS value.
                    if size > 536 { size = 536 }
                    // Extract data from the buffer. This may return less than what we want,
                    // in case it's not possible to extract a contiguous slice.
                    let offset = self.remote_last_seq - self.local_seq_no;
                    let data = self.tx_buffer.peek(offset, size);
                    assert!(data.len() > 0);
                    // Send the extracted data.
                    net_trace!("tcp:{}:{}: tx buffer: peeking at {} octets (from {})",
                               self.local_endpoint, self.remote_endpoint, data.len(), offset);
                    repr.seq_number += offset;
                    repr.payload = data;
                    // Speculatively shrink the remote window. This will get updated the next
                    // time we receive a packet.
                    self.remote_win_len  -= data.len();
                    // Advance the in-flight sequence number.
                    self.remote_last_seq += data.len();
                    should_send = true;
                }

                match self.state {
                    State::FinWait1 | State::LastAck if may_send => {
                        // We should notify the other side that we've closed the transmit half
                        // of the connection.
                        net_trace!("tcp:{}:{}: sending FIN|ACK",
                                   self.local_endpoint, self.remote_endpoint);
                        repr.control = TcpControl::Fin;
                        should_send = true;
                    },
                    _ => ()
                }
            }
        }

        let ack_number = self.remote_seq_no + self.rx_buffer.len();
        if !should_send && self.remote_last_ack != ack_number {
            // Acknowledge all data we have received, since it is all in order.
            net_trace!("tcp:{}:{}: sending ACK",
                       self.local_endpoint, self.remote_endpoint);
            should_send = true;
        }

        if should_send {
            repr.ack_number = Some(ack_number);
            self.remote_last_ack = ack_number;

            emit(&ip_repr, &repr)
        } else {
            Err(Error::Exhausted)
        }
    }
}

impl<'a> IpPayload for TcpRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.buffer_len()
    }

    fn emit(&self, ip_repr: &IpRepr, payload: &mut [u8]) {
        let mut packet = TcpPacket::new(payload).expect("undersized payload");
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
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 256, payload: &[]
    };
    const RECV_TEMPL:  TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT, dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0), ack_number: Some(TcpSeqNumber(0)),
        window_len: 64, payload: &[]
    };

    fn send(socket: &mut TcpSocket, repr: &TcpRepr) -> Result<(), Error> {
        trace!("send: {}", repr);
        let mut buffer = vec![0; repr.buffer_len()];
        let mut packet = TcpPacket::new(&mut buffer).unwrap();
        repr.emit(&mut packet, &REMOTE_IP, &LOCAL_IP);
        let ip_repr = IpRepr::Unspecified {
            src_addr: REMOTE_IP,
            dst_addr: LOCAL_IP,
            protocol: IpProtocol::Tcp
        };
        socket.process(&ip_repr, &packet.into_inner()[..])
    }

    fn recv<F>(socket: &mut TcpSocket, mut f: F)
            where F: FnMut(Result<TcpRepr, Error>) {
        let mut buffer = vec![];
        let result = socket.dispatch(&mut |ip_repr, payload| {
            assert_eq!(ip_repr.protocol(), IpProtocol::Tcp);
            assert_eq!(ip_repr.src_addr(), LOCAL_IP);
            assert_eq!(ip_repr.dst_addr(), REMOTE_IP);

            buffer.resize(payload.buffer_len(), 0);
            payload.emit(&ip_repr, &mut buffer[..]);
            let packet = TcpPacket::new(&buffer[..]).unwrap();
            let repr = try!(TcpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr()));
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
        ($socket:ident, [$( $repr:expr )*]) => ({
            $( send!($socket, $repr, Ok(())); )*
        });
        ($socket:ident, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, &$repr), $result))
    }

    macro_rules! recv {
        ($socket:ident, [$( $repr:expr )*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv!($socket, Err(Error::Exhausted))
        });
        ($socket:ident, $result:expr) =>
            (recv(&mut $socket, |repr| assert_eq!(repr, $result)))
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
    fn test_closed() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

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
    fn test_listen_syn_no_ack() {
        let mut s = socket_listen();
        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }, Err(Error::Malformed));
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        send!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }]);
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
        s.remote_seq_no   = REMOTE_SEQ;
        s
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        send!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }]);
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
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ;
        s
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }]);
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
        s.state          = State::Established;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = REMOTE_SEQ + 1;
        s.remote_win_len  = 128;
        s
    }

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }]);
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
        s.tx_buffer.enqueue_slice(b"abcdef");
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        assert_eq!(s.tx_buffer.len(), 6);
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.tx_buffer.enqueue_slice(b"foobar");
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            ..RECV_TEMPL
        }]);
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.tx_buffer.enqueue_slice(b"abcdef");
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        s.tx_buffer.enqueue_slice(b"foobar");
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
        s.tx_buffer.enqueue_slice(&[0; 32][..]);
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
        }, Err(Error::Malformed));
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 10),
            ..SEND_TEMPL
        }, Err(Error::Malformed));
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
        }, Err(Error::Malformed));
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::CloseWait);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.tx_buffer.enqueue_slice(b"abcdef");
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
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
        send!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(s, [TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
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
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::FinWait2);
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
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::Closing);
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
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
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
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
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
        s.tx_buffer.enqueue_slice(b"abcdef");
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]);
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }]);
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
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
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
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
        send!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
        recv!(s, [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]);
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
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
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
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
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::FinWait2);
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
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
        send!(s, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::Closing);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]);
        // ... at this point
        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }]);
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }
}
