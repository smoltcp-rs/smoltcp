use core::fmt;

use Error;
use Managed;
use wire::{IpProtocol, IpEndpoint};
use wire::{TcpPacket, TcpRepr, TcpControl};
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

    fn clamp_reader(&self, mut size: usize) -> (usize, usize) {
        let read_at = self.read_at;
        // We can't dequeue more than was queued.
        if size > self.length { size = self.length }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.storage.len() - read_at;
        if size > until_end { size = until_end }

        (read_at, size)
    }

    fn peek(&self, size: usize) -> &[u8] {
        let (read_at, size) = self.clamp_reader(size);
        &self.storage[read_at..read_at + size]
    }

    fn advance(&mut self, size: usize) {
        let (read_at, size) = self.clamp_reader(size);
        self.read_at = (read_at + size) % self.storage.len();
        self.length -= size;
    }

    fn dequeue(&mut self, size: usize) -> &[u8] {
        let (read_at, size) = self.clamp_reader(size);
        self.read_at = (self.read_at + size) % self.storage.len();
        self.length -= size;
        &self.storage[read_at..read_at + size]
    }
}

impl<'a> Into<SocketBuffer<'a>> for Managed<'a, [u8]> {
    fn into(self) -> SocketBuffer<'a> {
        SocketBuffer::new(self)
    }
}

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
            &State::SynSent     => write!(f, "SYN_SENT"),
            &State::SynReceived => write!(f, "SYN_RECEIVED"),
            &State::Established => write!(f, "ESTABLISHED"),
            &State::FinWait1    => write!(f, "FIN_WAIT_1"),
            &State::FinWait2    => write!(f, "FIN_WAIT_2"),
            &State::CloseWait   => write!(f, "CLOSE_WAIT"),
            &State::Closing     => write!(f, "CLOSING"),
            &State::LastAck     => write!(f, "LAST_ACK"),
            &State::TimeWait    => write!(f, "TIME_WAIT")
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

/// A Transmission Control Protocol data stream.
#[derive(Debug)]
pub struct TcpSocket<'a> {
    state:           State,
    local_endpoint:  IpEndpoint,
    remote_endpoint: IpEndpoint,
    local_seq_no:    i32,
    remote_seq_no:   i32,
    remote_last_ack: i32,
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
            local_endpoint:  IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            local_seq_no:    0,
            remote_seq_no:   0,
            remote_win_len:  0,
            remote_last_ack: 0,
            retransmit:      Retransmit::new(),
            tx_buffer:       tx_buffer.into(),
            rx_buffer:       rx_buffer.into()
        })
    }

    /// Return the connection state.
    #[inline(always)]
    pub fn state(&self) -> State {
        self.state
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

    /// Start listening on the given endpoint.
    ///
    /// # Panics
    /// This function will panic if the socket is not in the CLOSED state.
    pub fn listen(&mut self, endpoint: IpEndpoint) {
        assert!(self.state == State::Closed);

        self.local_endpoint  = endpoint;
        self.remote_endpoint = IpEndpoint::default();
        self.set_state(State::Listen);
    }

    /// See [Socket::collect](enum.Socket.html#method.collect).
    pub fn collect(&mut self, ip_repr: &IpRepr, payload: &[u8]) -> Result<(), Error> {
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
            net_trace!("tcp:{}:{}:{}: packet sent to a closed socket",
                       self.local_endpoint, ip_repr.src_addr(), repr.src_port);
            return Err(Error::Malformed)
        }

        // Reject unacceptable acknowledgements.
        match (self.state, repr) {
            // Don't care about ACKs when performing the handshake.
            (State::Listen, _) => (),
            (State::SynSent, _) => (),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, TcpRepr { ack_number: None, .. }) => {
                net_trace!("tcp:{}:{}: expecting an ACK",
                           self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (state, TcpRepr { ack_number: Some(ack_number), .. }) => {
                let control_len =
                    if state == State::SynReceived { 1 } else { 0 };
                let unacknowledged = self.tx_buffer.len() as i32 + control_len;
                if !(ack_number - self.local_seq_no >= 0 &&
                     ack_number - (self.local_seq_no + unacknowledged) <= 0) {
                    net_trace!("tcp:{}:{}: unacceptable ACK ({} not in {}..{})",
                               self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    return Err(Error::Malformed)
                }
            }
        }

        // Reject segments not occupying a valid portion of the receive window.
        // For now, do not try to reassemble out-of-order segments.
        if self.state != State::Listen {
            let next_remote_seq = self.remote_seq_no + self.rx_buffer.len() as i32 +
                                  repr.control.len();
            if repr.seq_number - next_remote_seq > 0 {
                net_trace!("tcp:{}:{}: unacceptable SEQ ({} not in {}..)",
                           self.local_endpoint, self.remote_endpoint,
                           repr.seq_number, next_remote_seq);
                return Err(Error::Malformed)
            } else if repr.seq_number - next_remote_seq != 0 {
                net_trace!("tcp:{}:{}: duplicate SEQ ({} in ..{})",
                           self.local_endpoint, self.remote_endpoint,
                           repr.seq_number, next_remote_seq);
                return Ok(())
            }
        }

        // Validate and update the state.
        let old_state = self.state;
        match (self.state, repr) {
            (State::Listen, TcpRepr {
                src_port, dst_port, control: TcpControl::Syn, seq_number, ack_number: None, ..
            }) => {
                self.local_endpoint  = IpEndpoint::new(ip_repr.dst_addr(), dst_port);
                self.remote_endpoint = IpEndpoint::new(ip_repr.src_addr(), src_port);
                self.local_seq_no    = -seq_number; // FIXME: use something more secure
                self.remote_seq_no   = seq_number + 1;
                self.set_state(State::SynReceived);
                self.retransmit.reset()
            }

            (State::SynReceived, TcpRepr { control: TcpControl::None, .. }) => {
                self.set_state(State::Established);
                self.retransmit.reset()
            }

            (State::Established, TcpRepr { control: TcpControl::None, .. }) => (),

            _ => {
                net_trace!("tcp:{}:{}: unexpected packet {}",
                           self.local_endpoint, self.remote_endpoint, repr);
                return Err(Error::Malformed)
            }
        }

        // Dequeue acknowledged octets.
        if let Some(ack_number) = repr.ack_number {
            let control_len =
                if old_state == State::SynReceived { 1 } else { 0 };
            if control_len > 0 {
                net_trace!("tcp:{}:{}: ACK for a control flag",
                           self.local_endpoint, self.remote_endpoint);
            }
            if ack_number - self.local_seq_no - control_len > 0 {
                net_trace!("tcp:{}:{}: ACK for {} octets",
                           self.local_endpoint, self.remote_endpoint,
                           ack_number - self.local_seq_no - control_len);
            }
            self.tx_buffer.advance((ack_number - self.local_seq_no - control_len) as usize);
            self.local_seq_no = ack_number;
        }

        // Enqueue payload octets, which is guaranteed to be in order, unless we already did.
        if repr.payload.len() > 0 {
            net_trace!("tcp:{}:{}: receiving {} octets",
                       self.local_endpoint, self.remote_endpoint, repr.payload.len());
            self.rx_buffer.enqueue_slice(repr.payload)
        }

        // Update window length.
        self.remote_win_len = repr.window_len as usize;

        Ok(())
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F, R>(&mut self, emit: &mut F) -> Result<R, Error>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R, Error> {
        let mut repr = TcpRepr {
            src_port:   self.local_endpoint.port,
            dst_port:   self.remote_endpoint.port,
            control:    TcpControl::None,
            seq_number: 0,
            ack_number: None,
            window_len: self.rx_buffer.window() as u16,
            payload:    &[]
        };

        // FIXME: process

        match self.state {
            State::Closed |
            State::Listen => {
                return Err(Error::Exhausted)
            }

            State::SynReceived => {
                if !self.retransmit.check() { return Err(Error::Exhausted) }

                repr.control    = TcpControl::Syn;
                repr.seq_number = self.local_seq_no;
                repr.ack_number = Some(self.remote_seq_no);
                net_trace!("tcp:{}:{}: SYN|ACK sent",
                           self.local_endpoint, self.remote_endpoint);
                self.remote_last_ack = self.remote_seq_no;
            }

            State::Established => {
                let ack_number = self.remote_seq_no + self.rx_buffer.len() as i32;
                if self.remote_last_ack == ack_number { return Err(Error::Exhausted) }

                repr.seq_number = self.local_seq_no;
                repr.ack_number = Some(ack_number);
                net_trace!("tcp:{}:{}: ACK sent",
                           self.local_endpoint, self.remote_endpoint);
                self.remote_last_ack = ack_number;
            }

            _ => unreachable!()
        }

        let ip_repr = IpRepr::Unspecified {
            src_addr: self.local_endpoint.addr,
            dst_addr: self.remote_endpoint.addr,
            protocol: IpProtocol::Tcp,
        };
        emit(&ip_repr, &repr)
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
    use wire::IpAddress;
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

    const LOCAL_IP:     IpAddress  = IpAddress::v4(10, 0, 0, 1);
    const REMOTE_IP:    IpAddress  = IpAddress::v4(10, 0, 0, 2);
    const LOCAL_PORT:   u16        = 80;
    const REMOTE_PORT:  u16        = 49500;
    const LOCAL_END:    IpEndpoint = IpEndpoint::new(LOCAL_IP, LOCAL_PORT);
    const REMOTE_END:   IpEndpoint = IpEndpoint::new(REMOTE_IP, REMOTE_PORT);
    const LOCAL_SEQ:    i32        = 10000;
    const REMOTE_SEQ:   i32        = -10000;

    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT, dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: 0, ack_number: Some(0),
        window_len: 256, payload: &[]
    };
    const RECV_TEMPL:  TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT, dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: 0, ack_number: Some(0),
        window_len: 128, payload: &[]
    };

    fn send(socket: &mut TcpSocket, repr: &TcpRepr) -> Result<(), Error> {
        let mut buffer = vec![0; repr.buffer_len()];
        let mut packet = TcpPacket::new(&mut buffer).unwrap();
        repr.emit(&mut packet, &REMOTE_IP, &LOCAL_IP);
        let ip_repr = IpRepr::Unspecified {
            src_addr: REMOTE_IP,
            dst_addr: LOCAL_IP,
            protocol: IpProtocol::Tcp
        };
        socket.collect(&ip_repr, &packet.into_inner()[..])
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

        let rx_buffer = SocketBuffer::new(vec![0; 128]);
        let tx_buffer = SocketBuffer::new(vec![0; 128]);
        match TcpSocket::new(rx_buffer, tx_buffer) {
            Socket::Tcp(socket) => socket,
            _ => unreachable!()
        }
    }

    #[test]
    fn test_closed() {
        let mut s = socket();
        assert_eq!(s.state(), State::Closed);

        send!(s, TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        }, Err(Error::Rejected));
    }

    #[test]
    fn test_handshake() {
        let mut s = socket();
        s.listen(IpEndpoint::new(IpAddress::default(), LOCAL_PORT));
        assert_eq!(s.state(), State::Listen);

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
    fn test_no_ack() {
        let mut s = socket();
        s.state = State::Established;
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1;

        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }, Err(Error::Malformed));
    }

    #[test]
    fn test_unacceptable_ack() {
        let mut s = socket();
        s.state = State::Established;
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1;
        s.tx_buffer.enqueue_slice(b"abcdef");

        // Already acknowledged data.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ - 1),
            ..SEND_TEMPL
        }, Err(Error::Malformed));

        // Data not yet transmitted.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 10),
            ..SEND_TEMPL
        }, Err(Error::Malformed));
    }

    #[test]
    fn test_unacceptable_seq() {
        let mut s = socket();
        s.state = State::Established;
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1;

        // Data outside of receive window.
        send!(s, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }, Err(Error::Malformed));
    }

    #[test]
    fn test_recv_data() {
        let mut s = socket();
        s.state = State::Established;
        s.local_endpoint  = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no    = LOCAL_SEQ + 1;
        s.remote_seq_no   = REMOTE_SEQ + 1;

        send!(s, [TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }]);
        recv!(s, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 122,
            ..RECV_TEMPL
        }]);
        assert_eq!(s.rx_buffer.dequeue(6), &b"abcdef"[..]);
    }
}
