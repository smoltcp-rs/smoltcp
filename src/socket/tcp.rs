use core::fmt;

use Error;
use Managed;
use wire::{IpProtocol, IpAddress, IpEndpoint};
use wire::{TcpPacket, TcpRepr, TcpControl};
use socket::{Socket, PacketRepr};

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

    /// Return the maximum amount of octets that can be enqueued in the buffer.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Return the amount of octets already enqueued in the buffer.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Return the amount of octets that remain to be enqueued in the buffer.
    pub fn window(&self) -> usize {
        self.capacity() - self.len()
    }

    /// Enqueue a slice of octets up to the given size into the buffer, and return a pointer
    /// to the slice.
    ///
    /// The returned slice may be shorter than requested, as short as an empty slice,
    /// if there is not enough contiguous free space in the buffer.
    pub fn enqueue(&mut self, mut size: usize) -> &mut [u8] {
        let write_at = (self.read_at + self.length) % self.storage.len();
        // We can't enqueue more than there is free space.
        let free = self.storage.len() - self.length;
        if size > free { size = free }
        // We can't contiguously enqueue past the beginning of the storage.
        let until_end = self.storage.len() - write_at;
        if size > until_end { size = until_end }

        self.length += size;
        &mut self.storage[write_at..write_at + size]
    }

    /// Dequeue a slice of octets up to the given size from the buffer, and return a pointer
    /// to the slice.
    ///
    /// The returned slice may be shorter than requested, as short as an empty slice,
    /// if there is not enough contiguous filled space in the buffer.
    pub fn dequeue(&mut self, mut size: usize) -> &[u8] {
        let read_at = self.read_at;
        // We can't dequeue more than was queued.
        if size > self.length { size = self.length }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.storage.len() - self.read_at;
        if size > until_end { size = until_end }

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
    pub fn collect(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress,
                   protocol: IpProtocol, payload: &[u8])
            -> Result<(), Error> {
        if protocol != IpProtocol::Tcp { return Err(Error::Rejected) }

        let packet = try!(TcpPacket::new(payload));
        let repr = try!(TcpRepr::parse(&packet, src_addr, dst_addr));

        // Reject packets with a wrong destination.
        if self.local_endpoint.port != repr.dst_port { return Err(Error::Rejected) }
        if !self.local_endpoint.addr.is_unspecified() &&
           self.local_endpoint.addr != *dst_addr { return Err(Error::Rejected) }

        // Reject packets from a source to which we aren't connected.
        if self.remote_endpoint.port != 0 &&
           self.remote_endpoint.port != repr.src_port { return Err(Error::Rejected) }
        if !self.remote_endpoint.addr.is_unspecified() &&
           self.remote_endpoint.addr != *src_addr { return Err(Error::Rejected) }

        match (self.state, repr) {
            // Reject packets addressed to a closed socket.
            (State::Closed, TcpRepr { src_port, .. }) => {
                net_trace!("tcp:{}:{}:{}: packet sent to a closed socket",
                           self.local_endpoint, src_addr, src_port);
                return Err(Error::Malformed)
            }
            // Don't care about ACKs when performing the handshake.
            (State::Listen, _) => (),
            (State::SynSent, _) => (),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, TcpRepr { ack_number: None, .. }) => {
                net_trace!("tcp:{}:{}: expecting an ACK packet",
                           self.local_endpoint, self.remote_endpoint);
                return Err(Error::Malformed)
            }
            // Reject unacceptable acknowledgements.
            (state, TcpRepr { ack_number: Some(ack_number), .. }) => {
                let unacknowledged =
                    if state != State::SynReceived { self.rx_buffer.len() as i32 } else { 1 };
                if !(ack_number - self.local_seq_no > 0 &&
                     ack_number - (self.local_seq_no + unacknowledged) <= 0) {
                    net_trace!("tcp:{}:{}: unacceptable ACK ({} not in {}..{})",
                               self.local_endpoint, self.remote_endpoint,
                               ack_number, self.local_seq_no, self.local_seq_no + unacknowledged);
                    return Err(Error::Malformed)
                }
            }
        }

        // Handle the incoming packet.
        match (self.state, repr) {
            (State::Listen, TcpRepr {
                src_port, dst_port, control: TcpControl::Syn, seq_number, ack_number: None,
                payload, ..
            }) => {
                // FIXME: don't do this, just enqueue the payload
                if payload.len() > 0 {
                    net_trace!("tcp:{}:{}: SYN with payload rejected",
                               IpEndpoint::new(*dst_addr, dst_port),
                               IpEndpoint::new(*src_addr, src_port));
                    return Err(Error::Malformed)
                }

                self.local_endpoint  = IpEndpoint::new(*dst_addr, dst_port);
                self.remote_endpoint = IpEndpoint::new(*src_addr, src_port);
                self.remote_seq_no   = seq_number + 1;
                self.local_seq_no    = -seq_number; // FIXME: use something more secure
                self.set_state(State::SynReceived);

                self.retransmit.reset();
                Ok(())
            }

            (State::SynReceived, TcpRepr {
                control: TcpControl::None, ack_number: Some(ack_number), ..
            }) => {
                self.local_seq_no    = ack_number;
                self.set_state(State::Established);

                // FIXME: queue data from ACK
                self.retransmit.reset();
                Ok(())
            }

            _ => Err(Error::Malformed)
        }
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch(&mut self, f: &mut FnMut(&IpAddress, &IpAddress,
                                             IpProtocol, &PacketRepr) -> Result<(), Error>)
            -> Result<(), Error> {
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
                net_trace!("tcp:{}:{}: SYN sent",
                           self.local_endpoint, self.remote_endpoint);
            }

            State::Established => {
                // FIXME: transmit something
                return Err(Error::Exhausted)
            }

            _ => unreachable!()
        }

        f(&self.local_endpoint.addr, &self.remote_endpoint.addr, IpProtocol::Tcp, &repr)
    }
}

impl<'a> PacketRepr for TcpRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.buffer_len()
    }

    fn emit(&self, src_addr: &IpAddress, dst_addr: &IpAddress, payload: &mut [u8]) {
        let mut packet = TcpPacket::new(payload).expect("undersized payload");
        self.emit(&mut packet, src_addr, dst_addr)
    }
}

#[cfg(test)]
mod test {
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

    const LOCAL_IP:     IpAddress  = IpAddress::v4(10, 0, 0, 1);
    const REMOTE_IP:    IpAddress  = IpAddress::v4(10, 0, 0, 2);
    const LOCAL_PORT:   u16        = 80;
    const REMOTE_PORT:  u16        = 49500;
    const LOCAL_END:    IpEndpoint = IpEndpoint::new(LOCAL_IP, LOCAL_PORT);
    const REMOTE_END:   IpEndpoint = IpEndpoint::new(REMOTE_IP, REMOTE_PORT);
    const LOCAL_SEQ:    i32        = 100;
    const REMOTE_SEQ:   i32        = -100;

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

    macro_rules! send {
        ($socket:ident, $repr:expr) => ({
            let repr = $repr;
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = TcpPacket::new(&mut buffer).unwrap();
            repr.emit(&mut packet, &REMOTE_IP, &LOCAL_IP);
            let result = $socket.collect(&REMOTE_IP, &LOCAL_IP, IpProtocol::Tcp,
                                         &packet.into_inner()[..]);
            result.expect("send error")
        })
    }

    macro_rules! recv {
        ($socket:ident, $expected:expr) => ({
            let result = $socket.dispatch(&mut |src_addr, dst_addr, protocol, payload| {
                assert_eq!(protocol, IpProtocol::Tcp);
                assert_eq!(src_addr, &LOCAL_IP);
                assert_eq!(dst_addr, &REMOTE_IP);

                let mut buffer = vec![0; payload.buffer_len()];
                payload.emit(src_addr, dst_addr, &mut buffer);
                let packet = TcpPacket::new(&buffer[..]).unwrap();
                let repr = TcpRepr::parse(&packet, src_addr, dst_addr).unwrap();
                assert_eq!(repr, $expected);
                Ok(())
            });
            assert_eq!(result, Ok(()));
            let result = $socket.dispatch(&mut |_src_addr, _dst_addr, _protocol, _payload| {
                Ok(())
            });
            assert_eq!(result, Err(Error::Exhausted));
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

        let rx_buffer = SocketBuffer::new(vec![0; 128]);
        let tx_buffer = SocketBuffer::new(vec![0; 128]);
        match TcpSocket::new(rx_buffer, tx_buffer) {
            Socket::Tcp(socket) => socket,
            _ => unreachable!()
        }
    }

    #[test]
    fn test_handshake() {
        let mut s = socket();
        s.listen(IpEndpoint::new(IpAddress::default(), LOCAL_PORT));
        assert_eq!(s.state(), State::Listen);

        send!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ, ack_number: None,
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
        recv!(s, TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ, ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        });
        send!(s, TcpRepr {
            control: TcpControl::None,
            seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }
}
