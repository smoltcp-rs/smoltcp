use core::cmp::min;
use managed::Managed;

use {Error, Result};
use phy::DeviceLimits;
use wire::{IpProtocol, IpEndpoint};
use wire::{UdpPacket, UdpRepr};
use socket::{Socket, IpRepr, IpPayload};
use storage::{Resettable, RingBuffer};

/// A buffered UDP packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    endpoint: IpEndpoint,
    size:     usize,
    payload:  Managed<'a, [u8]>
}

impl<'a> PacketBuffer<'a> {
    /// Create a buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        PacketBuffer {
            endpoint: IpEndpoint::default(),
            size:     0,
            payload:  payload.into()
        }
    }

    fn as_ref<'b>(&'b self) -> &'b [u8] {
        &self.payload[..self.size]
    }

    fn as_mut<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.payload[..self.size]
    }

    fn resize<'b>(&'b mut self, size: usize) -> Result<&'b mut Self> {
        if self.payload.len() >= size {
            self.size = size;
            Ok(self)
        } else {
            Err(Error::Truncated)
        }
    }
}

impl<'a> Resettable for PacketBuffer<'a> {
    fn reset(&mut self) {
        self.endpoint = Default::default();
        self.size = 0;
    }
}

/// An UDP packet ring buffer.
pub type SocketBuffer<'a, 'b : 'a> = RingBuffer<'a, PacketBuffer<'b>>;

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct UdpSocket<'a, 'b: 'a> {
    endpoint:  IpEndpoint,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    debug_id:  usize
}

impl<'a, 'b> UdpSocket<'a, 'b> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>,
               tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Udp(UdpSocket {
            endpoint:  IpEndpoint::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            debug_id:  0
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

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpEndpoint {
        self.endpoint
    }

    /// Bind the socket to the given endpoint.
    ///
    /// Returns `Err(Error::Illegal)` if the socket is already bound,
    /// and `Err(Error::Unaddressable)` if the port is unspecified.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<()> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 { return Err(Error::Unaddressable) }

        if self.endpoint.port != 0 { return Err(Error::Illegal) }

        self.endpoint = endpoint;
        Ok(())
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.empty()
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Truncated)` if the requested size is larger than the packet buffer
    /// size, and `Err(Error::Unaddressable)` if local or remote port, or remote address,
    /// are unspecified.
    pub fn send(&mut self, size: usize, endpoint: IpEndpoint) -> Result<&mut [u8]> {
        if self.endpoint.port == 0 { return Err(Error::Unaddressable) }
        if !endpoint.is_specified() { return Err(Error::Unaddressable) }

        let packet_buf = self.tx_buffer.try_enqueue(|buf| buf.resize(size))?;
        packet_buf.endpoint = endpoint;
        net_trace!("[{}]{}:{}: buffer to send {} octets",
                   self.debug_id, self.endpoint, packet_buf.endpoint, size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpEndpoint) -> Result<usize> {
        self.send(data.len(), endpoint)?.copy_from_slice(data);
        Ok(data.len())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpEndpoint)> {
        let packet_buf = self.rx_buffer.dequeue()?;
        net_trace!("[{}]{}:{}: receive {} buffered octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok((&packet_buf.as_ref(), packet_buf.endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpEndpoint)> {
        let (buffer, endpoint) = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    pub(crate) fn process(&mut self, _timestamp: u64, ip_repr: &IpRepr,
                          payload: &[u8]) -> Result<()> {
        debug_assert!(ip_repr.protocol() == IpProtocol::Udp);

        let packet = UdpPacket::new_checked(&payload[..ip_repr.payload_len()])?;
        let repr = UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        let endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        if !self.endpoint.accepts(&endpoint) { return Err(Error::Rejected) }

        let packet_buf = self.rx_buffer.try_enqueue(|buf| buf.resize(repr.payload.len()))?;
        packet_buf.as_mut().copy_from_slice(repr.payload);
        packet_buf.endpoint = endpoint;
        net_trace!("[{}]{}:{}: receiving {} octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    pub(crate) fn dispatch<F, R>(&mut self, _timestamp: u64, _limits: &DeviceLimits,
                                 emit: &mut F) -> Result<R>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R> {
        let packet_buf = self.tx_buffer.dequeue()?;
        net_trace!("[{}]{}:{}: sending {} octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);

        let repr = UdpRepr {
            src_port: self.endpoint.port,
            dst_port: packet_buf.endpoint.port,
            payload:  &packet_buf.as_ref()[..]
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr:    self.endpoint.addr,
            dst_addr:    packet_buf.endpoint.addr,
            protocol:    IpProtocol::Udp,
            payload_len: repr.buffer_len()
        };
        emit(&ip_repr, &repr)
    }
}

impl<'a> IpPayload for UdpRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.buffer_len()
    }

    fn emit(&self, repr: &IpRepr, payload: &mut [u8]) {
        let mut packet = UdpPacket::new(payload);
        self.emit(&mut packet, &repr.src_addr(), &repr.dst_addr())
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use wire::{IpAddress, Ipv4Address, IpRepr, Ipv4Repr, UdpRepr};
    use socket::AsSocket;
    use super::*;

    fn buffer(packets: usize) -> SocketBuffer<'static, 'static> {
        let mut storage = vec![];
        for _ in 0..packets {
            storage.push(PacketBuffer::new(vec![0; 16]))
        }
        SocketBuffer::new(storage)
    }

    fn socket(rx_buffer: SocketBuffer<'static, 'static>,
              tx_buffer: SocketBuffer<'static, 'static>)
            -> UdpSocket<'static, 'static> {
        match UdpSocket::new(rx_buffer, tx_buffer) {
            Socket::Udp(socket) => socket,
            _ => unreachable!()
        }
    }

    const LOCAL_IP:    IpAddress  = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1]));
    const REMOTE_IP:   IpAddress  = IpAddress::Ipv4(Ipv4Address([10, 0, 0, 2]));
    const LOCAL_PORT:  u16        = 53;
    const REMOTE_PORT: u16        = 49500;
    const LOCAL_END:   IpEndpoint = IpEndpoint { addr: LOCAL_IP,  port: LOCAL_PORT  };
    const REMOTE_END:  IpEndpoint = IpEndpoint { addr: REMOTE_IP, port: REMOTE_PORT };

    #[test]
    fn test_bind_unaddressable() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(0), Err(Error::Unaddressable));
    }

    #[test]
    fn test_bind_twice() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(1), Ok(()));
        assert_eq!(socket.bind(2), Err(Error::Illegal));
    }

    const LOCAL_IP_REPR: IpRepr = IpRepr::Unspecified {
        src_addr: LOCAL_IP,
        dst_addr: REMOTE_IP,
        protocol: IpProtocol::Udp,
        payload_len: 8 + 6
    };
    const LOCAL_UDP_REPR: UdpRepr = UdpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        payload: b"abcdef"
    };

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Err(Error::Unaddressable));
        socket.bind(LOCAL_PORT);
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { addr: IpAddress::Unspecified, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { port: 0, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(6));
    }

    #[test]
    fn test_send_truncated() {
        let mut socket = socket(buffer(0), buffer(1));
        socket.bind(LOCAL_END);
        assert_eq!(socket.send_slice(&[0; 32][..], REMOTE_END), Err(Error::Truncated));
    }

    #[test]
    fn test_send_dispatch() {
        let limits = DeviceLimits::default();

        let mut socket = socket(buffer(0), buffer(1));
        socket.bind(LOCAL_END);

        assert!(socket.can_send());
        assert_eq!(socket.dispatch(0, &limits, &mut |ip_repr, ip_payload| {
            unreachable!()
        }), Err(Error::Exhausted) as Result<()>);

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(6));
        assert_eq!(socket.send_slice(b"123456", REMOTE_END), Err(Error::Exhausted));
        assert!(!socket.can_send());

        macro_rules! assert_payload_eq {
            ($ip_repr:expr, $ip_payload:expr, $expected:expr) => {{
                let mut buffer = vec![0; $ip_payload.buffer_len()];
                $ip_payload.emit($ip_repr, &mut buffer);
                let udp_packet = UdpPacket::new_checked(&buffer).unwrap();
                let udp_repr = UdpRepr::parse(&udp_packet, &LOCAL_IP, &REMOTE_IP).unwrap();
                assert_eq!(&udp_repr, $expected)
            }}
        }

        assert_eq!(socket.dispatch(0, &limits, &mut |ip_repr, ip_payload| {
            assert_eq!(ip_repr, &LOCAL_IP_REPR);
            assert_payload_eq!(ip_repr, ip_payload, &LOCAL_UDP_REPR);
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable) as Result<()>);
        /*assert!(!socket.can_send());*/

        assert_eq!(socket.dispatch(0, &limits, &mut |ip_repr, ip_payload| {
            assert_eq!(ip_repr, &LOCAL_IP_REPR);
            assert_payload_eq!(ip_repr, ip_payload, &LOCAL_UDP_REPR);
            Ok(())
        }), /*Ok(())*/ Err(Error::Exhausted));
        assert!(socket.can_send());
    }

    const REMOTE_IP_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([10, 0, 0, 2]),
        dst_addr: Ipv4Address([10, 0, 0, 1]),
        protocol: IpProtocol::Udp,
        payload_len: 8 + 6
    });
    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        payload: b"abcdef"
    };

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(0));
        socket.bind(LOCAL_PORT);
        assert!(!socket.can_recv());

        let mut buffer = vec![0; REMOTE_UDP_REPR.buffer_len()];
        REMOTE_UDP_REPR.emit(&mut UdpPacket::new(&mut buffer), &LOCAL_IP, &REMOTE_IP);

        assert_eq!(socket.recv(), Err(Error::Exhausted));
        assert_eq!(socket.process(0, &REMOTE_IP_REPR, &buffer),
                   Ok(()));
        assert!(socket.can_recv());

        assert_eq!(socket.process(0, &REMOTE_IP_REPR, &buffer),
                   Err(Error::Exhausted));
        assert_eq!(socket.recv(), Ok((&b"abcdef"[..], REMOTE_END)));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_recv_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));
        socket.bind(LOCAL_PORT);

        let mut buffer = vec![0; REMOTE_UDP_REPR.buffer_len()];
        REMOTE_UDP_REPR.emit(&mut UdpPacket::new(&mut buffer), &LOCAL_IP, &REMOTE_IP);
        assert_eq!(socket.process(0, &REMOTE_IP_REPR, &buffer), Ok(()));

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok((4, REMOTE_END)));
        assert_eq!(&slice, b"abcd");
    }

    #[test]
    fn test_recv_truncated_packet() {
        let mut socket = socket(buffer(1), buffer(0));
        socket.bind(LOCAL_PORT);

        let udp_repr = UdpRepr { payload: &[0; 100][..], ..REMOTE_UDP_REPR };
        let mut buffer = vec![0; udp_repr.buffer_len()];
        udp_repr.emit(&mut UdpPacket::new(&mut buffer), &LOCAL_IP, &REMOTE_IP);
        assert_eq!(socket.process(0, &REMOTE_IP_REPR, &buffer),
                   Err(Error::Truncated));
    }
}
