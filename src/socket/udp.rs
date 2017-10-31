use core::cmp::min;
use managed::Managed;

use {Error, Result};
use wire::{IpProtocol, IpEndpoint, UdpRepr};
use socket::{Socket, SocketHandle, IpRepr};
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
pub type SocketBuffer<'a, 'b: 'a> = RingBuffer<'a, PacketBuffer<'b>>;

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct UdpSocket<'a, 'b: 'a> {
    handle:    SocketHandle,
    endpoint:  IpEndpoint,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ttl:       Option<u8>
}

impl<'a, 'b> UdpSocket<'a, 'b> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>,
               tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Udp(UdpSocket {
            handle:    SocketHandle::EMPTY,
            endpoint:  IpEndpoint::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            ttl:       None
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

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpEndpoint {
        self.endpoint
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

    /// Bind the socket to the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<()> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 { return Err(Error::Unaddressable) }

        if self.is_open() { return Err(Error::Illegal) }

        self.endpoint = endpoint;
        Ok(())
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint.port != 0
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
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

        let packet_buf = self.tx_buffer.enqueue_one_with(|buf| buf.resize(size))?;
        packet_buf.endpoint = endpoint;
        net_trace!("{}:{}:{}: buffer to send {} octets",
                   self.handle, self.endpoint, packet_buf.endpoint, size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpEndpoint) -> Result<()> {
        self.send(data.len(), endpoint)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpEndpoint)> {
        let packet_buf = self.rx_buffer.dequeue_one()?;
        net_trace!("{}:{}:{}: receive {} buffered octets",
                   self.handle, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok((&packet_buf.as_ref(), packet_buf.endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpEndpoint)> {
        let (buffer, endpoint) = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        if self.endpoint.port != repr.dst_port { return false }
        if !self.endpoint.addr.is_unspecified() &&
           self.endpoint.addr != ip_repr.dst_addr() { return false }

        true
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, repr: &UdpRepr) -> Result<()> {
        debug_assert!(self.accepts(ip_repr, repr));

        let packet_buf = self.rx_buffer.enqueue_one_with(|buf| buf.resize(repr.payload.len()))?;
        packet_buf.as_mut().copy_from_slice(repr.payload);
        packet_buf.endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        net_trace!("{}:{}:{}: receiving {} octets",
                   self.handle, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, emit: F) -> Result<()>
            where F: FnOnce((IpRepr, UdpRepr)) -> Result<()> {
        let handle   = self.handle;
        let endpoint = self.endpoint;
        let ttl = self.ttl.unwrap_or(64);
        self.tx_buffer.dequeue_one_with(|packet_buf| {
            net_trace!("{}:{}:{}: sending {} octets",
                       handle, endpoint,
                       packet_buf.endpoint, packet_buf.size);

            let repr = UdpRepr {
                src_port: endpoint.port,
                dst_port: packet_buf.endpoint.port,
                payload:  &packet_buf.as_ref()[..]
            };
            let ip_repr = IpRepr::Unspecified {
                src_addr:    endpoint.addr,
                dst_addr:    packet_buf.endpoint.addr,
                protocol:    IpProtocol::Udp,
                payload_len: repr.buffer_len(),
                ttl:         ttl,
            };
            emit((ip_repr, repr))
        })
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        if self.tx_buffer.is_empty() {
            None
        } else {
            Some(0)
        }
    }
}

#[cfg(test)]
mod test {
    use wire::{IpAddress, Ipv4Address, IpRepr, Ipv4Repr, UdpRepr};
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
        payload_len: 8 + 6,
        ttl: 64,
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
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { addr: IpAddress::Unspecified, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { port: 0, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
    }

    #[test]
    fn test_send_truncated() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert_eq!(socket.send_slice(&[0; 32][..], REMOTE_END), Err(Error::Truncated));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert!(socket.can_send());
        assert_eq!(socket.dispatch(|_| unreachable!()),
                   Err(Error::Exhausted));

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(socket.send_slice(b"123456", REMOTE_END), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, udp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(udp_repr, LOCAL_UDP_REPR);
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, udp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(udp_repr, LOCAL_UDP_REPR);
            Ok(())
        }), Ok(()));
        assert!(socket.can_send());
    }

    const REMOTE_IP_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([10, 0, 0, 2]),
        dst_addr: Ipv4Address([10, 0, 0, 1]),
        protocol: IpProtocol::Udp,
        payload_len: 8 + 6,
        ttl: 64
    });
    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        payload: b"abcdef"
    };

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(Error::Exhausted));

        assert!(socket.accepts(&REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &REMOTE_UDP_REPR),
                   Ok(()));
        assert!(socket.can_recv());

        assert!(socket.accepts(&REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &REMOTE_UDP_REPR),
                   Err(Error::Exhausted));
        assert_eq!(socket.recv(), Ok((&b"abcdef"[..], REMOTE_END)));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_recv_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.accepts(&REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &REMOTE_UDP_REPR),
                   Ok(()));

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok((4, REMOTE_END)));
        assert_eq!(&slice, b"abcd");
    }

    #[test]
    fn test_recv_truncated_packet() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let udp_repr = UdpRepr { payload: &[0; 100][..], ..REMOTE_UDP_REPR };
        assert!(socket.accepts(&REMOTE_IP_REPR, &udp_repr));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &udp_repr),
                   Err(Error::Truncated));
    }

    #[test]
    fn test_set_ttl() {
        let mut s = socket(buffer(0), buffer(1));
        assert_eq!(s.bind(LOCAL_END), Ok(()));

        s.set_ttl(Some(0x2a));
        assert_eq!(s.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(s.dispatch(|(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Unspecified{
                src_addr: LOCAL_IP,
                dst_addr: REMOTE_IP,
                protocol: IpProtocol::Udp,
                payload_len: 8 + 6,
                ttl: 0x2a,
            });
            Ok(())
        }), Ok(()));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_ttl_zero() {
        let mut s = socket(buffer(0), buffer(1));
        s.set_ttl(Some(0));
    }

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let mut udp_repr = REMOTE_UDP_REPR;
        assert!(socket.accepts(&REMOTE_IP_REPR, &udp_repr));
        udp_repr.dst_port += 1;
        assert!(!socket.accepts(&REMOTE_IP_REPR, &udp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([10, 0, 0, 2]),
            dst_addr: Ipv4Address([10, 0, 0, 10]),
            protocol: IpProtocol::Udp,
            payload_len: 8 + 6,
            ttl: 64
        });

        let mut port_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(port_bound_socket.bind(LOCAL_PORT), Ok(()));
        assert!(port_bound_socket.accepts(&ip_repr, &REMOTE_UDP_REPR));

        let mut ip_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(ip_bound_socket.bind(LOCAL_END), Ok(()));
        assert!(!ip_bound_socket.accepts(&ip_repr, &REMOTE_UDP_REPR));
    }
}
