use core::cmp;
use managed::Managed;

use {Error, Result};
use phy::{ChecksumCapabilities, DeviceCapabilities};
use socket::{Socket, SocketMeta, SocketHandle};
use storage::{Resettable, RingBuffer};
use wire::{IpAddress, IpEndpoint, IpProtocol, IpRepr};
use wire::{Ipv4Address, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr};
use wire::{UdpPacket, UdpRepr};

/// Type of endpoint to bind the ICMP socket to. See [IcmpSocket::bind] for
/// more details.
///
/// [IcmpSocket::bind]: struct.IcmpSocket.html#method.bind
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Endpoint {
    Unspecified,
    Ident(u16),
    Udp(IpEndpoint)
}

impl Endpoint {
    pub fn is_specified(&self) -> bool {
        match *self {
            Endpoint::Ident(_) => true,
            Endpoint::Udp(endpoint) => endpoint.port != 0,
            Endpoint::Unspecified => false
        }
    }
}

impl Default for Endpoint {
    fn default() -> Endpoint { Endpoint::Unspecified }
}

/// A buffered ICMPv4 packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    endpoint: IpAddress,
    size:     usize,
    payload:  Managed<'a, [u8]>
}

impl<'a> PacketBuffer<'a> {
    /// Create a buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        PacketBuffer {
            endpoint: IpAddress::default(),
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
        self.size = 0;
    }
}

/// An ICMPv4 packet ring buffer.
pub type SocketBuffer<'a, 'b: 'a> = RingBuffer<'a, PacketBuffer<'b>>;

/// An ICMPv4 socket
///
/// An ICMPv4 socket is bound to a specific [IcmpEndpoint] which may
/// be a sepecific UDP port to listen for ICMP error messages related
/// to the port or a specific ICMP identifier value. See [bind] for
/// more details.
///
/// [IcmpEndpoint]: enum.IcmpEndpoint.html
/// [bind]: #method.bind
#[derive(Debug)]
pub struct IcmpSocket<'a, 'b: 'a> {
    pub(crate) meta: SocketMeta,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    /// The endpoint this socket is communicating with
    endpoint:  Endpoint,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ttl:       Option<u8>
}

impl<'a, 'b> IcmpSocket<'a, 'b> {
    /// Create an ICMPv4 socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>, tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Icmp(IcmpSocket {
            meta:      SocketMeta::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            endpoint:  Endpoint::default(),
            ttl:       None
        })
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
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
    /// if `endpoint` is unspecified (see [is_specified]).
    ///
    /// # Examples
    ///
    /// ## Bind to ICMP Error messages associated with a specific UDP port:
    ///
    /// To [recv] ICMP error messages that are associated with a specific local
    /// UDP port, the socket may be bound to a given port using [IcmpEndpoint::Udp].
    /// This may be useful for applications using UDP attempting to detect and/or
    /// diagnose connection problems.
    ///
    /// ```
    /// # use smoltcp::socket::{Socket, IcmpSocket, IcmpPacketBuffer, IcmpSocketBuffer};
    /// # let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 20])]);
    /// # let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 20])]);
    /// use smoltcp::wire::IpEndpoint;
    /// use smoltcp::socket::IcmpEndpoint;
    ///
    /// let mut icmp_socket = // ...
    /// # match IcmpSocket::new(rx_buffer, tx_buffer) {
    /// #     Socket::Icmp(socket) => socket,
    /// #     _ => unreachable!()
    /// # };
    ///
    /// // Bind to ICMP error responses for UDP packets sent from port 53.
    /// let endpoint = IpEndpoint::from(53);
    /// icmp_socket.bind(IcmpEndpoint::Udp(endpoint)).unwrap();
    /// ```
    ///
    /// ## Bind to a specific ICMP identifier:
    ///
    /// To [send] and [recv] ICMP packets that are not associated with a specific UDP
    /// port, the socket may be bound to a specific ICMP identifier using
    /// [IcmpEndpoint::Ident]. This is useful for sending and receiving Echo Request/Reply
    /// messages.
    ///
    /// ```
    /// # use smoltcp::socket::{Socket, IcmpSocket, IcmpPacketBuffer, IcmpSocketBuffer};
    /// # let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 20])]);
    /// # let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 20])]);
    /// use smoltcp::socket::IcmpEndpoint;
    ///
    /// let mut icmp_socket = // ...
    /// # match IcmpSocket::new(rx_buffer, tx_buffer) {
    /// #     Socket::Icmp(socket) => socket,
    /// #     _ => unreachable!()
    /// # };
    ///
    /// // Bind to ICMP messages with the ICMP identifier 0x1234
    /// icmp_socket.bind(IcmpEndpoint::Ident(0x1234)).unwrap();
    /// ```
    ///
    /// [is_specified]: enum.IcmpEndpoint.html#method.is_specified
    /// [IcmpEndpoint::Ident]: enum.IcmpEndpoint.html#variant.Ident
    /// [IcmpEndpoint::Udp]: enum.IcmpEndpoint.html#variant.Udp
    /// [send]: #method.send
    /// [recv]: #method.recv
    pub fn bind<T: Into<Endpoint>>(&mut self, endpoint: T) -> Result<()> {
        let endpoint = endpoint.into();
        if !endpoint.is_specified() {
            return Err(Error::Unaddressable);
        }

        if self.is_open() { return Err(Error::Illegal) }

        self.endpoint = endpoint;
        Ok(())
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

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint != Endpoint::Unspecified
    }

    /// Enqueue a packet to be sent to a given remote address, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Truncated)` if the requested size is larger than the packet buffer
    /// size, and `Err(Error::Unaddressable)` if the remote address is unspecified.
    pub fn send(&mut self, size: usize, endpoint: IpAddress) -> Result<&mut [u8]> {
        if endpoint.is_unspecified() {
            return Err(Error::Unaddressable)
        }

        let packet_buf = self.tx_buffer.enqueue_one_with(|buf| buf.resize(size))?;
        packet_buf.endpoint = endpoint;
        net_trace!("{}:{}: buffer to send {} octets",
                   self.meta.handle, packet_buf.endpoint, size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to be sent to a given remote address, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpAddress) -> Result<()> {
        let packet_buf = self.send(data.len(), endpoint)?;
        packet_buf.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the `IpAddress` as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpAddress)> {
        let packet_buf = self.rx_buffer.dequeue_one()?;
        net_trace!("{}:{}: receive {} buffered octets",
                   self.meta.handle, packet_buf.endpoint, packet_buf.size);
        Ok((&packet_buf.as_ref(), packet_buf.endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the `IpAddress`
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpAddress)> {
        let (buffer, endpoint) = self.recv()?;
        let length = cmp::min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Filter determining which packets received by the interface are appended to
    /// the given sockets received buffer.
    pub(crate) fn accepts(&self, ip_repr: &IpRepr, icmp_repr: &Icmpv4Repr,
                          cksum: &ChecksumCapabilities) -> bool {
        match (&self.endpoint, icmp_repr) {
            // If we are bound to ICMP errors associated to a UDP port, only
            // accept Destination Unreachable messages with the data containing
            // a UDP packet send from the local port we are bound to.
            (&Endpoint::Udp(endpoint), &Icmpv4Repr::DstUnreachable { data, .. })
                    if endpoint.addr.is_unspecified() || endpoint.addr == ip_repr.dst_addr() => {
                let packet = UdpPacket::new(data);
                match UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr(), cksum) {
                    Ok(repr) => endpoint.port == repr.src_port,
                    Err(_) => false,
                }
            }
            // If we are bound to a specific ICMP identifier value, only accept an
            // Echo Request/Reply with the identifier field matching the endpoint
            // port.
            (&Endpoint::Ident(bound_ident), &Icmpv4Repr::EchoRequest { ident, .. }) |
            (&Endpoint::Ident(bound_ident), &Icmpv4Repr::EchoReply { ident, .. }) =>
                ident == bound_ident,
            _ => false,
        }
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, ip_payload: &[u8]) -> Result<()> {
        let packet_buf = self.rx_buffer.enqueue_one_with(|buf| buf.resize(ip_payload.len()))?;
        packet_buf.as_mut().copy_from_slice(ip_payload);
        packet_buf.endpoint = ip_repr.src_addr();
        net_trace!("{}:{}: receiving {} octets",
                   self.meta.handle, packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, caps: &DeviceCapabilities, emit: F) -> Result<()>
        where F: FnOnce((IpRepr, Icmpv4Repr)) -> Result<()>
    {
        let handle = self.meta.handle;
        let ttl = self.ttl.unwrap_or(64);
        let checksum = &caps.checksum;
        self.tx_buffer.dequeue_one_with(|packet_buf| {
            net_trace!("{}:{}: sending {} octets",
                       handle, packet_buf.endpoint, packet_buf.size);
            match packet_buf.endpoint {
                IpAddress::Ipv4(ipv4_addr) => {
                    let packet = Icmpv4Packet::new(packet_buf.as_ref());
                    let repr = Icmpv4Repr::parse(&packet, checksum)?;
                    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
                        src_addr:    Ipv4Address::default(),
                        dst_addr:    ipv4_addr,
                        protocol:    IpProtocol::Icmp,
                        payload_len: repr.buffer_len(),
                        ttl:         ttl,
                    });
                    emit((ip_repr, repr))
                },
                _ => Err(Error::Unaddressable)
            }
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
    use phy::DeviceCapabilities;
    use wire::{IpAddress, Icmpv4DstUnreachable};
    use super::*;

    fn buffer(packets: usize) -> SocketBuffer<'static, 'static> {
        let mut storage = vec![];
        for _ in 0..packets {
            storage.push(PacketBuffer::new(vec![0; 24]))
        }
        SocketBuffer::new(storage)
    }

    fn socket(rx_buffer: SocketBuffer<'static, 'static>,
              tx_buffer: SocketBuffer<'static, 'static>) -> IcmpSocket<'static, 'static> {
        match IcmpSocket::new(rx_buffer, tx_buffer) {
            Socket::Icmp(socket) => socket,
            _ => unreachable!()
        }
    }

    const REMOTE_IPV4: Ipv4Address = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
    const LOCAL_IPV4: Ipv4Address  = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
    const REMOTE_IP: IpAddress     = IpAddress::Ipv4(REMOTE_IPV4);
    const LOCAL_IP: IpAddress      = IpAddress::Ipv4(LOCAL_IPV4);
    const LOCAL_PORT:  u16         = 53;
    const LOCAL_END:   IpEndpoint  = IpEndpoint { addr: LOCAL_IP,  port: LOCAL_PORT  };

    static ECHO_REPR: Icmpv4Repr = Icmpv4Repr::EchoRequest {
            ident:  0x1234,
            seq_no: 0x5678,
            data:   &[0xff; 16]
    };

    static UDP_REPR: UdpRepr = UdpRepr {
        src_port: 53,
        dst_port: 9090,
        payload:  &[0xff; 10]
    };

    static LOCAL_IP_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::UNSPECIFIED,
        dst_addr: REMOTE_IPV4,
        protocol: IpProtocol::Icmp,
        payload_len: 24,
        ttl: 0x40
    });

    static REMOTE_IP_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: REMOTE_IPV4,
        dst_addr: LOCAL_IPV4,
        protocol: IpProtocol::Icmp,
        payload_len: 24,
        ttl: 0x40
    });

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(b"abcdef", IpAddress::default()),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_IP), Ok(()));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        assert_eq!(socket.dispatch(&caps, |_| unreachable!()),
                   Err(Error::Exhausted));

        // This buffer is too long
        assert_eq!(socket.send_slice(&[0xff; 25], REMOTE_IP), Err(Error::Truncated));
        assert!(socket.can_send());

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new(&mut bytes);
        ECHO_REPR.emit(&mut packet, &caps.checksum);

        assert_eq!(socket.send_slice(&packet.into_inner()[..], REMOTE_IP), Ok(()));
        assert_eq!(socket.send_slice(b"123456", REMOTE_IP), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(icmp_repr, ECHO_REPR);
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        // buffer is not taken off of the tx queue due to the error
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(icmp_repr, ECHO_REPR);
            Ok(())
        }), Ok(()));
        // buffer is taken off of the queue this time
        assert!(socket.can_send());
    }

    #[test]
    fn test_set_ttl() {
        let mut s = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new(&mut bytes);
        ECHO_REPR.emit(&mut packet, &caps.checksum);

        s.set_ttl(Some(0x2a));

        assert_eq!(s.send_slice(&packet.into_inner()[..], REMOTE_IP), Ok(()));
        assert_eq!(s.dispatch(&caps, |(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::UNSPECIFIED,
                dst_addr: REMOTE_IPV4,
                protocol: IpProtocol::Icmp,
                payload_len: ECHO_REPR.buffer_len(),
                ttl: 0x2a,
            }));
            Ok(())
        }), Ok(()));
    }

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Ident(0x1234)), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(Error::Exhausted));

        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 20];
        let mut packet = Icmpv4Packet::new(&mut bytes);
        ECHO_REPR.emit(&mut packet, &caps.checksum);
        let data = &packet.into_inner()[..];

        assert!(socket.accepts(&REMOTE_IP_REPR, &ECHO_REPR, &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &data[..]),
                   Ok(()));
        assert!(socket.can_recv());

        assert!(socket.accepts(&REMOTE_IP_REPR, &ECHO_REPR, &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IP_REPR, &data[..]),
                   Err(Error::Exhausted));
        assert_eq!(socket.recv(), Ok((&data[..], REMOTE_IP)));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_accept_bad_id() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Ident(0x1234)), Ok(()));

        let caps = DeviceCapabilities::default();
        let mut bytes = [0xff; 20];
        let mut packet = Icmpv4Packet::new(&mut bytes);
        let icmp_repr = Icmpv4Repr::EchoRequest {
            ident:  0x4321,
            seq_no: 0x5678,
            data:   &[0xff; 16]
        };
        icmp_repr.emit(&mut packet, &caps.checksum);

        // Ensure that a packet with an identifier that isn't the bound
        // ID is not accepted
        assert!(!socket.accepts(&REMOTE_IP_REPR, &icmp_repr, &caps.checksum));
    }

    #[test]
    fn test_accepts_udp() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Udp(LOCAL_END)), Ok(()));

        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 18];
        let mut packet = UdpPacket::new(&mut bytes);
        UDP_REPR.emit(&mut packet, &REMOTE_IP, &LOCAL_IP, &caps.checksum);

        let data = &packet.into_inner()[..];

        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: LOCAL_IPV4,
                dst_addr: REMOTE_IPV4,
                protocol: IpProtocol::Icmp,
                payload_len: 12,
                ttl: 0x40
            },
            data: data
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr: REMOTE_IP,
            dst_addr: LOCAL_IP,
            protocol: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            ttl: 0x40
        };

        assert!(!socket.can_recv());

        // Ensure we can accept ICMP error response to the bound
        // UDP port
        assert!(socket.accepts(&ip_repr, &icmp_repr, &caps.checksum));
        assert_eq!(socket.process(&ip_repr, &data[..]),
                   Ok(()));
        assert!(socket.can_recv());
    }
}
