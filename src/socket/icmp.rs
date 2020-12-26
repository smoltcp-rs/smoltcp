use core::cmp;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::{Error, Result};
use crate::phy::{ChecksumCapabilities, DeviceCapabilities};
use crate::socket::{Socket, SocketMeta, SocketHandle, PollAt};
use crate::storage::{PacketBuffer, PacketMetadata};
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;

#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Repr, Icmpv4Packet, Icmpv4Repr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Repr, Icmpv6Packet, Icmpv6Repr};
use crate::wire::IcmpRepr;
use crate::wire::{UdpPacket, UdpRepr};
use crate::wire::{IpAddress, IpEndpoint, IpProtocol, IpRepr};

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

/// An ICMP packet metadata.
pub type IcmpPacketMetadata = PacketMetadata<IpAddress>;

/// An ICMP packet ring buffer.
pub type IcmpSocketBuffer<'a, 'b> = PacketBuffer<'a, 'b, IpAddress>;

/// A ICMP socket
///
/// An ICMP socket is bound to a specific [IcmpEndpoint] which may
/// be a sepecific UDP port to listen for ICMP error messages related
/// to the port or a specific ICMP identifier value. See [bind] for
/// more details.
///
/// [IcmpEndpoint]: enum.IcmpEndpoint.html
/// [bind]: #method.bind
#[derive(Debug)]
pub struct IcmpSocket<'a, 'b: 'a> {
    pub(crate) meta: SocketMeta,
    rx_buffer: IcmpSocketBuffer<'a, 'b>,
    tx_buffer: IcmpSocketBuffer<'a, 'b>,
    /// The endpoint this socket is communicating with
    endpoint:  Endpoint,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a, 'b> IcmpSocket<'a, 'b> {
    /// Create an ICMP socket with the given buffers.
    pub fn new(rx_buffer: IcmpSocketBuffer<'a, 'b>,
               tx_buffer: IcmpSocketBuffer<'a, 'b>) -> IcmpSocket<'a, 'b> {
        IcmpSocket {
            meta:      SocketMeta::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            endpoint:  Endpoint::default(),
            hop_limit: None,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    /// 
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes. 
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    /// 
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes. 
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
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
    /// # use smoltcp::socket::{Socket, IcmpSocket, IcmpSocketBuffer, IcmpPacketMetadata};
    /// # let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 20]);
    /// # let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 20]);
    /// use smoltcp::wire::IpEndpoint;
    /// use smoltcp::socket::IcmpEndpoint;
    ///
    /// let mut icmp_socket = // ...
    /// # IcmpSocket::new(rx_buffer, tx_buffer);
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
    /// # use smoltcp::socket::{Socket, IcmpSocket, IcmpSocketBuffer, IcmpPacketMetadata};
    /// # let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 20]);
    /// # let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 20]);
    /// use smoltcp::socket::IcmpEndpoint;
    ///
    /// let mut icmp_socket = // ...
    /// # IcmpSocket::new(rx_buffer, tx_buffer);
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

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }

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

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
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

        let packet_buf = self.tx_buffer.enqueue(size, endpoint)?;

        net_trace!("{}:{}: buffer to send {} octets",
                   self.meta.handle, endpoint, size);
        Ok(packet_buf)
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
        let (endpoint, packet_buf) = self.rx_buffer.dequeue()?;

        net_trace!("{}:{}: receive {} buffered octets",
                   self.meta.handle, endpoint, packet_buf.len());
        Ok((packet_buf, endpoint))
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
    pub(crate) fn accepts(&self, ip_repr: &IpRepr, icmp_repr: &IcmpRepr,
                          cksum: &ChecksumCapabilities) -> bool {
        match (&self.endpoint, icmp_repr) {
            // If we are bound to ICMP errors associated to a UDP port, only
            // accept Destination Unreachable messages with the data containing
            // a UDP packet send from the local port we are bound to.
            #[cfg(feature = "proto-ipv4")]
            (&Endpoint::Udp(endpoint), &IcmpRepr::Ipv4(Icmpv4Repr::DstUnreachable { data, .. }))
                    if endpoint.addr.is_unspecified() || endpoint.addr == ip_repr.dst_addr() => {
                let packet = UdpPacket::new_unchecked(data);
                match UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr(), cksum) {
                    Ok(repr) => endpoint.port == repr.src_port,
                    Err(_) => false,
                }
            }
            #[cfg(feature = "proto-ipv6")]
            (&Endpoint::Udp(endpoint), &IcmpRepr::Ipv6(Icmpv6Repr::DstUnreachable { data, .. }))
                    if endpoint.addr.is_unspecified() || endpoint.addr == ip_repr.dst_addr() => {
                let packet = UdpPacket::new_unchecked(data);
                match UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr(), cksum) {
                    Ok(repr) => endpoint.port == repr.src_port,
                    Err(_) => false,
                }
            }
            // If we are bound to a specific ICMP identifier value, only accept an
            // Echo Request/Reply with the identifier field matching the endpoint
            // port.
            #[cfg(feature = "proto-ipv4")]
            (&Endpoint::Ident(bound_ident),
             &IcmpRepr::Ipv4(Icmpv4Repr::EchoRequest { ident, .. })) |
            (&Endpoint::Ident(bound_ident),
             &IcmpRepr::Ipv4(Icmpv4Repr::EchoReply { ident, .. })) =>
                ident == bound_ident,
            #[cfg(feature = "proto-ipv6")]
            (&Endpoint::Ident(bound_ident),
             &IcmpRepr::Ipv6(Icmpv6Repr::EchoRequest { ident, .. })) |
            (&Endpoint::Ident(bound_ident),
             &IcmpRepr::Ipv6(Icmpv6Repr::EchoReply { ident, .. })) =>
                ident == bound_ident,
            _ => false,
        }
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, icmp_repr: &IcmpRepr,
                          _cksum: &ChecksumCapabilities) -> Result<()> {
        match *icmp_repr {
            #[cfg(feature = "proto-ipv4")]
            IcmpRepr::Ipv4(ref icmp_repr) => {
                let packet_buf = self.rx_buffer.enqueue(icmp_repr.buffer_len(),
                                                        ip_repr.src_addr())?;
                icmp_repr.emit(&mut Icmpv4Packet::new_unchecked(packet_buf),
                               &ChecksumCapabilities::default());

                net_trace!("{}:{}: receiving {} octets",
                           self.meta.handle, icmp_repr.buffer_len(), packet_buf.len());
            },
            #[cfg(feature = "proto-ipv6")]
            IcmpRepr::Ipv6(ref icmp_repr) => {
                let packet_buf = self.rx_buffer.enqueue(icmp_repr.buffer_len(),
                                                        ip_repr.src_addr())?;
                icmp_repr.emit(&ip_repr.src_addr(), &ip_repr.dst_addr(),
                               &mut Icmpv6Packet::new_unchecked(packet_buf),
                               &ChecksumCapabilities::default());

                net_trace!("{}:{}: receiving {} octets",
                           self.meta.handle, icmp_repr.buffer_len(), packet_buf.len());
            },
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();

        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, _caps: &DeviceCapabilities, emit: F) -> Result<()>
        where F: FnOnce((IpRepr, IcmpRepr)) -> Result<()>
    {
        let handle    = self.meta.handle;
        let hop_limit = self.hop_limit.unwrap_or(64);
        self.tx_buffer.dequeue_with(|remote_endpoint, packet_buf| {
            net_trace!("{}:{}: sending {} octets",
                       handle, remote_endpoint, packet_buf.len());
            match *remote_endpoint {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(ipv4_addr) => {
                    let packet = Icmpv4Packet::new_unchecked(&*packet_buf);
                    let repr = Icmpv4Repr::parse(&packet, &ChecksumCapabilities::ignored())?;
                    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
                        src_addr:    Ipv4Address::default(),
                        dst_addr:    ipv4_addr,
                        protocol:    IpProtocol::Icmp,
                        payload_len: repr.buffer_len(),
                        hop_limit:   hop_limit,
                    });
                    emit((ip_repr, IcmpRepr::Ipv4(repr)))
                },
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(ipv6_addr) => {
                    let packet = Icmpv6Packet::new_unchecked(&*packet_buf);
                    let src_addr = Ipv6Address::default();
                    let repr = Icmpv6Repr::parse(&src_addr.into(), &ipv6_addr.into(), &packet, &ChecksumCapabilities::ignored())?;
                    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
                        src_addr:    src_addr,
                        dst_addr:    ipv6_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: repr.buffer_len(),
                        hop_limit:   hop_limit,
                    });
                    emit((ip_repr, IcmpRepr::Ipv6(repr)))
                },
                _ => Err(Error::Unaddressable)
            }
        })?;
        
        #[cfg(feature = "async")]
        self.tx_waker.wake();

        Ok(())
    }

    pub(crate) fn poll_at(&self) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

impl<'a, 'b> Into<Socket<'a, 'b>> for IcmpSocket<'a, 'b> {
    fn into(self) -> Socket<'a, 'b> {
        Socket::Icmp(self)
    }
}

#[cfg(test)]
mod tests_common {
    pub use crate::phy::DeviceCapabilities;
    pub use crate::wire::IpAddress;
    pub use super::*;

    pub fn buffer(packets: usize) -> IcmpSocketBuffer<'static, 'static> {
        IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY; packets], vec![0; 66 * packets])
    }

    pub fn socket(rx_buffer: IcmpSocketBuffer<'static, 'static>,
              tx_buffer: IcmpSocketBuffer<'static, 'static>) -> IcmpSocket<'static, 'static> {
        IcmpSocket::new(rx_buffer, tx_buffer)
    }

    pub const LOCAL_PORT:  u16         = 53;

    pub static UDP_REPR: UdpRepr = UdpRepr {
        src_port: 53,
        dst_port: 9090,
        payload:  &[0xff; 10]
    };
}

#[cfg(all(test, feature = "proto-ipv4"))]
mod test_ipv4 {
    use super::tests_common::*;

    use crate::wire::Icmpv4DstUnreachable;

    const REMOTE_IPV4: Ipv4Address = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
    const LOCAL_IPV4:  Ipv4Address = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
    const LOCAL_END_V4: IpEndpoint = IpEndpoint { addr: IpAddress::Ipv4(LOCAL_IPV4), port: LOCAL_PORT };

    static ECHOV4_REPR: Icmpv4Repr = Icmpv4Repr::EchoRequest {
            ident:  0x1234,
            seq_no: 0x5678,
            data:   &[0xff; 16]
    };

    static LOCAL_IPV4_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::UNSPECIFIED,
        dst_addr: REMOTE_IPV4,
        protocol: IpProtocol::Icmp,
        payload_len: 24,
        hop_limit: 0x40
    });

    static REMOTE_IPV4_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: REMOTE_IPV4,
        dst_addr: LOCAL_IPV4,
        protocol: IpProtocol::Icmp,
        payload_len: 24,
        hop_limit: 0x40
    });

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(b"abcdef", IpAddress::default()),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_IPV4.into()), Ok(()));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        assert_eq!(socket.dispatch(&caps, |_| unreachable!()),
                   Err(Error::Exhausted));

        // This buffer is too long
        assert_eq!(socket.send_slice(&[0xff; 67], REMOTE_IPV4.into()), Err(Error::Truncated));
        assert!(socket.can_send());

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        ECHOV4_REPR.emit(&mut packet, &caps.checksum);

        assert_eq!(socket.send_slice(&packet.into_inner()[..], REMOTE_IPV4.into()), Ok(()));
        assert_eq!(socket.send_slice(b"123456", REMOTE_IPV4.into()), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IPV4_REPR);
            assert_eq!(icmp_repr, ECHOV4_REPR.into());
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        // buffer is not taken off of the tx queue due to the error
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IPV4_REPR);
            assert_eq!(icmp_repr, ECHOV4_REPR.into());
            Ok(())
        }), Ok(()));
        // buffer is taken off of the queue this time
        assert!(socket.can_send());
    }

    #[test]
    fn test_set_hop_limit_v4() {
        let mut s = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        ECHOV4_REPR.emit(&mut packet, &caps.checksum);

        s.set_hop_limit(Some(0x2a));

        assert_eq!(s.send_slice(&packet.into_inner()[..], REMOTE_IPV4.into()), Ok(()));
        assert_eq!(s.dispatch(&caps, |(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::UNSPECIFIED,
                dst_addr: REMOTE_IPV4,
                protocol: IpProtocol::Icmp,
                payload_len: ECHOV4_REPR.buffer_len(),
                hop_limit: 0x2a,
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

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        ECHOV4_REPR.emit(&mut packet, &caps.checksum);
        let data = &packet.into_inner()[..];

        assert!(socket.accepts(&REMOTE_IPV4_REPR, &ECHOV4_REPR.into(), &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IPV4_REPR, &ECHOV4_REPR.into(), &caps.checksum),
                   Ok(()));
        assert!(socket.can_recv());

        assert!(socket.accepts(&REMOTE_IPV4_REPR, &ECHOV4_REPR.into(), &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IPV4_REPR, &ECHOV4_REPR.into(), &caps.checksum),
                   Err(Error::Exhausted));

        assert_eq!(socket.recv(), Ok((&data[..], REMOTE_IPV4.into())));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_accept_bad_id() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Ident(0x1234)), Ok(()));

        let caps = DeviceCapabilities::default();
        let mut bytes = [0xff; 20];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        let icmp_repr = Icmpv4Repr::EchoRequest {
            ident:  0x4321,
            seq_no: 0x5678,
            data:   &[0xff; 16]
        };
        icmp_repr.emit(&mut packet, &caps.checksum);

        // Ensure that a packet with an identifier that isn't the bound
        // ID is not accepted
        assert!(!socket.accepts(&REMOTE_IPV4_REPR, &icmp_repr.into(), &caps.checksum));
    }

    #[test]
    fn test_accepts_udp() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Udp(LOCAL_END_V4)), Ok(()));

        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 18];
        let mut packet = UdpPacket::new_unchecked(&mut bytes);
        UDP_REPR.emit(&mut packet, &REMOTE_IPV4.into(), &LOCAL_IPV4.into(), &caps.checksum);

        let data = &packet.into_inner()[..];

        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: LOCAL_IPV4,
                dst_addr: REMOTE_IPV4,
                protocol: IpProtocol::Icmp,
                payload_len: 12,
                hop_limit: 0x40
            },
            data: data
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr: REMOTE_IPV4.into(),
            dst_addr: LOCAL_IPV4.into(),
            protocol: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 0x40
        };

        assert!(!socket.can_recv());

        // Ensure we can accept ICMP error response to the bound
        // UDP port
        assert!(socket.accepts(&ip_repr, &icmp_repr.into(), &caps.checksum));
        assert_eq!(socket.process(&ip_repr, &icmp_repr.into(), &caps.checksum),
                   Ok(()));
        assert!(socket.can_recv());

        let mut bytes = [0x00; 46];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes[..]);
        icmp_repr.emit(&mut packet, &caps.checksum);
        assert_eq!(socket.recv(), Ok((&packet.into_inner()[..], REMOTE_IPV4.into())));
        assert!(!socket.can_recv());
    }
}

#[cfg(all(test, feature = "proto-ipv6"))]
mod test_ipv6 {
    use super::tests_common::*;

    use crate::wire::Icmpv6DstUnreachable;

    const REMOTE_IPV6: Ipv6Address = Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 1]);
    const LOCAL_IPV6:  Ipv6Address = Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 2]);
    const LOCAL_END_V6: IpEndpoint = IpEndpoint { addr: IpAddress::Ipv6(LOCAL_IPV6), port: LOCAL_PORT };
    static ECHOV6_REPR: Icmpv6Repr = Icmpv6Repr::EchoRequest {
            ident:  0x1234,
            seq_no: 0x5678,
            data:   &[0xff; 16]
    };

    static LOCAL_IPV6_REPR: IpRepr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: Ipv6Address::UNSPECIFIED,
        dst_addr: REMOTE_IPV6,
        next_header: IpProtocol::Icmpv6,
        payload_len: 24,
        hop_limit: 0x40
    });

    static REMOTE_IPV6_REPR: IpRepr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: REMOTE_IPV6,
        dst_addr: LOCAL_IPV6,
        next_header: IpProtocol::Icmpv6,
        payload_len: 24,
        hop_limit: 0x40
    });

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(b"abcdef", IpAddress::default()),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_IPV6.into()), Ok(()));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        assert_eq!(socket.dispatch(&caps, |_| unreachable!()),
                   Err(Error::Exhausted));

        // This buffer is too long
        assert_eq!(socket.send_slice(&[0xff; 67], REMOTE_IPV6.into()), Err(Error::Truncated));
        assert!(socket.can_send());

        let mut bytes = vec![0xff; 24];
        let mut packet = Icmpv6Packet::new_unchecked(&mut bytes);
        ECHOV6_REPR.emit(&LOCAL_IPV6.into(), &REMOTE_IPV6.into(), &mut packet, &caps.checksum);

        assert_eq!(socket.send_slice(&packet.into_inner()[..], REMOTE_IPV6.into()), Ok(()));
        assert_eq!(socket.send_slice(b"123456", REMOTE_IPV6.into()), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IPV6_REPR);
            assert_eq!(icmp_repr, ECHOV6_REPR.into());
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        // buffer is not taken off of the tx queue due to the error
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(&caps, |(ip_repr, icmp_repr)| {
            assert_eq!(ip_repr, LOCAL_IPV6_REPR);
            assert_eq!(icmp_repr, ECHOV6_REPR.into());
            Ok(())
        }), Ok(()));
        // buffer is taken off of the queue this time
        assert!(socket.can_send());
    }

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket(buffer(0), buffer(1));
        let caps = DeviceCapabilities::default();

        let mut bytes = vec![0xff; 24];
        let mut packet = Icmpv6Packet::new_unchecked(&mut bytes);
        ECHOV6_REPR.emit(&LOCAL_IPV6.into(), &REMOTE_IPV6.into(), &mut packet, &caps.checksum);

        s.set_hop_limit(Some(0x2a));

        assert_eq!(s.send_slice(&packet.into_inner()[..], REMOTE_IPV6.into()), Ok(()));
        assert_eq!(s.dispatch(&caps, |(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::UNSPECIFIED,
                dst_addr: REMOTE_IPV6,
                next_header: IpProtocol::Icmpv6,
                payload_len: ECHOV6_REPR.buffer_len(),
                hop_limit: 0x2a,
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

        let mut bytes = [0xff; 24];
        let mut packet = Icmpv6Packet::new_unchecked(&mut bytes);
        ECHOV6_REPR.emit(&LOCAL_IPV6.into(), &REMOTE_IPV6.into(), &mut packet, &caps.checksum);
        let data = &packet.into_inner()[..];

        assert!(socket.accepts(&REMOTE_IPV6_REPR, &ECHOV6_REPR.into(), &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IPV6_REPR, &ECHOV6_REPR.into(), &caps.checksum),
                   Ok(()));
        assert!(socket.can_recv());

        assert!(socket.accepts(&REMOTE_IPV6_REPR, &ECHOV6_REPR.into(), &caps.checksum));
        assert_eq!(socket.process(&REMOTE_IPV6_REPR, &ECHOV6_REPR.into(), &caps.checksum),
                   Err(Error::Exhausted));

        assert_eq!(socket.recv(), Ok((&data[..], REMOTE_IPV6.into())));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_accept_bad_id() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Ident(0x1234)), Ok(()));

        let caps = DeviceCapabilities::default();
        let mut bytes = [0xff; 20];
        let mut packet = Icmpv6Packet::new_unchecked(&mut bytes);
        let icmp_repr = Icmpv6Repr::EchoRequest {
            ident:  0x4321,
            seq_no: 0x5678,
            data:   &[0xff; 16]
        };
        icmp_repr.emit(&LOCAL_IPV6.into(), &REMOTE_IPV6.into(), &mut packet, &caps.checksum);

        // Ensure that a packet with an identifier that isn't the bound
        // ID is not accepted
        assert!(!socket.accepts(&REMOTE_IPV6_REPR, &icmp_repr.into(), &caps.checksum));
    }

    #[test]
    fn test_accepts_udp() {
        let mut socket = socket(buffer(1), buffer(1));
        assert_eq!(socket.bind(Endpoint::Udp(LOCAL_END_V6)), Ok(()));

        let caps = DeviceCapabilities::default();

        let mut bytes = [0xff; 18];
        let mut packet = UdpPacket::new_unchecked(&mut bytes);
        UDP_REPR.emit(&mut packet, &REMOTE_IPV6.into(), &LOCAL_IPV6.into(), &caps.checksum);

        let data = &packet.into_inner()[..];

        let icmp_repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: Ipv6Repr {
                src_addr: LOCAL_IPV6,
                dst_addr: REMOTE_IPV6,
                next_header: IpProtocol::Icmpv6,
                payload_len: 12,
                hop_limit: 0x40
            },
            data: data
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr: REMOTE_IPV6.into(),
            dst_addr: LOCAL_IPV6.into(),
            protocol: IpProtocol::Icmpv6,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 0x40
        };

        assert!(!socket.can_recv());

        // Ensure we can accept ICMP error response to the bound
        // UDP port
        assert!(socket.accepts(&ip_repr, &icmp_repr.into(), &caps.checksum));
        assert_eq!(socket.process(&ip_repr, &icmp_repr.into(), &caps.checksum),
                   Ok(()));
        assert!(socket.can_recv());

        let mut bytes = [0x00; 66];
        let mut packet = Icmpv6Packet::new_unchecked(&mut bytes[..]);
        icmp_repr.emit(&LOCAL_IPV6.into(), &REMOTE_IPV6.into(), &mut packet, &caps.checksum);
        assert_eq!(socket.recv(), Ok((&packet.into_inner()[..], REMOTE_IPV6.into())));
        assert!(!socket.can_recv());
    }
}
