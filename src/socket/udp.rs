use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::storage::{PacketBuffer, PacketMetadata};
use crate::wire::{IpEndpoint, IpProtocol, IpRepr, UdpRepr};
use crate::{Error, Result};

/// A UDP packet metadata.
pub type UdpPacketMetadata = PacketMetadata<IpEndpoint>;

/// A UDP packet ring buffer.
pub type UdpSocketBuffer<'a> = PacketBuffer<'a, IpEndpoint>;

/// A User Datagram Protocol socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct UdpSocket<'a> {
    endpoint: IpEndpoint,
    rx_buffer: UdpSocketBuffer<'a>,
    tx_buffer: UdpSocketBuffer<'a>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> UdpSocket<'a> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: UdpSocketBuffer<'a>, tx_buffer: UdpSocketBuffer<'a>) -> UdpSocket<'a> {
        UdpSocket {
            endpoint: IpEndpoint::default(),
            rx_buffer,
            tx_buffer,
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

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpEndpoint {
        self.endpoint
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
    /// if the port in the given endpoint is zero.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<()> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 {
            return Err(Error::Unaddressable);
        }

        if self.is_open() {
            return Err(Error::Illegal);
        }

        self.endpoint = endpoint;

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }

        Ok(())
    }

    /// Close the socket.
    pub fn close(&mut self) {
        // Clear the bound endpoint of the socket.
        self.endpoint = IpEndpoint::default();

        // Reset the RX and TX buffers of the socket.
        self.tx_buffer.reset();
        self.rx_buffer.reset();

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
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

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Unaddressable)` if local or remote port, or remote address are unspecified,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    pub fn send(&mut self, size: usize, endpoint: IpEndpoint) -> Result<&mut [u8]> {
        if self.endpoint.port == 0 {
            return Err(Error::Unaddressable);
        }
        if !endpoint.is_specified() {
            return Err(Error::Unaddressable);
        }

        let payload_buf = self.tx_buffer.enqueue(size, endpoint)?;

        net_trace!(
            "udp:{}:{}: buffer to send {} octets",
            self.endpoint,
            endpoint,
            size
        );
        Ok(payload_buf)
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
        let (endpoint, payload_buf) = self.rx_buffer.dequeue()?;

        net_trace!(
            "udp:{}:{}: receive {} buffered octets",
            self.endpoint,
            endpoint,
            payload_buf.len()
        );
        Ok((payload_buf, endpoint))
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

    /// Peek at a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<(&[u8], &IpEndpoint)> {
        let endpoint = self.endpoint;
        self.rx_buffer.peek().map(|(remote_endpoint, payload_buf)| {
            net_trace!(
                "udp:{}:{}: peek {} buffered octets",
                endpoint,
                remote_endpoint,
                payload_buf.len()
            );
            (payload_buf, remote_endpoint)
        })
    }

    /// Peek at a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint without removing the
    /// packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, &IpEndpoint)> {
        let (buffer, endpoint) = self.peek()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    pub(crate) fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        if self.endpoint.port != repr.dst_port {
            return false;
        }
        if !self.endpoint.addr.is_unspecified()
            && self.endpoint.addr != ip_repr.dst_addr()
            && !ip_repr.dst_addr().is_broadcast()
            && !ip_repr.dst_addr().is_multicast()
        {
            return false;
        }

        true
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &UdpRepr,
        payload: &[u8],
    ) -> Result<()> {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        let size = payload.len();

        let endpoint = IpEndpoint {
            addr: ip_repr.src_addr(),
            port: repr.src_port,
        };

        // If local address is not provided, choose it automatically.
        if self.endpoint.addr.is_unspecified() {
            self.endpoint.addr = cx
                .get_source_address(endpoint.addr)
                .ok_or(Error::Unaddressable)?;
        }

        self.rx_buffer
            .enqueue(size, endpoint)?
            .copy_from_slice(payload);

        net_trace!(
            "udp:{}:{}: receiving {} octets",
            self.endpoint,
            endpoint,
            size
        );

        #[cfg(feature = "async")]
        self.rx_waker.wake();

        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, cx: &mut Context, emit: F) -> Result<()>
    where
        F: FnOnce(&mut Context, (IpRepr, UdpRepr, &[u8])) -> Result<()>,
    {
        let endpoint = self.endpoint;
        let hop_limit = self.hop_limit.unwrap_or(64);

        self.tx_buffer
            .dequeue_with(|remote_endpoint, payload_buf| {
                net_trace!(
                    "udp:{}:{}: sending {} octets",
                    endpoint,
                    endpoint,
                    payload_buf.len()
                );

                let repr = UdpRepr {
                    src_port: endpoint.port,
                    dst_port: remote_endpoint.port,
                };
                let ip_repr = IpRepr::new(
                    endpoint.addr,
                    remote_endpoint.addr,
                    IpProtocol::Udp,
                    repr.header_len() + payload_buf.len(),
                    hop_limit,
                );
                emit(cx, (ip_repr, repr, payload_buf))
            })?;

        #[cfg(feature = "async")]
        self.tx_waker.wake();

        Ok(())
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::{IpAddress, IpRepr, UdpRepr};

    fn buffer(packets: usize) -> UdpSocketBuffer<'static> {
        UdpSocketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; packets],
            vec![0; 16 * packets],
        )
    }

    fn socket(
        rx_buffer: UdpSocketBuffer<'static>,
        tx_buffer: UdpSocketBuffer<'static>,
    ) -> UdpSocket<'static> {
        UdpSocket::new(rx_buffer, tx_buffer)
    }

    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 1]);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 2]);
            const OTHER_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 3]);
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]);
            const OTHER_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            ]);
        }
    }

    pub const LOCAL_END: IpEndpoint = IpEndpoint {
        addr: LOCAL_ADDR.into_address(),
        port: LOCAL_PORT,
    };
    pub const REMOTE_END: IpEndpoint = IpEndpoint {
        addr: REMOTE_ADDR.into_address(),
        port: REMOTE_PORT,
    };

    pub const LOCAL_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const REMOTE_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const BAD_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: OTHER_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    const LOCAL_UDP_REPR: UdpRepr = UdpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
    };

    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
    };

    const PAYLOAD: &[u8] = b"abcdef";

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

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket(buffer(0), buffer(1));
        s.set_hop_limit(Some(0));
    }

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(
            socket.send_slice(b"abcdef", REMOTE_END),
            Err(Error::Unaddressable)
        );
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    addr: IpAddress::Unspecified,
                    ..REMOTE_END
                }
            ),
            Err(Error::Unaddressable)
        );
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    port: 0,
                    ..REMOTE_END
                }
            ),
            Err(Error::Unaddressable)
        );
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert!(socket.can_send());
        assert_eq!(
            socket.dispatch(&mut cx, |_, _| unreachable!()),
            Err(Error::Exhausted)
        );

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(
            socket.send_slice(b"123456", REMOTE_END),
            Err(Error::Exhausted)
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(&mut cx, |_, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Err(Error::Unaddressable)
            }),
            Err(Error::Unaddressable)
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(&mut cx, |_, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Ok(())
            }),
            Ok(())
        );
        assert!(socket.can_send());
    }

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(Error::Exhausted));

        assert!(socket.accepts(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(
            socket.process(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR, PAYLOAD),
            Ok(())
        );
        assert!(socket.can_recv());

        assert!(socket.accepts(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(
            socket.process(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR, PAYLOAD),
            Err(Error::Exhausted)
        );
        assert_eq!(socket.recv(), Ok((&b"abcdef"[..], REMOTE_END)));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_peek_process() {
        let mut socket = socket(buffer(1), buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert_eq!(socket.peek(), Err(Error::Exhausted));

        assert_eq!(
            socket.process(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR, PAYLOAD),
            Ok(())
        );
        assert_eq!(socket.peek(), Ok((&b"abcdef"[..], &REMOTE_END)));
        assert_eq!(socket.recv(), Ok((&b"abcdef"[..], REMOTE_END)));
        assert_eq!(socket.peek(), Err(Error::Exhausted));
    }

    #[test]
    fn test_recv_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.accepts(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        assert_eq!(
            socket.process(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR, PAYLOAD),
            Ok(())
        );

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok((4, REMOTE_END)));
        assert_eq!(&slice, b"abcd");
    }

    #[test]
    fn test_peek_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert_eq!(
            socket.process(&mut cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR, PAYLOAD),
            Ok(())
        );

        let mut slice = [0; 4];
        assert_eq!(socket.peek_slice(&mut slice[..]), Ok((4, &REMOTE_END)));
        assert_eq!(&slice, b"abcd");
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok((4, REMOTE_END)));
        assert_eq!(&slice, b"abcd");
        assert_eq!(socket.peek_slice(&mut slice[..]), Err(Error::Exhausted));
    }

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket(buffer(0), buffer(1));
        let mut cx = Context::mock();

        assert_eq!(s.bind(LOCAL_END), Ok(()));

        s.set_hop_limit(Some(0x2a));
        assert_eq!(s.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(
            s.dispatch(&mut cx, |_, (ip_repr, _, _)| {
                assert_eq!(
                    ip_repr,
                    IpReprIpvX(IpvXRepr {
                        src_addr: LOCAL_ADDR,
                        dst_addr: REMOTE_ADDR,
                        next_header: IpProtocol::Udp,
                        payload_len: 8 + 6,
                        hop_limit: 0x2a,
                    })
                );
                Ok(())
            }),
            Ok(())
        );
    }

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut socket = socket(buffer(1), buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let mut udp_repr = REMOTE_UDP_REPR;
        assert!(socket.accepts(&mut cx, &REMOTE_IP_REPR, &udp_repr));
        udp_repr.dst_port += 1;
        assert!(!socket.accepts(&mut cx, &REMOTE_IP_REPR, &udp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut cx = Context::mock();

        let mut port_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(port_bound_socket.bind(LOCAL_PORT), Ok(()));
        assert!(port_bound_socket.accepts(&mut cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));

        let mut ip_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(ip_bound_socket.bind(LOCAL_END), Ok(()));
        assert!(!ip_bound_socket.accepts(&mut cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));
    }

    #[test]
    fn test_send_large_packet() {
        // buffer(4) creates a payload buffer of size 16*4
        let mut socket = socket(buffer(0), buffer(4));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        let too_large = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefx";
        assert_eq!(
            socket.send_slice(too_large, REMOTE_END),
            Err(Error::Truncated)
        );
        assert_eq!(socket.send_slice(&too_large[..16 * 4], REMOTE_END), Ok(()));
    }

    #[test]
    fn test_process_empty_payload() {
        let recv_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 1], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));
        let mut cx = Context::mock();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        assert_eq!(socket.process(&mut cx, &REMOTE_IP_REPR, &repr, &[]), Ok(()));
        assert_eq!(socket.recv(), Ok((&[][..], REMOTE_END)));
    }

    #[test]
    fn test_closing() {
        let recv_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 1], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.is_open());
        socket.close();
        assert!(!socket.is_open());
    }
}
