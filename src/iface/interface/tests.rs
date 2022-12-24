#[cfg(feature = "proto-igmp")]
use std::vec::Vec;

use super::*;

use crate::iface::Interface;
#[cfg(feature = "medium-ethernet")]
use crate::iface::NeighborCache;
use crate::phy::{ChecksumCapabilities, Loopback};
#[cfg(feature = "proto-igmp")]
use crate::time::Instant;
use crate::{Error, Result};

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

#[cfg(feature = "medium-ethernet")]
const MEDIUM: Medium = Medium::Ethernet;
#[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ip"))]
const MEDIUM: Medium = Medium::Ip;
#[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ieee802154"))]
const MEDIUM: Medium = Medium::Ieee802154;

fn create<'a>(medium: Medium) -> (Interface<'a>, SocketSet<'a>, Loopback) {
    match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => create_ethernet(),
        #[cfg(feature = "medium-ip")]
        Medium::Ip => create_ip(),
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => create_ieee802154(),
    }
}

#[cfg(feature = "medium-ip")]
#[allow(unused)]
fn create_ip<'a>() -> (Interface<'a>, SocketSet<'a>, Loopback) {
    // Create a basic device
    let mut device = Loopback::new(Medium::Ip);
    let mut ip_addrs = heapless::Vec::<IpCidr, MAX_IP_ADDR_COUNT>::new();
    #[cfg(feature = "proto-ipv4")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .unwrap();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
        .unwrap();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
        .unwrap();

    let iface_builder = InterfaceBuilder::new().ip_addrs(ip_addrs);

    #[cfg(feature = "proto-ipv4-fragmentation")]
    let iface_builder = iface_builder.ipv4_fragmentation_buffer(vec![]);

    let iface = iface_builder.finalize(&mut device);

    (iface, SocketSet::new(vec![]), device)
}

#[cfg(feature = "medium-ethernet")]
fn create_ethernet<'a>() -> (Interface<'a>, SocketSet<'a>, Loopback) {
    // Create a basic device
    let mut device = Loopback::new(Medium::Ethernet);
    let mut ip_addrs = heapless::Vec::<IpCidr, MAX_IP_ADDR_COUNT>::new();
    #[cfg(feature = "proto-ipv4")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .unwrap();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
        .unwrap();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
        .unwrap();

    let iface_builder = InterfaceBuilder::new()
        .hardware_addr(EthernetAddress::default().into())
        .neighbor_cache(NeighborCache::new())
        .ip_addrs(ip_addrs);

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    let iface_builder = iface_builder.sixlowpan_fragmentation_buffer(vec![]);

    #[cfg(feature = "proto-ipv4-fragmentation")]
    let iface_builder = iface_builder.ipv4_fragmentation_buffer(vec![]);

    let iface = iface_builder.finalize(&mut device);

    (iface, SocketSet::new(vec![]), device)
}

#[cfg(feature = "medium-ieee802154")]
fn create_ieee802154<'a>() -> (Interface<'a>, SocketSet<'a>, Loopback) {
    // Create a basic device
    let mut device = Loopback::new(Medium::Ieee802154);
    let mut ip_addrs = heapless::Vec::<IpCidr, MAX_IP_ADDR_COUNT>::new();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
        .unwrap();
    #[cfg(feature = "proto-ipv6")]
    ip_addrs
        .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
        .unwrap();

    let iface_builder = InterfaceBuilder::new()
        .hardware_addr(Ieee802154Address::default().into())
        .neighbor_cache(NeighborCache::new())
        .ip_addrs(ip_addrs);

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    let iface_builder = iface_builder.sixlowpan_fragmentation_buffer(vec![]);

    let iface = iface_builder.finalize(&mut device);

    (iface, SocketSet::new(vec![]), device)
}

#[cfg(feature = "proto-igmp")]
fn recv_all(device: &mut Loopback, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some((rx, _tx)) = device.receive() {
        rx.consume(timestamp, |pkt| {
            pkts.push(pkt.to_vec());
            Ok(())
        })
        .unwrap();
    }
    pkts
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MockTxToken;

impl TxToken for MockTxToken {
    fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        Err(Error::Unaddressable)
    }
}

#[test]
#[should_panic(expected = "hardware_addr required option was not set")]
#[cfg(all(feature = "medium-ethernet"))]
fn test_builder_initialization_panic() {
    let mut device = Loopback::new(Medium::Ethernet);
    InterfaceBuilder::new().finalize(&mut device);
}

#[test]
#[cfg(feature = "proto-ipv4")]
fn test_no_icmp_no_unicast_ipv4() {
    let (mut iface, mut sockets, _device) = create(MEDIUM);

    // Unknown Ipv4 Protocol
    //
    // Because the destination is the broadcast address
    // this should not trigger and Destination Unreachable
    // response. See RFC 1122 § 3.2.2.
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 54];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes);

    // Ensure that the unknown protocol frame does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address

    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
    assert_eq!(iface.inner.process_ipv4(&mut sockets, &frame, None), None);
    #[cfg(feature = "proto-ipv4-fragmentation")]
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            &frame,
            Some(&mut iface.fragments.ipv4_fragments)
        ),
        None
    );
}

#[test]
#[cfg(feature = "proto-ipv6")]
fn test_no_icmp_no_unicast_ipv6() {
    let (mut iface, mut sockets, _device) = create(MEDIUM);

    // Unknown Ipv6 Protocol
    //
    // Because the destination is the broadcast address
    // this should not trigger and Destination Unreachable
    // response. See RFC 1122 § 3.2.2.
    let repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 54];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv6Packet::new_unchecked(&bytes);

    // Ensure that the unknown protocol frame does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address
    assert_eq!(iface.inner.process_ipv6(&mut sockets, &frame), None);
}

#[test]
#[cfg(feature = "proto-ipv4")]
fn test_icmp_error_no_payload() {
    static NO_BYTES: [u8; 0] = [];
    let (mut iface, mut sockets, _device) = create(MEDIUM);

    // Unknown Ipv4 Protocol with no payload
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
        dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 34];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes);

    // The expected Destination Unreachable response due to the
    // unknown protocol
    let icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::ProtoUnreachable,
        header: Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            next_header: IpProtocol::Unknown(12),
            payload_len: 0,
            hop_limit: 64,
        },
        data: &NO_BYTES,
    };

    let expected_repr = IpPacket::Icmpv4((
        Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        },
        icmp_repr,
    ));

    // Ensure that the unknown protocol triggers an error response.
    // And we correctly handle no payload.

    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
    assert_eq!(
        iface.inner.process_ipv4(&mut sockets, &frame, None),
        Some(expected_repr)
    );

    #[cfg(feature = "proto-ipv4-fragmentation")]
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            &frame,
            Some(&mut iface.fragments.ipv4_fragments)
        ),
        Some(expected_repr)
    );
}

#[test]
#[cfg(feature = "proto-ipv4")]
fn test_local_subnet_broadcasts() {
    let (mut iface, _, _device) = create(MEDIUM);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 1, 23]), 24));
        });
    });

    assert!(iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 1, 255])),);
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 1, 254])),);

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 16));
        });
    });
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 23, 255])),);
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 23, 254])),);
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 255, 254])),);
    assert!(iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 168, 255, 255])),);

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 8));
        });
    });
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 23, 1, 255])),);
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 23, 1, 254])),);
    assert!(!iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 255, 255, 254])),);
    assert!(iface
        .inner
        .is_subnet_broadcast(Ipv4Address([192, 255, 255, 255])),);
}

#[test]
#[cfg(all(feature = "socket-udp", feature = "proto-ipv4"))]
fn test_icmp_error_port_unreachable() {
    static UDP_PAYLOAD: [u8; 12] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21,
    ];
    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let mut udp_bytes_unicast = vec![0u8; 20];
    let mut udp_bytes_broadcast = vec![0u8; 20];
    let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
    let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
        dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 64,
    });

    // Emit the representations to a packet
    udp_repr.emit(
        &mut packet_unicast,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    let data = packet_unicast.into_inner();

    // The expected Destination Unreachable ICMPv4 error response due
    // to no sockets listening on the destination port.
    let icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        },
        data,
    };
    let expected_repr = IpPacket::Icmpv4((
        Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        },
        icmp_repr,
    ));

    // Ensure that the unknown protocol triggers an error response.
    // And we correctly handle no payload.
    assert_eq!(
        iface
            .inner
            .process_udp(&mut sockets, ip_repr, udp_repr, false, &UDP_PAYLOAD, data),
        Some(expected_repr)
    );

    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 64,
    });

    // Emit the representations to a packet
    udp_repr.emit(
        &mut packet_broadcast,
        &ip_repr.src_addr(),
        &IpAddress::Ipv4(Ipv4Address::BROADCAST),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Ensure that the port unreachable error does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address and no socket is bound to the port.
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            ip_repr,
            udp_repr,
            false,
            &UDP_PAYLOAD,
            packet_broadcast.into_inner(),
        ),
        None
    );
}

#[test]
#[cfg(feature = "socket-udp")]
fn test_handle_udp_broadcast() {
    use crate::wire::IpEndpoint;

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);

    let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

    let mut udp_bytes = vec![0u8; 13];
    let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

    let socket_handle = sockets.add(udp_socket);

    #[cfg(feature = "proto-ipv6")]
    let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    #[cfg(feature = "proto-ipv6")]
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: src_ip,
        dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: src_ip,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });

    // Bind the socket to port 68
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert_eq!(socket.bind(68), Ok(()));
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    udp_repr.emit(
        &mut packet,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Packet should be handled by bound UDP socket
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            ip_repr,
            udp_repr,
            false,
            &UDP_PAYLOAD,
            packet.into_inner(),
        ),
        None
    );

    // Make sure the payload to the UDP packet processed by process_udp is
    // appended to the bound sockets rx_buffer
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67)))
    );
}

#[test]
#[cfg(feature = "proto-ipv4")]
fn test_handle_ipv4_broadcast() {
    use crate::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet};

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let our_ipv4_addr = iface.ipv4_address().unwrap();
    let src_ipv4_addr = Ipv4Address([127, 0, 0, 2]);

    // ICMPv4 echo request
    let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    let icmpv4_repr = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };

    // Send to IPv4 broadcast address
    let ipv4_repr = Ipv4Repr {
        src_addr: src_ipv4_addr,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: icmpv4_repr.buffer_len(),
    };

    // Emit to ip frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        icmpv4_repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes)
    };

    // Expected ICMPv4 echo reply
    let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };
    let expected_ipv4_repr = Ipv4Repr {
        src_addr: our_ipv4_addr,
        dst_addr: src_ipv4_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmpv4_repr.buffer_len(),
    };
    let expected_packet = IpPacket::Icmpv4((expected_ipv4_repr, expected_icmpv4_repr));

    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
    assert_eq!(
        iface.inner.process_ipv4(&mut sockets, &frame, None),
        Some(expected_packet)
    );

    #[cfg(feature = "proto-ipv4-fragmentation")]
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            &frame,
            Some(&mut iface.fragments.ipv4_fragments)
        ),
        Some(expected_packet)
    );
}

#[test]
#[cfg(feature = "socket-udp")]
fn test_icmp_reply_size() {
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::Icmpv6DstUnreachable;
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    use crate::wire::IPV4_MIN_MTU as MIN_MTU;
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::IPV6_MIN_MTU as MIN_MTU;

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    const MAX_PAYLOAD_LEN: usize = 528;
    #[cfg(feature = "proto-ipv6")]
    const MAX_PAYLOAD_LEN: usize = 1192;

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    let src_addr = Ipv4Address([192, 168, 1, 1]);
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    let dst_addr = Ipv4Address([192, 168, 1, 2]);
    #[cfg(feature = "proto-ipv6")]
    let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(feature = "proto-ipv6")]
    let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    // UDP packet that if not tructated will cause a icmp port unreachable reply
    // to exeed the minimum mtu bytes in length.
    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + MAX_PAYLOAD_LEN];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        MAX_PAYLOAD_LEN,
        |buf| fill_slice(buf, 0x2a),
        &ChecksumCapabilities::default(),
    );
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    #[cfg(feature = "proto-ipv6")]
    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    // Expected packets
    #[cfg(feature = "proto-ipv6")]
    let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
        reason: Icmpv6DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };
    #[cfg(feature = "proto-ipv6")]
    let expected_ip_repr = Ipv6Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 64,
        payload_len: expected_icmp_repr.buffer_len(),
    };
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    let expected_ip_repr = Ipv4Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmp_repr.buffer_len(),
    };

    // The expected packet does not exceed the IPV4_MIN_MTU
    #[cfg(feature = "proto-ipv6")]
    assert_eq!(
        expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
        MIN_MTU
    );
    // The expected packet does not exceed the IPV4_MIN_MTU
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    assert_eq!(
        expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
        MIN_MTU
    );
    // The expected packet and the generated packet are equal
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            ip_repr.into(),
            udp_repr,
            false,
            &vec![0x2a; MAX_PAYLOAD_LEN],
            payload,
        ),
        Some(IpPacket::Icmpv4((expected_ip_repr, expected_icmp_repr)))
    );
    #[cfg(feature = "proto-ipv6")]
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            ip_repr.into(),
            udp_repr,
            false,
            &vec![0x2a; MAX_PAYLOAD_LEN],
            payload,
        ),
        Some(IpPacket::Icmpv6((expected_ip_repr, expected_icmp_repr)))
    );
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
fn test_handle_valid_arp_request() {
    let (mut iface, mut sockets, _device) = create_ethernet();

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
    let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
    let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip_addr,
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface
            .inner
            .process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requestor was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(local_ip_addr),
            &IpAddress::Ipv4(remote_ip_addr)
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
fn test_handle_valid_ndisc_request() {
    let (mut iface, mut sockets, _device) = create_ethernet();

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
        target_addr: local_ip_addr,
        lladdr: Some(remote_hw_addr.into()),
    });
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr,
        dst_addr: local_ip_addr.solicited_node(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: solicit.buffer_len(),
    });

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    solicit.emit(
        &remote_ip_addr.into(),
        &local_ip_addr.solicited_node().into(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
        flags: NdiscNeighborFlags::SOLICITED,
        target_addr: local_ip_addr,
        lladdr: Some(local_hw_addr.into()),
    });

    let ipv6_expected = Ipv6Repr {
        src_addr: local_ip_addr,
        dst_addr: remote_ip_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: icmpv6_expected.buffer_len(),
    };

    // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
    assert_eq!(
        iface
            .inner
            .process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
        Some(EthernetPacket::Ip(IpPacket::Icmpv6((
            ipv6_expected,
            icmpv6_expected
        ))))
    );

    // Ensure the address of the requestor was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv6(local_ip_addr),
            &IpAddress::Ipv6(remote_ip_addr)
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
fn test_handle_other_arp_request() {
    let (mut iface, mut sockets, _device) = create_ethernet();

    let mut eth_bytes = vec![0u8; 42];

    let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x03]),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for someone else does not trigger an ARP Reply
    assert_eq!(
        iface
            .inner
            .process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
        None
    );

    // Ensure the address of the requestor was NOT entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr)
        ),
        Err(Error::Unaddressable)
    );
}

#[test]
#[cfg(all(
    feature = "medium-ethernet",
    feature = "proto-ipv4",
    not(feature = "medium-ieee802154")
))]
fn test_arp_flush_after_update_ip() {
    let (mut iface, mut sockets, _device) = create_ethernet();

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
    let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
    let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    {
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);
    }

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface
            .inner
            .process_ethernet(&mut sockets, frame.into_inner(), &mut iface.fragments),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requestor was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(local_ip_addr),
            &IpAddress::Ipv4(remote_ip_addr)
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );

    // Update IP addrs to trigger ARP cache flush
    let local_ip_addr_new = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(local_ip_addr_new, 24));
        });
    });

    // ARP cache flush after address change
    assert!(!iface.inner.has_neighbor(&IpAddress::Ipv4(remote_ip_addr)));
}

#[test]
#[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
fn test_icmpv4_socket() {
    use crate::wire::Icmpv4Packet;

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);
    let tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);

    let icmpv4_socket = icmp::Socket::new(rx_buffer, tx_buffer);

    let socket_handle = sockets.add(icmpv4_socket);

    let ident = 0x1234;
    let seq_no = 0x5432;
    let echo_data = &[0xff; 16];

    let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
    // Bind to the ID 0x1234
    assert_eq!(socket.bind(icmp::Endpoint::Ident(ident)), Ok(()));

    // Ensure the ident we bound to and the ident of the packet are the same.
    let mut bytes = [0xff; 24];
    let mut packet = Icmpv4Packet::new_unchecked(&mut bytes[..]);
    let echo_repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data: echo_data,
    };
    echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
    let icmp_data = &*packet.into_inner();

    let ipv4_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Icmp,
        payload_len: 24,
        hop_limit: 64,
    };
    let ip_repr = IpRepr::Ipv4(ipv4_repr);

    // Open a socket and ensure the packet is handled due to the listening
    // socket.
    assert!(!sockets.get_mut::<icmp::Socket>(socket_handle).can_recv());

    // Confirm we still get EchoReply from `smoltcp` even with the ICMP socket listening
    let echo_reply = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data: echo_data,
    };
    let ipv4_reply = Ipv4Repr {
        src_addr: ipv4_repr.dst_addr,
        dst_addr: ipv4_repr.src_addr,
        ..ipv4_repr
    };
    assert_eq!(
        iface.inner.process_icmpv4(&mut sockets, ip_repr, icmp_data),
        Some(IpPacket::Icmpv4((ipv4_reply, echo_reply)))
    );

    let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            icmp_data,
            IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02))
        ))
    );
}

#[test]
#[cfg(feature = "proto-ipv6")]
fn test_solicited_node_addrs() {
    let (mut iface, _, _device) = create(MEDIUM);
    let mut new_addrs = heapless::Vec::<IpCidr, MAX_IP_ADDR_COUNT>::new();
    new_addrs
        .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64))
        .unwrap();
    new_addrs
        .push(IpCidr::new(
            IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff),
            64,
        ))
        .unwrap();
    iface.update_ip_addrs(|addrs| {
        new_addrs.extend(addrs.to_vec());
        *addrs = new_addrs;
    });
    assert!(iface
        .inner
        .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
    assert!(iface
        .inner
        .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
    assert!(!iface
        .inner
        .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
}

#[test]
#[cfg(feature = "proto-ipv6")]
fn test_icmpv6_nxthdr_unknown() {
    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    let payload = [0x12, 0x34, 0x56, 0x78];

    let ipv6_repr = Ipv6Repr {
        src_addr: remote_ip_addr,
        dst_addr: Ipv6Address::LOOPBACK,
        next_header: IpProtocol::HopByHop,
        payload_len: 12,
        hop_limit: 0x40,
    };

    let mut bytes = vec![0; 52];
    let frame = {
        let ip_repr = IpRepr::Ipv6(ipv6_repr);
        ip_repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let mut offset = ipv6_repr.buffer_len();
        {
            let mut hbh_pkt = Ipv6HopByHopHeader::new_unchecked(&mut bytes[offset..]);
            hbh_pkt.set_next_header(IpProtocol::Unknown(0x0c));
            hbh_pkt.set_header_len(0);
            offset += 8;
            {
                let mut pad_pkt = Ipv6Option::new_unchecked(&mut *hbh_pkt.options_mut());
                Ipv6OptionRepr::PadN(3).emit(&mut pad_pkt);
            }
            {
                let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[5..]);
                Ipv6OptionRepr::Pad1.emit(&mut pad_pkt);
            }
        }
        bytes[offset..].copy_from_slice(&payload);
        Ipv6Packet::new_unchecked(&bytes)
    };

    let reply_icmp_repr = Icmpv6Repr::ParamProblem {
        reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
        pointer: 40,
        header: ipv6_repr,
        data: &payload[..],
    };

    let reply_ipv6_repr = Ipv6Repr {
        src_addr: Ipv6Address::LOOPBACK,
        dst_addr: remote_ip_addr,
        next_header: IpProtocol::Icmpv6,
        payload_len: reply_icmp_repr.buffer_len(),
        hop_limit: 0x40,
    };

    // Ensure the unknown next header causes a ICMPv6 Parameter Problem
    // error message to be sent to the sender.
    assert_eq!(
        iface.inner.process_ipv6(&mut sockets, &frame),
        Some(IpPacket::Icmpv6((reply_ipv6_repr, reply_icmp_repr)))
    );
}

#[test]
#[cfg(feature = "proto-igmp")]
fn test_handle_igmp() {
    fn recv_igmp(device: &mut Loopback, timestamp: Instant) -> Vec<(Ipv4Repr, IgmpRepr)> {
        let caps = device.capabilities();
        let checksum_caps = &caps.checksum;
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv4_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv4Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv4Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, checksum_caps).ok()?;
                let ip_payload = ipv4_packet.payload();
                let igmp_packet = IgmpPacket::new_checked(ip_payload).ok()?;
                let igmp_repr = IgmpRepr::parse(&igmp_packet).ok()?;
                Some((ipv4_repr, igmp_repr))
            })
            .collect::<Vec<_>>()
    }

    let groups = [
        Ipv4Address::new(224, 0, 0, 22),
        Ipv4Address::new(224, 0, 0, 56),
    ];

    let (mut iface, mut sockets, mut device) = create(MEDIUM);

    // Join multicast groups
    let timestamp = Instant::now();
    for group in &groups {
        iface
            .join_multicast_group(&mut device, *group, timestamp)
            .unwrap();
    }

    let reports = recv_igmp(&mut device, timestamp);
    assert_eq!(reports.len(), 2);
    for (i, group_addr) in groups.iter().enumerate() {
        assert_eq!(reports[i].0.next_header, IpProtocol::Igmp);
        assert_eq!(reports[i].0.dst_addr, *group_addr);
        assert_eq!(
            reports[i].1,
            IgmpRepr::MembershipReport {
                group_addr: *group_addr,
                version: IgmpVersion::Version2,
            }
        );
    }

    // General query
    let timestamp = Instant::now();
    const GENERAL_QUERY_BYTES: &[u8] = &[
        0x46, 0xc0, 0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 0x01, 0x02, 0x47, 0x43, 0xac, 0x16, 0x63,
        0x04, 0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x64, 0xec, 0x8f, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    {
        // Transmit GENERAL_QUERY_BYTES into loopback
        let tx_token = device.transmit().unwrap();
        tx_token
            .consume(timestamp, GENERAL_QUERY_BYTES.len(), |buffer| {
                buffer.copy_from_slice(GENERAL_QUERY_BYTES);
                Ok(())
            })
            .unwrap();
    }
    // Trigger processing until all packets received through the
    // loopback have been processed, including responses to
    // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
    // pkts that could be checked.
    iface.socket_ingress(&mut device, &mut sockets);

    // Leave multicast groups
    let timestamp = Instant::now();
    for group in &groups {
        iface
            .leave_multicast_group(&mut device, *group, timestamp)
            .unwrap();
    }

    let leaves = recv_igmp(&mut device, timestamp);
    assert_eq!(leaves.len(), 2);
    for (i, group_addr) in groups.iter().cloned().enumerate() {
        assert_eq!(leaves[i].0.next_header, IpProtocol::Igmp);
        assert_eq!(leaves[i].0.dst_addr, Ipv4Address::MULTICAST_ALL_ROUTERS);
        assert_eq!(leaves[i].1, IgmpRepr::LeaveGroup { group_addr });
    }
}

#[test]
#[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
fn test_raw_socket_no_reply() {
    use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let packets = 1;
    let rx_buffer =
        raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
    let tx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; 48 * packets],
    );
    let raw_socket = raw::Socket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
    sockets.add(raw_socket);

    let src_addr = Ipv4Address([127, 0, 0, 2]);
    let dst_addr = Ipv4Address([127, 0, 0, 1]);

    const PAYLOAD_LEN: usize = 10;

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + PAYLOAD_LEN];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        PAYLOAD_LEN,
        |buf| fill_slice(buf, 0x2a),
        &ChecksumCapabilities::default(),
    );
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + PAYLOAD_LEN,
    };

    // Emit to frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + PAYLOAD_LEN];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes)
    };

    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
    assert_eq!(iface.inner.process_ipv4(&mut sockets, &frame, None), None);
    #[cfg(feature = "proto-ipv4-fragmentation")]
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            &frame,
            Some(&mut iface.fragments.ipv4_fragments)
        ),
        None
    );
}

#[test]
#[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
fn test_raw_socket_with_udp_socket() {
    use crate::wire::{IpEndpoint, IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _device) = create(MEDIUM);

    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_socket_handle = sockets.add(udp_socket);

    // Bind the socket to port 68
    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
    assert_eq!(socket.bind(68), Ok(()));
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    let packets = 1;
    let raw_rx_buffer =
        raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
    let raw_tx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; 48 * packets],
    );
    let raw_socket = raw::Socket::new(
        IpVersion::Ipv4,
        IpProtocol::Udp,
        raw_rx_buffer,
        raw_tx_buffer,
    );
    sockets.add(raw_socket);

    let src_addr = Ipv4Address([127, 0, 0, 2]);
    let dst_addr = Ipv4Address([127, 0, 0, 1]);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + UDP_PAYLOAD.len()];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
    };

    // Emit to frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + UDP_PAYLOAD.len()];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes)
    };

    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
    assert_eq!(iface.inner.process_ipv4(&mut sockets, &frame, None), None);
    #[cfg(feature = "proto-ipv4-fragmentation")]
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            &frame,
            Some(&mut iface.fragments.ipv4_fragments)
        ),
        None
    );

    // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67)))
    );
}

#[cfg(all(
    not(feature = "medium-ethernet"),
    feature = "proto-sixlowpan",
    feature = "proto-sixlowpan-fragmentation"
))]
#[test]
fn test_echo_request_sixlowpan_128_bytes() {
    use crate::phy::Checksum;

    let (mut iface, mut sockets, mut device) = create(Medium::Ieee802154);
    // TODO: modify the example, such that we can also test if the checksum is correctly
    // computed.
    iface.inner.caps.checksum.icmpv6 = Checksum::None;

    assert_eq!(iface.inner.caps.medium, Medium::Ieee802154);
    let now = iface.inner.now();

    iface.inner.neighbor_cache.as_mut().unwrap().fill(
        Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x2, 0, 0, 0, 0, 0, 0, 0]).into(),
        HardwareAddress::Ieee802154(Ieee802154Address::default()),
        now,
    );

    let mut ieee802154_repr = Ieee802154Repr {
        frame_type: Ieee802154FrameType::Data,
        security_enabled: false,
        frame_pending: false,
        ack_request: false,
        sequence_number: Some(5),
        pan_id_compression: true,
        frame_version: Ieee802154FrameVersion::Ieee802154_2003,
        dst_pan_id: Some(Ieee802154Pan(0xbeef)),
        dst_addr: Some(Ieee802154Address::Extended([
            0x90, 0xfc, 0x48, 0xc2, 0xa4, 0x41, 0xfc, 0x76,
        ])),
        src_pan_id: Some(Ieee802154Pan(0xbeef)),
        src_addr: Some(Ieee802154Address::Extended([
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a,
        ])),
    };

    // NOTE: this data is retrieved from tests with Contiki-NG

    let request_first_part_packet = SixlowpanFragPacket::new_checked(&[
        0xc0, 0xb0, 0x00, 0x8e, 0x6a, 0x33, 0x05, 0x25, 0x2c, 0x3a, 0x80, 0x00, 0xe0, 0x71, 0x00,
        0x27, 0x00, 0x02, 0xa2, 0xc2, 0x2d, 0x63, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x5e, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
        0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ])
    .unwrap();

    let request_first_part_iphc_packet =
        SixlowpanIphcPacket::new_checked(request_first_part_packet.payload()).unwrap();

    let request_first_part_iphc_repr = SixlowpanIphcRepr::parse(
        &request_first_part_iphc_packet,
        ieee802154_repr.src_addr,
        ieee802154_repr.dst_addr,
        iface.inner.sixlowpan_address_context,
    )
    .unwrap();

    assert_eq!(
        request_first_part_iphc_repr.src_addr,
        Ipv6Address([
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0xb,
            0x1a,
        ]),
    );
    assert_eq!(
        request_first_part_iphc_repr.dst_addr,
        Ipv6Address([
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x92, 0xfc, 0x48, 0xc2, 0xa4, 0x41, 0xfc,
            0x76,
        ]),
    );

    let request_second_part = [
        0xe0, 0xb0, 0x00, 0x8e, 0x10, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];

    assert_eq!(
        iface.inner.process_sixlowpan(
            &mut sockets,
            &ieee802154_repr,
            &request_first_part_packet.into_inner(),
            Some((
                &mut iface.fragments.sixlowpan_fragments,
                iface.fragments.sixlowpan_fragments_cache_timeout,
            )),
        ),
        None
    );

    ieee802154_repr.sequence_number = Some(6);

    // data that was generated when using `ping -s 128`
    let data = &[
        0xa2, 0xc2, 0x2d, 0x63, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x5e, 0x0c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
        0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];

    let result = iface.inner.process_sixlowpan(
        &mut sockets,
        &ieee802154_repr,
        &request_second_part,
        Some((
            &mut iface.fragments.sixlowpan_fragments,
            iface.fragments.sixlowpan_fragments_cache_timeout,
        )),
    );

    assert_eq!(
        result,
        Some(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address([
                    0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x92, 0xfc, 0x48, 0xc2, 0xa4, 0x41,
                    0xfc, 0x76,
                ]),
                dst_addr: Ipv6Address([
                    0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42,
                    0xb, 0x1a,
                ]),
                next_header: IpProtocol::Icmpv6,
                payload_len: 136,
                hop_limit: 64,
            },
            Icmpv6Repr::EchoReply {
                ident: 39,
                seq_no: 2,
                data,
            }
        )))
    );

    iface.inner.neighbor_cache.as_mut().unwrap().fill(
        IpAddress::Ipv6(Ipv6Address([
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0xb, 0x1a,
        ])),
        HardwareAddress::Ieee802154(Ieee802154Address::default()),
        Instant::now(),
    );

    let tx_token = device.transmit().unwrap();
    iface
        .inner
        .dispatch_ieee802154(
            Ieee802154Address::default(),
            tx_token,
            result.unwrap(),
            Some(&mut iface.out_packets),
        )
        .unwrap();

    assert_eq!(
        device.queue[0],
        &[
            0x41, 0xcc, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xc0, 0xb0, 0x5, 0x4e, 0x7a, 0x11, 0x3a, 0x92, 0xfc, 0x48, 0xc2,
            0xa4, 0x41, 0xfc, 0x76, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0xb, 0x1a, 0x81, 0x0, 0x0,
            0x0, 0x0, 0x27, 0x0, 0x2, 0xa2, 0xc2, 0x2d, 0x63, 0x0, 0x0, 0x0, 0x0, 0xd9, 0x5e, 0xc,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
            0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ]
    );

    iface.poll(Instant::now(), &mut device, &mut sockets);

    assert_eq!(
        device.queue[1],
        &[
            0x41, 0xcc, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xe0, 0xb0, 0x5, 0x4e, 0xf, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
            0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        ]
    );
}

#[cfg(all(
    not(feature = "medium-ethernet"),
    feature = "proto-sixlowpan",
    feature = "proto-sixlowpan-fragmentation"
))]
#[test]
fn test_sixlowpan_udp_with_fragmentation() {
    use crate::phy::Checksum;

    let mut ieee802154_repr = Ieee802154Repr {
        frame_type: Ieee802154FrameType::Data,
        security_enabled: false,
        frame_pending: false,
        ack_request: false,
        sequence_number: Some(5),
        pan_id_compression: true,
        frame_version: Ieee802154FrameVersion::Ieee802154_2003,
        dst_pan_id: Some(Ieee802154Pan(0xbeef)),
        dst_addr: Some(Ieee802154Address::Extended([
            0x90, 0xfc, 0x48, 0xc2, 0xa4, 0x41, 0xfc, 0x76,
        ])),
        src_pan_id: Some(Ieee802154Pan(0xbeef)),
        src_addr: Some(Ieee802154Address::Extended([
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a,
        ])),
    };

    let (mut iface, mut sockets, mut device) = create(Medium::Ieee802154);
    iface.inner.caps.checksum.udp = Checksum::None;

    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 1024 * 4]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 1024 * 4]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_socket_handle = sockets.add(udp_socket);

    {
        let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
        assert_eq!(socket.bind(6969), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());
    }

    let udp_first_part = &[
        0xc0, 0xbc, 0x00, 0x92, 0x6e, 0x33, 0x07, 0xe7, 0xdc, 0xf0, 0xd3, 0xc9, 0x1b, 0x39, 0xbf,
        0xa0, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f,
        0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63,
        0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70,
        0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x49, 0x6e,
        0x20, 0x61, 0x74, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73, 0x20, 0x74, 0x6f, 0x72,
        0x74, 0x6f, 0x72, 0x2e, 0x20, 0x43, 0x72, 0x61, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x6e,
    ];

    assert_eq!(
        iface.inner.process_sixlowpan(
            &mut sockets,
            &ieee802154_repr,
            udp_first_part,
            Some((
                &mut iface.fragments.sixlowpan_fragments,
                iface.fragments.sixlowpan_fragments_cache_timeout
            ))
        ),
        None
    );

    ieee802154_repr.sequence_number = Some(6);

    let udp_second_part = &[
        0xe0, 0xbc, 0x00, 0x92, 0x11, 0x64, 0x69, 0x74, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73,
        0x20, 0x64, 0x69, 0x61, 0x6d, 0x2c, 0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x76,
        0x65, 0x73, 0x74, 0x69, 0x62, 0x75, 0x6c, 0x75, 0x6d, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20,
        0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64, 0x6f, 0x20, 0x6e, 0x65, 0x63, 0x2e,
    ];

    assert_eq!(
        iface.inner.process_sixlowpan(
            &mut sockets,
            &ieee802154_repr,
            udp_second_part,
            Some((
                &mut iface.fragments.sixlowpan_fragments,
                iface.fragments.sixlowpan_fragments_cache_timeout
            ))
        ),
        None
    );

    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);

    let udp_data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                         In at rhoncus tortor. Cras blandit tellus diam, varius vestibulum nibh commodo nec.";
    assert_eq!(
        socket.recv(),
        Ok((
            &udp_data[..],
            IpEndpoint {
                addr: IpAddress::Ipv6(Ipv6Address([
                    0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42,
                    0xb, 0x1a,
                ])),
                port: 54217,
            }
        ))
    );

    let tx_token = device.transmit().unwrap();
    iface
        .inner
        .dispatch_ieee802154(
            Ieee802154Address::default(),
            tx_token,
            IpPacket::Udp((
                IpRepr::Ipv6(Ipv6Repr {
                    src_addr: Ipv6Address::default(),
                    dst_addr: Ipv6Address::default(),
                    next_header: IpProtocol::Udp,
                    payload_len: udp_data.len(),
                    hop_limit: 64,
                }),
                UdpRepr {
                    src_port: 1234,
                    dst_port: 1234,
                },
                udp_data,
            )),
            Some(&mut iface.out_packets),
        )
        .unwrap();

    iface.poll(Instant::now(), &mut device, &mut sockets);

    assert_eq!(
        device.queue[0],
        &[
            0x41, 0xcc, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xc0, 0xb4, 0x5, 0x4e, 0x7e, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf0, 0x4, 0xd2, 0x4, 0xd2, 0xf6,
            0x4d, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64,
            0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c,
            0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61,
            0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74,
            0x2e, 0x20, 0x49, 0x6e, 0x20, 0x61, 0x74, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75,
            0x73, 0x20, 0x74,
        ]
    );

    assert_eq!(
        device.queue[1],
        &[
            0x41, 0xcc, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xe0, 0xb4, 0x5, 0x4e, 0xf, 0x6f, 0x72, 0x74, 0x6f, 0x72, 0x2e,
            0x20, 0x43, 0x72, 0x61, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x6e, 0x64, 0x69, 0x74, 0x20,
            0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x2c, 0x20, 0x76,
            0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x76, 0x65, 0x73, 0x74, 0x69, 0x62, 0x75, 0x6c,
            0x75, 0x6d, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64,
            0x6f, 0x20, 0x6e, 0x65, 0x63, 0x2e,
        ]
    );
}
