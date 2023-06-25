use super::*;

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_no_icmp_no_unicast(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);

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

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_icmp_error_no_payload(#[case] medium: Medium) {
    static NO_BYTES: [u8; 0] = [];
    let (mut iface, mut sockets, _device) = setup(medium);

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

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_repr)
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_local_subnet_broadcasts(#[case] medium: Medium) {
    let (mut iface, _, _device) = setup(medium);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 1, 23]), 24));
        });
    });

    assert!(iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 255])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 254])));
    assert!(iface.inner.is_broadcast_v4(Ipv4Address([192, 168, 1, 255])));
    assert!(!iface.inner.is_broadcast_v4(Ipv4Address([192, 168, 1, 254])));

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 16));
        });
    });
    assert!(iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 255])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 254])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 168, 23, 255])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 168, 23, 254])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 168, 255, 254])));
    assert!(iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 168, 255, 255])));

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 8));
        });
    });
    assert!(iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 255])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([255, 255, 255, 254])));
    assert!(!iface.inner.is_broadcast_v4(Ipv4Address([192, 23, 1, 255])));
    assert!(!iface.inner.is_broadcast_v4(Ipv4Address([192, 23, 1, 254])));
    assert!(!iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 255, 255, 254])));
    assert!(iface
        .inner
        .is_broadcast_v4(Ipv4Address([192, 255, 255, 255])));
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "medium-ethernet", feature = "socket-udp"))]
fn test_icmp_error_port_unreachable(#[case] medium: Medium) {
    static UDP_PAYLOAD: [u8; 12] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21,
    ];
    let (mut iface, mut sockets, _device) = setup(medium);

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
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            ip_repr,
            udp_repr,
            false,
            &UDP_PAYLOAD,
            data
        ),
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
            PacketMeta::default(),
            ip_repr,
            udp_repr,
            false,
            &UDP_PAYLOAD,
            packet_broadcast.into_inner(),
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_ipv4_broadcast(#[case] medium: Medium) {
    use crate::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet};

    let (mut iface, mut sockets, _device) = setup(medium);

    let our_ipv4_addr = iface.ipv4_addr().unwrap();
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

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_packet)
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_valid_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

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
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
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
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_other_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

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
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        None
    );

    // Ensure the address of the requestor was NOT entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Err(DispatchError::NeighborPending)
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_arp_flush_after_update_ip(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

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
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
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
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
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

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-icmp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-icmp", feature = "medium-ethernet"))]
fn test_icmpv4_socket(#[case] medium: Medium) {
    use crate::wire::Icmpv4Packet;

    let (mut iface, mut sockets, _device) = setup(medium);

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

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "proto-igmp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "proto-igmp", feature = "medium-ethernet"))]
fn test_handle_igmp(#[case] medium: Medium) {
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

    let (mut iface, mut sockets, mut device) = setup(medium);

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
        let tx_token = device.transmit(timestamp).unwrap();
        tx_token.consume(GENERAL_QUERY_BYTES.len(), |buffer| {
            buffer.copy_from_slice(GENERAL_QUERY_BYTES);
        });
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

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-raw", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-raw", feature = "medium-ethernet"))]
fn test_raw_socket_no_reply(#[case] medium: Medium) {
    use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

    let (mut iface, mut sockets, _) = setup(medium);

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

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-raw", feature = "socket-udp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(
    feature = "socket-raw",
    feature = "socket-udp",
    feature = "medium-ethernet"
))]
fn test_raw_socket_with_udp_socket(#[case] medium: Medium) {
    use crate::wire::{IpEndpoint, IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _) = setup(medium);

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

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );

    // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            &UDP_PAYLOAD[..],
            IpEndpoint::new(src_addr.into(), 67).into()
        ))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-udp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-udp", feature = "medium-ethernet"))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::IPV4_MIN_MTU as MIN_MTU;
    const MAX_PAYLOAD_LEN: usize = 528;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv4Address([192, 168, 1, 1]);
    let dst_addr = Ipv4Address([192, 168, 1, 2]);

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

    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };

    let expected_ip_repr = Ipv4Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmp_repr.buffer_len(),
    };

    assert_eq!(
        expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
        MIN_MTU
    );

    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            ip_repr.into(),
            udp_repr,
            false,
            &vec![0x2a; MAX_PAYLOAD_LEN],
            payload,
        ),
        Some(IpPacket::Icmpv4((expected_ip_repr, expected_icmp_repr)))
    );
}
