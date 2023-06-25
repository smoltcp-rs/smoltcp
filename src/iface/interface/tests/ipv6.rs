use super::*;

fn parse_ipv6(data: &[u8]) -> crate::wire::Result<IpPacket<'_>> {
    let ipv6_header = Ipv6Packet::new_checked(data)?;
    let ipv6 = Ipv6Repr::parse(&ipv6_header)?;

    match ipv6.next_header {
        IpProtocol::HopByHop => todo!(),
        IpProtocol::Icmp => todo!(),
        IpProtocol::Igmp => todo!(),
        IpProtocol::Tcp => todo!(),
        IpProtocol::Udp => todo!(),
        IpProtocol::Ipv6Route => todo!(),
        IpProtocol::Ipv6Frag => todo!(),
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Repr::parse(
                &ipv6.src_addr.into(),
                &ipv6.dst_addr.into(),
                &Icmpv6Packet::new_checked(ipv6_header.payload())?,
                &Default::default(),
            )?;
            Ok(IpPacket::Icmpv6((ipv6, icmp)))
        }
        IpProtocol::Ipv6NoNxt => todo!(),
        IpProtocol::Ipv6Opts => todo!(),
        IpProtocol::Unknown(_) => todo!(),
    }
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn multicast_source_address(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn hop_by_hop_skip_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (skipped)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0xf, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(IpPacket::Icmpv6((
        Ipv6Repr {
            src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
            dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        },
    )));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn hop_by_hop_discard_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn imcp_empty_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x84, 0x3c, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            }
        )))
    );

    let response = Some(IpPacket::Icmpv6((
        Ipv6Repr {
            src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
            dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 8,
        },
        Icmpv6Repr::EchoReply {
            ident: 0,
            seq_no: 0,
            data: b"",
        },
    )));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn icmp_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72,
        0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            Icmpv6Repr::EchoRequest {
                ident: 42,
                seq_no: 420,
                data: b"Lorem Ipsum",
            }
        )))
    );

    let response = Some(IpPacket::Icmpv6((
        Ipv6Repr {
            src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
            dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        },
    )));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn icmp_echo_reply_as_input(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x81, 0x0, 0x2d, 0x56, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x6f, 0x72, 0x65,
        0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            Icmpv6Repr::EchoReply {
                ident: 0,
                seq_no: 0,
                data: b"Lorem Ipsum",
            }
        )))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn unknown_proto_with_multicast_dst_address(#[case] medium: Medium) {
    // Since the destination address is multicast, we should not answer with an ICMPv6 message.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn unknown_proto(#[case] medium: Medium) {
    // Since the destination address is multicast, we should not answer with an ICMPv6 message.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(IpPacket::Icmpv6((
        Ipv6Repr {
            src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
            dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        },
    )));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndsic_neighbor_advertisement_ethernet(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x9f, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 0x0002]),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 1])),
            })
        )))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002])),
            iface.inner.now,
        ),
        NeighborAnswer::Found(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
            0, 0, 0, 0, 0, 1
        ]))),
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndsic_neighbor_advertisement_ethernet_multicast_addr(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0xa0, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 0x0002]),
                lladdr: Some(RawHardwareAddress::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                ])),
            })
        )))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002])),
            iface.inner.now,
        ),
        NeighborAnswer::NotFound,
    );
}

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn ndsic_neighbor_advertisement_ieee802154(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x28, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x96, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(IpPacket::Icmpv6((
            Ipv6Repr {
                src_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002]),
                dst_addr: Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001]),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 40,
            },
            Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 0x0002]),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 1])),
            })
        )))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            &Ipv6Packet::new_checked(&data).unwrap()
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::from_parts(&[0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002])),
            iface.inner.now,
        ),
        NeighborAnswer::Found(HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(
            &[0, 0, 0, 0, 0, 0, 0, 1]
        ))),
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_valid_ndisc_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

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
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
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
            &IpAddress::Ipv6(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn test_solicited_node_addrs(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);
    let mut new_addrs = heapless::Vec::<IpCidr, IFACE_MAX_ADDR_COUNT>::new();
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

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-udp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-udp", feature = "medium-ethernet"))]
#[case(Medium::Ieee802154)]
#[cfg(all(feature = "socket-udp", feature = "medium-ieee802154"))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::Icmpv6DstUnreachable;
    use crate::wire::IPV6_MIN_MTU as MIN_MTU;
    const MAX_PAYLOAD_LEN: usize = 1192;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
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

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
        reason: Icmpv6DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };

    let expected_ip_repr = Ipv6Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmpv6,
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
        Some(IpPacket::Icmpv6((expected_ip_repr, expected_icmp_repr)))
    );
}
