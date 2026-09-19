use super::*;

fn parse_ipv6(data: &[u8]) -> crate::wire::Result<Packet<'_>> {
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
        IpProtocol::IpSecEsp => todo!(),
        IpProtocol::IpSecAh => todo!(),
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Repr::parse(
                &ipv6.src_addr,
                &ipv6.dst_addr,
                &Icmpv6Packet::new_checked(ipv6_header.payload())?,
                &Default::default(),
            )?;
            Ok(Packet::new_ipv6(ipv6, IpPayload::Icmpv6(icmp)))
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
fn any_ip(#[case] medium: Medium) {
    // An empty echo request with destination address fdbe::3, which is not part of the interface
    // address list.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x3, 0x80, 0x0, 0x84, 0x3a, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0003),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let (mut iface, mut sockets, _device) = setup(medium);

    // Add a route to the interface, otherwise, we don't know if the packet is routed localy.
    iface.routes_mut().update(|routes| {
        routes
            .push(crate::iface::Route {
                cidr: IpCidr::Ipv6(Ipv6Cidr::new(
                    Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0),
                    64,
                )),
                via_router: IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001)),
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();
    });

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        None
    );

    // Accept any IP:
    iface.set_any_ip(true);
    assert!(
        iface
            .inner
            .process_ipv6(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::default(),
                &Ipv6Packet::new_checked(&data[..]).unwrap(),
                Ipv6Reassembly::from(&mut iface.fragments)
            )
            .is_some()
    );
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
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_param_problem(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard + ParamProblem)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_with_multicast(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard (0b11) + ParamProblem)
    // - ICMP echo request
    //
    // In this case, even if the destination address is a multicast address, an ICMPv6 ParamProblem
    // should be transmitted.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 8,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 0,
            seq_no: 0,
            data: b"",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 42,
                seq_no: 420,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
                ident: 0,
                seq_no: 0,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
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
    // Since the destination address is multicast, we should answer with an ICMPv6 message.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndisc_neighbor_advertisement_ethernet(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x9f, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
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
fn ndisc_neighbor_advertisement_ethernet_multicast_addr(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0xa0, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                ])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        NeighborAnswer::NotFound,
    );
}

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn ndisc_neighbor_advertisement_ieee802154(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x28, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x96, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 40,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments)
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
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
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
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
        &remote_ip_addr,
        &local_ip_addr.solicited_node(),
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
        Some(EthernetPacket::Ip(Packet::new_ipv6(
            ipv6_expected,
            IpPayload::Icmpv6(icmpv6_expected)
        )))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv6(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "proto-ipv6-slaac")]
fn test_router_advertisement(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }
    let prefix_addr = Ipv6Address::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 0);

    let mut device = crate::tests::TestingDevice::new(medium);
    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;

    let mut eth_bytes = vec![0u8; 102];

    // Create mac addresses with derived link local addresses
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let ll_prefix = Ipv6Cidr::new(Ipv6Cidr::LINK_LOCAL_PREFIX.address(), 64);
    let local_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(local_hw_addr)).unwrap();
    let remote_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(remote_hw_addr)).unwrap();

    // Create config with slaac enabled
    let mut config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => HardwareAddress::Ethernet(local_hw_addr),
        _ => panic!("Not supported"),
    });
    config.slaac = true;

    // Set up interface with link local address
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::Ipv6(local_ip_addr)).unwrap();
    });

    let mut sockets = SocketSet::new(vec![]);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    let transmitted: std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> =
        recv_icmpv6(&mut device, Instant::ZERO)
            .into_iter()
            .filter(|packet| {
                // Filter for router solicitations
                packet.dst_addr() == IPV6_LINK_LOCAL_ALL_ROUTERS
            })
            .collect();

    assert_eq!(transmitted.len(), 1);

    for ipv6_packet in transmitted.into_iter() {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        if ipv6_repr.dst_addr == IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS {
            continue; // Skip MLD reports
        }
        let icmpv6_packet = Icmpv6Packet::new_checked(ipv6_packet.payload()).unwrap();
        let icmp_repr = Icmpv6Repr::parse(
            &ipv6_repr.src_addr,
            &ipv6_repr.dst_addr,
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        assert_eq!(
            icmp_repr,
            Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
                lladdr: Some(local_hw_addr.into()),
            })
        );

        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_ROUTERS);
        println!("repr {:?}", icmp_repr);
    }

    // Craft the router advertisement
    let mut prefix_information = NdiscPrefixInformation {
        prefix: prefix_addr,
        prefix_len: 64,
        flags: NdiscPrefixInfoFlags::ADDRCONF,
        valid_lifetime: Duration::from_secs(600),
        preferred_lifetime: Duration::from_secs(300),
    };
    let mut advertisement = NdiscRepr::RouterAdvert {
        hop_limit: 255,
        flags: NdiscRouterFlags::empty(),
        router_lifetime: Duration::from_secs(600),
        reachable_time: Duration::from_secs(0),
        retrans_time: Duration::from_secs(0),
        lladdr: None,
        mtu: None,
        prefix_info: Some(prefix_information),
    };
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr.address(),
        dst_addr: local_ip_addr.address(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255,
        payload_len: advertisement.buffer_len(),
    });
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Expect to have these two addresses after the router advertisement
    let expected_addrs = [
        IpCidr::Ipv6(local_ip_addr),
        IpCidr::Ipv6(Ipv6Cidr::new(
            Ipv6Address::new(0x2001, 0xdb8, 0x3, 0x0, 0x2, 0x2ff, 0xfe02, 0x202),
            64,
        )),
    ];
    for (generated, expected) in iface.ip_addrs().iter().zip(expected_addrs.iter()) {
        assert_eq!(generated, expected);
    }
    // Verify the pushed route matches expected
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
        assert_eq!(
            route[0].cidr,
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0)
        );
        assert_eq!(
            route[0].via_router,
            IpAddress::Ipv6(remote_ip_addr.address())
        );
        assert_eq!(route[0].preferred_until, None);
        assert_eq!(route[0].expires_at, None);
    });

    // Craft a router advertisement with zero lifetime for the prefix
    // to remove the prefix, but retain the route
    prefix_information.valid_lifetime = Duration::ZERO;
    prefix_information.preferred_lifetime = Duration::ZERO;
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ..
    } = advertisement
    {
        *prefix_info = Some(prefix_information);
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(10);

    iface.poll(now, &mut device, &mut sockets);
    assert_eq!(iface.ip_addrs().len(), 1);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
    });

    // Craft router advertisement with zero router lifetime
    // to remove the route
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ref mut router_lifetime,
        ..
    } = advertisement
    {
        *prefix_info = None;
        *router_lifetime = Duration::ZERO;
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(20);
    iface.poll(now, &mut device, &mut sockets);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 0);
    });
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
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002))
    );
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff))
    );
    assert!(
        !iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(all(feature = "socket-udp", feature = "medium-ip"))]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "socket-udp", feature = "medium-ethernet"))]
#[case(Medium::Ieee802154)]
#[cfg(all(feature = "socket-udp", feature = "medium-ieee802154"))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::IPV6_MIN_MTU as MIN_MTU;
    use crate::wire::Icmpv6DstUnreachable;
    const MAX_PAYLOAD_LEN: usize = 1192;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    // UDP packet that if not tructated will cause a icmp port unreachable reply
    // to exceed the minimum mtu bytes in length.
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
            false,
            ip_repr.into(),
            payload,
        ),
        Some(Packet::new_ipv6(
            expected_ip_repr,
            IpPayload::Icmpv6(expected_icmp_repr)
        ))
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address() {
    let (mut iface, _, _) = setup(Medium::Ip);

    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const OWN_UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 2);
    const OWN_GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 1);

    // List of addresses of the interface:
    //   fe80::1/64
    //   fd00::201:1:1:1:2/64
    //   fd01::201:1:1:1:2/64
    //   2001:db8:3::1/64
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 64)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_GLOBAL_UNICAST_ADDR1, 64)))
            .unwrap();
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fd00::201:1:1:1:2
    //   fd01::201:1:1:1:1 -> fd01::201:1:1:1:2
    //   fd02::201:1:1:1:1 -> fd00::201:1:1:1:2 (because first added in the list)
    //   fd01::201:1:1:1:3 -> fd01::201:1:1:1:2 (because in same subnet)
    //   ff02::1           -> fe80::1 (same scope)
    //   2001:db8:3::2     -> 2001:db8:3::1
    //   2001:db9:3::2     -> 2001:db8:3::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR4: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 3);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR4),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_only_link_local() {
    let (mut iface, _, _) = setup(Medium::Ip);

    // List of addresses in the interface:
    //   fe80::1/64
    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    iface.update_ip_addrs(|ips| {
        ips.clear();
        ips.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)))
            .unwrap();
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fe80::1
    //   fd01::201:1:1:1:1 -> fe80::1
    //   fd02::201:1:1:1:1 -> fe80::1
    //   ff02::1           -> fe80::1
    //   2001:db8:3::2     -> fe80::1
    //   2001:db9:3::2     -> fe80::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_empty_interface() {
    let (mut iface, _, _) = setup(Medium::Ip);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> ::1
    //   fd00::201:1:1:1:1 -> ::1
    //   fd01::201:1:1:1:1 -> ::1
    //   fd02::201:1:1:1:1 -> ::1
    //   ff02::1           -> ::1
    //   2001:db8:3::2     -> ::1
    //   2001:db9:3::2     -> ::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_join_ipv6_multicast_group(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let groups = [
        Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb),
        Ipv6Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x0017),
    ];

    let timestamp = Instant::from_millis(0);

    // Drain the unsolicited node multicast report from the device
    iface.poll(timestamp, &mut device, &mut sockets);
    let _ = recv_icmpv6(&mut device, timestamp);

    for &group in &groups {
        iface.join_multicast_group(group).unwrap();
        assert!(iface.has_multicast_group(group));
    }
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));
    iface.poll(timestamp, &mut device, &mut sockets);
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), 2);

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for (&group_addr, ipv6_packet) in groups.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let _ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, 1);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let record = MldAddressRecord::new_checked(record_data).unwrap();
        let record_repr = MldAddressRecordRepr::parse(&record).unwrap();

        assert_eq!(
            record_repr,
            MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: group_addr,
                record_type: MldRecordType::ChangeToInclude,
                aux_data_len: 0,
                payload: &[],
            }
        );

        if !group_addr.is_solicited_node_multicast() {
            iface.leave_multicast_group(group_addr).unwrap();
            assert!(!iface.has_multicast_group(group_addr));
            iface.poll(timestamp, &mut device, &mut sockets);
            assert!(!iface.has_multicast_group(group_addr));
        }
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_handle_valid_multicast_query(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let mut timestamp = Instant::ZERO;

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 100);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let query_ip_addr = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);

    iface.join_multicast_group(query_ip_addr).unwrap();

    iface.poll(timestamp, &mut device, &mut sockets);
    // flush multicast reports from the join_multicast_group calls
    recv_icmpv6(&mut device, timestamp);

    let queries = [
        // General query, expect both multicast addresses back
        (
            Ipv6Address::UNSPECIFIED,
            IPV6_LINK_LOCAL_ALL_NODES,
            vec![local_ip_addr.solicited_node(), query_ip_addr],
        ),
        // Address specific query, expect only the queried address back
        (query_ip_addr, query_ip_addr, vec![query_ip_addr]),
    ];

    for (mcast_query, address, _results) in queries.iter() {
        let query = Icmpv6Repr::Mld(MldRepr::Query {
            max_resp_code: 1000,
            mcast_addr: *mcast_query,
            s_flag: false,
            qrv: 1,
            qqic: 60,
            num_srcs: 0,
            data: &[0, 0, 0, 0],
        });

        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: *address,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 1,
            payload_len: query.buffer_len(),
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        query.emit(
            &remote_ip_addr,
            address,
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
            &ChecksumCapabilities::default(),
        );

        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments,
        );

        timestamp += crate::time::Duration::from_millis(1000);
        iface.poll(timestamp, &mut device, &mut sockets);
    }

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), queries.len());

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for ((_mcast_query, _address, results), ipv6_packet) in queries.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();
        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS);

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, results.len() as u16);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let mut record_reprs = Vec::new();
        let mut payload = record_data;

        // FIXME: parsing multiple address records should be done by the MLD code
        while !payload.is_empty() {
            let record = MldAddressRecord::new_checked(payload).unwrap();
            let mut record_repr = MldAddressRecordRepr::parse(&record).unwrap();
            payload = record_repr.payload;
            record_repr.payload = &[];
            record_reprs.push(record_repr);
        }

        let expected_records = results
            .iter()
            .map(|addr| MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: *addr,
                record_type: MldRecordType::ModeIsExclude,
                aux_data_len: 0,
                payload: &[],
            })
            .collect::<Vec<_>>();

        assert_eq!(record_reprs, expected_records);
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_solicited_node_multicast_autojoin(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    let addr1 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let addr2 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64)).unwrap();
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr2.into(), 64)).unwrap();
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64)).unwrap();
        ip_addrs.push(IpCidr::new(addr2.into(), 64)).unwrap();
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));
}

#[cfg(feature = "proto-ipv6-fragmentation")]
mod fragmentation {
    use super::*;

    const REMOTE: Ipv6Address = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002);
    const LOCAL: Ipv6Address = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001);
    /// Offset of the Fragment header's Fragment Offset field from the start
    /// of a packet whose only extension header is the Fragment header.
    const FRAG_OFFSET_FIELD: u32 = 40 + 2;

    /// `[IPv6 header][Fragment header][data]`, emitted by hand because the
    /// dispatch path cannot produce IPv6 fragments.
    #[allow(clippy::too_many_arguments)]
    fn fragment(
        dst_addr: Ipv6Address,
        next_header: IpProtocol,
        ident: u32,
        frag_offset: u16,
        more_frags: bool,
        hop_limit: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let repr = Ipv6Repr {
            src_addr: REMOTE,
            dst_addr,
            next_header: IpProtocol::Ipv6Frag,
            payload_len: 8 + data.len(),
            hop_limit,
        };
        let mut bytes = std::vec![0u8; repr.buffer_len() + repr.payload_len];
        repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes[..]));

        bytes[40] = u8::from(next_header);
        bytes[41] = 0;
        {
            let mut header = Ipv6FragmentHeader::new_unchecked(&mut bytes[42..48]);
            header.clear_reserved();
            header.set_frag_offset(frag_offset);
            header.set_more_frags(more_frags);
            header.set_ident(ident);
        }
        bytes[48..].copy_from_slice(data);
        bytes
    }

    /// A complete ICMPv6 echo request, checksummed over the whole message —
    /// which is what makes reassembly observable end to end: the reply only
    /// comes back if every octet landed at the right offset.
    fn echo_request(payload: &[u8]) -> Vec<u8> {
        let repr = Icmpv6Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0x5678,
            data: payload,
        };
        let mut bytes = std::vec![0u8; repr.buffer_len()];
        repr.emit(
            &REMOTE,
            &LOCAL,
            &mut Icmpv6Packet::new_unchecked(&mut bytes[..]),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn feed<'a>(
        iface: &'a mut Interface,
        sockets: &mut SocketSet<'_>,
        data: &'a [u8],
    ) -> Option<Packet<'a>> {
        iface.inner.process_ipv6(
            sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(data).unwrap(),
            Ipv6Reassembly::from(&mut iface.fragments),
        )
    }

    /// The reply an echo request of `payload` should draw once reassembled.
    fn expect_echo_reply(packet: Option<Packet<'_>>, payload: &[u8]) {
        match packet {
            Some(Packet::Ipv6(p)) => match p.payload {
                IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }) => {
                    assert_eq!(ident, 0x1234);
                    assert_eq!(seq_no, 0x5678);
                    assert_eq!(data, payload, "every octet, at its own offset");
                }
                other => panic!("expected an echo reply, got {other:?}"),
            },
            other => panic!("expected an IPv6 packet, got {other:?}"),
        }
    }

    /// The Parameter Problem a refused fragment should draw.
    fn expect_param_problem(
        packet: Option<Packet<'_>>,
        expected_reason: Icmpv6ParamProblem,
        expected_pointer: u32,
    ) {
        match packet {
            Some(Packet::Ipv6(p)) => match p.payload {
                IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
                    reason, pointer, ..
                }) => {
                    assert_eq!(reason, expected_reason);
                    assert_eq!(pointer, expected_pointer);
                }
                other => panic!("expected a parameter problem, got {other:?}"),
            },
            other => panic!("expected an IPv6 packet, got {other:?}"),
        }
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn two_fragments_reassemble(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);
        assert_eq!(message.len(), 8 + 64);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0xaa, 0, true, 64, &message[..40]);
        let last = fragment(LOCAL, IpProtocol::Icmpv6, 0xaa, 5, false, 64, &message[40..]);

        assert!(
            feed(&mut iface, &mut sockets, &first).is_none(),
            "a first fragment delivers nothing on its own"
        );
        expect_echo_reply(feed(&mut iface, &mut sockets, &last), &payload);
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn fragments_reassemble_out_of_order(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0xbb, 0, true, 64, &message[..40]);
        let last = fragment(LOCAL, IpProtocol::Icmpv6, 0xbb, 5, false, 64, &message[40..]);

        // The last fragment first: it fixes the total, and the datagram
        // completes only when the head finally lands.
        assert!(feed(&mut iface, &mut sockets, &last).is_none());
        expect_echo_reply(feed(&mut iface, &mut sockets, &first), &payload);
    }

    /// RFC 6946: offset zero with no more fragments is a whole datagram. It
    /// must not go through the assembler, where it would otherwise be able
    /// to collide with a genuinely fragmented datagram of the same identity.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn an_atomic_fragment_is_delivered_whole(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..16u8).collect();
        let message = echo_request(&payload);

        // A half-finished datagram under the SAME identification, which the
        // atomic fragment must leave untouched.
        let head = fragment(LOCAL, IpProtocol::Icmpv6, 0xcc, 0, true, 64, &message[..8]);
        assert!(feed(&mut iface, &mut sockets, &head).is_none());

        let atomic = fragment(LOCAL, IpProtocol::Icmpv6, 0xcc, 0, false, 64, &message);
        expect_echo_reply(feed(&mut iface, &mut sockets, &atomic), &payload);
    }

    /// RFC 8200 section 4.5: a non-final fragment that is not a multiple of
    /// eight octets is discarded, pointing at Payload Length.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn a_non_final_fragment_must_be_a_multiple_of_eight(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let data = [0u8; 12];
        let odd = fragment(LOCAL, IpProtocol::Icmpv6, 0xdd, 0, true, 64, &data);
        expect_param_problem(
            feed(&mut iface, &mut sockets, &odd),
            Icmpv6ParamProblem::ErroneousHdrField,
            4,
        );
    }

    /// ... and one whose tail would put the datagram past 65535 octets is
    /// discarded, pointing at Fragment Offset.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn a_fragment_past_the_payload_ceiling_is_refused(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let data = [0u8; 16];
        // 8191 * 8 + 16 = 65544.
        let beyond = fragment(LOCAL, IpProtocol::Icmpv6, 0xee, 8191, true, 64, &data);
        expect_param_problem(
            feed(&mut iface, &mut sockets, &beyond),
            Icmpv6ParamProblem::ErroneousHdrField,
            FRAG_OFFSET_FIELD,
        );
    }

    /// RFC 7112: a first fragment that does not carry its upper-layer header
    /// is discarded with code 3. Splitting the chain so a stateless filter
    /// cannot see the ports is the attack this closes.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn a_first_fragment_without_its_upper_layer_header_is_refused(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        // Sixteen octets: a whole number of eight-octet units, so the length
        // rule above lets it past, and still four short of a TCP header.
        let stub = [0u8; 16];
        let split = fragment(LOCAL, IpProtocol::Tcp, 0x11, 0, true, 64, &stub);
        expect_param_problem(
            feed(&mut iface, &mut sockets, &split),
            Icmpv6ParamProblem::IncompleteHdrChain,
            40,
        );
    }

    /// RFC 8200 section 4.5: the reassembled packet's header fields come
    /// from the FIRST fragment, not from whichever one completes it.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn the_reassembled_header_comes_from_the_first_fragment(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);

        // The first fragment names the protocol and carries hop limit 64;
        // the last one lies about both.
        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0x22, 0, true, 64, &message[..40]);
        let last = fragment(
            LOCAL,
            IpProtocol::Unknown(0xfd),
            0x22,
            5,
            false,
            1,
            &message[40..],
        );

        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        // Still an echo reply: the ICMPv6 next header came from the first
        // fragment. Had the last one's `Unknown(0xfd)` been taken, this
        // would be an unrecognised-next-header parameter problem instead.
        expect_echo_reply(feed(&mut iface, &mut sockets, &last), &payload);
    }

    /// Two finals that disagree on where the datagram ends are an attack,
    /// not a retransmission: the slot is dropped rather than resized.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn finals_that_disagree_on_the_total_are_dropped(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0x33, 0, true, 64, &message[..40]);
        let short_last = fragment(LOCAL, IpProtocol::Icmpv6, 0x33, 5, false, 64, &message[40..56]);
        let real_last = fragment(LOCAL, IpProtocol::Icmpv6, 0x33, 5, false, 64, &message[40..]);

        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        assert!(feed(&mut iface, &mut sockets, &short_last).is_none());
        // The second final disagrees, so the slot is reset and this one
        // starts over rather than completing a datagram of two minds.
        assert!(
            feed(&mut iface, &mut sockets, &real_last).is_none(),
            "the disagreement dropped the partial datagram"
        );
    }

    /// RFC 4443 section 2.4: no ICMPv6 error for a packet sent to a
    /// multicast group, or one answer is multiplied by every member.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn a_refused_fragment_to_a_multicast_group_is_silent(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let group = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let data = [0u8; 12];
        let odd = fragment(group, IpProtocol::Icmpv6, 0x44, 0, true, 64, &data);
        assert!(
            feed(&mut iface, &mut sockets, &odd).is_none(),
            "discarded, and silently"
        );
    }
    /// RFC 5722: an overlapping fragment condemns the whole datagram, and
    /// silently — an ICMP answer would be a reflection sized by the sender.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn an_overlapping_fragment_drops_the_datagram(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0x55, 0, true, 64, &message[..40]);
        // Offset 32 reaches back into the octets the first fragment already
        // claimed: 32..40 belongs to both.
        let overlapping = fragment(LOCAL, IpProtocol::Icmpv6, 0x55, 4, true, 64, &message[32..48]);
        let last = fragment(LOCAL, IpProtocol::Icmpv6, 0x55, 5, false, 64, &message[40..]);

        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        assert!(
            feed(&mut iface, &mut sockets, &overlapping).is_none(),
            "the overlap is answered with nothing at all"
        );
        assert!(
            feed(&mut iface, &mut sockets, &last).is_none(),
            "the datagram went with it: the final fragment completes nothing"
        );
    }

    /// The strict reading, written down so the trade is visible: a fragment
    /// that repeats an earlier one exactly counts as an overlap, because
    /// telling a rewrite from a network duplicate would mean comparing
    /// payloads.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn an_exactly_repeated_fragment_counts_as_an_overlap(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0x66, 0, true, 64, &message[..40]);
        let last = fragment(LOCAL, IpProtocol::Icmpv6, 0x66, 5, false, 64, &message[40..]);

        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        assert!(feed(&mut iface, &mut sockets, &first.clone()).is_none());
        assert!(
            feed(&mut iface, &mut sockets, &last).is_none(),
            "the repeat dropped the datagram, so the final completes nothing"
        );
    }

    /// The bound is a local resource decision, so it is enforced quietly —
    /// the sender did nothing a protocol error could name.
    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn a_datagram_past_the_reassembly_bound_is_dropped(#[case] medium: Medium) {
        let (mut iface, mut sockets, _device) = setup(medium);
        let payload: Vec<u8> = (0..64u8).collect();
        let message = echo_request(&payload);
        assert_eq!(message.len(), 72);

        // Room for the head but not for the whole datagram.
        iface.set_reassembly_max_len(48);
        assert_eq!(iface.reassembly_max_len(), 48);

        let first = fragment(LOCAL, IpProtocol::Icmpv6, 0x77, 0, true, 64, &message[..40]);
        let last = fragment(LOCAL, IpProtocol::Icmpv6, 0x77, 5, false, 64, &message[40..]);

        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        assert!(
            feed(&mut iface, &mut sockets, &last).is_none(),
            "72 octets is past the bound, and nothing is said about it"
        );

        // Raised again, the same datagram reassembles: the bound was the
        // only thing standing in its way.
        iface.set_reassembly_max_len(65_535);
        assert!(feed(&mut iface, &mut sockets, &first).is_none());
        expect_echo_reply(feed(&mut iface, &mut sockets, &last), &payload);
    }
}
