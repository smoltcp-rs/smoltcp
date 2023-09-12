use super::*;

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn ieee802154_wrong_pan_id(#[case] medium: Medium) {
    let data = [
        0x41, 0xcc, 0x3b, 0xff, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0x62, 0x3a,
        0xa6, 0x34, 0x57, 0x29, 0x1c, 0x26,
    ];

    let response = Ok(None);

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ieee802154(
            &mut sockets,
            PacketMeta::default(),
            &data[..],
            &mut iface.fragments
        ),
        response,
    );
}

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn icmp_echo_request(#[case] medium: Medium) {
    let data = [
        0x41, 0xcc, 0x3b, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0x62, 0x3a,
        0xa6, 0x34, 0x57, 0x29, 0x1c, 0x26, 0x6a, 0x33, 0x0a, 0x62, 0x17, 0x3a, 0x80, 0x00, 0xb0,
        0xe3, 0x00, 0x04, 0x00, 0x01, 0x82, 0xf2, 0x82, 0x64, 0x00, 0x00, 0x00, 0x00, 0x66, 0x23,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37,
    ];

    let response = Ok(Some(IpPacket::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242]),
            dst_addr: Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0x241c, 0x2957, 0x34a6, 0x3a62]),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 4,
            seq_no: 1,
            data: &[
                0x82, 0xf2, 0x82, 0x64, 0x00, 0x00, 0x00, 0x00, 0x66, 0x23, 0x0c, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            ],
        }),
    )));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ieee802154(
            &mut sockets,
            PacketMeta::default(),
            &data[..],
            &mut iface.fragments
        ),
        response,
    );
}

#[test]
#[cfg(feature = "proto-sixlowpan-fragmentation")]
fn test_echo_request_sixlowpan_128_bytes() {
    use crate::phy::Checksum;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ieee802154);
    // TODO: modify the example, such that we can also test if the checksum is correctly
    // computed.
    iface.inner.caps.checksum.icmpv6 = Checksum::None;

    assert_eq!(iface.inner.caps.medium, Medium::Ieee802154);
    let now = iface.inner.now();

    iface.inner.neighbor_cache.fill(
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
        &iface.inner.sixlowpan_address_context,
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
            PacketMeta::default(),
            &ieee802154_repr,
            &request_first_part_packet.into_inner()[..],
            &mut iface.fragments
        ),
        Ok(None),
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
        PacketMeta::default(),
        &ieee802154_repr,
        &request_second_part,
        &mut iface.fragments,
    );

    assert_eq!(
        result,
        Ok(Some(IpPacket::new_ipv6(
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
            IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
                ident: 39,
                seq_no: 2,
                data,
            })
        )))
    );

    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv6(Ipv6Address([
            0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0xb, 0x1a,
        ])),
        HardwareAddress::Ieee802154(Ieee802154Address::default()),
        Instant::now(),
    );

    let tx_token = device.transmit(Instant::now()).unwrap();
    iface.inner.dispatch_ieee802154(
        Ieee802154Address::default(),
        tx_token,
        PacketMeta::default(),
        result.unwrap().unwrap(),
        &mut iface.fragmenter,
    );

    assert_eq!(
        device.queue.pop_front().unwrap(),
        &[
            0x41, 0xcc, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0xc0, 0xb0, 0x5, 0x4e, 0x7a, 0x11, 0x3a, 0x92, 0xfc, 0x48, 0xc2,
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
        device.queue.pop_front().unwrap(),
        &[
            0x41, 0xcc, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0xe0, 0xb0, 0x5, 0x4e, 0xf, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
            0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        ]
    );
}

#[test]
#[cfg(feature = "proto-sixlowpan-fragmentation")]
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

    let (mut iface, mut sockets, mut device) = setup(Medium::Ieee802154);
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
            PacketMeta::default(),
            &ieee802154_repr,
            udp_first_part,
            &mut iface.fragments
        ),
        Ok(None)
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
            PacketMeta::default(),
            &ieee802154_repr,
            udp_second_part,
            &mut iface.fragments
        ),
        Ok(None)
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
            .into()
        ))
    );

    let tx_token = device.transmit(Instant::now()).unwrap();
    iface.inner.dispatch_ieee802154(
        Ieee802154Address::default(),
        tx_token,
        PacketMeta::default(),
        IpPacket::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::default(),
                dst_addr: Ipv6Address::default(),
                next_header: IpProtocol::Udp,
                payload_len: udp_data.len(),
                hop_limit: 64,
            },
            IpPayload::Udp(
                UdpRepr {
                    src_port: 1234,
                    dst_port: 1234,
                },
                udp_data,
            ),
        ),
        &mut iface.fragmenter,
    );

    iface.poll(Instant::now(), &mut device, &mut sockets);

    assert_eq!(
        device.queue.pop_front().unwrap(),
        &[
            0x41, 0xcc, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0xc0, 0xb4, 0x5, 0x4e, 0x7e, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf0, 0x4, 0xd2, 0x4, 0xd2, 0x0, 0x0,
            0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f,
            0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20,
            0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64,
            0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e,
            0x20, 0x49, 0x6e, 0x20, 0x61, 0x74, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73,
            0x20, 0x74,
        ],
    );

    assert_eq!(
        device.queue.pop_front().unwrap(),
        &[
            0x41, 0xcc, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0xe0, 0xb4, 0x5, 0x4e, 0xf, 0x6f, 0x72, 0x74, 0x6f, 0x72, 0x2e,
            0x20, 0x43, 0x72, 0x61, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x6e, 0x64, 0x69, 0x74, 0x20,
            0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x64, 0x69, 0x61, 0x6d, 0x2c, 0x20, 0x76,
            0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x76, 0x65, 0x73, 0x74, 0x69, 0x62, 0x75, 0x6c,
            0x75, 0x6d, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64,
            0x6f, 0x20, 0x6e, 0x65, 0x63, 0x2e,
        ]
    );
}
