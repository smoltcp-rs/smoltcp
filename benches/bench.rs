#![feature(test)]

mod wire {
    use test;
    #[cfg(feature = "proto-ipv6")]
    use smoltcp::wire::{Ipv6Address, Ipv6Repr, Ipv6Packet};
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::{Ipv4Address, Ipv4Repr, Ipv4Packet};
    use smoltcp::phy::{ChecksumCapabilities};
    use smoltcp::wire::{IpAddress, IpProtocol};
    use smoltcp::wire::{TcpRepr, TcpPacket, TcpSeqNumber, TcpControl};
    use smoltcp::wire::{UdpRepr, UdpPacket};

    #[cfg(feature = "proto-ipv6")]
    const SRC_ADDR: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                             0, 0, 0, 0, 0, 0, 0, 1]));
    #[cfg(feature = "proto-ipv6")]
    const DST_ADDR: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                             0, 0, 0, 0, 0, 0, 0, 2]));

    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    const SRC_ADDR: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1]));
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    const DST_ADDR: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 2]));

    #[bench]
    #[cfg(any(feature = "proto-ipv6", feature = "proto-ipv4"))]
    fn bench_emit_tcp(b: &mut test::Bencher) {
        static PAYLOAD_BYTES: [u8; 400] =
            [0x2a; 400];
        let repr = TcpRepr {
            src_port:     48896,
            dst_port:     80,
            seq_number:   TcpSeqNumber(0x01234567),
            ack_number:   None,
            window_len:   0x0123,
            control:      TcpControl::Syn,
            max_seg_size: None,
            window_scale: None,
            payload:      &PAYLOAD_BYTES
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = TcpPacket::new(&mut bytes);
            repr.emit(&mut packet, &SRC_ADDR, &DST_ADDR, &ChecksumCapabilities::default());
        });
    }

    #[bench]
    #[cfg(any(feature = "proto-ipv6", feature = "proto-ipv4"))]
    fn bench_emit_udp(b: &mut test::Bencher) {
        static PAYLOAD_BYTES: [u8; 400] =
            [0x2a; 400];
        let repr = UdpRepr {
            src_port: 48896,
            dst_port: 80,
            payload:  &PAYLOAD_BYTES
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = UdpPacket::new(&mut bytes);
            repr.emit(&mut packet, &SRC_ADDR, &DST_ADDR, &ChecksumCapabilities::default());
        });
    }

    #[bench]
    #[cfg(feature = "proto-ipv4")]
    fn bench_emit_ipv4(b: &mut test::Bencher) {
        let repr = Ipv4Repr {
            src_addr:    Ipv4Address([192, 168, 1, 1]),
            dst_addr:    Ipv4Address([192, 168, 1, 2]),
            protocol:    IpProtocol::Tcp,
            payload_len: 100,
            hop_limit:   64
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = Ipv4Packet::new(&mut bytes);
            repr.emit(&mut packet, &ChecksumCapabilities::default());
        });
    }

    #[bench]
    #[cfg(feature = "proto-ipv6")]
    fn bench_emit_ipv6(b: &mut test::Bencher) {
        let repr = Ipv6Repr {
            src_addr:    Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1]),
            dst_addr:    Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 2]),
            next_header: IpProtocol::Tcp,
            payload_len: 100,
            hop_limit:   64
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = Ipv6Packet::new(&mut bytes);
            repr.emit(&mut packet);
        });
    }
}
