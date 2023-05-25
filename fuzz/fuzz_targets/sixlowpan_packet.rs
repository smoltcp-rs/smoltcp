#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::{phy::ChecksumCapabilities, wire::*};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, arbitrary::Arbitrary)]
pub enum AddressFuzzer {
    Absent,
    Short([u8; 2]),
    Extended([u8; 8]),
}

impl From<AddressFuzzer> for Ieee802154Address {
    fn from(val: AddressFuzzer) -> Self {
        match val {
            AddressFuzzer::Absent => Ieee802154Address::Absent,
            AddressFuzzer::Short(b) => Ieee802154Address::Short(b),
            AddressFuzzer::Extended(b) => Ieee802154Address::Extended(b),
        }
    }
}

#[derive(Debug, arbitrary::Arbitrary)]
struct SixlowpanPacketFuzzer<'a> {
    data: &'a [u8],
    ll_src_addr: Option<AddressFuzzer>,
    ll_dst_addr: Option<AddressFuzzer>,
}

fuzz_target!(|fuzz: SixlowpanPacketFuzzer| {
    match SixlowpanPacket::dispatch(fuzz.data) {
        Ok(SixlowpanPacket::FragmentHeader) => {
            if let Ok(frame) = SixlowpanFragPacket::new_checked(fuzz.data) {
                if let Ok(repr) = SixlowpanFragRepr::parse(&frame) {
                    let mut buffer = vec![0; repr.buffer_len()];
                    let mut frame = SixlowpanFragPacket::new_unchecked(&mut buffer[..]);
                    repr.emit(&mut frame);
                }
            }
        }
        Ok(SixlowpanPacket::IphcHeader) => {
            if let Ok(frame) = SixlowpanIphcPacket::new_checked(fuzz.data) {
                if let Ok(iphc_repr) = SixlowpanIphcRepr::parse(
                    &frame,
                    fuzz.ll_src_addr.map(Into::into),
                    fuzz.ll_dst_addr.map(Into::into),
                    &[],
                ) {
                    let mut buffer = vec![0; iphc_repr.buffer_len()];
                    let mut iphc_frame = SixlowpanIphcPacket::new_unchecked(&mut buffer[..]);
                    iphc_repr.emit(&mut iphc_frame);

                    let payload = frame.payload();
                    match iphc_repr.next_header {
                        SixlowpanNextHeader::Compressed => {
                            if let Ok(p) = SixlowpanNhcPacket::dispatch(payload) {
                                match p {
                                    SixlowpanNhcPacket::ExtHeader => {
                                        if let Ok(frame) =
                                            SixlowpanExtHeaderPacket::new_checked(payload)
                                        {
                                            if let Ok(repr) = SixlowpanExtHeaderRepr::parse(&frame)
                                            {
                                                let mut buffer = vec![0; repr.buffer_len()];
                                                let mut ext_header_frame =
                                                    SixlowpanExtHeaderPacket::new_unchecked(
                                                        &mut buffer[..],
                                                    );
                                                repr.emit(&mut ext_header_frame);
                                            }
                                        }
                                    }
                                    SixlowpanNhcPacket::UdpHeader => {
                                        if let Ok(frame) =
                                            SixlowpanUdpNhcPacket::new_checked(payload)
                                        {
                                            if let Ok(repr) = SixlowpanUdpNhcRepr::parse(
                                                &frame,
                                                &iphc_repr.src_addr,
                                                &iphc_repr.dst_addr,
                                                &Default::default(),
                                            ) {
                                                let mut buffer = vec![
                                                    0;
                                                    repr.header_len()
                                                        + frame.payload().len()
                                                ];
                                                let mut udp_packet =
                                                    SixlowpanUdpNhcPacket::new_unchecked(
                                                        &mut buffer[..],
                                                    );
                                                repr.emit(
                                                    &mut udp_packet,
                                                    &iphc_repr.src_addr,
                                                    &iphc_repr.dst_addr,
                                                    frame.payload().len(),
                                                    |b| b.copy_from_slice(frame.payload()),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        SixlowpanNextHeader::Uncompressed(proto) => match proto {
                            IpProtocol::HopByHop => {
                                if let Ok(frame) = Ipv6HopByHopHeader::new_checked(payload) {
                                    if let Ok(repr) = Ipv6HopByHopRepr::parse(&frame) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut hop_by_hop_frame =
                                            Ipv6HopByHopHeader::new_unchecked(&mut buffer[..]);
                                        repr.emit(&mut hop_by_hop_frame);
                                    }
                                }
                            }
                            IpProtocol::Icmp => {
                                if let Ok(frame) = Icmpv4Packet::new_checked(payload) {
                                    if let Ok(repr) =
                                        Icmpv4Repr::parse(&frame, &ChecksumCapabilities::default())
                                    {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut icmpv4_packet =
                                            Icmpv4Packet::new_unchecked(&mut buffer[..]);
                                        repr.emit(
                                            &mut icmpv4_packet,
                                            &ChecksumCapabilities::default(),
                                        );
                                    }
                                }
                            }
                            IpProtocol::Igmp => {
                                if let Ok(frame) = IgmpPacket::new_checked(payload) {
                                    if let Ok(repr) = IgmpRepr::parse(&frame) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut frame = IgmpPacket::new_unchecked(&mut buffer[..]);
                                        repr.emit(&mut frame);
                                    }
                                }
                            }
                            IpProtocol::Tcp => {
                                if let Ok(frame) = TcpPacket::new_checked(payload) {
                                    if let Ok(repr) = TcpRepr::parse(
                                        &frame,
                                        &iphc_repr.src_addr.into_address(),
                                        &iphc_repr.dst_addr.into_address(),
                                        &ChecksumCapabilities::default(),
                                    ) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut frame = TcpPacket::new_unchecked(&mut buffer[..]);
                                        repr.emit(
                                            &mut frame,
                                            &iphc_repr.src_addr.into_address(),
                                            &iphc_repr.dst_addr.into_address(),
                                            &ChecksumCapabilities::default(),
                                        );
                                    }
                                }
                            }
                            IpProtocol::Udp => {
                                if let Ok(frame) = UdpPacket::new_checked(payload) {
                                    if let Ok(repr) = UdpRepr::parse(
                                        &frame,
                                        &iphc_repr.src_addr.into_address(),
                                        &iphc_repr.dst_addr.into_address(),
                                        &ChecksumCapabilities::default(),
                                    ) {
                                        let mut buffer =
                                            vec![0; repr.header_len() + frame.payload().len()];
                                        let mut packet = UdpPacket::new_unchecked(&mut buffer[..]);
                                        repr.emit(
                                            &mut packet,
                                            &iphc_repr.src_addr.into_address(),
                                            &iphc_repr.dst_addr.into_address(),
                                            frame.payload().len(),
                                            |b| b.copy_from_slice(frame.payload()),
                                            &ChecksumCapabilities::default(),
                                        );
                                    }
                                }
                            }
                            IpProtocol::Ipv6Route => {
                                if let Ok(frame) = Ipv6RoutingHeader::new_checked(payload) {
                                    if let Ok(repr) = Ipv6RoutingRepr::parse(&frame) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut packet = Ipv6RoutingHeader::new(&mut buffer[..]);
                                        repr.emit(&mut packet);
                                    }
                                }
                            }
                            IpProtocol::Ipv6Frag => {
                                if let Ok(frame) = Ipv6FragmentHeader::new_checked(payload) {
                                    if let Ok(repr) = Ipv6FragmentRepr::parse(&frame) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut frame =
                                            Ipv6FragmentHeader::new_unchecked(&mut buffer[..]);
                                        repr.emit(&mut frame);
                                    }
                                }
                            }
                            IpProtocol::Icmpv6 => {
                                if let Ok(packet) = Icmpv6Packet::new_checked(payload) {
                                    if let Ok(repr) = Icmpv6Repr::parse(
                                        &iphc_repr.src_addr.into_address(),
                                        &iphc_repr.dst_addr.into_address(),
                                        &packet,
                                        &ChecksumCapabilities::default(),
                                    ) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut packet =
                                            Icmpv6Packet::new_unchecked(&mut buffer[..]);
                                        repr.emit(
                                            &iphc_repr.src_addr.into_address(),
                                            &iphc_repr.dst_addr.into_address(),
                                            &mut packet,
                                            &ChecksumCapabilities::default(),
                                        );
                                    }
                                }
                            }
                            IpProtocol::Ipv6NoNxt => (),
                            IpProtocol::Ipv6Opts => {
                                if let Ok(packet) = Ipv6Option::new_checked(payload) {
                                    if let Ok(repr) = Ipv6OptionRepr::parse(&packet) {
                                        let mut buffer = vec![0; repr.buffer_len()];
                                        let mut packet = Ipv6Option::new_unchecked(&mut buffer[..]);
                                        repr.emit(&mut packet);
                                    }
                                }
                            }
                            IpProtocol::Unknown(_) => (),
                        },
                    };

                    let mut buffer = vec![0; iphc_repr.buffer_len()];

                    let mut frame = SixlowpanIphcPacket::new_unchecked(&mut buffer[..]);
                    iphc_repr.emit(&mut frame);
                }
            };
        }
        Err(_) => (),
    }
});
