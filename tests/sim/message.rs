use super::Position;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::*;
use smoltcp::wire::*;

#[derive(Debug, Clone)]
pub struct Message {
    pub at: Instant,
    pub to: Ieee802154Address,
    pub from: (usize, Position),
    pub data: Vec<u8>,
}

impl Message {
    pub fn is_broadcast(&self) -> bool {
        self.to == Ieee802154Address::BROADCAST
    }

    pub fn udp(&self) -> Option<SixlowpanUdpNhcRepr> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data).unwrap();
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().unwrap()).unwrap();
        let src_addr = lowpan
            .src_addr()
            .unwrap()
            .resolve(ieee802154.src_addr(), &[])
            .unwrap();
        let dst_addr = lowpan
            .dst_addr()
            .unwrap()
            .resolve(ieee802154.src_addr(), &[])
            .unwrap();

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();
        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => {
                    match SixlowpanNhcPacket::dispatch(payload).unwrap() {
                        SixlowpanNhcPacket::ExtHeader => {
                            let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload).unwrap();
                            next_hdr = ext_hdr.next_header();
                            payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                            continue;
                        }
                        SixlowpanNhcPacket::UdpHeader => {
                            let udp = SixlowpanUdpNhcPacket::new_checked(payload).unwrap();
                            return Some(
                                SixlowpanUdpNhcRepr::parse(
                                    &udp,
                                    &src_addr,
                                    &dst_addr,
                                    &ChecksumCapabilities::ignored(),
                                )
                                .unwrap(),
                            );
                        }
                    }
                }
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => return None,
                _ => unreachable!(),
            };
        }
    }

    pub fn icmp(&self) -> Option<Icmpv6Repr<'_>> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data).unwrap();
        let lowpan =
            SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error).unwrap()).unwrap();
        let src_addr = lowpan
            .src_addr()
            .unwrap()
            .resolve(ieee802154.src_addr(), &[])
            .unwrap();
        let dst_addr = lowpan
            .dst_addr()
            .unwrap()
            .resolve(ieee802154.src_addr(), &[])
            .unwrap();

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();
        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => {
                    match SixlowpanNhcPacket::dispatch(payload).unwrap() {
                        SixlowpanNhcPacket::ExtHeader => {
                            let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload).unwrap();
                            next_hdr = ext_hdr.next_header();
                            payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                            continue;
                        }
                        SixlowpanNhcPacket::UdpHeader => return None,
                    }
                }
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    let icmp = Icmpv6Packet::new_checked(payload).unwrap();

                    return Some(
                        Icmpv6Repr::parse(
                            &src_addr,
                            &dst_addr,
                            &icmp,
                            &ChecksumCapabilities::ignored(),
                        )
                        .unwrap(),
                    );
                }
                _ => unreachable!(),
            };
        }
    }

    pub fn has_routing(&self) -> bool {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data).unwrap();
        let lowpan =
            SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error).unwrap()).unwrap();

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();

        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)
                    .unwrap()
                {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload).unwrap();
                        if ext_hdr.extension_header_id() == SixlowpanExtHeaderId::RoutingHeader {
                            return true;
                        }
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => return false,
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    return false;
                }
                _ => unreachable!(),
            };
        }
    }

    pub fn has_hbh(&self) -> bool {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data).unwrap();
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().unwrap()).unwrap();

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();

        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)
                    .unwrap()
                {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload).unwrap();
                        if ext_hdr.extension_header_id() == SixlowpanExtHeaderId::HopByHopHeader {
                            return true;
                        }
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => return false,
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    return false;
                }
                _ => unreachable!(),
            };
        }
    }

    pub fn is_udp(&self) -> bool {
        matches!(self.udp(), Some(SixlowpanUdpNhcRepr(_)))
    }

    pub fn is_dis(&self) -> bool {
        matches!(
            self.icmp(),
            Some(Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation(_)))
        )
    }

    pub fn is_dio(&self) -> bool {
        matches!(
            self.icmp(),
            Some(Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(_)))
        )
    }

    pub fn is_dao(&self) -> bool {
        matches!(
            self.icmp(),
            Some(Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(_)))
        )
    }

    pub fn is_dao_ack(&self) -> bool {
        matches!(
            self.icmp(),
            Some(Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObjectAck(
                _
            )))
        )
    }
}
