use super::check;
use super::icmp_reply_payload_len;
use super::InterfaceInner;
use super::SocketSet;
use super::{IpPacket, IpPayload};

#[cfg(feature = "socket-icmp")]
use crate::socket::icmp;
use crate::socket::AnySocket;

use crate::iface::ip_packet::Ipv6Packet;
use crate::phy::PacketMeta;
use crate::wire::{Ipv6Packet as Ipv6PacketWire, *};

impl InterfaceInner {
    #[cfg(feature = "proto-ipv6")]
    pub(super) fn process_ipv6<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_packet: &Ipv6PacketWire<&'frame [u8]>,
    ) -> Option<IpPacket<'frame>> {
        let ipv6_repr = check!(Ipv6Repr::parse(ipv6_packet));
        let packet = check!(self.parse_ipv6(ipv6_repr, ipv6_packet.payload()));

        if !packet.header.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        if let Some(hbh) = &packet.hop_by_hop {
            self.process_hopbyhop(&packet.header, hbh)?;
        }

        #[cfg(feature = "proto-ipv6-routing")]
        if let Some(routing) = &packet.routing {
            self.process_routing(&packet.header, routing);
        }

        #[cfg(feature = "proto-ipv6-fragmentation")]
        if let Some(fragment) = &packet.fragment {
            self.process_fragment(&packet.header, fragment);
        }

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket =
            self.raw_socket_filter(sockets, &IpRepr::Ipv6(packet.header), ipv6_packet.payload());
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        match &packet.payload {
            #[cfg(feature = "socket-tcp")]
            IpPayload::Tcp(tcp) => self.process_tcp(sockets, IpRepr::Ipv6(ipv6_repr), tcp),
            #[cfg(feature = "socket-udp")]
            IpPayload::Udp(udp, data) => self.process_udp(
                sockets,
                meta,
                &IpRepr::Ipv6(packet.header),
                udp,
                false,
                data,
                ipv6_packet.payload(),
            ),
            IpPayload::Icmpv6(icmp) => self.process_icmpv6(sockets, &packet.header, icmp),
            _ if handled_by_raw_socket => None,
            _ => {
                // Send back as much of the original payload as we can.
                let payload_len = icmp_reply_payload_len(
                    ipv6_packet.payload().len(),
                    IPV6_MIN_MTU,
                    ipv6_repr.buffer_len(),
                );
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data: &ipv6_packet.payload()[0..payload_len],
                };
                self.icmpv6_reply(&ipv6_repr, &icmp_reply_repr)
            }
        }
    }

    fn parse_ipv6<'payload>(
        &self,
        header: Ipv6Repr,
        mut data: &'payload [u8],
    ) -> Result<Ipv6Packet<'payload>> {
        let mut packet = Ipv6Packet {
            header,
            hop_by_hop: None,
            #[cfg(feature = "proto-ipv6-routing")]
            routing: None,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            fragment: None,
            payload: IpPayload::Raw(data),
        };

        let mut next_header = Some(header.next_header);

        while let Some(nh) = next_header {
            match nh {
                IpProtocol::HopByHop => {
                    let ext_hdr = Ipv6ExtHeader::new_checked(data)?;
                    let ext_repr = Ipv6ExtHeaderRepr::parse(&ext_hdr)?;
                    let hbh_hdr = Ipv6HopByHopHeader::new_checked(ext_repr.data)?;
                    let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_hdr)?;

                    next_header = Some(ext_repr.next_header);
                    data = &data[ext_repr.header_len() + ext_repr.data.len()..];

                    packet.hop_by_hop = Some(hbh_repr);
                }
                #[cfg(feature = "proto-ipv6-routing")]
                IpProtocol::Ipv6Route => {
                    let ext_hdr = Ipv6ExtHeader::new_checked(data)?;
                    let ext_repr = Ipv6ExtHeaderRepr::parse(&ext_hdr)?;
                    let routing_hdr = Ipv6RoutingHeader::new_checked(ext_repr.data)?;
                    let routing_repr = Ipv6RoutingRepr::parse(&routing_hdr)?;

                    next_header = Some(ext_repr.next_header);
                    data = &data[ext_repr.header_len() + ext_repr.data.len()..];
                    packet.routing = Some(routing_repr);
                }
                #[cfg(feature = "proto-ipv6-fragmentation")]
                IpProtocol::Ipv6Frag => {
                    let ext_hdr = Ipv6ExtHeader::new_checked(data)?;
                    let ext_repr = Ipv6ExtHeaderRepr::parse(&ext_hdr)?;
                    let fragment_hdr = Ipv6FragmentHeader::new_checked(ext_repr.data)?;
                    let fragment_repr = Ipv6FragmentRepr::parse(&fragment_hdr)?;

                    next_header = Some(ext_repr.next_header);
                    data = &data[ext_repr.header_len() + ext_repr.data.len()..];
                    packet.fragment = Some(fragment_repr);
                }

                IpProtocol::Icmpv6 => {
                    let icmp_packet = Icmpv6Packet::new_checked(data)?;
                    let icmp_repr = Icmpv6Repr::parse(
                        &header.src_addr.into(),
                        &header.dst_addr.into(),
                        &icmp_packet,
                        &self.caps.checksum,
                    )?;

                    packet.payload = IpPayload::Icmpv6(icmp_repr);
                    break;
                }
                #[cfg(feature = "socket-tcp")]
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_checked(data)?;
                    let tcp_repr = TcpRepr::parse(
                        &tcp_packet,
                        &header.src_addr.into(),
                        &header.dst_addr.into(),
                        &self.caps.checksum,
                    )?;

                    packet.payload = IpPayload::Tcp(tcp_repr);
                    break;
                }
                #[cfg(feature = "socket-udp")]
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_checked(data)?;
                    let udp_repr = UdpRepr::parse(
                        &udp_packet,
                        &header.src_addr.into(),
                        &header.dst_addr.into(),
                        &self.checksum_caps(),
                    )?;

                    packet.payload = IpPayload::Udp(udp_repr, udp_packet.payload());
                    break;
                }

                _ => {
                    packet.payload = IpPayload::Raw(data);
                    break;
                }
            }
        }

        Ok(packet)
    }

    pub(super) fn process_icmpv6<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        header: &Ipv6Repr,
        icmp: &Icmpv6Repr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(feature = "socket-icmp")]
        for icmp_socket in _sockets
            .items_mut()
            .filter_map(|i| icmp::Socket::downcast_mut(&mut i.socket))
        {
            if icmp_socket.accepts(self, &IpRepr::Ipv6(*header), &IcmpRepr::Ipv6(*icmp)) {
                icmp_socket.process(self, &IpRepr::Ipv6(*header), &IcmpRepr::Ipv6(*icmp));
                handled_by_icmp_socket = true;
            }
        }

        match icmp {
            // Respond to echo requests.
            Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                let icmp_reply_repr = Icmpv6Repr::EchoReply {
                    ident: *ident,
                    seq_no: *seq_no,
                    data,
                };
                self.icmpv6_reply(header, &icmp_reply_repr)
            }

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => None,

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Repr::Ndisc(repr) if header.hop_limit == 0xff => self.process_ndisc(header, repr),

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => None,

            // FIXME: do something correct here?
            _ => None,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub(super) fn process_ndisc<'frame>(
        &mut self,
        ip_repr: &Ipv6Repr,
        repr: &NdiscRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        match repr {
            NdiscRepr::NeighborAdvert {
                lladdr,
                target_addr,
                flags,
            } => {
                let ip_addr = ip_repr.src_addr.into();
                if let Some(lladdr) = lladdr {
                    let lladdr = check!(lladdr.parse(self.caps.medium));
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return None;
                    }
                    if flags.contains(NdiscNeighborFlags::OVERRIDE)
                        || !self.neighbor_cache.lookup(&ip_addr, self.now).found()
                    {
                        self.neighbor_cache.fill(ip_addr, lladdr, self.now)
                    }
                }
                None
            }
            NdiscRepr::NeighborSolicit {
                target_addr,
                lladdr,
                ..
            } => {
                if let Some(lladdr) = lladdr {
                    let lladdr = check!(lladdr.parse(self.caps.medium));
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return None;
                    }
                    self.neighbor_cache
                        .fill(ip_repr.src_addr.into(), lladdr, self.now);
                }

                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(*target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: *target_addr,
                        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                        lladdr: Some(self.hardware_addr.into()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: *target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Some(IpPacket::new_ipv6(ip_repr, IpPayload::Icmpv6(advert)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(super) fn process_hopbyhop(
        &mut self,
        _ipv6_repr: &Ipv6Repr,
        hbh: &Ipv6HopByHopRepr,
    ) -> Option<()> {
        for opt_repr in &hbh.options {
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                #[cfg(feature = "proto-rpl")]
                Ipv6OptionRepr::Rpl(_) => {}

                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(*type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return None;
                        }
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return None;
                        }
                    }
                }
            }
        }

        Some(())
    }

    #[cfg(feature = "proto-ipv6-routing")]
    pub(super) fn process_routing<'frame>(
        &mut self,
        ipv6_repr: &Ipv6Repr,
        routing: &Ipv6RoutingRepr<'frame>,
    ) {
        match routing {
            Ipv6RoutingRepr::Type2 { .. } => {
                net_debug!("IPv6 Type2 routing header not supported yet");
            }
            Ipv6RoutingRepr::Rpl { .. } => {
                net_debug!("IPv6 Rpl routing header not supported yet");
            }
        }
    }

    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(super) fn process_fragment(&mut self, ipv6_repr: &ipv6repr, fragment: &ipv6fragmentrepr) {
        net_debug!("IPv6 Fragment header not supported yet");
    }

    pub(super) fn icmpv6_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv6_repr: &Ipv6Repr,
        icmp_repr: &Icmpv6Repr<'icmp>,
    ) -> Option<IpPacket<'frame>> {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr: ipv6_repr.dst_addr,
                dst_addr: ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(IpPacket::new_ipv6(
                ipv6_reply_repr,
                IpPayload::Icmpv6(*icmp_repr),
            ))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }
}
