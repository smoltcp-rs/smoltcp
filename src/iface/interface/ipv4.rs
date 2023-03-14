use super::*;

#[cfg(feature = "socket-dhcpv4")]
use crate::socket::dhcpv4;
#[cfg(feature = "socket-icmp")]
use crate::socket::icmp;
use crate::socket::AnySocket;

use crate::phy::{Medium, TxToken};
use crate::time::Instant;
use crate::wire::*;

impl InterfaceInner {
    pub(super) fn process_ipv4<'a, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv4_packet: &Ipv4Packet<&'a T>,
        frag: &'a mut FragmentsBuffer,
    ) -> Option<IpPacket<'a>> {
        let ipv4_repr = check!(Ipv4Repr::parse(ipv4_packet, &self.caps.checksum));
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ip_payload = {
            if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
                let key = FragKey::Ipv4(ipv4_packet.get_key());

                let f = match frag.assembler.get(&key, self.now + frag.reassembly_timeout) {
                    Ok(f) => f,
                    Err(_) => {
                        net_debug!("No available packet assembler for fragmented packet");
                        return None;
                    }
                };

                if !ipv4_packet.more_frags() {
                    // This is the last fragment, so we know the total size
                    check!(f.set_total_size(
                        ipv4_packet.total_len() as usize - ipv4_packet.header_len() as usize
                            + ipv4_packet.frag_offset() as usize,
                    ));
                }

                if let Err(e) = f.add(ipv4_packet.payload(), ipv4_packet.frag_offset() as usize) {
                    net_debug!("fragmentation error: {:?}", e);
                    return None;
                }

                // NOTE: according to the standard, the total length needs to be
                // recomputed, as well as the checksum. However, we don't really use
                // the IPv4 header after the packet is reassembled.
                match f.assemble() {
                    Some(payload) => payload,
                    None => return None,
                }
            } else {
                ipv4_packet.payload()
            }
        };

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let ip_payload = ipv4_packet.payload();

        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        #[cfg(feature = "socket-dhcpv4")]
        {
            if ipv4_repr.next_header == IpProtocol::Udp && self.hardware_addr.is_some() {
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                if let Some(dhcp_socket) = sockets
                    .items_mut()
                    .find_map(|i| dhcpv4::Socket::downcast_mut(&mut i.socket))
                {
                    // First check for source and dest ports, then do `UdpRepr::parse` if they match.
                    // This way we avoid validating the UDP checksum twice for all non-DHCP UDP packets (one here, one in `process_udp`)
                    if udp_packet.src_port() == dhcp_socket.server_port
                        && udp_packet.dst_port() == dhcp_socket.client_port
                    {
                        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
                        let udp_repr = check!(UdpRepr::parse(
                            &udp_packet,
                            &src_addr,
                            &dst_addr,
                            &self.caps.checksum
                        ));
                        let udp_payload = udp_packet.payload();

                        dhcp_socket.process(self, &ipv4_repr, &udp_repr, udp_payload);
                        return None;
                    }
                }
            }
        }

        if !self.has_ip_addr(ipv4_repr.dst_addr)
            && !self.has_multicast_group(ipv4_repr.dst_addr)
            && !self.is_broadcast_v4(ipv4_repr.dst_addr)
        {
            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.any_ip
                || !ipv4_repr.dst_addr.is_unicast()
                || self
                    .routes
                    .lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), self.now)
                    .map_or(true, |router_addr| !self.has_ip_addr(router_addr))
            {
                return None;
            }
        }

        match ipv4_repr.next_header {
            IpProtocol::Icmp => self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "proto-igmp")]
            IpProtocol::Igmp => self.process_igmp(ipv4_repr, ip_payload),

            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpProtocol::Udp => {
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                let udp_repr = check!(UdpRepr::parse(
                    &udp_packet,
                    &ipv4_repr.src_addr.into(),
                    &ipv4_repr.dst_addr.into(),
                    &self.checksum_caps(),
                ));

                self.process_udp(
                    sockets,
                    ip_repr,
                    udp_repr,
                    handled_by_raw_socket,
                    udp_packet.payload(),
                    ip_payload,
                )
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ip_repr, ip_payload),

            _ if handled_by_raw_socket => None,

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv4_reply(ipv4_repr, icmp_reply_repr)
            }
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_arp<'frame, T: AsRef<[u8]>>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame T>,
    ) -> Option<EthernetPacket<'frame>> {
        let arp_packet = check!(ArpPacket::new_checked(eth_frame.payload()));
        let arp_repr = check!(ArpRepr::parse(&arp_packet));

        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Only process ARP packets for us.
                if !self.has_ip_addr(target_protocol_addr) {
                    return None;
                }

                // Only process REQUEST and RESPONSE.
                if let ArpOperation::Unknown(_) = operation {
                    net_debug!("arp: unknown operation code");
                    return None;
                }

                // Discard packets with non-unicast source addresses.
                if !source_protocol_addr.is_unicast() || !source_hardware_addr.is_unicast() {
                    net_debug!("arp: non-unicast source address");
                    return None;
                }

                if !self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
                    net_debug!("arp: source IP address not in same network as us");
                    return None;
                }

                // Fill the ARP cache from any ARP packet aimed at us (both request or response).
                // We fill from requests too because if someone is requesting our address they
                // are probably going to talk to us, so we avoid having to request their address
                // when we later reply to them.
                self.neighbor_cache.as_mut().unwrap().fill(
                    source_protocol_addr.into(),
                    source_hardware_addr.into(),
                    timestamp,
                );

                if operation == ArpOperation::Request {
                    let src_hardware_addr = match self.hardware_addr {
                        Some(HardwareAddress::Ethernet(addr)) => addr,
                        _ => unreachable!(),
                    };

                    Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub(super) fn process_icmpv4<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let icmp_packet = check!(Icmpv4Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv4Repr::parse(&icmp_packet, &self.caps.checksum));

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
        for icmp_socket in _sockets
            .items_mut()
            .filter_map(|i| icmp::Socket::downcast_mut(&mut i.socket))
        {
            if icmp_socket.accepts(self, &ip_repr, &icmp_repr.into()) {
                icmp_socket.process(self, &ip_repr, &icmp_repr.into());
                handled_by_icmp_socket = true;
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            #[cfg(feature = "proto-ipv4")]
            Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                match ip_repr {
                    IpRepr::Ipv4(ipv4_repr) => self.icmpv4_reply(ipv4_repr, icmp_reply_repr),
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => None,

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => None,

            // FIXME: do something correct here?
            _ => None,
        }
    }

    pub(super) fn icmpv4_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv4_repr: Ipv4Repr,
        icmp_repr: Icmpv4Repr<'icmp>,
    ) -> Option<IpPacket<'frame>> {
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if self.is_unicast_v4(ipv4_repr.dst_addr) {
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr: ipv4_repr.dst_addr,
                dst_addr: ipv4_repr.src_addr,
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            let mut headers = heapless::Vec::new();
            headers.push(IpHeader::Icmpv4(icmp_repr)).unwrap();
            Some(IpPacket {
                hdr: IpRepr::Ipv4(ipv4_reply_repr),
                headers,
            })
        } else if self.is_broadcast_v4(ipv4_repr.dst_addr) {
            // Only reply to broadcasts for echo replies and not other ICMP messages
            match icmp_repr {
                Icmpv4Repr::EchoReply { .. } => match self.ipv4_addr() {
                    Some(src_addr) => {
                        let ipv4_reply_repr = Ipv4Repr {
                            src_addr,
                            dst_addr: ipv4_repr.src_addr,
                            next_header: IpProtocol::Icmp,
                            payload_len: icmp_repr.buffer_len(),
                            hop_limit: 64,
                        };
                        let mut headers = heapless::Vec::new();
                        headers.push(IpHeader::Icmpv4(icmp_repr)).unwrap();
                        Some(IpPacket {
                            hdr: IpRepr::Ipv4(ipv4_reply_repr),
                            headers,
                        })
                    }
                    None => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(super) fn dispatch_ipv4_frag<Tx: TxToken>(&mut self, tx_token: Tx, frag: &mut Fragmenter) {
        let caps = self.caps.clone();

        let mtu_max = self.ip_mtu();
        let ip_len = (frag.packet_len - frag.sent_bytes + frag.ipv4.repr.buffer_len()).min(mtu_max);
        let payload_len = ip_len - frag.ipv4.repr.buffer_len();

        let more_frags = (frag.packet_len - frag.sent_bytes) != payload_len;
        frag.ipv4.repr.payload_len = payload_len;
        frag.sent_bytes += payload_len;

        let mut tx_len = ip_len;
        #[cfg(feature = "medium-ethernet")]
        if matches!(caps.medium, Medium::Ethernet) {
            tx_len += EthernetFrame::<&[u8]>::header_len();
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.unwrap().ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(frag.ipv4.dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }
        };

        tx_token.consume(tx_len, |mut tx_buffer| {
            #[cfg(feature = "medium-ethernet")]
            if matches!(self.caps.medium, Medium::Ethernet) {
                emit_ethernet(&IpRepr::Ipv4(frag.ipv4.repr), tx_buffer);
                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
            }

            let mut packet =
                Ipv4Packet::new_unchecked(&mut tx_buffer[..frag.ipv4.repr.buffer_len()]);
            frag.ipv4.repr.emit(&mut packet, &caps.checksum);
            packet.set_ident(frag.ipv4.ident);
            packet.set_more_frags(more_frags);
            packet.set_dont_frag(false);
            packet.set_frag_offset(frag.ipv4.frag_offset);

            if caps.checksum.ipv4.tx() {
                packet.fill_checksum();
            }

            tx_buffer[frag.ipv4.repr.buffer_len()..][..payload_len].copy_from_slice(
                &frag.buffer[frag.ipv4.frag_offset as usize + frag.ipv4.repr.buffer_len()..]
                    [..payload_len],
            );

            // Update the frag offset for the next fragment.
            frag.ipv4.frag_offset += payload_len as u16;
        })
    }

    #[cfg(feature = "proto-igmp")]
    pub(super) fn igmp_report_packet<'any>(
        &self,
        version: IgmpVersion,
        group_addr: Ipv4Address,
    ) -> Option<IpPacket<'any>> {
        let iface_addr = self.ipv4_addr()?;
        let igmp_repr = IgmpRepr::MembershipReport {
            group_addr,
            version,
        };
        let payload_len = igmp_repr.buffer_len();
        let mut headers = heapless::Vec::new();
        headers.push(IpHeader::Igmp(igmp_repr)).unwrap();

        let pkt = IpPacket {
            hdr: IpRepr::Ipv4(Ipv4Repr {
                src_addr: iface_addr,
                // Send to the group being reported
                dst_addr: group_addr,
                next_header: IpProtocol::Igmp,
                payload_len,
                hop_limit: 1,
                // [#183](https://github.com/m-labs/smoltcp/issues/183).
            }),
            headers,
        };
        Some(pkt)
    }

    #[cfg(feature = "proto-igmp")]
    pub(super) fn igmp_leave_packet<'any>(
        &self,
        group_addr: Ipv4Address,
    ) -> Option<IpPacket<'any>> {
        self.ipv4_addr().map(|iface_addr| {
            let igmp_repr = IgmpRepr::LeaveGroup { group_addr };

            let payload_len = igmp_repr.buffer_len();
            let mut headers = heapless::Vec::new();
            headers.push(IpHeader::Igmp(igmp_repr)).unwrap();

            IpPacket {
                hdr: IpRepr::Ipv4(Ipv4Repr {
                    src_addr: iface_addr,
                    dst_addr: Ipv4Address::MULTICAST_ALL_ROUTERS,
                    next_header: IpProtocol::Igmp,
                    payload_len,
                    hop_limit: 1,
                }),
                headers,
            }
        })
    }
}
