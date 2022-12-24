use super::check;
use super::icmp_reply_payload_len;
use super::InterfaceInner;
use super::IpPacket;
use super::PacketAssemblerSet;
use super::SocketSet;

#[cfg(feature = "proto-igmp")]
use super::IgmpReportState;

#[cfg(feature = "medium-ethernet")]
use super::EthernetPacket;

#[cfg(feature = "proto-ipv4-fragmentation")]
use super::Ipv4OutPacket;

#[cfg(feature = "socket-dhcpv4")]
use crate::socket::dhcpv4;
#[cfg(feature = "socket-icmp")]
use crate::socket::icmp;
use crate::socket::AnySocket;

use crate::phy::{Medium, TxToken};
use crate::{time::*, wire::*, Error, Result};

impl<'a> InterfaceInner<'a> {
    pub(super) fn process_ipv4<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv4_packet: &Ipv4Packet<&'payload T>,
        _fragments: Option<&'output mut PacketAssemblerSet<'a, Ipv4FragKey>>,
    ) -> Option<IpPacket<'output>> {
        let ipv4_repr = check!(Ipv4Repr::parse(ipv4_packet, &self.caps.checksum));
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ip_payload = {
            const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(90);

            let fragments = _fragments.unwrap();

            if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
                let key = ipv4_packet.get_key();

                let f = match fragments.get_packet_assembler_mut(&key) {
                    Ok(f) => f,
                    Err(_) => {
                        let p = match fragments.reserve_with_key(&key) {
                            Ok(p) => p,
                            Err(Error::PacketAssemblerSetFull) => {
                                net_debug!("No available packet assembler for fragmented packet");
                                return Default::default();
                            }
                            e => check!(e),
                        };

                        check!(p.start(None, self.now + REASSEMBLY_TIMEOUT, 0));

                        check!(fragments.get_packet_assembler_mut(&key))
                    }
                };

                if !ipv4_packet.more_frags() {
                    // This is the last fragment, so we know the total size
                    check!(f.set_total_size(
                        ipv4_packet.total_len() as usize - ipv4_packet.header_len() as usize
                            + ipv4_packet.frag_offset() as usize,
                    ));
                }

                match f.add(ipv4_packet.payload(), ipv4_packet.frag_offset() as usize) {
                    Ok(true) => {
                        // NOTE: according to the standard, the total length needs to be
                        // recomputed, as well as the checksum. However, we don't really use
                        // the IPv4 header after the packet is reassembled.
                        check!(fragments.get_assembled_packet(&key))
                    }
                    Ok(false) => {
                        return None;
                    }
                    Err(e) => {
                        net_debug!("fragmentation error: {}", e);
                        return None;
                    }
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
                // First check for source and dest ports, then do `UdpRepr::parse` if they match.
                // This way we avoid validating the UDP checksum twice for all non-DHCP UDP packets (one here, one in `process_udp`)
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                if udp_packet.src_port() == DHCP_SERVER_PORT
                    && udp_packet.dst_port() == DHCP_CLIENT_PORT
                {
                    if let Some(dhcp_socket) = sockets
                        .items_mut()
                        .find_map(|i| dhcpv4::Socket::downcast_mut(&mut i.socket))
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

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    #[cfg(feature = "proto-igmp")]
    pub(super) fn process_igmp<'frame>(
        &mut self,
        ipv4_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let igmp_packet = check!(IgmpPacket::new_checked(ip_payload));
        let igmp_repr = check!(IgmpRepr::parse(&igmp_packet));

        // FIXME: report membership after a delay
        match igmp_repr {
            IgmpRepr::MembershipQuery {
                group_addr,
                version,
                max_resp_time,
            } => {
                // General query
                if group_addr.is_unspecified()
                    && ipv4_repr.dst_addr == Ipv4Address::MULTICAST_ALL_SYSTEMS
                {
                    // Are we member in any groups?
                    if self.ipv4_multicast_groups.iter().next().is_some() {
                        let interval = match version {
                            IgmpVersion::Version1 => Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = self.ipv4_multicast_groups.len() as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: self.now + interval,
                            interval,
                            next_index: 0,
                        };
                    }
                } else {
                    // Group-specific query
                    if self.has_multicast_group(group_addr) && ipv4_repr.dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version,
                            timeout: self.now + timeout,
                            group: group_addr,
                        };
                    }
                }
            }
            // Ignore membership reports
            IgmpRepr::MembershipReport { .. } => (),
            // Ignore hosts leaving groups
            IgmpRepr::LeaveGroup { .. } => (),
        }

        None
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
            Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
        } else if self.is_broadcast_v4(ipv4_repr.dst_addr) {
            // Only reply to broadcasts for echo replies and not other ICMP messages
            match icmp_repr {
                Icmpv4Repr::EchoReply { .. } => match self.ipv4_address() {
                    Some(src_addr) => {
                        let ipv4_reply_repr = Ipv4Repr {
                            src_addr,
                            dst_addr: ipv4_repr.src_addr,
                            next_header: IpProtocol::Icmp,
                            payload_len: icmp_repr.buffer_len(),
                            hop_limit: 64,
                        };
                        Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
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
    pub(super) fn dispatch_ipv4_out_packet<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        out_packet: &mut Ipv4OutPacket,
    ) -> Result<()> {
        let Ipv4OutPacket {
            buffer,
            packet_len,
            sent_bytes,
            repr,
            dst_hardware_addr,
            frag_offset,
            ident,
            ..
        } = out_packet;

        let caps = self.caps.clone();

        let mtu_max = self.ip_mtu();
        let ip_len = (*packet_len - *sent_bytes + repr.buffer_len()).min(mtu_max);
        let payload_len = ip_len - repr.buffer_len();

        let more_frags = (*packet_len - *sent_bytes) != payload_len;
        repr.payload_len = payload_len;
        *sent_bytes += payload_len;

        let mut tx_len = ip_len;
        #[cfg(feature = "medium-ethernet")]
        if matches!(caps.medium, Medium::Ethernet) {
            tx_len += EthernetFrame::<&[u8]>::header_len();
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                addr
            } else {
                return Err(Error::Malformed);
            };

            frame.set_src_addr(src_addr);
            frame.set_dst_addr(*dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }

            Ok(())
        };

        tx_token.consume(self.now, tx_len, |mut tx_buffer| {
            #[cfg(feature = "medium-ethernet")]
            if matches!(self.caps.medium, Medium::Ethernet) {
                emit_ethernet(&IpRepr::Ipv4(*repr), tx_buffer)?;
                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
            }

            let mut packet = Ipv4Packet::new_unchecked(&mut tx_buffer[..repr.buffer_len()]);
            repr.emit(&mut packet, &caps.checksum);
            packet.set_ident(*ident);
            packet.set_more_frags(more_frags);
            packet.set_dont_frag(false);
            packet.set_frag_offset(*frag_offset);

            if caps.checksum.ipv4.tx() {
                packet.fill_checksum();
            }

            tx_buffer[repr.buffer_len()..][..payload_len].copy_from_slice(
                &buffer[*frag_offset as usize + repr.buffer_len()..][..payload_len],
            );

            // Update the frag offset for the next fragment.
            *frag_offset += payload_len as u16;

            Ok(())
        })
    }

    #[cfg(feature = "proto-igmp")]
    pub(super) fn igmp_report_packet<'any>(
        &self,
        version: IgmpVersion,
        group_addr: Ipv4Address,
    ) -> Option<IpPacket<'any>> {
        let iface_addr = self.ipv4_address()?;
        let igmp_repr = IgmpRepr::MembershipReport {
            group_addr,
            version,
        };
        let pkt = IpPacket::Igmp((
            Ipv4Repr {
                src_addr: iface_addr,
                // Send to the group being reported
                dst_addr: group_addr,
                next_header: IpProtocol::Igmp,
                payload_len: igmp_repr.buffer_len(),
                hop_limit: 1,
                // [#183](https://github.com/m-labs/smoltcp/issues/183).
            },
            igmp_repr,
        ));
        Some(pkt)
    }

    #[cfg(feature = "proto-igmp")]
    pub(super) fn igmp_leave_packet<'any>(
        &self,
        group_addr: Ipv4Address,
    ) -> Option<IpPacket<'any>> {
        self.ipv4_address().map(|iface_addr| {
            let igmp_repr = IgmpRepr::LeaveGroup { group_addr };
            IpPacket::Igmp((
                Ipv4Repr {
                    src_addr: iface_addr,
                    dst_addr: Ipv4Address::MULTICAST_ALL_ROUTERS,
                    next_header: IpProtocol::Igmp,
                    payload_len: igmp_repr.buffer_len(),
                    hop_limit: 1,
                },
                igmp_repr,
            ))
        })
    }
}
