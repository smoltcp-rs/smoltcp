use super::*;

#[cfg(feature = "socket-icmp")]
use crate::socket::icmp;
use crate::socket::AnySocket;

use crate::phy::PacketMeta;
use crate::wire::*;

impl InterfaceInner {
    pub(super) fn process_ipv6<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_packet: &Ipv6Packet<&'frame [u8]>,
    ) -> Option<Packet<'frame>> {
        let ipv6_repr = check!(Ipv6Repr::parse(ipv6_packet));

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(
            sockets,
            meta,
            ipv6_repr,
            ipv6_repr.next_header,
            handled_by_raw_socket,
            ip_payload,
        )
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    pub(super) fn process_nxt_hdr<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        match nxt_hdr {
            IpProtocol::Icmpv6 => self.process_icmpv6(sockets, ipv6_repr.into(), ip_payload),

            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpProtocol::Udp => {
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                let udp_repr = check!(UdpRepr::parse(
                    &udp_packet,
                    &ipv6_repr.src_addr.into(),
                    &ipv6_repr.dst_addr.into(),
                    &self.checksum_caps(),
                ));

                self.process_udp(
                    sockets,
                    meta,
                    ipv6_repr.into(),
                    udp_repr,
                    handled_by_raw_socket,
                    udp_packet.payload(),
                    ip_payload,
                )
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop => {
                self.process_hopbyhop(sockets, meta, ipv6_repr, handled_by_raw_socket, ip_payload)
            }

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket => None,

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv6_reply(ipv6_repr, icmp_reply_repr)
            }
        }
    }

    pub(super) fn process_icmpv6<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let icmp_packet = check!(Icmpv6Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv6Repr::parse(
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            &icmp_packet,
            &self.caps.checksum,
        ));

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(feature = "socket-icmp")]
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
            Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => {
                    let icmp_reply_repr = Icmpv6Repr::EchoReply {
                        ident,
                        seq_no,
                        data,
                    };
                    self.icmpv6_reply(ipv6_repr, icmp_reply_repr)
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            },

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => None,

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => self.process_ndisc(ipv6_repr, repr),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => self.process_ndisc(ipv6_repr, repr),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => None,
                },
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            },

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
        ip_repr: Ipv6Repr,
        repr: NdiscRepr<'frame>,
    ) -> Option<Packet<'frame>> {
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

                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr,
                        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                        lladdr: Some(self.hardware_addr.into()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Some(Packet::new_ipv6(ip_repr, IpPayload::Icmpv6(advert)))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(super) fn process_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));
        let ext_repr = check!(Ipv6ExtHeaderRepr::parse(&ext_hdr));
        let hbh_hdr = check!(Ipv6HopByHopHeader::new_checked(ext_repr.data));
        let hbh_repr = check!(Ipv6HopByHopRepr::parse(&hbh_hdr));

        for opt_repr in &hbh_repr.options {
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
        self.process_nxt_hdr(
            sockets,
            meta,
            ipv6_repr,
            ext_repr.next_header,
            handled_by_raw_socket,
            &ip_payload[ext_repr.header_len() + ext_repr.data.len()..],
        )
    }

    pub(super) fn icmpv6_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv6_repr: Ipv6Repr,
        icmp_repr: Icmpv6Repr<'icmp>,
    ) -> Option<Packet<'frame>> {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr: ipv6_repr.dst_addr,
                dst_addr: ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(Packet::new_ipv6(
                ipv6_reply_repr,
                IpPayload::Icmpv6(icmp_repr),
            ))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }
}
