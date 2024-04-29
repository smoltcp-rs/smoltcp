use super::*;

use crate::socket::AnySocket;

use crate::phy::PacketMeta;
use crate::wire::*;

/// Enum used for the process_hopbyhop function. In some cases, when discarding a packet, an ICMMP
/// parameter problem message needs to be transmitted to the source of the address. In other cases,
/// the processing of the IP packet can continue.
#[allow(clippy::large_enum_variant)]
enum HopByHopResponse<'frame> {
    /// Continue processing the IPv6 packet.
    Continue(Ipv6HopByHopRepr<'frame>, IpProtocol, &'frame [u8]),
    /// Discard the packet and maybe send back an ICMPv6 packet.
    Discard(Option<Packet<'frame>>),
}

// We implement `Default` such that we can use the check! macro.
impl Default for HopByHopResponse<'_> {
    fn default() -> Self {
        Self::Discard(None)
    }
}

/// Enum used for the process_routing function.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RoutingResponse<'frame> {
    /// Continue processing the IP packet.
    Continue(IpProtocol, &'frame [u8]),
    /// Forward the packet based on the information from the routing header.
    Forward(Packet<'frame>),
    /// There was an error processing the routing header, discard the packet.
    Discard,
}

impl InterfaceInner {
    /// Return the IPv6 address that is a candidate source address for the given destination
    /// address, based on RFC 6724.
    ///
    /// # Panics
    /// This function panics if the destination address is unspecified.
    #[allow(unused)]
    pub(crate) fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        assert!(!dst_addr.is_unspecified());

        // See RFC 6724 Section 4: Candidate source address
        fn is_candidate_source_address(dst_addr: &Ipv6Address, src_addr: &Ipv6Address) -> bool {
            // For all multicast and link-local destination addresses, the candidate address MUST
            // only be an address from the same link.
            if dst_addr.is_link_local() && !src_addr.is_link_local() {
                return false;
            }

            if dst_addr.is_multicast()
                && matches!(dst_addr.multicast_scope(), Ipv6MulticastScope::LinkLocal)
                && src_addr.is_multicast()
                && !matches!(src_addr.multicast_scope(), Ipv6MulticastScope::LinkLocal)
            {
                return false;
            }

            // Unspecified addresses and multicast address can not be in the candidate source address
            // list. Except when the destination multicast address has a link-local scope, then the
            // source address can also be link-local multicast.
            if src_addr.is_unspecified() || src_addr.is_multicast() {
                return false;
            }

            true
        }

        // See RFC 6724 Section 2.2: Common Prefix Length
        fn common_prefix_length(dst_addr: &Ipv6Cidr, src_addr: &Ipv6Address) -> usize {
            let addr = dst_addr.address();
            let mut bits = 0;
            for (l, r) in addr.as_bytes().iter().zip(src_addr.as_bytes().iter()) {
                if l == r {
                    bits += 8;
                } else {
                    bits += (l ^ r).leading_zeros();
                    break;
                }
            }

            bits = bits.min(dst_addr.prefix_len() as u32);

            bits as usize
        }

        // If the destination address is a loopback address, or when there are no IPv6 addresses in
        // the interface, then the loopback address is the only candidate source address.
        if dst_addr.is_loopback()
            || self
                .ip_addrs
                .iter()
                .filter(|a| matches!(a, IpCidr::Ipv6(_)))
                .count()
                == 0
        {
            return Ipv6Address::LOOPBACK;
        }

        let mut candidate = self
            .ip_addrs
            .iter()
            .find_map(|a| match a {
                #[cfg(feature = "proto-ipv4")]
                IpCidr::Ipv4(_) => None,
                IpCidr::Ipv6(a) => Some(a),
            })
            .unwrap(); // NOTE: we check above that there is at least one IPv6 address.

        for addr in self.ip_addrs.iter().filter_map(|a| match a {
            #[cfg(feature = "proto-ipv4")]
            IpCidr::Ipv4(_) => None,
            #[cfg(feature = "proto-ipv6")]
            IpCidr::Ipv6(a) => Some(a),
        }) {
            if !is_candidate_source_address(dst_addr, &addr.address()) {
                continue;
            }

            // Rule 1: prefer the address that is the same as the output destination address.
            if candidate.address() != *dst_addr && addr.address() == *dst_addr {
                candidate = addr;
            }

            // Rule 2: prefer appropriate scope.
            if (candidate.address().multicast_scope() as u8)
                < (addr.address().multicast_scope() as u8)
            {
                if (candidate.address().multicast_scope() as u8)
                    < (dst_addr.multicast_scope() as u8)
                {
                    candidate = addr;
                }
            } else if (addr.address().multicast_scope() as u8) > (dst_addr.multicast_scope() as u8)
            {
                candidate = addr;
            }

            // Rule 3: avoid deprecated addresses (TODO)
            // Rule 4: prefer home addresses (TODO)
            // Rule 5: prefer outgoing interfaces (TODO)
            // Rule 5.5: prefer addresses in a prefix advertises by the next-hop (TODO).
            // Rule 6: prefer matching label (TODO)
            // Rule 7: prefer temporary addresses (TODO)
            // Rule 8: use longest matching prefix
            if common_prefix_length(candidate, dst_addr) < common_prefix_length(addr, dst_addr) {
                candidate = addr;
            }
        }

        candidate.address()
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK => {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[..14]
                        == Ipv6Address::new(0xFF02, 0, 0, 0, 0, 1, 0xFF00, 0).as_bytes()[..14]
                        && addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        })
    }

    /// Get the first IPv6 address if present.
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv6(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    pub(super) fn process_ipv6<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_packet: &Ipv6Packet<&'frame [u8]>,
        previous_hop: Option<&HardwareAddress>,
        multicast_queue: &mut PacketBuffer<'_, MulticastMetadata>,
    ) -> Option<Packet<'frame>> {
        let mut ipv6_repr = check!(Ipv6Repr::parse(ipv6_packet));

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        let (hbh, next_header, ip_payload) = if ipv6_repr.next_header == IpProtocol::HopByHop {
            match self.process_hopbyhop(ipv6_repr, ipv6_packet.payload()) {
                HopByHopResponse::Discard(e) => return e,
                HopByHopResponse::Continue(hbh, next_header, payload) => {
                    (Some(hbh), next_header, payload)
                }
            }
        } else {
            (None, ipv6_repr.next_header, ipv6_packet.payload())
        };

        // Forward if not for us
        if !self.has_ip_addr(ipv6_repr.dst_addr)
            && !self.has_multicast_group(ipv6_repr.dst_addr)
            && !ipv6_repr.dst_addr.is_loopback()
        {
            #[cfg(not(feature = "proto-rpl"))]
            {
                net_trace!("packet IP address not for this interface");
                return None;
            }

            #[cfg(feature = "proto-rpl")]
            {
                ipv6_repr.next_header = next_header;
                if let Some(hbh) = &hbh {
                    ipv6_repr.payload_len -= 2 + hbh.buffer_len();
                }
                return self.forward(ipv6_repr, hbh, None, ip_payload);
            }
        }

        // Disallow list of forwardable multicast packets
        let should_forward_multicast = match ipv6_repr.dst_addr.into() {
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_NODES) => false,
            #[cfg(feature = "proto-rpl")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES) => false,
            _ => true,
        };
        // if for us and multicast, process further and schedule forwarding
        if should_forward_multicast && ipv6_repr.dst_addr.is_multicast() {
            // Construct forwarding packet if possible
            let forwarding_packet = self.forward(ipv6_repr, hbh, None, ip_payload);
            // Lookup hardware addresses to which we would like to forward the multicast packet
            let haddrs =
                self.lookup_hardware_addr_multicast(&ipv6_repr.dst_addr.into(), previous_hop);

            // Schedule forwarding and process further if possible
            match (&forwarding_packet, haddrs) {
                (Some(Packet::Ipv6(forwarding_packet)), Ok(haddrs)) => {
                    if !haddrs.is_empty() {
                        let _ = self
                            .schedule_multicast_packet(
                                meta,
                                forwarding_packet,
                                haddrs,
                                multicast_queue,
                            )
                            .inspect_err(|err| {
                                net_trace!(
                                    "Could not schedule multicast packets with reason {:?}",
                                    err
                                );
                            });
                    }
                }
                (Some(Packet::Ipv4(_)), Ok(_haddrs)) => unimplemented!(),
                _ => {}
            }
        }

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(
            sockets,
            meta,
            ipv6_repr,
            next_header,
            handled_by_raw_socket,
            ip_payload,
        )
    }

    fn process_hopbyhop<'frame>(
        &mut self,
        ipv6_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
    ) -> HopByHopResponse<'frame> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));
        let ext_repr = check!(Ipv6ExtHeaderRepr::parse(&ext_hdr));
        let hbh_hdr = check!(Ipv6HopByHopHeader::new_checked(ext_repr.data));
        let mut hbh_repr = check!(Ipv6HopByHopRepr::parse(&hbh_hdr));

        for opt_repr in &mut hbh_repr.options {
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                #[cfg(feature = "proto-rpl")]
                Ipv6OptionRepr::Rpl(hbh) if self.rpl.dodag.is_some() => {
                    match self.process_rpl_hopbyhop(*hbh) {
                        Ok(mut hbh) => {
                            if self.rpl.is_root {
                                hbh.down = true;
                            } else {
                                #[cfg(feature = "rpl-mop-2")]
                                if matches!(
                                    self.rpl.mode_of_operation,
                                    crate::iface::RplModeOfOperation::StoringMode
                                ) {
                                    hbh.down = self
                                        .rpl
                                        .dodag
                                        .as_ref()
                                        .unwrap()
                                        .relations
                                        .find_next_hop(ipv6_repr.dst_addr)
                                        .is_some();
                                }
                            }

                            hbh.sender_rank = self.rpl.dodag.as_ref().unwrap().rank.raw_value();
                            // FIXME: really update the RPL Hop-by-Hop. When forwarding,
                            // we need to update the RPL Hop-by-Hop header.
                            *opt_repr = Ipv6OptionRepr::Rpl(hbh);
                        }
                        Err(_) => {
                            // TODO: check if we need to silently drop the packet or if we need to send
                            // back to the original sender (global/local repair).
                            return HopByHopResponse::Discard(None);
                        }
                    }
                }

                Ipv6OptionRepr::Rpl(_) => {
                    // If we are not part of a RPL network, we should silently drop the packet.
                    return HopByHopResponse::Discard(None);
                }

                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(*type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return HopByHopResponse::Discard(None);
                        }
                        Ipv6OptionFailureType::DiscardSendAll => {
                            return HopByHopResponse::Discard(self.icmpv6_problem(
                                ipv6_repr,
                                ip_payload,
                                Icmpv6ParamProblem::UnrecognizedOption,
                            ));
                        }
                        Ipv6OptionFailureType::DiscardSendUnicast
                            if !ipv6_repr.dst_addr.is_multicast() =>
                        {
                            return HopByHopResponse::Discard(self.icmpv6_problem(
                                ipv6_repr,
                                ip_payload,
                                Icmpv6ParamProblem::UnrecognizedOption,
                            ));
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        HopByHopResponse::Continue(
            hbh_repr,
            ext_repr.next_header,
            &ip_payload[ext_repr.header_len() + ext_repr.data.len()..],
        )
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    fn process_nxt_hdr<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        match nxt_hdr {
            IpProtocol::Icmpv6 => self.process_icmpv6(sockets, ipv6_repr, ip_payload),

            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpProtocol::Udp => self.process_udp(
                sockets,
                meta,
                handled_by_raw_socket,
                ipv6_repr.into(),
                ip_payload,
            ),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "proto-ipv6-routing")]
            IpProtocol::Ipv6Route => {
                self.process_routing(sockets, meta, ipv6_repr, handled_by_raw_socket, ip_payload)
            }

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket => None,

            _ => self.icmpv6_problem(
                ipv6_repr,
                ip_payload,
                Icmpv6ParamProblem::UnrecognizedNxtHdr,
            ),
        }
    }

    pub(super) fn process_icmpv6<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        ip_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let icmp_packet = check!(Icmpv6Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv6Repr::parse(
            &ip_repr.src_addr,
            &ip_repr.dst_addr,
            &icmp_packet,
            &self.checksum_caps(),
        ));

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(feature = "socket-icmp")]
        {
            use crate::socket::icmp::Socket as IcmpSocket;
            for icmp_socket in _sockets
                .items_mut()
                .filter_map(|i| IcmpSocket::downcast_mut(&mut i.socket))
            {
                if icmp_socket.accepts_v6(self, &ip_repr, &icmp_repr) {
                    icmp_socket.process_v6(self, &ip_repr, &icmp_repr);
                    handled_by_icmp_socket = true;
                }
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                let icmp_reply_repr = Icmpv6Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                self.icmpv6_reply(ip_repr, icmp_reply_repr)
            }

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => None,

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit == 0xff => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self.process_ndisc(ip_repr, repr),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self.process_ndisc(ip_repr, repr),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => None,
            },

            #[cfg(feature = "proto-rpl")]
            Icmpv6Repr::Rpl(rpl) => self.process_rpl(ip_repr, rpl),

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

    #[cfg(feature = "proto-ipv6-routing")]
    pub(super) fn process_routing<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));

        let routing_header = check!(Ipv6RoutingHeader::new_checked(ext_hdr.payload()));
        let routing_repr = check!(Ipv6RoutingRepr::parse(&routing_header));

        let (next_header, payload) = match routing_repr {
            Ipv6RoutingRepr::Type2 { .. } => {
                // TODO: we should respond with an ICMPv6 unknown protocol message.
                net_debug!("IPv6 Type2 routing header not supported yet, dropping packet.");
                return None;
            }
            #[cfg(not(feature = "proto-rpl"))]
            Ipv6RoutingRepr::Rpl { .. } => {
                net_debug!("RPL routing header not supported, dropping packet.");
                return None;
            }
            #[cfg(feature = "proto-rpl")]
            Ipv6RoutingRepr::Rpl(routing) => {
                match self.process_source_routing(ipv6_repr, &ext_hdr, routing, ip_payload) {
                    RoutingResponse::Discard => return None,
                    RoutingResponse::Forward(packet) => return Some(packet),
                    RoutingResponse::Continue(next_header, payload) => (next_header, payload),
                }
            }
        };

        self.process_nxt_hdr(
            sockets,
            meta,
            ipv6_repr,
            next_header,
            handled_by_raw_socket,
            payload,
        )
    }

    pub(super) fn icmpv6_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv6_repr: Ipv6Repr,
        icmp_repr: Icmpv6Repr<'icmp>,
    ) -> Option<Packet<'frame>> {
        let src_addr = ipv6_repr.dst_addr;
        let dst_addr = ipv6_repr.src_addr;

        let src_addr = if src_addr.is_unicast() {
            src_addr
        } else {
            self.get_source_address_ipv6(&dst_addr)
        };

        let ipv6_reply_repr = Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        };
        Some(Packet::new_ipv6(
            ipv6_reply_repr,
            IpPayload::Icmpv6(icmp_repr),
        ))
    }

    #[cfg(feature = "proto-rpl")]
    pub(super) fn forward<'frame>(
        &self,
        mut ipv6_repr: Ipv6Repr,
        mut _hop_by_hop: Option<Ipv6HopByHopRepr<'frame>>,
        mut _routing: Option<Ipv6RoutingRepr>,
        payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        net_trace!("forwarding packet");

        if ipv6_repr.hop_limit <= 1 {
            net_trace!("hop limit reached 0, dropping packet");
            // FIXME: we should transmit an ICMPv6 Time Exceeded message, as defined
            // in RFC 2460. However, this is not trivial with the current state of
            // smoltcp. When sending this message back, as much as possible of the
            // original message should be transmitted back. This is after updating the
            // addresses in the source routing headers. At this time, we only update
            // the parsed list of addresses, not the `ip_payload` buffer. It is this
            // buffer we would use when sending back the ICMPv6 message. And since we
            // can't update that buffer here, we can't update the source routing header
            // and it would send back an incorrect header. The standard does not
            // specify if we SHOULD or MUST transmit an ICMPv6 message.
            return None;
        }

        ipv6_repr.hop_limit -= 1;

        let mut p = PacketV6::new(ipv6_repr, IpPayload::Raw(payload));

        if let Some(hbh) = _hop_by_hop {
            p.add_hop_by_hop(hbh);
        } else {
            #[cfg(feature = "proto-rpl")]
            if p.header().dst_addr.is_unicast() && self.rpl.dodag.is_some() {
                let mut options = heapless::Vec::new();
                options
                    .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                        down: self.rpl.is_root,
                        rank_error: false,
                        forwarding_error: false,
                        instance_id: self.rpl.dodag.as_ref().unwrap().instance_id,
                        sender_rank: self.rpl.dodag.as_ref().unwrap().rank.raw_value(),
                    }))
                    .unwrap();

                let hbh = Ipv6HopByHopRepr { options };
                p.add_hop_by_hop(hbh);
            }
        }

        if let Some(routing) = _routing {
            p.add_routing(routing);
        }

        Some(Packet::Ipv6(p))
    }

    fn icmpv6_problem<'frame>(
        &self,
        ipv6_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
        reason: Icmpv6ParamProblem,
    ) -> Option<Packet<'frame>> {
        let payload_len =
            icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
        self.icmpv6_reply(
            ipv6_repr,
            Icmpv6Repr::ParamProblem {
                reason,
                pointer: ipv6_repr.buffer_len() as u32,
                header: ipv6_repr,
                data: &ip_payload[0..payload_len],
            },
        )
    }
}
