use super::*;

/// Enum used for the process_hopbyhop function. In some cases, when discarding a packet, an ICMP
/// parameter problem message needs to be transmitted to the source of the address. In other cases,
/// the processing of the IP packet can continue.
#[allow(clippy::large_enum_variant)]
enum HopByHopResponse<'frame> {
    /// Continue processing the IPv6 packet.
    Continue((IpProtocol, &'frame [u8])),
    /// Discard the packet and maybe send back an ICMPv6 packet.
    Discard(Option<Packet<'frame>>),
}

// We implement `Default` such that we can use the check! macro.
impl Default for HopByHopResponse<'_> {
    fn default() -> Self {
        Self::Discard(None)
    }
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
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
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

    /// Get the first link-local IPv6 address of the interface, if present.
    fn link_local_ipv6_address(&self) -> Option<Ipv6Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            #[cfg(feature = "proto-ipv4")]
            IpCidr::Ipv4(_) => None,
            #[cfg(feature = "proto-ipv6")]
            IpCidr::Ipv6(cidr) => {
                let addr = cidr.address();
                if addr.is_link_local() {
                    Some(addr)
                } else {
                    None
                }
            }
        })
    }

    pub(super) fn process_ipv6<'frame, 'socket, S>(
        &mut self,
        sockets: &mut S,
        meta: PacketMeta,
        ipv6_packet: &Ipv6Packet<&'frame [u8]>,
    ) -> Option<Packet<'frame>>
    where
        S: AnySocketSet<'socket>,
    {
        let ipv6_repr = check!(Ipv6Repr::parse(ipv6_packet));

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        let (next_header, ip_payload) = if ipv6_repr.next_header == IpProtocol::HopByHop {
            match self.process_hopbyhop(ipv6_repr, ipv6_packet.payload()) {
                HopByHopResponse::Discard(e) => return e,
                HopByHopResponse::Continue(next) => next,
            }
        } else {
            (ipv6_repr.next_header, ipv6_packet.payload())
        };

        if !self.has_ip_addr(ipv6_repr.dst_addr)
            && !self.has_multicast_group(ipv6_repr.dst_addr)
            && !ipv6_repr.dst_addr.is_loopback()
        {
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.any_ip
                || !ipv6_repr.dst_addr.is_unicast()
                || self
                    .routes
                    .lookup(&IpAddress::Ipv6(ipv6_repr.dst_addr), self.now)
                    .map_or(true, |router_addr| !self.has_ip_addr(router_addr))
            {
                net_trace!("packet IP address not for this interface");
                return None;
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
        let param_problem = || {
            let payload_len =
                icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
            self.icmpv6_reply(
                ipv6_repr,
                Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedOption,
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                },
            )
        };

        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));
        let ext_repr = check!(Ipv6ExtHeaderRepr::parse(&ext_hdr));
        let hbh_hdr = check!(Ipv6HopByHopHeader::new_checked(ext_repr.data));
        let hbh_repr = check!(Ipv6HopByHopRepr::parse(&hbh_hdr));

        for opt_repr in &hbh_repr.options {
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) | Ipv6OptionRepr::RouterAlert(_) => {
                }
                #[cfg(feature = "proto-rpl")]
                Ipv6OptionRepr::Rpl(_) => {}

                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(*type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return HopByHopResponse::Discard(None);
                        }
                        Ipv6OptionFailureType::DiscardSendAll => {
                            return HopByHopResponse::Discard(param_problem());
                        }
                        Ipv6OptionFailureType::DiscardSendUnicast
                            if !ipv6_repr.dst_addr.is_multicast() =>
                        {
                            return HopByHopResponse::Discard(param_problem());
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        HopByHopResponse::Continue((
            ext_repr.next_header,
            &ip_payload[ext_repr.header_len() + ext_repr.data.len()..],
        ))
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    fn process_nxt_hdr<'frame, 'socket, S>(
        &mut self,
        sockets: &mut S,
        meta: PacketMeta,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>>
    where
        S: AnySocketSet<'socket>,
    {
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

    pub(super) fn process_icmpv6<'frame, 'socket, S>(
        &mut self,
        _sockets: &mut S,
        ip_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>>
    where
        S: AnySocketSet<'socket>,
    {
        let icmp_packet = check!(Icmpv6Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv6Repr::parse(
            &ip_repr.src_addr,
            &ip_repr.dst_addr,
            &icmp_packet,
            &self.caps.checksum,
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

    pub(super) fn mldv2_report_packet<'any>(
        &self,
        records: &'any [MldAddressRecordRepr<'any>],
    ) -> Option<Packet<'any>> {
        // Per [RFC 3810 § 5.2.13], source addresses must be link-local, falling
        // back to the unspecified address if we haven't acquired one.
        // [RFC 3810 § 5.2.13]: https://tools.ietf.org/html/rfc3810#section-5.2.13
        let src_addr = self
            .link_local_ipv6_address()
            .unwrap_or(Ipv6Address::UNSPECIFIED);

        // Per [RFC 3810 § 5.2.14], all MLDv2 reports are sent to ff02::16.
        // [RFC 3810 § 5.2.14]: https://tools.ietf.org/html/rfc3810#section-5.2.14
        let dst_addr = Ipv6Address::LINK_LOCAL_ALL_MLDV2_ROUTERS;

        // Create a dummy IPv6 extension header so we can calculate the total length of the packet.
        // The actual extension header will be created later by Packet::emit_payload().
        let dummy_ext_hdr = Ipv6ExtHeaderRepr {
            next_header: IpProtocol::Unknown(0),
            length: 0,
            data: &[],
        };

        let mut hbh_repr = Ipv6HopByHopRepr::mldv2_router_alert();
        hbh_repr.push_padn_option(0);

        let mld_repr = MldRepr::ReportRecordReprs(records);
        let records_len = records
            .iter()
            .map(MldAddressRecordRepr::buffer_len)
            .sum::<usize>();

        // All MLDv2 messages must be sent with an IPv6 Hop limit of 1.
        Some(Packet::new_ipv6(
            Ipv6Repr {
                src_addr,
                dst_addr,
                next_header: IpProtocol::HopByHop,
                payload_len: dummy_ext_hdr.header_len()
                    + hbh_repr.buffer_len()
                    + mld_repr.buffer_len()
                    + records_len,
                hop_limit: 1,
            },
            IpPayload::HopByHopIcmpv6(hbh_repr, Icmpv6Repr::Mld(mld_repr)),
        ))
    }
}
