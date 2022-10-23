use super::check;
use super::FragmentsBuffer;
use super::InterfaceInner;
use super::IpPacket;
use super::OutPackets;
use super::PacketAssemblerSet;
use super::SocketSet;

#[cfg(feature = "proto-sixlowpan-fragmentation")]
use super::SixlowpanOutPacket;

use crate::phy::TxToken;
use crate::time::*;
use crate::wire::*;
use crate::Error;
use crate::Result;

impl<'a> InterfaceInner<'a> {
    #[cfg(feature = "medium-ieee802154")]
    pub(super) fn process_ieee802154<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        sixlowpan_payload: &'payload T,
        _fragments: &'output mut FragmentsBuffer<'a>,
    ) -> Option<IpPacket<'output>> {
        let ieee802154_frame = check!(Ieee802154Frame::new_checked(sixlowpan_payload));
        let ieee802154_repr = check!(Ieee802154Repr::parse(&ieee802154_frame));

        if ieee802154_repr.frame_type != Ieee802154FrameType::Data {
            return None;
        }

        // Drop frames when the user has set a PAN id and the PAN id from frame is not equal to this
        // When the user didn't set a PAN id (so it is None), then we accept all PAN id's.
        // We always accept the broadcast PAN id.
        if self.pan_id.is_some()
            && ieee802154_repr.dst_pan_id != self.pan_id
            && ieee802154_repr.dst_pan_id != Some(Ieee802154Pan::BROADCAST)
        {
            net_debug!(
                "IEEE802.15.4: dropping {:?} because not our PAN id (or not broadcast)",
                ieee802154_repr
            );
            return None;
        }

        match ieee802154_frame.payload() {
            Some(payload) => {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                {
                    self.process_sixlowpan(
                        sockets,
                        &ieee802154_repr,
                        payload,
                        Some((
                            &mut _fragments.sixlowpan_fragments,
                            _fragments.sixlowpan_fragments_cache_timeout,
                        )),
                    )
                }

                #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
                {
                    self.process_sixlowpan(sockets, &ieee802154_repr, payload, None)
                }
            }
            None => None,
        }
    }

    pub(super) fn process_sixlowpan<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        _fragments: Option<(
            &'output mut PacketAssemblerSet<'a, SixlowpanFragKey>,
            Duration,
        )>,
    ) -> Option<IpPacket<'output>> {
        let payload = match check!(SixlowpanPacket::dispatch(payload)) {
            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            SixlowpanPacket::FragmentHeader => {
                net_debug!("Fragmentation is not supported, use the `proto-sixlowpan-fragmentation` feature to add support.");
                return None;
            }
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            SixlowpanPacket::FragmentHeader => {
                match self.process_sixlowpan_fragment(ieee802154_repr, payload, _fragments) {
                    Some(payload) => payload,
                    None => return None,
                }
            }
            SixlowpanPacket::IphcHeader => payload.as_ref(),
        };

        // At this point we should have a valid 6LoWPAN packet.
        // The first header needs to be an IPHC header.
        let iphc_packet = check!(SixlowpanIphcPacket::new_checked(payload));
        let iphc_repr = check!(SixlowpanIphcRepr::parse(
            &iphc_packet,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
            self.sixlowpan_address_context,
        ));

        let payload = iphc_packet.payload();
        let mut ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            hop_limit: iphc_repr.hop_limit,
            next_header: IpProtocol::Unknown(0),
            payload_len: 40,
        };

        match iphc_repr.next_header {
            SixlowpanNextHeader::Compressed => {
                match check!(SixlowpanNhcPacket::dispatch(payload)) {
                    SixlowpanNhcPacket::ExtHeader => {
                        net_debug!("Extension headers are currently not supported for 6LoWPAN");
                        None
                    }
                    #[cfg(not(feature = "socket-udp"))]
                    SixlowpanNhcPacket::UdpHeader => {
                        net_debug!("UDP support is disabled, enable cargo feature `socket-udp`.");
                        None
                    }
                    #[cfg(feature = "socket-udp")]
                    SixlowpanNhcPacket::UdpHeader => {
                        let udp_packet = check!(SixlowpanUdpNhcPacket::new_checked(payload));
                        ipv6_repr.next_header = IpProtocol::Udp;
                        ipv6_repr.payload_len += 8 + udp_packet.payload().len();

                        let udp_repr = check!(SixlowpanUdpNhcRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr
                        ));

                        self.process_udp(
                            sockets,
                            IpRepr::Ipv6(ipv6_repr),
                            udp_repr.0,
                            false,
                            udp_packet.payload(),
                            payload,
                        )
                    }
                }
            }
            SixlowpanNextHeader::Uncompressed(nxt_hdr) => match nxt_hdr {
                IpProtocol::Icmpv6 => {
                    ipv6_repr.next_header = IpProtocol::Icmpv6;
                    self.process_icmpv6(sockets, IpRepr::Ipv6(ipv6_repr), iphc_packet.payload())
                }
                #[cfg(feature = "socket-tcp")]
                IpProtocol::Tcp => {
                    ipv6_repr.next_header = nxt_hdr;
                    ipv6_repr.payload_len += payload.len();
                    self.process_tcp(sockets, IpRepr::Ipv6(ipv6_repr), iphc_packet.payload())
                }
                proto => {
                    net_debug!("6LoWPAN: {} currently not supported", proto);
                    None
                }
            },
        }
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn process_sixlowpan_fragment<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        fragments: Option<(
            &'output mut PacketAssemblerSet<'a, SixlowpanFragKey>,
            Duration,
        )>,
    ) -> Option<&'output [u8]> {
        let (fragments, timeout) = fragments.unwrap();

        // We have a fragment header, which means we cannot process the 6LoWPAN packet,
        // unless we have a complete one after processing this fragment.
        let frag = check!(SixlowpanFragPacket::new_checked(payload));

        // The key specifies to which 6LoWPAN fragment it belongs too.
        // It is based on the link layer addresses, the tag and the size.
        let key = frag.get_key(ieee802154_repr);

        // The offset of this fragment in increments of 8 octets.
        let offset = frag.datagram_offset() as usize * 8;

        if frag.is_first_fragment() {
            // The first fragment contains the total size of the IPv6 packet.
            // However, we received a packet that is compressed following the 6LoWPAN
            // standard. This means we need to convert the IPv6 packet size to a 6LoWPAN
            // packet size. The packet size can be different because of first the
            // compression of the IP header and when UDP is used (because the UDP header
            // can also be compressed). Other headers are not compressed by 6LoWPAN.

            let iphc = check!(SixlowpanIphcPacket::new_checked(frag.payload()));
            let iphc_repr = check!(SixlowpanIphcRepr::parse(
                &iphc,
                ieee802154_repr.src_addr,
                ieee802154_repr.dst_addr,
                self.sixlowpan_address_context,
            ));

            // The uncompressed header size always starts with 40, since this is the size
            // of a IPv6 header.
            let mut uncompressed_header_size = 40;
            let mut compressed_header_size = iphc.header_len();

            // We need to check if we have an UDP packet, since this header can also be
            // compressed by 6LoWPAN. We currently don't support extension headers yet.
            match iphc_repr.next_header {
                SixlowpanNextHeader::Compressed => {
                    match check!(SixlowpanNhcPacket::dispatch(iphc.payload())) {
                        SixlowpanNhcPacket::ExtHeader => {
                            net_debug!("6LoWPAN: extension headers not supported");
                            return None;
                        }
                        SixlowpanNhcPacket::UdpHeader => {
                            let udp_packet =
                                check!(SixlowpanUdpNhcPacket::new_checked(iphc.payload()));

                            uncompressed_header_size += 8;
                            compressed_header_size +=
                                1 + udp_packet.ports_size() + udp_packet.checksum_size();
                        }
                    }
                }
                SixlowpanNextHeader::Uncompressed(_) => (),
            }

            // We reserve a spot in the packet assembler set and add the required
            // information to the packet assembler.
            // This information is the total size of the packet when it is fully assmbled.
            // We also pass the header size, since this is needed when other fragments
            // (other than the first one) are added.
            let frag_slot = match fragments.reserve_with_key(&key) {
                Ok(frag) => frag,
                Err(Error::PacketAssemblerSetFull) => {
                    net_debug!("No available packet assembler for fragmented packet");
                    return Default::default();
                }
                e => check!(e),
            };

            check!(frag_slot.start(
                Some(
                    frag.datagram_size() as usize - uncompressed_header_size
                        + compressed_header_size
                ),
                self.now + timeout,
                -((uncompressed_header_size - compressed_header_size) as isize),
            ));
        }

        let frags = check!(fragments.get_packet_assembler_mut(&key));

        net_trace!("6LoWPAN: received packet fragment");

        // Add the fragment to the packet assembler.
        match frags.add(frag.payload(), offset) {
            Ok(true) => {
                net_trace!("6LoWPAN: fragmented packet now complete");
                match fragments.get_assembled_packet(&key) {
                    Ok(packet) => Some(packet),
                    _ => unreachable!(),
                }
            }
            Ok(false) => None,
            Err(Error::PacketAssemblerOverlap) => {
                net_trace!("6LoWPAN: overlap in packet");
                frags.mark_discarded();
                None
            }
            Err(_) => None,
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    pub(super) fn dispatch_ieee802154<Tx: TxToken>(
        &mut self,
        ll_dst_a: Ieee802154Address,
        ip_repr: &IpRepr,
        tx_token: Tx,
        packet: IpPacket,
        _out_packet: Option<&mut OutPackets>,
    ) -> Result<()> {
        // We first need to convert the IPv6 packet to a 6LoWPAN compressed packet.
        // Whenever this packet is to big to fit in the IEEE802.15.4 packet, then we need to
        // fragment it.
        let ll_src_a = self.hardware_addr.map_or_else(
            || Err(Error::Malformed),
            |addr| match addr {
                HardwareAddress::Ieee802154(addr) => Ok(addr),
                _ => Err(Error::Malformed),
            },
        )?;

        let (src_addr, dst_addr) = match (ip_repr.src_addr(), ip_repr.dst_addr()) {
            (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => (src_addr, dst_addr),
            #[allow(unreachable_patterns)]
            _ => return Err(Error::Unaddressable),
        };

        // Create the IEEE802.15.4 header.
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(self.get_sequence_number()),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: self.pan_id,
            dst_addr: Some(ll_dst_a),
            src_pan_id: self.pan_id,
            src_addr: Some(ll_src_a),
        };

        // Create the 6LoWPAN IPHC header.
        let iphc_repr = SixlowpanIphcRepr {
            src_addr,
            ll_src_addr: Some(ll_src_a),
            dst_addr,
            ll_dst_addr: Some(ll_dst_a),
            next_header: match &packet {
                IpPacket::Icmpv6(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
                #[cfg(feature = "socket-tcp")]
                IpPacket::Tcp(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
                #[cfg(feature = "socket-udp")]
                IpPacket::Udp(_) => SixlowpanNextHeader::Compressed,
                #[allow(unreachable_patterns)]
                _ => return Err(Error::Unrecognized),
            },
            hop_limit: ip_repr.hop_limit(),
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        // Now we calculate the total size of the packet.
        // We need to know this, such that we know when to do the fragmentation.
        let mut total_size = 0;
        total_size += iphc_repr.buffer_len();
        let mut _compressed_headers_len = iphc_repr.buffer_len();
        let mut _uncompressed_headers_len = ip_repr.header_len();

        #[allow(unreachable_patterns)]
        match packet {
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udpv6_repr, payload)) => {
                let udp_repr = SixlowpanUdpNhcRepr(udpv6_repr);
                _compressed_headers_len += udp_repr.header_len();
                _uncompressed_headers_len += udpv6_repr.header_len();
                total_size += udp_repr.header_len() + payload.len();
            }
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((_, tcp_repr)) => {
                total_size += tcp_repr.buffer_len();
            }
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((_, icmp_repr)) => {
                total_size += icmp_repr.buffer_len();
            }
            _ => return Err(Error::Unrecognized),
        }

        let ieee_len = ieee_repr.buffer_len();

        if total_size + ieee_len > 125 {
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            {
                // The packet does not fit in one Ieee802154 frame, so we need fragmentation.
                // We do this by emitting everything in the `out_packet.buffer` from the interface.
                // After emitting everything into that buffer, we send the first fragment heere.
                // When `poll` is called again, we check if out_packet was fully sent, otherwise we
                // call `dispatch_ieee802154_out_packet`, which will transmit the other fragments.

                // `dispatch_ieee802154_out_packet` requires some information about the total packet size,
                // the link local source and destination address...
                let SixlowpanOutPacket {
                    buffer,
                    packet_len,
                    datagram_size,
                    datagram_tag,
                    sent_bytes,
                    fragn_size,
                    ll_dst_addr,
                    ll_src_addr,
                    datagram_offset,
                    ..
                } = &mut _out_packet.unwrap().sixlowpan_out_packet;

                if buffer.len() < total_size {
                    net_debug!("6LoWPAN: Fragmentation buffer is too small");
                    return Err(Error::Exhausted);
                }

                *ll_dst_addr = ll_dst_a;
                *ll_src_addr = ll_src_a;

                let mut iphc_packet =
                    SixlowpanIphcPacket::new_unchecked(&mut buffer[..iphc_repr.buffer_len()]);
                iphc_repr.emit(&mut iphc_packet);

                let b = &mut buffer[iphc_repr.buffer_len()..];

                #[allow(unreachable_patterns)]
                match packet {
                    #[cfg(feature = "socket-udp")]
                    IpPacket::Udp((_, udpv6_repr, payload)) => {
                        let udp_repr = SixlowpanUdpNhcRepr(udpv6_repr);
                        let mut udp_packet = SixlowpanUdpNhcPacket::new_unchecked(
                            &mut b[..udp_repr.header_len() + payload.len()],
                        );
                        udp_repr.emit(
                            &mut udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            payload.len(),
                            |buf| buf.copy_from_slice(payload),
                        );
                    }
                    #[cfg(feature = "socket-tcp")]
                    IpPacket::Tcp((_, tcp_repr)) => {
                        let mut tcp_packet =
                            TcpPacket::new_unchecked(&mut b[..tcp_repr.buffer_len()]);
                        tcp_repr.emit(
                            &mut tcp_packet,
                            &iphc_repr.src_addr.into(),
                            &iphc_repr.dst_addr.into(),
                            &self.caps.checksum,
                        );
                    }
                    #[cfg(feature = "proto-ipv6")]
                    IpPacket::Icmpv6((_, icmp_repr)) => {
                        let mut icmp_packet =
                            Icmpv6Packet::new_unchecked(&mut b[..icmp_repr.buffer_len()]);
                        icmp_repr.emit(
                            &iphc_repr.src_addr.into(),
                            &iphc_repr.dst_addr.into(),
                            &mut icmp_packet,
                            &self.caps.checksum,
                        );
                    }
                    _ => return Err(Error::Unrecognized),
                }

                *packet_len = total_size;

                // The datagram size that we need to set in the first fragment header is equal to the
                // IPv6 payload length + 40.
                *datagram_size = (packet.ip_repr().payload_len() + 40) as u16;

                // We generate a random tag.
                let tag = self.get_sixlowpan_fragment_tag();
                // We save the tag for the other fragments that will be created when calling `poll`
                // multiple times.
                *datagram_tag = tag;

                let frag1 = SixlowpanFragRepr::FirstFragment {
                    size: *datagram_size,
                    tag,
                };
                let fragn = SixlowpanFragRepr::Fragment {
                    size: *datagram_size,
                    tag,
                    offset: 0,
                };

                // We calculate how much data we can send in the first fragment and the other
                // fragments. The eventual IPv6 sizes of these fragments need to be a multiple of eight
                // (except for the last fragment) since the offset field in the fragment is an offset
                // in multiples of 8 octets. This is explained in [RFC 4944 § 5.3].
                //
                // [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

                let header_diff = _uncompressed_headers_len - _compressed_headers_len;
                let frag1_size =
                    (125 - ieee_len - frag1.buffer_len() + header_diff) / 8 * 8 - (header_diff);

                *fragn_size = (125 - ieee_len - fragn.buffer_len()) / 8 * 8;

                *sent_bytes = frag1_size;
                *datagram_offset = frag1_size + header_diff;

                tx_token.consume(
                    self.now,
                    ieee_len + frag1.buffer_len() + frag1_size,
                    |mut tx_buf| {
                        // Add the IEEE header.
                        let mut ieee_packet =
                            Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                        ieee_repr.emit(&mut ieee_packet);
                        tx_buf = &mut tx_buf[ieee_len..];

                        // Add the first fragment header
                        let mut frag1_packet = SixlowpanFragPacket::new_unchecked(&mut tx_buf);
                        frag1.emit(&mut frag1_packet);
                        tx_buf = &mut tx_buf[frag1.buffer_len()..];

                        // Add the buffer part.
                        tx_buf[..frag1_size].copy_from_slice(&buffer[..frag1_size]);

                        Ok(())
                    },
                )
            }

            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            {
                net_debug!(
                    "Enable the `proto-sixlowpan-fragmentation` feature for fragmentation support."
                );
                Ok(())
            }
        } else {
            // We don't need fragmentation, so we emit everything to the TX token.
            tx_token.consume(self.now, total_size + ieee_len, |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];

                let mut iphc_packet =
                    SixlowpanIphcPacket::new_unchecked(&mut tx_buf[..iphc_repr.buffer_len()]);
                iphc_repr.emit(&mut iphc_packet);
                tx_buf = &mut tx_buf[iphc_repr.buffer_len()..];

                #[allow(unreachable_patterns)]
                match packet {
                    #[cfg(feature = "socket-udp")]
                    IpPacket::Udp((_, udpv6_repr, payload)) => {
                        let udp_repr = SixlowpanUdpNhcRepr(udpv6_repr);
                        let mut udp_packet = SixlowpanUdpNhcPacket::new_unchecked(
                            &mut tx_buf[..udp_repr.header_len() + payload.len()],
                        );
                        udp_repr.emit(
                            &mut udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            payload.len(),
                            |buf| buf.copy_from_slice(payload),
                        );
                    }
                    #[cfg(feature = "socket-tcp")]
                    IpPacket::Tcp((_, tcp_repr)) => {
                        let mut tcp_packet =
                            TcpPacket::new_unchecked(&mut tx_buf[..tcp_repr.buffer_len()]);
                        tcp_repr.emit(
                            &mut tcp_packet,
                            &iphc_repr.src_addr.into(),
                            &iphc_repr.dst_addr.into(),
                            &self.caps.checksum,
                        );
                    }
                    #[cfg(feature = "proto-ipv6")]
                    IpPacket::Icmpv6((_, icmp_repr)) => {
                        let mut icmp_packet =
                            Icmpv6Packet::new_unchecked(&mut tx_buf[..icmp_repr.buffer_len()]);
                        icmp_repr.emit(
                            &iphc_repr.src_addr.into(),
                            &iphc_repr.dst_addr.into(),
                            &mut icmp_packet,
                            &self.caps.checksum,
                        );
                    }
                    _ => return Err(Error::Unrecognized),
                }
                Ok(())
            })
        }
    }

    #[cfg(all(
        feature = "medium-ieee802154",
        feature = "proto-sixlowpan-fragmentation"
    ))]
    pub(super) fn dispatch_ieee802154_out_packet<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        out_packet: &mut SixlowpanOutPacket,
    ) -> Result<()> {
        let SixlowpanOutPacket {
            buffer,
            packet_len,
            datagram_size,
            datagram_tag,
            datagram_offset,
            sent_bytes,
            fragn_size,
            ll_dst_addr,
            ll_src_addr,
            ..
        } = out_packet;

        // Create the IEEE802.15.4 header.
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(self.get_sequence_number()),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: self.pan_id,
            dst_addr: Some(*ll_dst_addr),
            src_pan_id: self.pan_id,
            src_addr: Some(*ll_src_addr),
        };

        // Create the FRAG_N header.
        let fragn = SixlowpanFragRepr::Fragment {
            size: *datagram_size,
            tag: *datagram_tag,
            offset: (*datagram_offset / 8) as u8,
        };

        let ieee_len = ieee_repr.buffer_len();
        let frag_size = (*packet_len - *sent_bytes).min(*fragn_size);

        tx_token.consume(
            self.now,
            ieee_repr.buffer_len() + fragn.buffer_len() + frag_size,
            |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];

                let mut frag_packet =
                    SixlowpanFragPacket::new_unchecked(&mut tx_buf[..fragn.buffer_len()]);
                fragn.emit(&mut frag_packet);
                tx_buf = &mut tx_buf[fragn.buffer_len()..];

                // Add the buffer part
                tx_buf[..frag_size].copy_from_slice(&buffer[*sent_bytes..][..frag_size]);

                *sent_bytes += frag_size;
                *datagram_offset += frag_size;

                Ok(())
            },
        )
    }
}
