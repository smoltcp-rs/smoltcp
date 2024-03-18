use super::*;
use crate::wire::Result;

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

impl Interface {
    /// Process fragments that still need to be sent for 6LoWPAN packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub(super) fn sixlowpan_egress<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        // Reset the buffer when we transmitted everything.
        if self.fragmenter.finished() {
            self.fragmenter.reset();
        }

        if self.fragmenter.is_empty() {
            return false;
        }

        let pkt = &self.fragmenter;
        if pkt.packet_len > pkt.sent_bytes {
            if let Some(tx_token) = device.transmit(self.inner.now) {
                self.inner
                    .dispatch_ieee802154_frag(tx_token, &mut self.fragmenter);
                return true;
            }
        }
        false
    }

    /// Get the 6LoWPAN address contexts.
    pub fn sixlowpan_address_context(&self) -> &[SixlowpanAddressContext] {
        &self.inner.sixlowpan_address_context[..]
    }

    /// Get a mutable reference to the 6LoWPAN address contexts.
    pub fn sixlowpan_address_context_mut(
        &mut self,
    ) -> &mut Vec<SixlowpanAddressContext, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT> {
        &mut self.inner.sixlowpan_address_context
    }
}

impl InterfaceInner {
    /// Get the next tag for a 6LoWPAN fragment.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn get_sixlowpan_fragment_tag(&mut self) -> u16 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        tag
    }

    pub(super) fn process_sixlowpan<'output, 'payload: 'output>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload [u8],
        f: &'output mut FragmentsBuffer,
    ) -> Option<Packet<'output>> {
        let payload = match check!(SixlowpanPacket::dispatch(payload)) {
            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            SixlowpanPacket::FragmentHeader => {
                net_debug!(
                    "Fragmentation is not supported, \
                    use the `proto-sixlowpan-fragmentation` feature to add support."
                );
                return None;
            }
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            SixlowpanPacket::FragmentHeader => {
                match self.process_sixlowpan_fragment(ieee802154_repr, payload, f) {
                    Some(payload) => payload,
                    None => return None,
                }
            }
            SixlowpanPacket::IphcHeader => {
                match Self::sixlowpan_to_ipv6(
                    &self.sixlowpan_address_context,
                    ieee802154_repr,
                    payload,
                    None,
                    &mut f.decompress_buf,
                ) {
                    Ok(len) => &f.decompress_buf[..len],
                    Err(e) => {
                        net_debug!("sixlowpan decompress failed: {:?}", e);
                        return None;
                    }
                }
            }
        };

        self.process_ipv6(
            src_ll_addr,
            sockets,
            meta,
            &check!(Ipv6Packet::new_checked(payload)),
        )
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn process_sixlowpan_fragment<'output, 'payload: 'output>(
        &mut self,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload [u8],
        f: &'output mut FragmentsBuffer,
    ) -> Option<&'output [u8]> {
        use crate::iface::fragmentation::{AssemblerError, AssemblerFullError};

        // We have a fragment header, which means we cannot process the 6LoWPAN packet,
        // unless we have a complete one after processing this fragment.
        let frag = check!(SixlowpanFragPacket::new_checked(payload));

        // The key specifies to which 6LoWPAN fragment it belongs too.
        // It is based on the link layer addresses, the tag and the size.
        let key = FragKey::Sixlowpan(frag.get_key(ieee802154_repr));

        // The offset of this fragment in increments of 8 octets.
        let offset = frag.datagram_offset() as usize * 8;

        // We reserve a spot in the packet assembler set and add the required
        // information to the packet assembler.
        // This information is the total size of the packet when it is fully assmbled.
        // We also pass the header size, since this is needed when other fragments
        // (other than the first one) are added.
        let frag_slot = match f.assembler.get(&key, self.now + f.reassembly_timeout) {
            Ok(frag) => frag,
            Err(AssemblerFullError) => {
                net_debug!("No available packet assembler for fragmented packet");
                return None;
            }
        };

        if frag.is_first_fragment() {
            // The first fragment contains the total size of the IPv6 packet.
            // However, we received a packet that is compressed following the 6LoWPAN
            // standard. This means we need to convert the IPv6 packet size to a 6LoWPAN
            // packet size. The packet size can be different because of first the
            // compression of the IP header and when UDP is used (because the UDP header
            // can also be compressed). Other headers are not compressed by 6LoWPAN.

            // First segment tells us the total size.
            let total_size = frag.datagram_size() as usize;
            if frag_slot.set_total_size(total_size).is_err() {
                net_debug!("No available packet assembler for fragmented packet");
                return None;
            }

            // Decompress headers+payload into the assembler.
            if let Err(e) = frag_slot.add_with(0, |buffer| {
                Self::sixlowpan_to_ipv6(
                    &self.sixlowpan_address_context,
                    ieee802154_repr,
                    frag.payload(),
                    Some(total_size),
                    buffer,
                )
                .map_err(|_| AssemblerError)
            }) {
                net_debug!("fragmentation error: {:?}", e);
                return None;
            }
        } else {
            // Add the fragment to the packet assembler.
            if let Err(e) = frag_slot.add(frag.payload(), offset) {
                net_debug!("fragmentation error: {:?}", e);
                return None;
            }
        }

        match frag_slot.assemble() {
            Some(payload) => {
                net_trace!("6LoWPAN: fragmented packet now complete");
                Some(payload)
            }
            None => None,
        }
    }

    /// Decompress a 6LoWPAN packet into an IPv6 packet.
    ///
    /// The return value is the length of the decompressed packet, but not including the total
    /// length of the payload of the UDP packet. This value is then used by the assembler to know
    /// how far in the assembler buffer the packet is.
    ///
    /// **NOTE**: when decompressing a fragmented packet, the `total_len` parameter should be
    /// passed. This is the total length of the IPv6 packet, including the IPv6 header. It is used
    /// for calculating the length field in the UDP header.
    fn sixlowpan_to_ipv6(
        address_context: &[SixlowpanAddressContext],
        ieee802154_repr: &Ieee802154Repr,
        iphc_payload: &[u8],
        total_len: Option<usize>,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let iphc = SixlowpanIphcPacket::new_checked(iphc_payload)?;
        let iphc_repr = SixlowpanIphcRepr::parse(
            &iphc,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
            address_context,
        )?;

        // The first thing we have to decompress is the IPv6 header. However, at this point we
        // don't know the total size of the packet, neither the next header, since that can be a
        // compressed header. However, we know that the IPv6 header is 40 bytes, so we can reserve
        // this space in the buffer such that we can decompress the IPv6 header into it at a later
        // point.
        let (ipv6_buffer, mut buffer) = buffer.split_at_mut(40);
        let mut ipv6_header = Ipv6Packet::new_unchecked(ipv6_buffer);

        // If the total length is given, we are dealing with a fragmented packet. The total
        // length is then used to calculate the length field for the UDP header. If the total
        // length is not given, we are not working with a fragmented packet, and we need to
        // calculate the length of the payload ourselves.
        let mut payload_len = 40;
        let mut decompressed_len = 40;

        let mut next_header = Some(iphc_repr.next_header);
        let mut data = iphc.payload();

        while let Some(nh) = next_header {
            match nh {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(data)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        (buffer, data) = decompress_ext_hdr(
                            data,
                            &mut next_header,
                            buffer,
                            &mut payload_len,
                            &mut decompressed_len,
                        )?;
                    }
                    SixlowpanNhcPacket::UdpHeader => {
                        decompress_udp(
                            data,
                            &iphc_repr,
                            buffer,
                            total_len,
                            &mut payload_len,
                            &mut decompressed_len,
                        )?;

                        break;
                    }
                },
                SixlowpanNextHeader::Uncompressed(proto) => {
                    // We have a 6LoWPAN uncompressed header.
                    match proto {
                        IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmpv6 => {
                            // There can be no protocol after this one, so we can just copy the
                            // rest of the data buffer. There is also no length field in the UDP
                            // header that we need to correct as this header was not changed by the
                            // 6LoWPAN compressor.
                            if data.len() > buffer.len() {
                                return Err(Error);
                            }
                            buffer[..data.len()].copy_from_slice(data);
                            payload_len += data.len();
                            decompressed_len += data.len();
                            break;
                        }
                        proto => {
                            net_debug!("Unsupported uncompressed next header: {:?}", proto);
                            return Err(Error);
                        }
                    }
                }
            }
        }

        let ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            next_header: decompress_next_header(iphc_repr.next_header, iphc.payload())?,
            payload_len: total_len.unwrap_or(payload_len) - 40,
            hop_limit: iphc_repr.hop_limit,
        };
        ipv6_repr.emit(&mut ipv6_header);

        Ok(decompressed_len)
    }

    pub(super) fn dispatch_sixlowpan<Tx: TxToken>(
        &mut self,
        mut tx_token: Tx,
        meta: PacketMeta,
        mut packet: PacketV6,
        ieee_repr: Ieee802154Repr,
        frag: &mut Fragmenter,
    ) {
        #[cfg(feature = "proto-rpl")]
        if packet.header().dst_addr.is_unicast()
            && self.rpl.dodag.is_some()
            && packet.hop_by_hop().is_none()
            && packet.routing().is_none()
        {
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
            packet.add_hop_by_hop(hbh);
        }

        let sixlowpan_packet = PacketSixlowpan::new(&packet, &ieee_repr);
        let total_size = sixlowpan_packet.buffer_len();

        let ieee_len = ieee_repr.buffer_len();

        // TODO(thvdveld): use the MTU of the device.
        if total_size + ieee_len > 125 {
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            {
                // The packet does not fit in one Ieee802154 frame, so we need fragmentation.
                // We do this by emitting everything in the `frag.buffer` from the interface.
                // After emitting everything into that buffer, we send the first fragment heere.
                // When `poll` is called again, we check if frag was fully sent, otherwise we
                // call `dispatch_ieee802154_frag`, which will transmit the other fragments.

                // `dispatch_ieee802154_frag` requires some information about the total packet size,
                // the link local source and destination address...

                let pkt = frag;
                if pkt.buffer.len() < total_size {
                    net_debug!(
                        "dispatch_ieee802154: dropping, \
                        fragmentation buffer is too small, at least {} needed",
                        total_size
                    );
                    return;
                }

                let payload_length = packet.header().payload_len;

                sixlowpan_packet.emit(&mut pkt.buffer[..], &self.checksum_caps());

                pkt.sixlowpan.ll_dst_addr = ieee_repr.dst_addr.unwrap();
                pkt.sixlowpan.ll_src_addr = ieee_repr.src_addr.unwrap();
                pkt.packet_len = total_size;

                // The datagram size that we need to set in the first fragment header is equal to the
                // IPv6 payload length + 40.
                pkt.sixlowpan.datagram_size = (payload_length + 40) as u16;

                let tag = self.get_sixlowpan_fragment_tag();
                // We save the tag for the other fragments that will be created when calling `poll`
                // multiple times.
                pkt.sixlowpan.datagram_tag = tag;

                let frag1 = SixlowpanFragRepr::FirstFragment {
                    size: pkt.sixlowpan.datagram_size,
                    tag,
                };
                let fragn = SixlowpanFragRepr::Fragment {
                    size: pkt.sixlowpan.datagram_size,
                    tag,
                    offset: 0,
                };

                // We calculate how much data we can send in the first fragment and the other
                // fragments. The eventual IPv6 sizes of these fragments need to be a multiple of eight
                // (except for the last fragment) since the offset field in the fragment is an offset
                // in multiples of 8 octets. This is explained in [RFC 4944 § 5.3].
                //
                // [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

                let header_diff = sixlowpan_packet.header_diff();
                let frag1_size =
                    (125 - ieee_len - frag1.buffer_len() + header_diff) / 8 * 8 - header_diff;

                pkt.sixlowpan.fragn_size = (125 - ieee_len - fragn.buffer_len()) / 8 * 8;
                pkt.sent_bytes = frag1_size;
                pkt.sixlowpan.datagram_offset = frag1_size + header_diff;

                tx_token.set_meta(meta);
                tx_token.consume(ieee_len + frag1.buffer_len() + frag1_size, |mut tx_buf| {
                    // Add the IEEE header.
                    let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                    ieee_repr.emit(&mut ieee_packet);
                    tx_buf = &mut tx_buf[ieee_len..];

                    // Add the first fragment header
                    let mut frag1_packet = SixlowpanFragPacket::new_unchecked(&mut tx_buf);
                    frag1.emit(&mut frag1_packet);
                    tx_buf = &mut tx_buf[frag1.buffer_len()..];

                    // Add the buffer part.
                    tx_buf[..frag1_size].copy_from_slice(&pkt.buffer[..frag1_size]);
                });
            }

            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            {
                net_debug!(
                    "Enable the `proto-sixlowpan-fragmentation` feature for fragmentation support."
                );
                return;
            }
        } else {
            tx_token.set_meta(meta);

            // We don't need fragmentation, so we emit everything to the TX token.
            tx_token.consume(total_size + ieee_len, |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];

                sixlowpan_packet.emit(tx_buf, &self.checksum_caps());
            });
        }
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub(super) fn dispatch_sixlowpan_frag<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        ieee_repr: Ieee802154Repr,
        frag: &mut Fragmenter,
    ) {
        // Create the FRAG_N header.
        let fragn = SixlowpanFragRepr::Fragment {
            size: frag.sixlowpan.datagram_size,
            tag: frag.sixlowpan.datagram_tag,
            offset: (frag.sixlowpan.datagram_offset / 8) as u8,
        };

        let ieee_len = ieee_repr.buffer_len();
        let frag_size = (frag.packet_len - frag.sent_bytes).min(frag.sixlowpan.fragn_size);

        tx_token.consume(
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
                tx_buf[..frag_size].copy_from_slice(&frag.buffer[frag.sent_bytes..][..frag_size]);

                frag.sent_bytes += frag_size;
                frag.sixlowpan.datagram_offset += frag_size;
            },
        );
    }
}

/// Convert a 6LoWPAN next header to an IPv6 next header.
#[inline]
fn decompress_next_header(next_header: SixlowpanNextHeader, payload: &[u8]) -> Result<IpProtocol> {
    match next_header {
        SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
            SixlowpanNhcPacket::ExtHeader => {
                let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload)?;
                Ok(ext_hdr.extension_header_id().into())
            }
            SixlowpanNhcPacket::UdpHeader => Ok(IpProtocol::Udp),
        },
        SixlowpanNextHeader::Uncompressed(proto) => Ok(proto),
    }
}

// NOTE: we always inline this function into the sixlowpan_to_ipv6 function, since it is only used there.
#[inline(always)]
fn decompress_ext_hdr<'d>(
    mut data: &'d [u8],
    next_header: &mut Option<SixlowpanNextHeader>,
    mut buffer: &'d mut [u8],
    payload_len: &mut usize,
    decompressed_len: &mut usize,
) -> Result<(&'d mut [u8], &'d [u8])> {
    let ext_hdr = SixlowpanExtHeaderPacket::new_checked(data)?;
    let ext_repr = SixlowpanExtHeaderRepr::parse(&ext_hdr)?;
    let nh = decompress_next_header(
        ext_repr.next_header,
        &data[ext_repr.length as usize + ext_repr.buffer_len()..],
    )?;
    *next_header = Some(ext_repr.next_header);
    let ipv6_ext_hdr = Ipv6ExtHeaderRepr {
        next_header: nh,
        length: ext_repr.length / 8,
        data: ext_hdr.payload(),
    };
    if ipv6_ext_hdr.header_len() + ipv6_ext_hdr.data.len() > buffer.len() {
        return Err(Error);
    }
    ipv6_ext_hdr.emit(&mut Ipv6ExtHeader::new_unchecked(
        &mut buffer[..ipv6_ext_hdr.header_len()],
    ));
    buffer[ipv6_ext_hdr.header_len()..][..ipv6_ext_hdr.data.len()]
        .copy_from_slice(ipv6_ext_hdr.data);
    buffer = &mut buffer[ipv6_ext_hdr.header_len() + ipv6_ext_hdr.data.len()..];
    *payload_len += ipv6_ext_hdr.header_len() + ipv6_ext_hdr.data.len();
    *decompressed_len += ipv6_ext_hdr.header_len() + ipv6_ext_hdr.data.len();
    data = &data[ext_repr.buffer_len() + ext_repr.length as usize..];
    Ok((buffer, data))
}

// NOTE: we always inline this function into the sixlowpan_to_ipv6 function, since it is only used there.
#[inline(always)]
fn decompress_udp(
    data: &[u8],
    iphc_repr: &SixlowpanIphcRepr,
    buffer: &mut [u8],
    total_len: Option<usize>,
    payload_len: &mut usize,
    decompressed_len: &mut usize,
) -> Result<()> {
    let udp_packet = SixlowpanUdpNhcPacket::new_checked(data)?;
    let payload = udp_packet.payload();
    let udp_repr = SixlowpanUdpNhcRepr::parse(
        &udp_packet,
        &iphc_repr.src_addr,
        &iphc_repr.dst_addr,
        &ChecksumCapabilities::ignored(),
    )?;
    if udp_repr.header_len() + payload.len() > buffer.len() {
        return Err(Error);
    }
    let udp_payload_len = if let Some(total_len) = total_len {
        total_len - *payload_len - 8
    } else {
        payload.len()
    };
    *payload_len += udp_payload_len + 8;
    *decompressed_len += udp_repr.0.header_len() + payload.len();
    let mut udp = UdpPacket::new_unchecked(&mut buffer[..payload.len() + 8]);
    udp_repr.0.emit_header(&mut udp, udp_payload_len);
    buffer[8..][..payload.len()].copy_from_slice(payload);
    Ok(())
}

struct PacketSixlowpan<'p> {
    iphc: SixlowpanIphcRepr,
    #[cfg(feature = "proto-ipv6-hbh")]
    hbh: Option<(SixlowpanExtHeaderRepr, &'p [Ipv6OptionRepr<'p>])>,
    #[cfg(feature = "proto-ipv6-routing")]
    routing: Option<(SixlowpanExtHeaderRepr, &'p Ipv6RoutingRepr)>,
    payload: SixlowpanPayload<'p>,

    header_diff: usize,
}

enum SixlowpanPayload<'p> {
    Icmpv6(&'p Icmpv6Repr<'p>),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    Udp(UdpRepr, &'p [u8], Option<u16>),
    #[cfg(feature = "proto-rpl")]
    Raw(&'p [u8]),
}

impl<'p> PacketSixlowpan<'p> {
    /// Create a 6LoWPAN compressed representation packet from an IPv6 representation.
    fn new(packet: &'p PacketV6<'_>, ieee_repr: &Ieee802154Repr) -> Self {
        let mut compressed = 0;
        let mut uncompressed = 0;

        let iphc = SixlowpanIphcRepr {
            src_addr: packet.header().src_addr,
            ll_src_addr: ieee_repr.src_addr,
            dst_addr: packet.header().dst_addr,
            ll_dst_addr: ieee_repr.dst_addr,
            next_header: packet.header().next_header.into(),
            hop_limit: packet.header().hop_limit,
            ecn: None,
            dscp: None,
            flow_label: None,
        };
        compressed += iphc.buffer_len();
        uncompressed += packet.header().buffer_len();

        let mut last_header = packet.header().next_header;

        #[cfg(feature = "proto-ipv6-hbh")]
        let hbh = if let Some((next_header, hbh)) = packet.hop_by_hop() {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::HopByHopHeader,
                next_header: next_header.into(),
                length: hbh.options.iter().map(|o| o.buffer_len() as u8).sum(),
            };

            compressed += ext_hdr.buffer_len();
            uncompressed += hbh.buffer_len();

            last_header = next_header;
            Some((ext_hdr, &hbh.options[..]))
        } else {
            None
        };

        #[cfg(feature = "proto-ipv6-routing")]
        let routing = if let Some((next_header, routing)) = packet.routing() {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::RoutingHeader,
                next_header: next_header.into(),
                length: routing.buffer_len() as u8,
            };

            compressed += ext_hdr.buffer_len() + routing.buffer_len();
            uncompressed += routing.buffer_len();

            last_header = next_header;
            Some((ext_hdr, routing))
        } else {
            None
        };

        let payload = match packet.payload() {
            IpPayload::Icmpv6(icmp_repr) => SixlowpanPayload::Icmpv6(icmp_repr),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayload::Udp(udp_repr, payload) => {
                compressed += SixlowpanUdpNhcRepr(*udp_repr).header_len();
                uncompressed += udp_repr.header_len();

                SixlowpanPayload::Udp(*udp_repr, payload, None)
            }
            #[cfg(feature = "proto-rpl")]
            IpPayload::Raw(raw) => {
                match last_header {
                    IpProtocol::Udp => {
                        // TODO: remove unwrap
                        let udp_packet = UdpPacket::new_checked(raw).unwrap();
                        let udp_repr = UdpRepr::parse(
                            &udp_packet,
                            &packet.header().src_addr.into(),
                            &packet.header().dst_addr.into(),
                            &ChecksumCapabilities::ignored(),
                        )
                        .unwrap();

                        compressed += SixlowpanUdpNhcRepr(udp_repr).header_len();
                        uncompressed += udp_repr.header_len();

                        SixlowpanPayload::Udp(
                            udp_repr,
                            udp_packet.payload(),
                            Some(udp_packet.checksum()),
                        )
                    }
                    // Any other protocol does not need compression.
                    _ => SixlowpanPayload::Raw(raw),
                }
            }
            _ => unreachable!(),
        };

        PacketSixlowpan {
            iphc,
            #[cfg(feature = "proto-ipv6-hbh")]
            hbh,
            #[cfg(feature = "proto-ipv6-routing")]
            routing,
            payload,

            header_diff: uncompressed - compressed,
        }
    }

    /// Return the required length for the underlying buffer when emitting the packet.
    fn buffer_len(&self) -> usize {
        let mut len = 0;

        len += self.iphc.buffer_len();

        #[cfg(feature = "proto-ipv6-hbh")]
        if let Some((ext_hdr, hbh)) = &self.hbh {
            len += ext_hdr.buffer_len();
            len += hbh.iter().map(|o| o.buffer_len()).sum::<usize>();
        }

        #[cfg(feature = "proto-ipv6-routing")]
        if let Some((ext_hdr, routing)) = &self.routing {
            len += ext_hdr.buffer_len() + routing.buffer_len();
        }

        match self.payload {
            SixlowpanPayload::Icmpv6(icmp_repr) => len + icmp_repr.buffer_len(),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            SixlowpanPayload::Udp(udp_repr, payload, _) => {
                len + SixlowpanUdpNhcRepr(udp_repr).header_len() + payload.len()
            }
            #[cfg(feature = "proto-rpl")]
            SixlowpanPayload::Raw(payload) => len + payload.len(),
        }
    }

    /// Return the difference between the compressed and uncompressed header sizes.
    fn header_diff(&self) -> usize {
        self.header_diff
    }

    /// Emit the packet into the given buffer.
    fn emit(&self, mut buffer: &mut [u8], caps: &ChecksumCapabilities) {
        let mut checksum_dst_addr = self.iphc.dst_addr;

        self.iphc.emit(&mut SixlowpanIphcPacket::new_unchecked(
            &mut buffer[..self.iphc.buffer_len()],
        ));

        buffer = &mut buffer[self.iphc.buffer_len()..];

        #[cfg(feature = "proto-ipv6-hbh")]
        if let Some((ext_hdr, hbh)) = &self.hbh {
            ext_hdr.emit(&mut SixlowpanExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            buffer = &mut buffer[ext_hdr.buffer_len()..];

            for opt in hbh.iter() {
                opt.emit(&mut Ipv6Option::new_unchecked(
                    &mut buffer[..opt.buffer_len()],
                ));
                buffer = &mut buffer[opt.buffer_len()..];
            }
        }

        #[cfg(feature = "proto-ipv6-routing")]
        if let Some((ext_hdr, routing)) = &self.routing {
            if let Ipv6RoutingRepr::Rpl { addresses, .. } = routing {
                checksum_dst_addr = *addresses.last().unwrap();
            }

            ext_hdr.emit(&mut SixlowpanExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            buffer = &mut buffer[ext_hdr.buffer_len()..];

            routing.emit(&mut Ipv6RoutingHeader::new_unchecked(
                &mut buffer[..routing.buffer_len()],
            ));
            buffer = &mut buffer[routing.buffer_len()..];
        }

        match self.payload {
            SixlowpanPayload::Icmpv6(icmp_repr) => icmp_repr.emit(
                &self.iphc.src_addr,
                &checksum_dst_addr,
                &mut Icmpv6Packet::new_unchecked(&mut buffer[..icmp_repr.buffer_len()]),
                caps,
            ),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            SixlowpanPayload::Udp(udp_repr, payload, checksum) => {
                let udp = SixlowpanUdpNhcRepr(udp_repr);
                let mut udp_packet = SixlowpanUdpNhcPacket::new_unchecked(
                    &mut buffer[..udp.header_len() + payload.len()],
                );
                udp.emit(
                    &mut udp_packet,
                    &self.iphc.src_addr,
                    &checksum_dst_addr,
                    payload.len(),
                    |buf| buf.copy_from_slice(payload),
                    caps,
                );

                if let Some(checksum) = checksum {
                    udp_packet.set_checksum(checksum);
                }
            }
            #[cfg(feature = "proto-rpl")]
            SixlowpanPayload::Raw(payload) => buffer[..payload.len()].copy_from_slice(payload),
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "proto-rpl", feature = "proto-ipv6-hbh"))]
mod tests {
    use super::*;

    static SIXLOWPAN_COMPRESSED_RPL_DAO: [u8; 99] = [
        0x61, 0xdc, 0x45, 0xcd, 0xab, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x7e, 0xf7, 0x00, 0xe0, 0x3a, 0x06, 0x63, 0x04, 0x00,
        0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e, 0x63, 0x1e, 0x40, 0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x05, 0x12, 0x00,
        0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    static SIXLOWPAN_UNCOMPRESSED_RPL_DAO: [u8; 114] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x3a, 0x00, 0x63, 0x04, 0x00,
        0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e, 0x63, 0x1e, 0x40, 0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x05, 0x12, 0x00,
        0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn test_sixlowpan_decompress_hop_by_hop_with_icmpv6() {
        let address_context = [SixlowpanAddressContext([
            0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ])];

        let ieee_frame = Ieee802154Frame::new_checked(&SIXLOWPAN_COMPRESSED_RPL_DAO).unwrap();
        let ieee_repr = Ieee802154Repr::parse(&ieee_frame).unwrap();

        let mut buffer = [0u8; 256];
        let len = InterfaceInner::sixlowpan_to_ipv6(
            &address_context,
            &ieee_repr,
            ieee_frame.payload().unwrap(),
            None,
            &mut buffer[..],
        )
        .unwrap();

        assert_eq!(&buffer[..len], &SIXLOWPAN_UNCOMPRESSED_RPL_DAO);
    }

    #[test]
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    fn test_sixlowpan_compress_hop_by_hop_with_icmpv6() {
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            sequence_number: Some(69),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2006,
            dst_pan_id: Some(Ieee802154Pan(43981)),
            dst_addr: Some(Ieee802154Address::Extended([0, 1, 0, 1, 0, 1, 0, 1])),
            src_pan_id: None,
            src_addr: Some(Ieee802154Address::Extended([0, 3, 0, 3, 0, 3, 0, 3])),
        };

        let dao = Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(RplDao {
            rpl_instance_id: RplInstanceId::Global(30),
            expect_ack: false,
            sequence: 241.into(),
            dodag_id: Some(Ipv6Address::from_bytes(&[
                253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
            ])),
            options: heapless::Vec::new(),
        }));

        let ip_packet = PacketV6::new(
            Ipv6Repr {
                src_addr: Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 0, 3, 0, 3,
                ]),
                dst_addr: Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
                ]),
                next_header: IpProtocol::Icmpv6,
                payload_len: dao.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Icmpv6(dao),
        );

        let sixlowpan_packet = PacketSixlowpan::new(&ip_packet, &ieee_repr);
        let total_size = sixlowpan_packet.buffer_len();
        let mut buffer = vec![0u8; total_size];

        sixlowpan_packet.emit(&mut buffer[..total_size], &ChecksumCapabilities::default());

        let result = [
            0x7e, 0x0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3, 0x0, 0x3, 0x0,
            0x3, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
            0xe0, 0x3a, 0x6, 0x63, 0x4, 0x0, 0x1e, 0x3, 0x0, 0x9b, 0x2, 0x3e, 0x63, 0x1e, 0x40,
            0x0, 0xf1, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x1, 0x5, 0x12, 0x0, 0x80, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3,
            0x0, 0x3, 0x0, 0x3, 0x6, 0x14, 0x0, 0x0, 0x0, 0x1e, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
        ];

        assert_eq!(&result, &result);
    }

    #[test]
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    fn test_sixlowpan_compress_hop_by_hop_with_udp() {
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            sequence_number: Some(69),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2006,
            dst_pan_id: Some(Ieee802154Pan(43981)),
            dst_addr: Some(Ieee802154Address::Extended([0, 1, 0, 1, 0, 1, 0, 1])),
            src_pan_id: None,
            src_addr: Some(Ieee802154Address::Extended([0, 3, 0, 3, 0, 3, 0, 3])),
        };

        let addr = Ipv6Address::from_bytes(&[253, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 0, 3, 0, 3]);
        let parent_address =
            Ipv6Address::from_bytes(&[253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1]);

        let mut hbh_options = heapless::Vec::new();
        hbh_options
            .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                down: false,
                rank_error: false,
                forwarding_error: false,
                instance_id: RplInstanceId::from(0x1e),
                sender_rank: 0x300,
            }))
            .unwrap();

        let mut options = heapless::Vec::new();
        options
            .push(RplOptionRepr::RplTarget(RplTarget {
                prefix_length: 128,
                prefix: heapless::Vec::from_slice(addr.as_bytes()).unwrap(),
            }))
            .unwrap();
        options
            .push(RplOptionRepr::TransitInformation(RplTransitInformation {
                external: false,
                path_control: 0,
                path_sequence: 0,
                path_lifetime: 30,
                parent_address: Some(parent_address),
            }))
            .unwrap();

        let icmp = Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(RplDao {
            rpl_instance_id: RplInstanceId::Global(30),
            expect_ack: false,
            sequence: 241.into(),
            dodag_id: Some(Ipv6Address::from_bytes(&[
                253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
            ])),
            options,
        }));

        let mut ip_packet = PacketV6::new(
            Ipv6Repr {
                src_addr: addr,
                dst_addr: parent_address,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Icmpv6(icmp),
        );

        #[cfg(feature = "proto-rpl")]
        ip_packet.add_hop_by_hop(Ipv6HopByHopRepr {
            options: hbh_options,
        });

        let sixlowpan_packet = PacketSixlowpan::new(&ip_packet, &ieee_repr);
        let total_size = sixlowpan_packet.buffer_len();
        let mut buffer = vec![0u8; total_size];

        sixlowpan_packet.emit(&mut buffer[..total_size], &ChecksumCapabilities::default());

        let result = [
            0x7e, 0x0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3, 0x0, 0x3, 0x0,
            0x3, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
            0xe0, 0x3a, 0x6, 0x63, 0x4, 0x0, 0x1e, 0x3, 0x0, 0x9b, 0x2, 0x3e, 0x63, 0x1e, 0x40,
            0x0, 0xf1, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x1, 0x5, 0x12, 0x0, 0x80, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3,
            0x0, 0x3, 0x0, 0x3, 0x6, 0x14, 0x0, 0x0, 0x0, 0x1e, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
        ];

        assert_eq!(&buffer[..total_size], &result);
    }
}
