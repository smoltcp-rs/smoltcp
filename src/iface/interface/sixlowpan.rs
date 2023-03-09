use super::check;
use super::FragmentsBuffer;
use super::InterfaceInner;
use super::IpPacket;
use super::OutPackets;
use super::SocketSet;

#[cfg(feature = "proto-sixlowpan-fragmentation")]
use super::SixlowpanOutPacket;

use crate::phy::ChecksumCapabilities;
use crate::phy::TxToken;
use crate::wire::*;

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

impl InterfaceInner {
    #[cfg(feature = "medium-ieee802154")]
    pub(super) fn process_ieee802154<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        sixlowpan_payload: &'payload T,
        _fragments: &'output mut FragmentsBuffer,
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
            Some(payload) => self.process_sixlowpan(sockets, &ieee802154_repr, payload, _fragments),
            None => None,
        }
    }

    pub(super) fn process_sixlowpan<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        f: &'output mut FragmentsBuffer,
    ) -> Option<IpPacket<'output>> {
        let payload = match check!(SixlowpanPacket::dispatch(payload)) {
            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            SixlowpanPacket::FragmentHeader => {
                net_debug!("Fragmentation is not supported, use the `proto-sixlowpan-fragmentation` feature to add support.");
                return None;
            }
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            SixlowpanPacket::FragmentHeader => {
                match Self::process_sixlowpan_fragment(
                    ieee802154_repr,
                    payload,
                    f,
                    self.now,
                    &self.sixlowpan_address_context,
                ) {
                    Some(payload) => payload,
                    None => return None,
                }
            }
            SixlowpanPacket::IphcHeader => {
                match Self::decompress_sixlowpan(
                    &self.sixlowpan_address_context,
                    ieee802154_repr,
                    payload.as_ref(),
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
            sockets,
            ieee802154_repr.src_addr.map(|a| a.into()),
            &check!(Ipv6Packet::new_checked(payload)),
        )
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub(super) fn process_sixlowpan_fragment<
        'output,
        'payload: 'output,
        T: AsRef<[u8]> + ?Sized,
    >(
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        f: &'output mut FragmentsBuffer,
        now: crate::time::Instant,
        address_context: &[SixlowpanAddressContext],
    ) -> Option<&'output [u8]> {
        use crate::iface::fragmentation::{AssemblerError, AssemblerFullError};

        // We have a fragment header, which means we cannot process the 6LoWPAN packet,
        // unless we have a complete one after processing this fragment.
        let frag = check!(SixlowpanFragPacket::new_checked(payload));

        // The key specifies to which 6LoWPAN fragment it belongs too.
        // It is based on the link layer addresses, the tag and the size.
        let key = frag.get_key(ieee802154_repr);

        // The offset of this fragment in increments of 8 octets.
        let offset = frag.datagram_offset() as usize * 8;

        // We reserve a spot in the packet assembler set and add the required
        // information to the packet assembler.
        // This information is the total size of the packet when it is fully assmbled.
        // We also pass the header size, since this is needed when other fragments
        // (other than the first one) are added.
        let frag_slot = match f
            .sixlowpan_fragments
            .get(&key, now + f.sixlowpan_fragments_cache_timeout)
        {
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
                Self::decompress_sixlowpan(
                    address_context,
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

    pub(crate) fn decompress_sixlowpan(
        address_context: &[SixlowpanAddressContext],
        ieee802154_repr: &Ieee802154Repr,
        iphc_payload: &[u8],
        total_size: Option<usize>,
        buffer: &mut [u8],
    ) -> core::result::Result<usize, crate::wire::Error> {
        let iphc = SixlowpanIphcPacket::new_checked(iphc_payload)?;
        let iphc_repr = SixlowpanIphcRepr::parse(
            &iphc,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
            address_context,
        )?;

        // First we calculate the length of the decompressed packet.
        let calculate_decompressed_size = || -> Result<usize> {
            let mut decompressed_size = 40 + iphc.payload().len();
            let mut nh = Some(iphc_repr.next_header);
            let mut buffer = iphc.payload();

            while let Some(next_hdr) = nh {
                match next_hdr {
                    SixlowpanNextHeader::Compressed => {
                        match SixlowpanNhcPacket::dispatch(buffer)? {
                            SixlowpanNhcPacket::ExtHeader => {
                                let ext_packet = SixlowpanExtHeaderPacket::new_checked(buffer)?;
                                let ext_repr = SixlowpanExtHeaderRepr::parse(&ext_packet)?;
                                nh = Some(ext_repr.next_header);

                                match ext_packet.extension_header_id() {
                                    SixlowpanExtHeaderId::HopByHopHeader => {
                                        buffer = &buffer[2 + ext_packet.header_len() as usize..];
                                    }
                                    _ => todo!(),
                                }
                            }
                            SixlowpanNhcPacket::UdpHeader => {
                                let udp_repr = SixlowpanUdpNhcRepr::parse(
                                    &SixlowpanUdpNhcPacket::new_checked(buffer)?,
                                    &iphc_repr.src_addr,
                                    &iphc_repr.dst_addr,
                                    &crate::phy::ChecksumCapabilities::ignored(),
                                )?;

                                decompressed_size += 8;
                                decompressed_size -= udp_repr.header_len();

                                nh = None;
                            }
                        }
                    }
                    SixlowpanNextHeader::Uncompressed(_) => nh = None,
                }
            }

            Ok(decompressed_size)
        };

        let decompressed_size = calculate_decompressed_size()?;

        if buffer.len() < decompressed_size {
            net_debug!("sixlowpan decompress: buffer too short");
            return Err(crate::wire::Error);
        }
        let buffer = &mut buffer[..decompressed_size];

        let total_size = if let Some(size) = total_size {
            size
        } else {
            decompressed_size
        };

        // Create the IPv6 representation and emit into the buffer.
        let ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            next_header: match iphc_repr.next_header {
                SixlowpanNextHeader::Compressed => {
                    match SixlowpanNhcPacket::dispatch(iphc.payload())? {
                        SixlowpanNhcPacket::ExtHeader => {
                            SixlowpanExtHeaderPacket::new_checked(iphc.payload())?
                                .extension_header_id()
                                .into()
                        }
                        SixlowpanNhcPacket::UdpHeader => IpProtocol::Udp,
                    }
                }
                SixlowpanNextHeader::Uncompressed(proto) => proto,
            },
            payload_len: total_size - 40,
            hop_limit: iphc_repr.hop_limit,
        };

        // Emit the decompressed IPHC header (decompressed to an IPv6 header).
        let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut buffer[..ipv6_repr.buffer_len()]);
        ipv6_repr.emit(&mut ipv6_packet);
        let mut buffer = &mut buffer[ipv6_repr.buffer_len()..];

        let mut processed_headers = 40;

        // Emit all other things:
        let mut nh = Some(iphc_repr.next_header);
        let mut tmp_buffer = iphc.payload();
        while let Some(next_header) = nh {
            match next_header {
                SixlowpanNextHeader::Compressed => {
                    match SixlowpanNhcPacket::dispatch(tmp_buffer)? {
                        SixlowpanNhcPacket::ExtHeader => {
                            let ext_packet = SixlowpanExtHeaderPacket::new_checked(tmp_buffer)?;
                            let ext_repr = SixlowpanExtHeaderRepr::parse(&ext_packet)?;
                            nh = Some(ext_repr.next_header);

                            match ext_packet.extension_header_id() {
                                SixlowpanExtHeaderId::HopByHopHeader => {
                                    let ipv6_hbh = Ipv6HopByHopRepr {
                                        next_header: Some(IpProtocol::Udp),
                                        length: 0,
                                        options: &ext_packet.payload()
                                            [..ext_packet.header_len() as usize],
                                    };
                                    ipv6_hbh.emit(&mut Ipv6HopByHopHeader::new_unchecked(
                                        &mut buffer[..ipv6_hbh.buffer_len()],
                                    ));
                                    buffer = &mut buffer[ipv6_hbh.buffer_len()..];

                                    tmp_buffer =
                                        &tmp_buffer[2 + ext_packet.header_len() as usize..];
                                    processed_headers += 2 + ext_packet.header_len() as usize;
                                }
                                _ => todo!(),
                            }
                        }
                        SixlowpanNhcPacket::UdpHeader => {
                            // We need to uncompress the UDP packet and emit it to the
                            // buffer.
                            let udp_packet = SixlowpanUdpNhcPacket::new_checked(tmp_buffer)?;
                            let udp_repr = SixlowpanUdpNhcRepr::parse(
                                &udp_packet,
                                &iphc_repr.src_addr,
                                &iphc_repr.dst_addr,
                                &ChecksumCapabilities::ignored(),
                            )?;

                            let len = udp_repr.0.header_len() + udp_packet.payload().len();
                            let mut udp = UdpPacket::new_unchecked(&mut buffer[..len]);
                            processed_headers += udp_repr.0.header_len();

                            udp_repr
                                .0
                                .emit_header(&mut udp, total_size - processed_headers);

                            buffer[8..].copy_from_slice(&tmp_buffer[udp_repr.header_len()..]);
                            nh = None;
                        }
                    }
                }
                SixlowpanNextHeader::Uncompressed(_) => {
                    // For uncompressed headers we just copy the slice.
                    let len = iphc.payload().len();
                    buffer[..len].copy_from_slice(iphc.payload());
                    nh = None;
                }
            }
        }

        Ok(decompressed_size)
    }

    #[cfg(feature = "medium-ieee802154")]
    pub(super) fn dispatch_ieee802154<Tx: TxToken>(
        &mut self,
        ll_dst_a: Ieee802154Address,
        tx_token: Tx,
        mut packet: IpPacket,
        _out_packet: Option<&mut OutPackets>,
    ) {
        // We first need to convert the IPv6 packet to a 6LoWPAN compressed packet.
        // Whenever this packet is to big to fit in the IEEE802.15.4 packet, then we need to
        // fragment it.
        let ll_src_a = self.hardware_addr.unwrap().ieee802154_or_panic();

        let ip_repr = packet.ip_repr();

        let (src_addr, dst_addr) = match (ip_repr.src_addr(), ip_repr.dst_addr()) {
            (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => (src_addr, dst_addr),
            #[allow(unreachable_patterns)]
            _ => {
                net_debug!("dispatch_ieee802154: dropping because src or dst addrs are not ipv6.");
                return;
            }
        };

        // Keep track of the total size of the packet, size of the normal headers and the size of
        // the compressed headers. This is required for the fragmentation.
        let mut total_size = 0;
        let mut compressed_headers_len = 0;
        let mut uncompressed_headers_len = 0;

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
        let ieee_len = ieee_repr.buffer_len();

        // Create the 6LoWPAN IPHC header.
        let iphc_repr = SixlowpanIphcRepr {
            src_addr,
            ll_src_addr: Some(ll_src_a),
            dst_addr,
            ll_dst_addr: Some(ll_dst_a),
            next_header: match &mut packet {
                IpPacket::Forward((_, hbh, _)) => {
                    if hbh.is_some() {
                        // We use 6LoWPAN Extension header compression.
                        SixlowpanNextHeader::Compressed
                    } else {
                        // Forwarding a packet is only supported for RPL networks.
                        // In RPL networks, there should always be a HopByHop option.
                        net_debug!("dispatch_ieee802154: dropping because forwarding packet does not contain HopByHop option,");
                        net_debug!("                     which is required in RPL networks.");
                        return;
                    }
                }

                // When in a RPL network, a HopByHop option header with RPL option should be
                // transmitted. When not in a RPL network, only the UDP packets are compressed.
                #[cfg(all(feature = "socket-tcp", feature = "proto-rpl"))]
                IpPacket::Tcp(_) => SixlowpanNextHeader::Compressed,
                #[cfg(all(feature = "socket-udp", feature = "proto-rpl"))]
                IpPacket::Udp(_) => SixlowpanNextHeader::Compressed,

                #[cfg(all(feature = "socket-tcp", not(feature = "proto-rpl")))]
                IpPacket::Tcp(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
                #[cfg(all(feature = "socket-udp", not(feature = "proto-rpl")))]
                IpPacket::Udp(_) => SixlowpanNextHeader::Compressed,

                IpPacket::Icmpv6(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),

                #[allow(unreachable_patterns)]
                _ => {
                    net_debug!("dispatch_ieee802154: dropping, unhandled protocol.");
                    return;
                }
            },
            hop_limit: ip_repr.hop_limit() - u8::from(matches!(packet, IpPacket::Forward(_))),
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        total_size += iphc_repr.buffer_len();
        compressed_headers_len += iphc_repr.buffer_len();
        uncompressed_headers_len += ip_repr.header_len();

        #[cfg(feature = "proto-rpl")]
        let mut calculate_rpl_header_sizes =
            |ext_next_header: SixlowpanNextHeader, next_header: IpProtocol| {
                // TODO(thdveld): fill this struct with correct data.
                let rpl_hbh = Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                    down: false,
                    rank_error: false,
                    forwarding_error: false,
                    instance_id: self.rpl.instance_id,
                    sender_rank: self.rpl.rank.raw_value(),
                });

                let ipv6_hbh = Ipv6HopByHopRepr {
                    next_header: Some(next_header),
                    length: 0,
                    options: &[0u8; 6][..],
                };

                let ext_hdr = SixlowpanExtHeaderRepr {
                    ext_header_id: IpProtocol::HopByHop.into(),
                    next_header: ext_next_header,
                    length: rpl_hbh.buffer_len() as u8,
                };

                compressed_headers_len += ext_hdr.buffer_len() + rpl_hbh.buffer_len();
                uncompressed_headers_len += ipv6_hbh.buffer_len();
                total_size += ext_hdr.buffer_len() + rpl_hbh.buffer_len();
            };

        match packet {
            #[cfg(feature = "proto-rpl")]
            IpPacket::Forward((_, hbh, data)) => {
                match hbh {
                    Some(hbh) => {
                        total_size += 2 + hbh.options.len();

                        let udp_packet = UdpPacket::new_checked(data).unwrap();
                        let udp_repr = SixlowpanUdpNhcRepr(UdpRepr {
                            src_port: udp_packet.src_port(),
                            dst_port: udp_packet.dst_port(),
                        });

                        total_size += udp_repr.header_len();
                    }
                    None => todo!(),
                }

                total_size += data[8..].len();
            }
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udpv6_repr, payload)) => {
                #[cfg(feature = "proto-rpl")]
                {
                    calculate_rpl_header_sizes(SixlowpanNextHeader::Compressed, IpProtocol::Udp);
                }

                let udp_repr = SixlowpanUdpNhcRepr(udpv6_repr);
                compressed_headers_len += udp_repr.header_len();
                uncompressed_headers_len += udpv6_repr.header_len();
                total_size += udp_repr.header_len() + payload.len();
            }
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((_, tcp_repr)) => {
                #[cfg(feature = "proto-rpl")]
                {
                    calculate_rpl_header_sizes(
                        SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
                        IpProtocol::Tcp,
                    );
                }

                total_size += tcp_repr.buffer_len();
            }
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((_, ref icmp_repr)) => {
                total_size += icmp_repr.buffer_len();
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }

        // FIXME(thvdveld): Replace the following with a closure when
        // https://github.com/rust-lang/rust/issues/97362 is stable
        // ```
        // let mut emit_rpl_hbh = for<'b> |buffer: &'b mut [u8]| -> &'b mut [u8] {
        //     // ...
        // };
        // ```
        #[cfg(feature = "proto-rpl")]
        fn emit_rpl_hbh<'b>(
            buffer: &'b mut [u8],
            next_header: SixlowpanNextHeader,
            rpl: &crate::iface::rpl::Rpl,
        ) -> &'b mut [u8] {
            // TODO(thvdveld): fill the RPL option with correct data.
            let rpl_hbh = Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                down: false,
                rank_error: false,
                forwarding_error: false,
                instance_id: rpl.instance_id,
                sender_rank: rpl.rank.raw_value(),
            });

            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: IpProtocol::HopByHop.into(),
                next_header,
                length: rpl_hbh.buffer_len() as u8,
            };

            ext_hdr.emit(&mut SixlowpanExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));

            rpl_hbh.emit(&mut Ipv6Option::new_unchecked(
                &mut buffer[ext_hdr.buffer_len()..][..rpl_hbh.buffer_len()],
            ));
            &mut buffer[ext_hdr.buffer_len() + rpl_hbh.buffer_len()..]
        }

        let emit_from_iphc = |buffer: &mut [u8]| {
            let mut iphc_packet =
                SixlowpanIphcPacket::new_unchecked(&mut buffer[..iphc_repr.buffer_len()]);
            iphc_repr.emit(&mut iphc_packet);

            let b = &mut buffer[iphc_repr.buffer_len()..];

            match packet {
                IpPacket::Forward((_, _, data)) => {
                    #[cfg(feature = "proto-rpl")]
                    let mut b = emit_rpl_hbh(b, SixlowpanNextHeader::Compressed, &self.rpl);

                    let udp_packet = UdpPacket::new_checked(data).unwrap();
                    let udp_repr = SixlowpanUdpNhcRepr(UdpRepr {
                        src_port: udp_packet.src_port(),
                        dst_port: udp_packet.dst_port(),
                    });

                    udp_repr.emit_header(&mut SixlowpanUdpNhcPacket::new_unchecked(
                        &mut b[..udp_repr.header_len()],
                    ));

                    b = &mut b[udp_repr.header_len()..];

                    b[..data[8..].len()].copy_from_slice(&data[8..]);
                }
                #[cfg(feature = "socket-udp")]
                IpPacket::Udp((_, udpv6_repr, payload)) => {
                    #[cfg(feature = "proto-rpl")]
                    let b = emit_rpl_hbh(b, SixlowpanNextHeader::Compressed, &self.rpl);

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
                    #[cfg(feature = "proto-rpl")]
                    let b = emit_rpl_hbh(
                        b,
                        SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
                        &self.rpl,
                    );

                    let mut tcp_packet = TcpPacket::new_unchecked(&mut b[..tcp_repr.buffer_len()]);
                    tcp_repr.emit(
                        &mut tcp_packet,
                        &iphc_repr.src_addr.into(),
                        &iphc_repr.dst_addr.into(),
                        &self.caps.checksum,
                    );
                }
                #[cfg(feature = "proto-ipv6")]
                IpPacket::Icmpv6((_, ref icmp_repr)) => {
                    let mut icmp_packet =
                        Icmpv6Packet::new_unchecked(&mut b[..icmp_repr.buffer_len()]);
                    icmp_repr.emit(
                        &iphc_repr.src_addr.into(),
                        &iphc_repr.dst_addr.into(),
                        &mut icmp_packet,
                        &self.caps.checksum,
                    );
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            }
        };

        if total_size + ieee_len > 125 {
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            {
                // The packet does not fit in one Ieee802154 frame, so we need fragmentation.
                // We do this by emitting everything in the `out_packet.buffer` from the interface.
                // After emitting everything into that buffer, we send the first fragment heere.
                // When `poll` is called again, we check if out_packet was fully sent, otherwise we
                // call `dispatch_ieee802154_out_packet`, which will transmit the other fragments.
                //
                // We calculate how much data we can send in the first fragment and the other
                // fragments. The eventual IPv6 sizes of these fragments need to be a multiple of eight
                // (except for the last fragment) since the offset field in the fragment is an offset
                // in multiples of 8 octets. This is explained in [RFC 4944 § 5.3].
                //
                // [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

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
                    net_debug!(
                        "dispatch_ieee802154: dropping, fragmentation buffer is too small, at least {} needed",
                        total_size
                    );
                    return;
                }

                // Emit everything starting from the IPHC header, without the IPHC fragment
                // headers, until the end into the a buffer.
                emit_from_iphc(buffer);

                // Generate a random tag to identify the stream of fragments.
                let tag = self.get_sixlowpan_fragment_tag();

                // Calculate the size of the uncompressed IPv6 packet.
                let size = (total_size - compressed_headers_len + uncompressed_headers_len) as u16;

                let frag1 = SixlowpanFragRepr::FirstFragment { size, tag };
                let fragn = SixlowpanFragRepr::Fragment {
                    size,
                    tag,
                    offset: 0,
                };

                // Calculate the size of the first IEEE802154 frame.
                let header_diff = uncompressed_headers_len - compressed_headers_len;
                let frag1_size =
                    (125 - ieee_len - frag1.buffer_len() + header_diff) / 8 * 8 - (header_diff);

                // Save all the settings for when the `dispatch_ieee802154_out_packet` function is
                // called.
                *fragn_size = (125 - ieee_len - fragn.buffer_len()) / 8 * 8;
                *packet_len = total_size;
                *ll_dst_addr = ll_dst_a;
                *ll_src_addr = ll_src_a;
                *sent_bytes = frag1_size;
                *datagram_size = size;
                *datagram_tag = tag;
                *datagram_offset = frag1_size + header_diff;

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
                    tx_buf[..frag1_size].copy_from_slice(&buffer[..frag1_size]);
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
            // We don't need fragmentation, so we emit everything to the TX token.
            tx_token.consume(total_size + ieee_len, |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];
                emit_from_iphc(tx_buf);
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
    ) {
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
            frame_version: Ieee802154FrameVersion::Ieee802154_2006,
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
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "proto-rpl")]
    fn decompress_sixlowpan() {
        let data = [
            0x61u8, 0xdc, 0x16, 0xcd, 0xab, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03,
            0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x7e, 0xf5, 0x00, 0x02, 0x01, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0xe1, 0x06, 0x63, 0x04, 0x00, 0x1e, 0x08, 0x00, 0xf0, 0x04,
            0xd2, 0x04, 0xd2, 0x40, 0xb4, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x30,
            0x00,
        ];
        let addr_context = [SixlowpanAddressContext([
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])];

        let ieee802154_packet = Ieee802154Frame::new_checked(&data).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_packet).unwrap();

        let mut buffer = [0u8; 1500];
        let len = InterfaceInner::decompress_sixlowpan(
            &addr_context,
            &ieee802154_repr,
            ieee802154_packet.payload().unwrap(),
            None,
            &mut buffer,
        )
        .unwrap();

        // The buffer should now contain an IPv6 packet.
        let buffer = &buffer[..len];
        let ipv6_packet = Ipv6Packet::new_checked(buffer).unwrap();
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();

        assert_eq!(
            ipv6_repr.src_addr,
            Ipv6Address::new(0xfd00, 0x00, 0x00, 0x00, 0x0203, 0x03, 0x03, 0x03)
        );
        assert_eq!(
            ipv6_repr.dst_addr,
            Ipv6Address::new(0xfd00, 0x00, 0x00, 0x00, 0x0201, 0x01, 0x01, 0x01)
        );
        assert_eq!(ipv6_repr.next_header, IpProtocol::HopByHop);
        assert_eq!(ipv6_repr.hop_limit, 64);

        // And a hop-by-hop header.
        let hbh = Ipv6HopByHopRepr::parse(
            &Ipv6HopByHopHeader::new_checked(ipv6_packet.payload()).unwrap(),
        )
        .unwrap();

        assert_eq!(hbh.next_header, Some(IpProtocol::Udp));
        assert_eq!(hbh.length, 0);

        for opt in hbh.options() {
            let opt = opt.unwrap();
            match opt {
                Ipv6OptionRepr::Rpl(rpl) => {
                    assert!(!rpl.down);
                    assert!(!rpl.rank_error);
                    assert!(!rpl.forwarding_error);
                    assert_eq!(rpl.instance_id, crate::wire::rpl::InstanceId::from(30));
                    assert_eq!(rpl.sender_rank, 2048);
                }
                _ => unreachable!(),
            }
        }

        // And a UDP header.
        let udp_packet =
            UdpPacket::new_checked(&ipv6_packet.payload()[hbh.buffer_len()..]).unwrap();
        let udp = UdpRepr::parse(
            &udp_packet,
            &ipv6_repr.src_addr.into(),
            &ipv6_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();

        assert_eq!(udp.src_port, 1234);
        assert_eq!(udp.dst_port, 1234);
        assert_eq!(udp_packet.payload(), b"Message 0\0");
    }
}
