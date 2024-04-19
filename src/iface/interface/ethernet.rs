use super::*;

impl InterfaceInner {
    pub(super) fn process_ethernet<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        fragments: &'frame mut FragmentsBuffer,
    ) -> Option<EthernetPacket<'frame>> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr
        {
            return None;
        }

        #[cfg(feature = "proto-vlan")]
        if let Some(vlan_config) = &self.vlan_config {
            // Drop all frames without VLAN header
            match vlan_config.outer_vlan_id {
                Some(_) if eth_frame.ethertype() != EthernetProtocol::VlanOuter => return None,
                None if eth_frame.ethertype() != EthernetProtocol::VlanInner => return None,
                _ => (),
            }
        }

        self.handle_ethertype(
            sockets,
            meta,
            eth_frame.payload(),
            eth_frame.ethertype(),
            fragments,
        )
    }

    fn handle_ethertype<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: crate::phy::PacketMeta,
        payload: &'frame [u8],
        ethertype: EthernetProtocol,
        fragments: &'frame mut FragmentsBuffer,
    ) -> Option<EthernetPacket<'frame>> {
        match ethertype {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(self.now, payload),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(payload));

                self.process_ipv4(sockets, meta, &ipv4_packet, fragments)
                    .map(EthernetPacket::Ip)
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(payload));
                self.process_ipv6(sockets, meta, &ipv6_packet)
                    .map(EthernetPacket::Ip)
            }
            #[cfg(feature = "proto-vlan")]
            EthernetProtocol::VlanInner | EthernetProtocol::VlanOuter => match &self.vlan_config {
                Some(vlan_config) => {
                    let vlan_packet = check!(VlanPacket::new_checked(payload));
                    if ethertype == EthernetProtocol::VlanOuter
                        && (vlan_config.outer_vlan_id.is_none()
                            || !matches!(
                                vlan_config.outer_vlan_id,
                                Some(vid) if vid == vlan_packet.vlan_identifier()
                            )
                            || vlan_packet.ethertype() != EthernetProtocol::VlanInner)
                    {
                        return None;
                    }
                    if ethertype == EthernetProtocol::VlanInner
                        && (vlan_packet.ethertype() == EthernetProtocol::VlanInner
                            || vlan_packet.ethertype() == EthernetProtocol::VlanOuter
                            || vlan_packet.vlan_identifier() != vlan_config.inner_vlan_id)
                    {
                        return None;
                    }
                    return self.handle_ethertype(
                        sockets,
                        meta,
                        &payload[VlanPacket::<&[u8]>::header_len()..],
                        vlan_packet.ethertype(),
                        fragments,
                    );
                }
                None => None,
            },
            // Drop all other traffic.
            _ => None,
        }
    }

    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);

            f(frame);

            Ok(())
        })
    }
}
