use super::check;
use super::EthernetPacket;
use super::FragmentsBuffer;
use super::InterfaceInner;
use super::SocketSet;

use crate::phy::TxToken;
use crate::wire::*;
use crate::Error;
use crate::Result;

impl<'i> InterfaceInner<'i> {
    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_ethernet<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        frame: &'frame T,
        _fragments: &'frame mut FragmentsBuffer<'i>,
    ) -> Option<EthernetPacket<'frame>> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr.unwrap()
        {
            return None;
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(self.now, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(eth_frame.payload()));

                #[cfg(feature = "proto-ipv4-fragmentation")]
                {
                    self.process_ipv4(sockets, &ipv4_packet, Some(&mut _fragments.ipv4_fragments))
                        .map(EthernetPacket::Ip)
                }

                #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                {
                    self.process_ipv4(sockets, &ipv4_packet, None)
                        .map(EthernetPacket::Ip)
                }
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(eth_frame.payload()));
                self.process_ipv6(sockets, &ipv6_packet)
                    .map(EthernetPacket::Ip)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<()>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(self.now, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                addr
            } else {
                return Err(Error::Malformed);
            };

            frame.set_src_addr(src_addr);

            f(frame);

            Ok(())
        })
    }
}
