use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocolType, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{InternetAddress, InternetProtocolType};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr};
use wire::{UdpPacket, UdpRepr};
use super::{ArpCache};

/// An Ethernet network interface.
#[derive(Debug)]
pub struct Interface<'a, DeviceT: Device, ArpCacheT: ArpCache> {
    device:         DeviceT,
    arp_cache:      ArpCacheT,
    hardware_addr:  EthernetAddress,
    protocol_addrs: &'a [InternetAddress]
}

impl<'a, DeviceT: Device, ArpCacheT: ArpCache> Interface<'a, DeviceT, ArpCacheT> {
    /// Create a network interface using the provided network device.
    ///
    /// The newly created interface uses hardware address `00-00-00-00-00-00` and
    /// has no assigned protocol addresses.
    pub fn new(device: DeviceT, arp_cache: ArpCacheT) -> Interface<'a, DeviceT, ArpCacheT> {
        Interface {
            device:         device,
            arp_cache:      arp_cache,
            hardware_addr:  EthernetAddress([0x00; 6]),
            protocol_addrs: &[]
        }
    }

    /// Get the hardware address of the interface.
    pub fn hardware_addr(&self) -> EthernetAddress {
        self.hardware_addr
    }

    /// Set the hardware address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_hardware_addr(&mut self, addr: EthernetAddress) {
        if addr.is_multicast() {
            panic!("hardware address {} is not unicast", addr)
        }

        self.hardware_addr = addr
    }

    /// Get the protocol addresses of the interface.
    pub fn protocol_addrs(&self) -> &'a [InternetAddress] {
        self.protocol_addrs
    }

    /// Set the protocol addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn set_protocol_addrs(&mut self, addrs: &'a [InternetAddress]) {
        for addr in addrs {
            if !addr.is_unicast() {
                panic!("protocol address {} is not unicast", addr)
            }
        }

        self.protocol_addrs = addrs
    }

    /// Checks whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<InternetAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.iter().any(|&probe| probe == addr)
    }

    /// Receive and process a packet, if available.
    pub fn poll(&mut self) -> Result<(), Error> {
        enum Response<'a> {
            Nop,
            Arp(ArpRepr),
            Icmpv4(Ipv4Repr, Icmpv4Repr<'a>)
        }

        let rx_buffer = try!(self.device.receive());
        let eth_frame = try!(EthernetFrame::new(&rx_buffer));

        let mut response = Response::Nop;
        match eth_frame.ethertype() {
            // Snoop all ARP traffic, and respond to ARP packets directed at us.
            EthernetProtocolType::Arp => {
                let arp_packet = try!(ArpPacket::new(eth_frame.payload()));
                match try!(ArpRepr::parse(&arp_packet)) {
                    // Respond to ARP requests aimed at us, and fill the ARP cache
                    // from all ARP requests, including gratuitous.
                    ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Request,
                        source_hardware_addr, source_protocol_addr,
                        target_protocol_addr, ..
                    } => {
                        self.arp_cache.fill(source_protocol_addr.into(), source_hardware_addr);

                        if self.has_protocol_addr(target_protocol_addr) {
                            response = Response::Arp(ArpRepr::EthernetIpv4 {
                                operation: ArpOperation::Reply,
                                source_hardware_addr: self.hardware_addr,
                                source_protocol_addr: target_protocol_addr,
                                target_hardware_addr: source_hardware_addr,
                                target_protocol_addr: source_protocol_addr
                            })
                        }
                    },

                    // Fill the ARP cache from gratuitous ARP replies.
                    ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr, source_protocol_addr, ..
                    } => {
                         self.arp_cache.fill(source_protocol_addr.into(), source_hardware_addr)
                    },

                    _ => return Err(Error::Unrecognized)
                }
            },

            // Handle IP packets directed at us.
            EthernetProtocolType::Ipv4 => {
                let ip_packet = try!(Ipv4Packet::new(eth_frame.payload()));
                match try!(Ipv4Repr::parse(&ip_packet)) {
                    // Ignore IP packets not directed at us.
                    Ipv4Repr { dst_addr, .. } if !self.has_protocol_addr(dst_addr) => (),

                    // Respond to ICMP packets.
                    Ipv4Repr { protocol: InternetProtocolType::Icmp, src_addr, dst_addr } => {
                        let icmp_packet = try!(Icmpv4Packet::new(ip_packet.payload()));
                        let icmp_repr = try!(Icmpv4Repr::parse(&icmp_packet));
                        match icmp_repr {
                            // Respond to echo requests.
                            Icmpv4Repr::EchoRequest {
                                ident, seq_no, data
                            } => {
                                let ip_reply_repr = Ipv4Repr {
                                    src_addr: dst_addr,
                                    dst_addr: src_addr,
                                    protocol: InternetProtocolType::Icmp
                                };
                                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                                    ident:  ident,
                                    seq_no: seq_no,
                                    data:   data
                                };
                                response = Response::Icmpv4(ip_reply_repr, icmp_reply_repr)
                            }

                            // Ignore any echo replies.
                            Icmpv4Repr::EchoReply { .. } => (),

                            // FIXME: do something correct here?
                            _ => return Err(Error::Unrecognized)
                        }
                    },

                    // Queue UDP packets.
                    Ipv4Repr { protocol: InternetProtocolType::Udp, src_addr, dst_addr } => {
                        let udp_packet = try!(UdpPacket::new(ip_packet.payload()));
                        let udp_repr = try!(UdpRepr::parse(&udp_packet,
                                                           &src_addr.into(), &dst_addr.into()));
                        println!("yes")
                    }

                    // FIXME: respond with ICMP unknown protocol here?
                    _ => return Err(Error::Unrecognized)
                }
            }

            // Drop all other traffic.
            _ => return Err(Error::Unrecognized)
        }
        if let Response::Nop = response { return Ok(()) }

        let tx_size = self.device.mtu();
        let mut tx_buffer = try!(self.device.transmit(tx_size));
        let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
        frame.set_src_addr(self.hardware_addr);

        match response {
            Response::Arp(repr) => {
                frame.set_dst_addr(match repr {
                    ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                    _ => unreachable!()
                });
                frame.set_ethertype(EthernetProtocolType::Arp);

                let mut packet = try!(ArpPacket::new(frame.payload_mut()));
                repr.emit(&mut packet)
            },

            Response::Icmpv4(ip_repr, icmp_repr) => {
                match self.arp_cache.lookup(ip_repr.dst_addr.into()) {
                    None => return Err(Error::Unaddressable),
                    Some(hardware_addr) => frame.set_dst_addr(hardware_addr)
                }
                frame.set_ethertype(EthernetProtocolType::Ipv4);

                let mut ip_packet = try!(Ipv4Packet::new(frame.payload_mut()));
                ip_repr.emit(&mut ip_packet, icmp_repr.len());

                let mut icmp_packet = try!(Icmpv4Packet::new(ip_packet.payload_mut()));
                icmp_repr.emit(&mut icmp_packet);
            }

            Response::Nop => unreachable!()
        }

        Ok(())
    }
}
