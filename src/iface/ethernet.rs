use core::borrow::BorrowMut;
use core::marker::PhantomData;

use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocolType, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{InternetAddress, InternetProtocolType};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr};
use socket::Socket;
use super::{ArpCache};

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
#[derive(Debug)]
pub struct Interface<'a,
    DeviceT:        Device,
    ArpCacheT:      ArpCache,
    ProtocolAddrsT: BorrowMut<[InternetAddress]>,
    SocketsT:       BorrowMut<[&'a mut Socket]>
> {
    device:         DeviceT,
    arp_cache:      ArpCacheT,
    hardware_addr:  EthernetAddress,
    protocol_addrs: ProtocolAddrsT,
    sockets:        SocketsT,
    phantom:        PhantomData<&'a mut Socket>
}

impl<'a,
    DeviceT:        Device,
    ArpCacheT:      ArpCache,
    ProtocolAddrsT: BorrowMut<[InternetAddress]>,
    SocketsT:       BorrowMut<[&'a mut Socket]>
> Interface<'a, DeviceT, ArpCacheT, ProtocolAddrsT, SocketsT> {
    /// Create a network interface using the provided network device.
    ///
    /// # Panics
    /// See the restrictions on [set_hardware_addr](#method.set_hardware_addr)
    /// and [set_protocol_addrs](#method.set_protocol_addrs) functions.
    pub fn new(device: DeviceT, arp_cache: ArpCacheT, hardware_addr: EthernetAddress,
               protocol_addrs: ProtocolAddrsT, sockets: SocketsT) ->
            Interface<'a, DeviceT, ArpCacheT, ProtocolAddrsT, SocketsT> {
        Self::check_hardware_addr(&hardware_addr);
        Self::check_protocol_addrs(protocol_addrs.borrow());
        Interface {
            device:         device,
            arp_cache:      arp_cache,
            hardware_addr:  hardware_addr,
            protocol_addrs: protocol_addrs,
            sockets:        sockets,
            phantom:        PhantomData
        }
    }

    fn check_hardware_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("hardware address {} is not unicast", addr)
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
        self.hardware_addr = addr;
        Self::check_hardware_addr(&self.hardware_addr);
    }

    fn check_protocol_addrs(addrs: &[InternetAddress]) {
        for addr in addrs {
            if !addr.is_unicast() {
                panic!("protocol address {} is not unicast", addr)
            }
        }
    }

    /// Get the protocol addresses of the interface.
    pub fn protocol_addrs(&self) -> &[InternetAddress] {
        self.protocol_addrs.borrow()
    }

    /// Update the protocol addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn update_protocol_addrs<F: FnOnce(&mut [InternetAddress])>(&mut self, f: F) {
        f(self.protocol_addrs.borrow_mut());
        Self::check_protocol_addrs(self.protocol_addrs.borrow())
    }

    /// Check whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<InternetAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.borrow().iter().any(|&probe| probe == addr)
    }

    /// Get the set of sockets owned by the interface.
    pub fn with_sockets<R, F: FnOnce(&mut [&'a mut Socket]) -> R>(&mut self, f: F) -> R {
        f(self.sockets.borrow_mut())
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

                    // Try dispatching a packet to a socket.
                    Ipv4Repr { src_addr, dst_addr, protocol } => {
                        for socket in self.sockets.borrow_mut() {
                            match socket.collect(&src_addr.into(), &dst_addr.into(),
                                                 protocol, ip_packet.payload()) {
                                Ok(()) => break,
                                Err(Error::Rejected) => continue,
                                Err(e) => return Err(e)
                            }
                        }

                        // FIXME: respond with ICMP destination unreachable here?
                    },
                }
            }

            // Drop all other traffic.
            _ => return Err(Error::Unrecognized)
        }

        let tx_size = self.device.mtu();
        match response {
            Response::Arp(repr) => {
                let mut tx_buffer = try!(self.device.transmit(tx_size));
                let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                frame.set_src_addr(self.hardware_addr);
                frame.set_dst_addr(match repr {
                    ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                    _ => unreachable!()
                });
                frame.set_ethertype(EthernetProtocolType::Arp);

                let mut packet = try!(ArpPacket::new(frame.payload_mut()));
                repr.emit(&mut packet)
            },

            Response::Icmpv4(ip_repr, icmp_repr) => {
                let dst_hardware_addr =
                    match self.arp_cache.lookup(ip_repr.dst_addr.into()) {
                        None => return Err(Error::Unaddressable),
                        Some(hardware_addr) => hardware_addr
                    };

                let mut tx_buffer = try!(self.device.transmit(tx_size));
                let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                frame.set_src_addr(self.hardware_addr);
                frame.set_dst_addr(dst_hardware_addr);
                frame.set_ethertype(EthernetProtocolType::Ipv4);

                let mut ip_packet = try!(Ipv4Packet::new(frame.payload_mut()));
                ip_repr.emit(&mut ip_packet, icmp_repr.len());

                let mut icmp_packet = try!(Icmpv4Packet::new(ip_packet.payload_mut()));
                icmp_repr.emit(&mut icmp_packet);
            }

            Response::Nop => {
                // Borrow checker is being overly careful around closures, so we have
                // to hack around that.
                let src_hardware_addr = self.hardware_addr;
                let arp_cache = &mut self.arp_cache;
                let device = &mut self.device;

                for socket in self.sockets.borrow_mut() {
                    let result = socket.dispatch(&mut |src_addr, dst_addr, protocol, payload| {
                        let dst_hardware_addr =
                            match arp_cache.lookup(*dst_addr) {
                                None => return Err(Error::Unaddressable),
                                Some(hardware_addr) => hardware_addr
                            };

                        let mut tx_buffer = try!(device.transmit(tx_size));
                        let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                        frame.set_src_addr(src_hardware_addr);
                        frame.set_dst_addr(dst_hardware_addr);
                        frame.set_ethertype(EthernetProtocolType::Ipv4);

                        let mut ip_packet = try!(Ipv4Packet::new(frame.payload_mut()));
                        let ip_repr =
                            match (src_addr, dst_addr) {
                                (&InternetAddress::Ipv4(src_addr),
                                 &InternetAddress::Ipv4(dst_addr)) => {
                                    Ipv4Repr {
                                        src_addr: src_addr,
                                        dst_addr: dst_addr,
                                        protocol: protocol
                                    }
                                },
                                _ => unreachable!()
                            };
                        ip_repr.emit(&mut ip_packet, payload.len());
                        payload.emit(src_addr, dst_addr, ip_packet.payload_mut());

                        Ok(())
                    });

                    match result {
                        Ok(()) => break,
                        Err(Error::Exhausted) => continue,
                        Err(e) => return Err(e)
                    }
                }
            }
        }

        Ok(())
    }
}

