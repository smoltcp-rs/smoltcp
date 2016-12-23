use core::borrow::BorrowMut;
use core::marker::PhantomData;

use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{IpAddress, IpProtocol};
use wire::{Ipv4Address, Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
use wire::{TcpPacket, TcpRepr, TcpControl};
use socket::Socket;
use super::{ArpCache};

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
#[derive(Debug)]
pub struct Interface<'a, 'b: 'a,
    DeviceT:        Device,
    ArpCacheT:      ArpCache,
    ProtocolAddrsT: BorrowMut<[IpAddress]>,
    SocketsT:       BorrowMut<[Socket<'a, 'b>]>
> {
    device:         DeviceT,
    arp_cache:      ArpCacheT,
    hardware_addr:  EthernetAddress,
    protocol_addrs: ProtocolAddrsT,
    sockets:        SocketsT,
    phantom:        PhantomData<Socket<'a, 'b>>
}

impl<'a, 'b: 'a,
    DeviceT:        Device,
    ArpCacheT:      ArpCache,
    ProtocolAddrsT: BorrowMut<[IpAddress]>,
    SocketsT:       BorrowMut<[Socket<'a, 'b>]>
> Interface<'a, 'b, DeviceT, ArpCacheT, ProtocolAddrsT, SocketsT> {
    /// Create a network interface using the provided network device.
    ///
    /// # Panics
    /// See the restrictions on [set_hardware_addr](#method.set_hardware_addr)
    /// and [set_protocol_addrs](#method.set_protocol_addrs) functions.
    pub fn new(device: DeviceT, arp_cache: ArpCacheT, hardware_addr: EthernetAddress,
               protocol_addrs: ProtocolAddrsT, sockets: SocketsT) ->
            Interface<'a, 'b, DeviceT, ArpCacheT, ProtocolAddrsT, SocketsT> {
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

    fn check_protocol_addrs(addrs: &[IpAddress]) {
        for addr in addrs {
            if !addr.is_unicast() {
                panic!("protocol address {} is not unicast", addr)
            }
        }
    }

    /// Get the protocol addresses of the interface.
    pub fn protocol_addrs(&self) -> &[IpAddress] {
        self.protocol_addrs.borrow()
    }

    /// Update the protocol addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn update_protocol_addrs<F: FnOnce(&mut ProtocolAddrsT)>(&mut self, f: F) {
        f(&mut self.protocol_addrs);
        Self::check_protocol_addrs(self.protocol_addrs.borrow())
    }

    /// Check whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.borrow().iter().any(|&probe| probe == addr)
    }

    /// Get the set of sockets owned by the interface.
    pub fn sockets(&mut self) -> &mut SocketsT {
        &mut self.sockets
    }

    /// Receive and process a packet, if available.
    pub fn poll(&mut self) -> Result<(), Error> {
        enum Response<'a> {
            Nop,
            Arp(ArpRepr),
            Icmpv4(Ipv4Repr, Icmpv4Repr<'a>),
            Tcpv4(Ipv4Repr, TcpRepr<'a>)
        }

        // First, transmit any outgoing packets.
        loop {
            if try!(self.emit()) { break }
        }

        // Now, receive any incoming packets.
        let rx_buffer = try!(self.device.receive());
        let eth_frame = try!(EthernetFrame::new(&rx_buffer));

        let mut response = Response::Nop;
        match eth_frame.ethertype() {
            // Snoop all ARP traffic, and respond to ARP packets directed at us.
            EthernetProtocol::Arp => {
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
            EthernetProtocol::Ipv4 => {
                let ip_packet = try!(Ipv4Packet::new(eth_frame.payload()));
                let ip_repr = try!(Ipv4Repr::parse(&ip_packet));

                // Fill the ARP cache from IP header.
                self.arp_cache.fill(IpAddress::Ipv4(ip_repr.src_addr), eth_frame.src_addr());

                match ip_repr {
                    // Ignore IP packets not directed at us.
                    Ipv4Repr { dst_addr, .. } if !self.has_protocol_addr(dst_addr) => (),

                    // Respond to ICMP packets.
                    Ipv4Repr { protocol: IpProtocol::Icmp, src_addr, dst_addr } => {
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
                                    protocol: IpProtocol::Icmp
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
                        let mut handled = false;
                        for socket in self.sockets.borrow_mut() {
                            match socket.collect(&src_addr.into(), &dst_addr.into(),
                                                 protocol, ip_packet.payload()) {
                                Ok(()) => { handled = true; break }
                                Err(Error::Rejected) => continue,
                                Err(e) => return Err(e)
                            }
                        }

                        if !handled && protocol == IpProtocol::Tcp {
                            let tcp_packet = try!(TcpPacket::new(ip_packet.payload()));

                            let ip_reply_repr = Ipv4Repr {
                                src_addr: dst_addr,
                                dst_addr: src_addr,
                                protocol: IpProtocol::Tcp
                            };
                            let tcp_reply_repr = TcpRepr {
                                src_port:   tcp_packet.dst_port(),
                                dst_port:   tcp_packet.src_port(),
                                control:    TcpControl::Rst,
                                seq_number: tcp_packet.ack_number(),
                                ack_number: Some(tcp_packet.seq_number() +
                                                 tcp_packet.segment_len()),
                                window_len: 0,
                                payload:    &[]
                            };
                            response = Response::Tcpv4(ip_reply_repr, tcp_reply_repr);
                        } else if !handled {
                            let reason;
                            if protocol == IpProtocol::Udp {
                                reason = Icmpv4DstUnreachable::PortUnreachable
                            } else {
                                reason = Icmpv4DstUnreachable::ProtoUnreachable
                            }

                            let mut data = [0; 8];
                            data.copy_from_slice(&ip_packet.payload()[0..8]);

                            let ip_reply_repr = Ipv4Repr {
                                src_addr: dst_addr,
                                dst_addr: src_addr,
                                protocol: IpProtocol::Icmp
                            };
                            let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                                reason:   reason,
                                header:   ip_repr,
                                length:   ip_packet.payload().len(),
                                data:     data
                            };
                            response = Response::Icmpv4(ip_reply_repr, icmp_reply_repr)
                        }
                    },
                }
            }

            // Drop all other traffic.
            _ => return Err(Error::Unrecognized)
        }

        macro_rules! ip_response {
            ($tx_buffer:ident, $frame:ident, $ip_repr:ident, $length:expr) => ({
                let dst_hardware_addr =
                    match self.arp_cache.lookup($ip_repr.dst_addr.into()) {
                        None => return Err(Error::Unaddressable),
                        Some(hardware_addr) => hardware_addr
                    };

                let payload_len = $length;
                let frame_len = EthernetFrame::<&[u8]>::buffer_len($ip_repr.buffer_len() +
                                                                   payload_len);
                $tx_buffer = try!(self.device.transmit(frame_len));
                $frame = try!(EthernetFrame::new(&mut $tx_buffer));
                $frame.set_src_addr(self.hardware_addr);
                $frame.set_dst_addr(dst_hardware_addr);
                $frame.set_ethertype(EthernetProtocol::Ipv4);

                let mut ip_packet = try!(Ipv4Packet::new($frame.payload_mut()));
                $ip_repr.emit(&mut ip_packet, payload_len);
                ip_packet
            })
        }

        match response {
            Response::Arp(repr) => {
                let tx_len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len());
                let mut tx_buffer = try!(self.device.transmit(tx_len));
                let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                frame.set_src_addr(self.hardware_addr);
                frame.set_dst_addr(match repr {
                    ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                    _ => unreachable!()
                });
                frame.set_ethertype(EthernetProtocol::Arp);

                let mut packet = try!(ArpPacket::new(frame.payload_mut()));
                repr.emit(&mut packet);

                Ok(())
            },

            Response::Icmpv4(ip_repr, icmp_repr) => {
                let mut tx_buffer;
                let mut frame;
                let mut ip_packet = ip_response!(tx_buffer, frame, ip_repr,
                                                 icmp_repr.buffer_len());
                let mut icmp_packet = try!(Icmpv4Packet::new(ip_packet.payload_mut()));
                icmp_repr.emit(&mut icmp_packet);
                Ok(())
            }

            Response::Tcpv4(ip_repr, tcp_repr) => {
                let mut tx_buffer;
                let mut frame;
                let mut ip_packet = ip_response!(tx_buffer, frame, ip_repr,
                                                 tcp_repr.buffer_len());
                let mut tcp_packet = try!(TcpPacket::new(ip_packet.payload_mut()));
                tcp_repr.emit(&mut tcp_packet,
                              &IpAddress::Ipv4(ip_repr.src_addr),
                              &IpAddress::Ipv4(ip_repr.dst_addr));
                Ok(())
            }

            Response::Nop => {
                Ok(())
            }
        }
    }

    pub fn emit(&mut self) -> Result<bool, Error> {
        // Borrow checker is being overly careful around closures, so we have
        // to hack around that.
        let src_hardware_addr = self.hardware_addr;
        let src_protocol_addrs = self.protocol_addrs.borrow();
        let arp_cache = &mut self.arp_cache;
        let device = &mut self.device;

        let mut nothing_to_transmit = true;
        for socket in self.sockets.borrow_mut() {
            let result = socket.dispatch(&mut |src_addr, dst_addr, protocol, payload| {
                let src_addr =
                    try!(match src_addr {
                        &IpAddress::Unspecified |
                        &IpAddress::Ipv4(Ipv4Address([0, _, _, _])) => {
                            let mut assigned_addr = None;
                            for addr in src_protocol_addrs {
                                match addr {
                                    addr @ &IpAddress::Ipv4(_) => {
                                        assigned_addr = Some(addr);
                                        break
                                    }
                                    _ => ()
                                }
                            }
                            assigned_addr.ok_or(Error::Unaddressable)
                        },
                        addr => Ok(addr)
                    });

                let ip_repr =
                    match (src_addr, dst_addr) {
                        (&IpAddress::Ipv4(src_addr),
                         &IpAddress::Ipv4(dst_addr)) => {
                            Ipv4Repr {
                                src_addr: src_addr,
                                dst_addr: dst_addr,
                                protocol: protocol
                            }
                        },
                        _ => unreachable!()
                    };

                let dst_hardware_addr =
                    match arp_cache.lookup(*dst_addr) {
                        None => return Err(Error::Unaddressable),
                        Some(hardware_addr) => hardware_addr
                    };

                let tx_len = EthernetFrame::<&[u8]>::buffer_len(ip_repr.buffer_len() +
                                                                payload.buffer_len());
                let mut tx_buffer = try!(device.transmit(tx_len));
                let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                frame.set_src_addr(src_hardware_addr);
                frame.set_dst_addr(dst_hardware_addr);
                frame.set_ethertype(EthernetProtocol::Ipv4);

                let mut ip_packet = try!(Ipv4Packet::new(frame.payload_mut()));
                ip_repr.emit(&mut ip_packet, payload.buffer_len());

                payload.emit(src_addr, dst_addr, ip_packet.payload_mut());

                Ok(())
            });

            match result {
                Ok(()) => {
                    nothing_to_transmit = false;
                    break
                }
                Err(Error::Exhausted) => continue,
                Err(e) => return Err(e)
            }
        }

        Ok(nothing_to_transmit)
    }
}

