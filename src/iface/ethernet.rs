use managed::{Managed, ManagedSlice};

use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
use wire::{IpAddress, IpProtocol, IpRepr};
use wire::{TcpPacket, TcpRepr, TcpControl};
use socket::Socket;
use super::{ArpCache};

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a, 'b, 'c, 'd, 'e: 'd, 'f: 'e + 'd, DeviceT: Device + 'a> {
    device:         Managed<'a, DeviceT>,
    hardware_addr:  EthernetAddress,
    protocol_addrs: ManagedSlice<'b, IpAddress>,
    arp_cache:      Managed<'c, ArpCache>,
    sockets:        ManagedSlice<'d, Socket<'e, 'f>>
}

impl<'a, 'b, 'c, 'd, 'e: 'd, 'f: 'e + 'd, DeviceT: Device + 'a>
        Interface<'a, 'b, 'c, 'd, 'e, 'f, DeviceT> {
    /// Create a network interface using the provided network device.
    ///
    /// # Panics
    /// See the restrictions on [set_hardware_addr](#method.set_hardware_addr)
    /// and [set_protocol_addrs](#method.set_protocol_addrs) functions.
    pub fn new<DeviceMT, ProtocolAddrsMT, ArpCacheMT, SocketsMT>
              (device: DeviceMT,
               hardware_addr: EthernetAddress, protocol_addrs: ProtocolAddrsMT,
               arp_cache: ArpCacheMT, sockets: SocketsMT) ->
              Interface<'a, 'b, 'c, 'd, 'e, 'f, DeviceT>
            where DeviceMT: Into<Managed<'a, DeviceT>>,
                  ProtocolAddrsMT: Into<ManagedSlice<'b, IpAddress>>,
                  ArpCacheMT: Into<Managed<'c, ArpCache>>,
                  SocketsMT: Into<ManagedSlice<'d, Socket<'e, 'f>>> {
        let device = device.into();
        let protocol_addrs = protocol_addrs.into();
        let arp_cache = arp_cache.into();
        let sockets = sockets.into();

        Self::check_hardware_addr(&hardware_addr);
        Self::check_protocol_addrs(&protocol_addrs);
        Interface {
            device:         device,
            arp_cache:      arp_cache,
            hardware_addr:  hardware_addr,
            protocol_addrs: protocol_addrs,
            sockets:        sockets
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
        self.protocol_addrs.as_ref()
    }

    /// Update the protocol addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn update_protocol_addrs<F: FnOnce(&mut ManagedSlice<'b, IpAddress>)>(&mut self, f: F) {
        f(&mut self.protocol_addrs);
        Self::check_protocol_addrs(&self.protocol_addrs)
    }

    /// Check whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.iter().any(|&probe| probe == addr)
    }

    /// Get the set of sockets owned by the interface.
    pub fn sockets(&mut self) -> &mut ManagedSlice<'d, Socket<'e, 'f>> {
        &mut self.sockets
    }

    /// Receive and process a packet, if available, and then transmit a packet, if necessary.
    ///
    /// The timestamp is a monotonically increasing number of milliseconds.
    pub fn poll(&mut self, timestamp: u64) -> Result<(), Error> {
        enum Response<'a> {
            Nop,
            Arp(ArpRepr),
            Icmpv4(Ipv4Repr, Icmpv4Repr<'a>),
            Tcpv4(Ipv4Repr, TcpRepr<'a>)
        }

        // First, transmit any outgoing packets.
        loop {
            if try!(self.emit(timestamp)) { break }
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
                        self.arp_cache.fill(&source_protocol_addr.into(), &source_hardware_addr);

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
                         self.arp_cache.fill(&source_protocol_addr.into(), &source_hardware_addr)
                    },

                    _ => return Err(Error::Unrecognized)
                }
            },

            // Handle IP packets directed at us.
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = try!(Ipv4Packet::new(eth_frame.payload()));
                let ipv4_repr = try!(Ipv4Repr::parse(&ipv4_packet));

                // Fill the ARP cache from IP header.
                self.arp_cache.fill(&IpAddress::Ipv4(ipv4_repr.src_addr), &eth_frame.src_addr());

                match ipv4_repr {
                    // Ignore IP packets not directed at us.
                    Ipv4Repr { dst_addr, .. } if !self.has_protocol_addr(dst_addr) => (),

                    // Respond to ICMP packets.
                    Ipv4Repr { protocol: IpProtocol::Icmp, src_addr, dst_addr } => {
                        let icmp_packet = try!(Icmpv4Packet::new(ipv4_packet.payload()));
                        let icmp_repr = try!(Icmpv4Repr::parse(&icmp_packet));
                        match icmp_repr {
                            // Respond to echo requests.
                            Icmpv4Repr::EchoRequest {
                                ident, seq_no, data
                            } => {
                                let ipv4_reply_repr = Ipv4Repr {
                                    src_addr: dst_addr,
                                    dst_addr: src_addr,
                                    protocol: IpProtocol::Icmp
                                };
                                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                                    ident:  ident,
                                    seq_no: seq_no,
                                    data:   data
                                };
                                response = Response::Icmpv4(ipv4_reply_repr, icmp_reply_repr)
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
                        for socket in self.sockets.iter_mut() {
                            let ip_repr = IpRepr::Ipv4(ipv4_repr);
                            match socket.process(timestamp, &ip_repr, ipv4_packet.payload()) {
                                Ok(()) => {
                                    // The packet was valid and handled by socket.
                                    handled = true;
                                    break
                                }
                                Err(Error::Rejected) => {
                                    // The packet wasn't addressed to the socket.
                                    // For TCP, send RST only if no other socket accepts
                                    // the packet.
                                    continue
                                }
                                Err(Error::Malformed) => {
                                    // The packet was addressed to the socket but is malformed.
                                    // For TCP, send RST immediately.
                                    break
                                }
                                Err(e) => return Err(e)
                            }
                        }

                        if !handled && protocol == IpProtocol::Tcp {
                            let tcp_packet = try!(TcpPacket::new(ipv4_packet.payload()));

                            let ipv4_reply_repr = Ipv4Repr {
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
                            response = Response::Tcpv4(ipv4_reply_repr, tcp_reply_repr);
                        } else if !handled {
                            let reason;
                            if protocol == IpProtocol::Udp {
                                reason = Icmpv4DstUnreachable::PortUnreachable
                            } else {
                                reason = Icmpv4DstUnreachable::ProtoUnreachable
                            }

                            let mut data = [0; 8];
                            data.copy_from_slice(&ipv4_packet.payload()[0..8]);

                            let ipv4_reply_repr = Ipv4Repr {
                                src_addr: dst_addr,
                                dst_addr: src_addr,
                                protocol: IpProtocol::Icmp
                            };
                            let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                                reason:   reason,
                                header:   ipv4_repr,
                                length:   ipv4_packet.payload().len(),
                                data:     data
                            };
                            response = Response::Icmpv4(ipv4_reply_repr, icmp_reply_repr)
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
                    match self.arp_cache.lookup(&$ip_repr.dst_addr.into()) {
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

    fn emit(&mut self, timestamp: u64) -> Result<bool, Error> {
        // Borrow checker is being overly careful around closures, so we have
        // to hack around that.
        let src_hardware_addr = self.hardware_addr;
        let src_protocol_addrs = self.protocol_addrs.as_ref();
        let arp_cache = &mut self.arp_cache;
        let device = &mut self.device;

        let mut nothing_to_transmit = true;
        for socket in self.sockets.iter_mut() {
            let result = socket.dispatch(timestamp, &mut |repr, payload| {
                let repr = try!(repr.lower(src_protocol_addrs));

                let dst_hardware_addr =
                    match arp_cache.lookup(&repr.dst_addr()) {
                        None => return Err(Error::Unaddressable),
                        Some(hardware_addr) => hardware_addr
                    };

                let tx_len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len() +
                                                                payload.buffer_len());
                let mut tx_buffer = try!(device.transmit(tx_len));
                let mut frame = try!(EthernetFrame::new(&mut tx_buffer));
                frame.set_src_addr(src_hardware_addr);
                frame.set_dst_addr(dst_hardware_addr);
                frame.set_ethertype(EthernetProtocol::Ipv4);

                repr.emit(frame.payload_mut(), payload.buffer_len());

                let mut ip_packet = try!(Ipv4Packet::new(frame.payload_mut()));
                payload.emit(&repr, ip_packet.payload_mut());

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

