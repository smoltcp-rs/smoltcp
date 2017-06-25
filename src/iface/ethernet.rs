use managed::{Managed, ManagedSlice};

use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
use wire::{IpAddress, IpProtocol, IpRepr};
use wire::{TcpPacket, TcpRepr, TcpControl};
use socket::{Socket, SocketSet, RawSocket, AsSocket};
use super::ArpCache;

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a, 'b, 'c, DeviceT: Device + 'a> {
    device:         Managed<'a, DeviceT>,
    arp_cache:      Managed<'b, ArpCache>,
    hardware_addr:  EthernetAddress,
    protocol_addrs: ManagedSlice<'c, IpAddress>,
}

impl<'a, 'b, 'c, DeviceT: Device + 'a> Interface<'a, 'b, 'c, DeviceT> {
    /// Create a network interface using the provided network device.
    ///
    /// # Panics
    /// See the restrictions on [set_hardware_addr](#method.set_hardware_addr)
    /// and [set_protocol_addrs](#method.set_protocol_addrs) functions.
    pub fn new<DeviceMT, ArpCacheMT, ProtocolAddrsMT>
              (device: DeviceMT, arp_cache: ArpCacheMT,
               hardware_addr: EthernetAddress, protocol_addrs: ProtocolAddrsMT) ->
              Interface<'a, 'b, 'c, DeviceT>
            where DeviceMT: Into<Managed<'a, DeviceT>>,
                  ArpCacheMT: Into<Managed<'b, ArpCache>>,
                  ProtocolAddrsMT: Into<ManagedSlice<'c, IpAddress>>, {
        let device = device.into();
        let arp_cache = arp_cache.into();
        let protocol_addrs = protocol_addrs.into();

        Self::check_hardware_addr(&hardware_addr);
        Self::check_protocol_addrs(&protocol_addrs);
        Interface {
            device:         device,
            arp_cache:      arp_cache,
            hardware_addr:  hardware_addr,
            protocol_addrs: protocol_addrs,
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
    pub fn update_protocol_addrs<F: FnOnce(&mut ManagedSlice<'c, IpAddress>)>(&mut self, f: F) {
        f(&mut self.protocol_addrs);
        Self::check_protocol_addrs(&self.protocol_addrs)
    }

    /// Check whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.iter().any(|&probe| probe == addr)
    }

    /// Receive and process a packet, if available, and then transmit a packet, if necessary,
    /// handling the given set of sockets.
    ///
    /// The timestamp is a monotonically increasing number of milliseconds.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<(), Error> {
        enum Response<'a> {
            Nop,
            Arp(ArpRepr),
            Icmpv4(Ipv4Repr, Icmpv4Repr<'a>),
            Tcpv4(Ipv4Repr, TcpRepr<'a>)
        }

        // First, transmit any outgoing packets.
        loop {
            if self.emit(sockets, timestamp)? { break }
        }

        // Now, receive any incoming packets.
        let rx_buffer = self.device.receive()?;
        let eth_frame = EthernetFrame::new_checked(&rx_buffer)?;

        if !eth_frame.dst_addr().is_broadcast() &&
                eth_frame.dst_addr() != self.hardware_addr {
            return Ok(())
        }

        let mut response = Response::Nop;
        match eth_frame.ethertype() {
            // Snoop all ARP traffic, and respond to ARP packets directed at us.
            EthernetProtocol::Arp => {
                let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
                match ArpRepr::parse(&arp_packet)? {
                    // Respond to ARP requests aimed at us, and fill the ARP cache
                    // from all ARP requests, including gratuitous.
                    ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Request,
                        source_hardware_addr, source_protocol_addr,
                        target_protocol_addr, ..
                    } => {
                        if source_protocol_addr.is_unicast() && source_hardware_addr.is_unicast() {
                            self.arp_cache.fill(&source_protocol_addr.into(),
                                                &source_hardware_addr);
                        }

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
                        if source_protocol_addr.is_unicast() && source_hardware_addr.is_unicast() {
                            self.arp_cache.fill(&source_protocol_addr.into(),
                                                &source_hardware_addr);
                        }
                    },

                    _ => return Err(Error::Unrecognized)
                }
            },

            // Handle IP packets directed at us.
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet)?;

                // Fill the ARP cache from IP header.
                if ipv4_repr.src_addr.is_unicast() && eth_frame.src_addr().is_unicast() {
                    self.arp_cache.fill(&IpAddress::Ipv4(ipv4_repr.src_addr),
                                        &eth_frame.src_addr());
                }

                // Pass every IP packet to all raw sockets we have registered.
                for raw_socket in sockets.iter_mut().filter_map(
                        <Socket as AsSocket<RawSocket>>::try_as_socket) {
                    match raw_socket.process(timestamp, &IpRepr::Ipv4(ipv4_repr),
                                             ipv4_packet.payload()) {
                        Ok(()) | Err(Error::Rejected) => (),
                        _ => unreachable!(),
                    }
                }

                match ipv4_repr {
                    // Ignore IP packets not directed at us.
                    Ipv4Repr { dst_addr, .. } if !self.has_protocol_addr(dst_addr) => (),

                    // Respond to ICMP packets.
                    Ipv4Repr { protocol: IpProtocol::Icmp, src_addr, dst_addr, .. } => {
                        let icmp_packet = Icmpv4Packet::new_checked(ipv4_packet.payload())?;
                        let icmp_repr = Icmpv4Repr::parse(&icmp_packet)?;
                        match icmp_repr {
                            // Respond to echo requests.
                            Icmpv4Repr::EchoRequest {
                                ident, seq_no, data
                            } => {
                                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                                    ident:  ident,
                                    seq_no: seq_no,
                                    data:   data
                                };
                                let ipv4_reply_repr = Ipv4Repr {
                                    src_addr:    dst_addr,
                                    dst_addr:    src_addr,
                                    protocol:    IpProtocol::Icmp,
                                    payload_len: icmp_reply_repr.buffer_len()
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
                    Ipv4Repr { src_addr, dst_addr, protocol, .. } => {
                        let mut handled = false;
                        for socket in sockets.iter_mut() {
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
                            let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
                            if !tcp_packet.rst() {
                                let tcp_reply_repr = TcpRepr {
                                    src_port:     tcp_packet.dst_port(),
                                    dst_port:     tcp_packet.src_port(),
                                    control:      TcpControl::Rst,
                                    push:         false,
                                    seq_number:   tcp_packet.ack_number(),
                                    ack_number:   Some(tcp_packet.seq_number() +
                                                       tcp_packet.segment_len()),
                                    window_len:   0,
                                    max_seg_size: None,
                                    payload:      &[]
                                };
                                let ipv4_reply_repr = Ipv4Repr {
                                    src_addr:    dst_addr,
                                    dst_addr:    src_addr,
                                    protocol:    IpProtocol::Tcp,
                                    payload_len: tcp_reply_repr.buffer_len()
                                };
                                response = Response::Tcpv4(ipv4_reply_repr, tcp_reply_repr);
                            }
                        } else if !handled {
                            let reason;
                            if protocol == IpProtocol::Udp {
                                reason = Icmpv4DstUnreachable::PortUnreachable
                            } else {
                                reason = Icmpv4DstUnreachable::ProtoUnreachable
                            }

                            let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                                reason: reason,
                                header: ipv4_repr,
                                data:   &ipv4_packet.payload()[0..8]
                            };
                            let ipv4_reply_repr = Ipv4Repr {
                                src_addr:    dst_addr,
                                dst_addr:    src_addr,
                                protocol:    IpProtocol::Icmp,
                                payload_len: icmp_reply_repr.buffer_len()
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
            ($tx_buffer:ident, $frame:ident, $ip_repr:ident) => ({
                let dst_hardware_addr =
                    match self.arp_cache.lookup(&$ip_repr.dst_addr.into()) {
                        None => return Err(Error::Unaddressable),
                        Some(hardware_addr) => hardware_addr
                    };

                let frame_len = EthernetFrame::<&[u8]>::buffer_len($ip_repr.buffer_len() +
                                                                   $ip_repr.payload_len);
                $tx_buffer = self.device.transmit(frame_len)?;
                $frame = EthernetFrame::new_checked(&mut $tx_buffer)
                                       .expect("transmit frame too small");
                $frame.set_src_addr(self.hardware_addr);
                $frame.set_dst_addr(dst_hardware_addr);
                $frame.set_ethertype(EthernetProtocol::Ipv4);

                let mut ip_packet = Ipv4Packet::new($frame.payload_mut());
                $ip_repr.emit(&mut ip_packet);
                ip_packet
            })
        }

        match response {
            Response::Arp(repr) => {
                let tx_len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len());
                let mut tx_buffer = self.device.transmit(tx_len)?;
                let mut frame = EthernetFrame::new_checked(&mut tx_buffer)
                                              .expect("transmit frame too small");
                frame.set_src_addr(self.hardware_addr);
                frame.set_dst_addr(match repr {
                    ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                    _ => unreachable!()
                });
                frame.set_ethertype(EthernetProtocol::Arp);

                let mut packet = ArpPacket::new(frame.payload_mut());
                repr.emit(&mut packet);

                Ok(())
            },

            Response::Icmpv4(ip_repr, icmp_repr) => {
                let mut tx_buffer;
                let mut frame;
                let mut ip_packet = ip_response!(tx_buffer, frame, ip_repr);
                let mut icmp_packet = Icmpv4Packet::new(ip_packet.payload_mut());
                icmp_repr.emit(&mut icmp_packet);
                Ok(())
            }

            Response::Tcpv4(ip_repr, tcp_repr) => {
                let mut tx_buffer;
                let mut frame;
                let mut ip_packet = ip_response!(tx_buffer, frame, ip_repr);
                let mut tcp_packet = TcpPacket::new(ip_packet.payload_mut());
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

    fn emit(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<bool, Error> {
        // Borrow checker is being overly careful around closures, so we have
        // to hack around that.
        let src_hardware_addr = self.hardware_addr;
        let src_protocol_addrs = self.protocol_addrs.as_ref();
        let arp_cache = &mut self.arp_cache;
        let device = &mut self.device;

        let mut limits = device.limits();
        limits.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len();

        let mut nothing_to_transmit = true;
        for socket in sockets.iter_mut() {
            let result = socket.dispatch(timestamp, &limits, &mut |repr, payload| {
                let repr = repr.lower(src_protocol_addrs)?;

                match arp_cache.lookup(&repr.dst_addr()) {
                    Some(dst_hardware_addr) => {
                        let tx_len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len() +
                                                                        payload.buffer_len());
                        let mut tx_buffer = device.transmit(tx_len)?;
                        let mut frame = EthernetFrame::new_checked(&mut tx_buffer)
                                                      .expect("transmit frame too small");
                        frame.set_src_addr(src_hardware_addr);
                        frame.set_dst_addr(dst_hardware_addr);
                        frame.set_ethertype(EthernetProtocol::Ipv4);

                        repr.emit(frame.payload_mut());

                        let mut ip_packet = Ipv4Packet::new(frame.payload_mut());
                        payload.emit(&repr, ip_packet.payload_mut());
                    }

                    None => {
                        let (src_addr, dst_addr) =
                            match (repr.src_addr(), repr.dst_addr()) {
                                (IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) =>
                                    (src_addr, dst_addr),
                                // We've lowered all addresses to a concrete form.
                                _ => unreachable!()
                            };

                        let payload = ArpRepr::EthernetIpv4 {
                            operation: ArpOperation::Request,
                            source_hardware_addr: src_hardware_addr,
                            source_protocol_addr: src_addr,
                            target_hardware_addr: EthernetAddress::default(),
                            target_protocol_addr: dst_addr,
                        };

                        let tx_len = EthernetFrame::<&[u8]>::buffer_len(payload.buffer_len());
                        let mut tx_buffer = device.transmit(tx_len)?;
                        let mut frame = EthernetFrame::new_checked(&mut tx_buffer)
                                                      .expect("transmit frame too small");
                        frame.set_src_addr(src_hardware_addr);
                        frame.set_dst_addr(EthernetAddress([0xff; 6]));
                        frame.set_ethertype(EthernetProtocol::Arp);

                        let mut arp_packet = ArpPacket::new(frame.payload_mut());
                        payload.emit(&mut arp_packet);
                    }
                }

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

