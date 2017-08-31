use managed::{Managed, ManagedSlice};

use {Error, Result};
use phy::Device;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
use wire::{IpAddress, IpProtocol, IpRepr};
use wire::{UdpPacket, UdpRepr, TcpPacket, TcpRepr, TcpControl};
use socket::{Socket, SocketSet, RawSocket, TcpSocket, UdpSocket, AsSocket};
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

enum Packet<'a> {
    None,
    Arp(ArpRepr),
    Icmpv4(Ipv4Repr, Icmpv4Repr<'a>),
    Raw((IpRepr, &'a [u8])),
    Udp((IpRepr, UdpRepr<'a>)),
    Tcp((IpRepr, TcpRepr<'a>))
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

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing
    /// since an arbitrary moment in time, such as system startup.
    ///
    /// This function returns a _soft deadline_ for calling it the next time.
    /// That is, if `iface.poll(&mut sockets, 1000)` returns `Ok(Some(2000))`,
    /// it harmless (but wastes energy) to call it 500 ms later, and potentially
    /// harmful (impacting quality of service) to call it 1500 ms later.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<Option<u64>> {
        self.socket_egress(sockets, timestamp)?;

        if self.socket_ingress(sockets, timestamp)? {
            Ok(Some(0))
        } else {
            Ok(sockets.iter().filter_map(|socket| socket.poll_at()).min())
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let frame =
                match self.device.receive(timestamp) {
                    Ok(frame) => frame,
                    Err(Error::Exhausted) => break, // nothing to receive
                    Err(err) => return Err(err)
                };

            let response =
                match self.process_ethernet(sockets, timestamp, &frame) {
                    Ok(response) => response,
                    Err(err) => {
                        net_debug!("cannot process ingress packet: {}", err);
                        return Err(err)
                    }
                };
            processed_any = true;

            match self.dispatch(timestamp, response) {
                Ok(()) => (),
                Err(err) => {
                    net_debug!("cannot dispatch response packet: {}", err);
                    return Err(err)
                }
            }
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<()> {
        let mut limits = self.device.limits();
        limits.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len();

        for socket in sockets.iter_mut() {
            let mut device_result = Ok(());
            let socket_result =
                match socket {
                    &mut Socket::Raw(ref mut socket) =>
                        socket.dispatch(|response| {
                            device_result = self.dispatch(timestamp, Packet::Raw(response));
                            device_result
                        }),
                    &mut Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response| {
                            device_result = self.dispatch(timestamp, Packet::Udp(response));
                            device_result
                        }),
                    &mut Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &limits, |response| {
                            device_result = self.dispatch(timestamp, Packet::Tcp(response));
                            device_result
                        }),
                    &mut Socket::__Nonexhaustive => unreachable!()
                };
            match (device_result, socket_result) {
                (Err(Error::Exhausted), Ok(())) => break, // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (), // nothing to transmit
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!("cannot dispatch egress packet: {}", err);
                    return Err(err)
                }
                (Ok(()), Ok(())) => ()
            }
        }

        Ok(())
    }

    fn process_ethernet<'frame, T: AsRef<[u8]>>
                       (&mut self, sockets: &mut SocketSet, timestamp: u64,
                        frame: &'frame T) ->
                       Result<Packet<'frame>> {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address.
        if !eth_frame.dst_addr().is_broadcast() &&
                eth_frame.dst_addr() != self.hardware_addr {
            return Ok(Packet::None)
        }

        match eth_frame.ethertype() {
            EthernetProtocol::Arp =>
                self.process_arp(&eth_frame),
            EthernetProtocol::Ipv4 =>
                self.process_ipv4(sockets, timestamp, &eth_frame),
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Packet<'frame>> {
        let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
        let arp_repr = ArpRepr::parse(&arp_packet)?;

        match arp_repr {
            // Respond to ARP requests aimed at us, and fill the ARP cache from all ARP
            // requests and replies, to minimize the chance that we have to perform
            // an explicit ARP request.
            ArpRepr::EthernetIpv4 {
                operation, source_hardware_addr, source_protocol_addr, target_protocol_addr, ..
            } => {
                if source_protocol_addr.is_unicast() && source_hardware_addr.is_unicast() {
                    self.arp_cache.fill(&source_protocol_addr.into(),
                                        &source_hardware_addr);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source in {}", arp_repr);
                    return Err(Error::Malformed)
                }

                if operation == ArpOperation::Request &&
                        self.has_protocol_addr(target_protocol_addr) {
                    Ok(Packet::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr
                    }))
                } else {
                    Ok(Packet::None)
                }
            }

            _ => Err(Error::Unrecognized)
        }
    }

    fn process_ipv4<'frame, T: AsRef<[u8]>>
                   (&mut self, sockets: &mut SocketSet, timestamp: u64,
                    eth_frame: &EthernetFrame<&'frame T>) ->
                   Result<Packet<'frame>> {
        let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source in {}", ipv4_repr);
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the ARP cache from IP header of unicast frames.
            self.arp_cache.fill(&IpAddress::Ipv4(ipv4_repr.src_addr),
                                &eth_frame.src_addr());
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        // Pass every IP packet to all raw sockets we have registered.
        let mut handled_by_raw_socket = false;
        for raw_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<RawSocket>>::try_as_socket) {
            if raw_socket.would_accept(&ip_repr) {
                match raw_socket.process_accepted(&ip_repr, ip_payload) {
                    // The packet is valid and handled by socket.
                    Ok(()) => handled_by_raw_socket = true,
                    // Raw sockets can't fail to process an accepted packet
                    _ => unreachable!(),
                }
            }
        }

        if !self.has_protocol_addr(ipv4_repr.dst_addr) {
            // Ignore IP packets not directed at us.
            return Ok(Packet::None)
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                Self::process_icmpv4(ipv4_repr, ip_payload),
            IpProtocol::Udp =>
                Self::process_udp(sockets, ip_repr, ip_payload),
            IpProtocol::Tcp =>
                Self::process_tcp(sockets, timestamp, ip_repr, ip_payload),
            _ if handled_by_raw_socket =>
                Ok(Packet::None),
            _ => {
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..8]
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmp_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmp_reply_repr))
            }
        }
    }

    fn process_icmpv4<'frame>(ipv4_repr: Ipv4Repr, ip_payload: &'frame [u8]) ->
                             Result<Packet<'frame>> {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet)?;

        match icmp_repr {
            // Respond to echo requests.
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident:  ident,
                    seq_no: seq_no,
                    data:   data
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmp_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmp_reply_repr))
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(Packet::None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    fn process_udp<'frame>(sockets: &mut SocketSet,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr)?;

        for udp_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<UdpSocket>>::try_as_socket) {
            if udp_socket.would_accept(&ip_repr, &udp_repr) {
                match udp_socket.process_accepted(&ip_repr, &udp_repr) {
                    // The packet is valid and handled by socket.
                    Ok(()) => return Ok(Packet::None),
                    // The packet is malformed, or addressed to the socket but cannot be accepted.
                    Err(e) => return Err(e)
                }
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => {
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..8]
                };
                let ipv4_reply_repr = Ipv4Repr {
                    src_addr:    ipv4_repr.dst_addr,
                    dst_addr:    ipv4_repr.src_addr,
                    protocol:    IpProtocol::Icmp,
                    payload_len: icmpv4_reply_repr.buffer_len()
                };
                Ok(Packet::Icmpv4(ipv4_reply_repr, icmpv4_reply_repr))
            },
            IpRepr::Unspecified { .. } |
            IpRepr::__Nonexhaustive =>
                unreachable!()
        }
    }

    fn process_tcp<'frame>(sockets: &mut SocketSet, timestamp: u64,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr)?;

        for tcp_socket in sockets.iter_mut().filter_map(
                <Socket as AsSocket<TcpSocket>>::try_as_socket) {
            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map_or(Packet::None, Packet::Tcp)),
                // The packet isn't addressed to the socket.
                // Send RST only if no other socket accepts the packet.
                Err(Error::Rejected) => continue,
                // The packet is malformed, or addressed to the socket but cannot be accepted.
                Err(e) => return Err(e)
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(Packet::None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Packet::Tcp(TcpSocket::rst_reply(&ip_repr, &tcp_repr)))
        }
    }

    fn dispatch(&mut self, timestamp: u64, packet: Packet) -> Result<()> {
        match packet {
            Packet::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    };

                self.dispatch_ethernet(timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            Packet::Icmpv4(ipv4_repr, icmpv4_repr) => {
                self.dispatch_ip(timestamp, IpRepr::Ipv4(ipv4_repr), |_ip_repr, payload| {
                    icmpv4_repr.emit(&mut Icmpv4Packet::new(payload));
                })
            }
            Packet::Raw((ip_repr, raw_packet)) => {
                self.dispatch_ip(timestamp, ip_repr, |_ip_repr, payload| {
                    payload.copy_from_slice(raw_packet);
                })
            }
            Packet::Udp((ip_repr, udp_repr)) => {
                self.dispatch_ip(timestamp, ip_repr, |ip_repr, payload| {
                    udp_repr.emit(&mut UdpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr());
                })
            }
            Packet::Tcp((ip_repr, mut tcp_repr)) => {
                let limits = self.device.limits();
                self.dispatch_ip(timestamp, ip_repr, |ip_repr, payload| {
                    // This is a terrible hack to make TCP performance more acceptable on systems
                    // where the TCP buffers are significantly larger than network buffers,
                    // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                    // together with four 1500 B Ethernet receive buffers. If left untreated,
                    // this would result in our peer pushing our window and sever packet loss.
                    //
                    // I'm really not happy about this "solution" but I don't know what else to do.
                    if let Some(max_burst_size) = limits.max_burst_size {
                        let mut max_segment_size = limits.max_transmission_unit;
                        max_segment_size -= EthernetFrame::<&[u8]>::header_len();
                        max_segment_size -= ip_repr.buffer_len();
                        max_segment_size -= tcp_repr.header_len();

                        let max_window_size = max_burst_size * max_segment_size;
                        if tcp_repr.window_len as usize > max_window_size {
                            tcp_repr.window_len = max_window_size as u16;
                        }
                    }

                    tcp_repr.emit(&mut TcpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr());
                })
            }
            Packet::None => Ok(())
        }
    }

    fn dispatch_ethernet<F>(&mut self, timestamp: u64, buffer_len: usize, f: F) -> Result<()>
            where F: FnOnce(EthernetFrame<&mut [u8]>) {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        let mut tx_buffer = self.device.transmit(timestamp, tx_len)?;
        debug_assert!(tx_buffer.as_ref().len() == tx_len);

        let mut frame = EthernetFrame::new(tx_buffer.as_mut());
        frame.set_src_addr(self.hardware_addr);

        f(frame);

        Ok(())
    }

    fn lookup_hardware_addr(&mut self, timestamp: u64,
                            src_addr: &IpAddress, dst_addr: &IpAddress) ->
                           Result<EthernetAddress> {
        if let Some(hardware_addr) = self.arp_cache.lookup(dst_addr) {
            return Ok(hardware_addr)
        }

        if dst_addr.is_broadcast() {
            return Ok(EthernetAddress([0xff; 6]))
        }

        match (src_addr, dst_addr) {
            (&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr)) => {
                net_debug!("address {} not in ARP cache, sending request",
                           dst_addr);

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.hardware_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress([0xff; 6]),
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress([0xff; 6]));
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new(frame.payload_mut()))
                })?;

                Err(Error::Unaddressable)
            }
            _ => unreachable!()
        }
    }

    fn dispatch_ip<F>(&mut self, timestamp: u64, ip_repr: IpRepr, f: F) -> Result<()>
            where F: FnOnce(IpRepr, &mut [u8]) {
        let ip_repr = ip_repr.lower(&self.protocol_addrs)?;

        let dst_hardware_addr =
            self.lookup_hardware_addr(timestamp, &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        self.dispatch_ethernet(timestamp, ip_repr.total_len(), |mut frame| {
            frame.set_dst_addr(dst_hardware_addr);
            match ip_repr {
                IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                _ => unreachable!()
            }

            ip_repr.emit(frame.payload_mut());

            let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
            f(ip_repr, payload)
        })
    }
}
