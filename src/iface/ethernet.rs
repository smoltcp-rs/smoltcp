// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP.

use core::cmp;
use managed::ManagedSlice;

use {Error, Result};
use phy::{Device, DeviceCapabilities, RxToken, TxToken};
use wire::pretty_print::PrettyPrinter;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{Ipv4Address};
use wire::{IpAddress, IpProtocol, IpRepr, IpCidr};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use wire::{Ipv4Packet, Ipv4Repr};
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
#[cfg(feature = "socket-udp")]
use wire::{UdpPacket, UdpRepr};
#[cfg(feature = "socket-tcp")]
use wire::{TcpPacket, TcpRepr, TcpControl};

use socket::{Socket, SocketSet, AnySocket};
#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(feature = "socket-icmp")]
use socket::IcmpSocket;
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use socket::TcpSocket;
use super::{NeighborCache, NeighborAnswer};

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'b, 'c, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    inner:  InterfaceInner<'b, 'c>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for prorcessing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
struct InterfaceInner<'b, 'c> {
    neighbor_cache:         NeighborCache<'b>,
    ethernet_addr:          EthernetAddress,
    ip_addrs:               ManagedSlice<'c, IpCidr>,
    ipv4_gateway:           Option<Ipv4Address>,
    device_capabilities:    DeviceCapabilities,
}

/// A builder structure used for creating a Ethernet network
/// interface.
pub struct InterfaceBuilder <'b, 'c, DeviceT: for<'d> Device<'d>> {
    device:              DeviceT,
    ethernet_addr:       Option<EthernetAddress>,
    neighbor_cache:      Option<NeighborCache<'b>>,
    ip_addrs:            ManagedSlice<'c, IpCidr>,
    ipv4_gateway:        Option<Ipv4Address>,
}

impl<'b, 'c, DeviceT> InterfaceBuilder<'b, 'c, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache};
    /// # use smoltcp::phy::Loopback;
    /// use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};
    ///
    /// let device = // ...
    /// # Loopback::new();
    /// let hw_addr = // ...
    /// # EthernetAddress::default();
    /// let neighbor_cache = // ...
    /// # NeighborCache::new(BTreeMap::new());
    /// let ip_addrs = // ...
    /// # [];
    /// let iface = EthernetInterfaceBuilder::new(device)
    ///         .ethernet_addr(hw_addr)
    ///         .neighbor_cache(neighbor_cache)
    ///         .ip_addrs(ip_addrs)
    ///         .finalize();
    /// ```
    pub fn new(device: DeviceT) -> InterfaceBuilder<'b, 'c, DeviceT> {
        InterfaceBuilder {
            device:              device,
            ethernet_addr:       None,
            neighbor_cache:      None,
            ip_addrs:            [].into(),
            ipv4_gateway:        None
        }
    }

    /// Set the Ethernet address the interface will use. See also
    /// [ethernet_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [ethernet_addr]: struct.EthernetInterface.html#method.ethernet_addr
    pub fn ethernet_addr(mut self, addr: EthernetAddress) -> InterfaceBuilder<'b, 'c, DeviceT> {
        InterfaceInner::check_ethernet_addr(&addr);
        self.ethernet_addr = Some(addr);
        self
    }

    /// Set the IP addresses the interface will use. See also
    /// [ip_addrs].
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    ///
    /// [ip_addrs]: struct.EthernetInterface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> InterfaceBuilder<'b, 'c, DeviceT>
            where T: Into<ManagedSlice<'c, IpCidr>>
    {
        let ip_addrs = ip_addrs.into();
        InterfaceInner::check_ip_addrs(&ip_addrs);
        self.ip_addrs = ip_addrs;
        self
    }

    /// Set the IPv4 gateway the interface will use. See also
    /// [ipv4_gateway].
    ///
    /// # Panics
    /// This function panics if the given address is not unicast.
    ///
    /// [ipv4_gateway]: struct.EthernetInterface.html#method.ipv4_gateway
    pub fn ipv4_gateway<T>(mut self, gateway: T) -> InterfaceBuilder<'b, 'c, DeviceT>
            where T: Into<Ipv4Address>
    {
        let addr = gateway.into();
        InterfaceInner::check_gateway_addr(&addr);
        self.ipv4_gateway = Some(addr);
        self
    }

    /// Set the Neighbor Cache the interface will use.
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'b>) ->
                         InterfaceBuilder<'b, 'c, DeviceT> {
        self.neighbor_cache = Some(neighbor_cache);
        self
    }

    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// If a required option is not provided, this function will panic. Required
    /// options are:
    ///
    /// - [ethernet_addr]
    /// - [neighbor_cache]
    ///
    /// [ethernet_addr]: #method.ethernet_addr
    /// [neighbor_cache]: #method.neighbor_cache
    pub fn finalize(self) -> Interface<'b, 'c, DeviceT> {
        match (self.ethernet_addr, self.neighbor_cache) {
            (Some(ethernet_addr), Some(neighbor_cache)) => {
                let device_capabilities = self.device.capabilities();
                Interface {
                    device: self.device,
                    inner: InterfaceInner {
                        ethernet_addr, device_capabilities, neighbor_cache,
                        ip_addrs: self.ip_addrs, ipv4_gateway: self.ipv4_gateway,
                    }
                }
            },
            _ => panic!("a required option was not set"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Packet<'a> {
    None,
    Arp(ArpRepr),
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> Packet<'a> {
    fn neighbor_addr(&self) -> Option<IpAddress> {
        match self {
            &Packet::None | &Packet::Arp(_) => None,
            &Packet::Icmpv4((ref ipv4_repr, _)) => Some(ipv4_repr.dst_addr.into()),
            #[cfg(feature = "socket-raw")]
            &Packet::Raw((ref ip_repr, _)) => Some(ip_repr.dst_addr()),
            #[cfg(feature = "socket-udp")]
            &Packet::Udp((ref ip_repr, _)) => Some(ip_repr.dst_addr()),
            #[cfg(feature = "socket-tcp")]
            &Packet::Tcp((ref ip_repr, _)) => Some(ip_repr.dst_addr())
        }
    }
}

impl<'b, 'c, DeviceT> Interface<'b, 'c, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Get the Ethernet address of the interface.
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.inner.ethernet_addr
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        self.inner.ethernet_addr = addr;
        InterfaceInner::check_ethernet_addr(&self.inner.ethernet_addr);
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'c, IpCidr>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    /// Get the IPv4 gateway of the interface.
    pub fn ipv4_gateway(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_gateway
    }

    /// Set the IPv4 gateway of the interface.
    pub fn set_ipv4_gateway<GatewayAddrT>(&mut self, gateway: GatewayAddrT)
            where GatewayAddrT: Into<Option<Ipv4Address>> {
        self.inner.ipv4_gateway = gateway.into();
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
    ///
    /// # Errors
    /// This method will routinely return errors in response to normal network
    /// activity as well as certain boundary conditions such as buffer exhaustion.
    /// These errors are provided as an aid for troubleshooting, and are meant
    /// to be logged and ignored.
    ///
    /// As a special case, `Err(Error::Unrecognized)` is returned in response to
    /// packets containing any unsupported protocol, option, or form, which is
    /// a very common occurrence and on a production system it should not even
    /// be logged.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<Option<u64>> {
        self.socket_egress(sockets, timestamp)?;

        if self.socket_ingress(sockets, timestamp)? {
            Ok(Some(0))
        } else {
            Ok(sockets.iter().filter_map(|socket| {
                let socket_poll_at = socket.poll_at();
                socket.meta().poll_at(socket_poll_at, |ip_addr|
                    self.inner.has_neighbor(&ip_addr, timestamp))
            }).min())
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let &mut Self { ref mut device, ref mut inner } = self;
            let (rx_token, tx_token) = match device.receive() {
                None => break,
                Some(tokens) => tokens,
            };
            let dispatch_result = rx_token.consume(timestamp, |frame| {
                let response = inner.process_ethernet(sockets, timestamp, &frame).map_err(|err| {
                    net_debug!("cannot process ingress packet: {}", err);
                    net_debug!("packet dump follows:\n{}",
                               PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame));
                    err
                })?;
                processed_any = true;

                inner.dispatch(tx_token, timestamp, response)
            });
            dispatch_result.map_err(|err| {
                net_debug!("cannot dispatch response packet: {}", err);
                err
            })?;
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: u64) -> Result<()> {
        let mut caps = self.device.capabilities();
        caps.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len();

        for mut socket in sockets.iter_mut() {
            if !socket.meta_mut().egress_permitted(|ip_addr|
                    self.inner.has_neighbor(&ip_addr, timestamp)) {
                continue
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());
            let &mut Self { ref mut device, ref mut inner } = self;
            let socket_result =
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(ref mut socket) =>
                        socket.dispatch(|response| {
                            let response = Packet::Raw(response);
                            neighbor_addr = response.neighbor_addr();
                            let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                            device_result = inner.dispatch(tx_token, timestamp, response);
                            device_result
                        }, &caps.checksum),
                    #[cfg(feature = "socket-icmp")]
                    Socket::Icmp(ref mut socket) =>
                        socket.dispatch(&caps, |response| {
                            let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                            device_result = match response {
                                (IpRepr::Ipv4(ipv4_repr), icmpv4_repr) => {
                                    let response = Packet::Icmpv4((ipv4_repr, icmpv4_repr));
                                    neighbor_addr = response.neighbor_addr();
                                    inner.dispatch(tx_token, timestamp, response)
                                }
                                _ => Err(Error::Unaddressable),
                            };
                            device_result
                        }),
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response| {
                            let response = Packet::Udp(response);
                            neighbor_addr = response.neighbor_addr();
                            let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                            device_result = inner.dispatch(tx_token, timestamp, response);
                            device_result
                        }),
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &caps, |response| {
                            let response = Packet::Tcp(response);
                            neighbor_addr = response.neighbor_addr();
                            let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                            device_result = inner.dispatch(tx_token, timestamp, response);
                            device_result
                        }),
                    Socket::__Nonexhaustive(_) => unreachable!()
                };
            match (device_result, socket_result) {
                (Err(Error::Exhausted), _) => break,     // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (),   // nothing to transmit
                (Err(Error::Unaddressable), _) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighboor.
                    socket.meta_mut().neighbor_missing(timestamp,
                        neighbor_addr.expect("non-IP response packet"));
                    break
                }
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!("{}: cannot dispatch egress packet: {}",
                               socket.meta().handle, err);
                    return Err(err)
                }
                (Ok(()), Ok(())) => ()
            }
        }
        Ok(())
    }
}

impl<'b, 'c> InterfaceInner<'b, 'c> {
    fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    fn check_gateway_addr(addr: &Ipv4Address) {
        if !addr.is_unicast() {
            panic!("gateway IP address {} is not unicast", addr);
        }
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    fn process_ethernet<'frame, T: AsRef<[u8]>>
                       (&mut self, sockets: &mut SocketSet, timestamp: u64, frame: &'frame T) ->
                       Result<Packet<'frame>>
    {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address.
        if !eth_frame.dst_addr().is_broadcast() &&
                eth_frame.dst_addr() != self.ethernet_addr {
            return Ok(Packet::None)
        }

        match eth_frame.ethertype() {
            EthernetProtocol::Arp =>
                self.process_arp(timestamp, &eth_frame),
            EthernetProtocol::Ipv4 =>
                self.process_ipv4(sockets, timestamp, &eth_frame),
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, timestamp: u64, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Packet<'frame>>
    {
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
                    self.neighbor_cache.fill(source_protocol_addr.into(),
                                             source_hardware_addr,
                                             timestamp);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
                    return Err(Error::Malformed)
                }

                if operation == ArpOperation::Request && self.has_ip_addr(target_protocol_addr) {
                    Ok(Packet::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.ethernet_addr,
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
                   Result<Packet<'frame>>
    {
        let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the neighbor cache from IP header of unicast frames.
            let ip_addr = IpAddress::Ipv4(ipv4_repr.src_addr);
            if self.in_same_network(&ip_addr) {
                self.neighbor_cache.fill(ip_addr, eth_frame.src_addr(), timestamp);
            }
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        #[cfg(feature = "socket-raw")]
        for mut raw_socket in sockets.iter_mut().filter_map(RawSocket::downcast) {
            if !raw_socket.accepts(&ip_repr) { continue }

            match raw_socket.process(&ip_repr, ip_payload, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_raw_socket = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }

        if !ipv4_repr.dst_addr.is_broadcast() && !self.has_ip_addr(ipv4_repr.dst_addr) {
            // Ignore IP packets not directed at us.
            return Ok(Packet::None)
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ip_repr, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ip_repr, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(Packet::None),

            _ => {
                // Send back as much of the original payload as we can
                let payload_len = cmp::min(
                    ip_payload.len(), self.device_capabilities.max_transmission_unit);
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr))
            }
        }
    }

    fn process_icmpv4<'frame>(&self, _sockets: &mut SocketSet, ip_repr: IpRepr,
                              ip_payload: &'frame [u8]) -> Result<Packet<'frame>>
    {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &checksum_caps)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(feature = "socket-icmp")]
        for mut icmp_socket in _sockets.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr, &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_icmp_socket = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // ICMP sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            Icmpv4Repr::EchoRequest { ident, seq_no, data } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident:  ident,
                    seq_no: seq_no,
                    data:   data
                };
                match ip_repr {
                    IpRepr::Ipv4(ipv4_repr) => Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr)),
                    _ => Err(Error::Unrecognized),
                }
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(Packet::None),

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(Packet::None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    fn icmpv4_reply<'frame, 'icmp: 'frame>
                   (&self, ipv4_repr: Ipv4Repr, icmp_repr: Icmpv4Repr<'icmp>) ->
                   Packet<'frame>
    {
        if ipv4_repr.dst_addr.is_unicast() {
            let ipv4_reply_repr = Ipv4Repr {
                src_addr:    ipv4_repr.dst_addr,
                dst_addr:    ipv4_repr.src_addr,
                protocol:    IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Packet::Icmpv4((ipv4_reply_repr, icmp_repr))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            Packet::None
        }
    }

    #[cfg(feature = "socket-udp")]
    fn process_udp<'frame>(&self, sockets: &mut SocketSet,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) { continue }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(Packet::None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            IpRepr::Ipv4(ipv4_repr) => {
                // Send back as much of the original payload as we can
                let payload_len = cmp::min(
                    ip_payload.len(), self.device_capabilities.max_transmission_unit);
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr))
            },
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) => Err(Error::Unaddressable),
            IpRepr::Unspecified { .. } |
            IpRepr::__Nonexhaustive =>
                unreachable!()
        }
    }

    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(&self, sockets: &mut SocketSet, timestamp: u64,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Packet<'frame>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut tcp_socket in sockets.iter_mut().filter_map(TcpSocket::downcast) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) { continue }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map_or(Packet::None, Packet::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
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

    fn dispatch<Tx>(&mut self, tx_token: Tx, timestamp: u64,
                    packet: Packet) -> Result<()>
        where Tx: TxToken
    {
        let checksum_caps = self.device_capabilities.checksum.clone();
        match packet {
            Packet::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            Packet::Icmpv4((ipv4_repr, icmpv4_repr)) => {
                self.dispatch_ip(tx_token, timestamp, IpRepr::Ipv4(ipv4_repr),
                                 |_ip_repr, payload| {
                    icmpv4_repr.emit(&mut Icmpv4Packet::new(payload), &checksum_caps);
                })
            }
            #[cfg(feature = "socket-raw")]
            Packet::Raw((ip_repr, raw_packet)) => {
                self.dispatch_ip(tx_token, timestamp, ip_repr, |_ip_repr, payload| {
                    payload.copy_from_slice(raw_packet);
                })
            }
            #[cfg(feature = "socket-udp")]
            Packet::Udp((ip_repr, udp_repr)) => {
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    udp_repr.emit(&mut UdpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            #[cfg(feature = "socket-tcp")]
            Packet::Tcp((ip_repr, mut tcp_repr)) => {
                let caps = self.device_capabilities.clone();
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    // This is a terrible hack to make TCP performance more acceptable on systems
                    // where the TCP buffers are significantly larger than network buffers,
                    // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                    // together with four 1500 B Ethernet receive buffers. If left untreated,
                    // this would result in our peer pushing our window and sever packet loss.
                    //
                    // I'm really not happy about this "solution" but I don't know what else to do.
                    if let Some(max_burst_size) = caps.max_burst_size {
                        let mut max_segment_size = caps.max_transmission_unit;
                        max_segment_size -= EthernetFrame::<&[u8]>::header_len();
                        max_segment_size -= ip_repr.buffer_len();
                        max_segment_size -= tcp_repr.header_len();

                        let max_window_size = max_burst_size * max_segment_size;
                        if tcp_repr.window_len as usize > max_window_size {
                            tcp_repr.window_len = max_window_size as u16;
                        }
                    }

                    tcp_repr.emit(&mut TcpPacket::new(payload),
                                  &ip_repr.src_addr(), &ip_repr.dst_addr(),
                                  &checksum_caps);
                })
            }
            Packet::None => Ok(())
        }
    }

    fn dispatch_ethernet<Tx, F>(&mut self, tx_token: Tx, timestamp: u64,
                                buffer_len: usize, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(EthernetFrame<&mut [u8]>)
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(timestamp, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new(tx_buffer.as_mut());
            frame.set_src_addr(self.ethernet_addr);

            f(frame);

            Ok(())
        })
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs
            .iter()
            .find(|cidr| cidr.contains_addr(addr))
            .is_some()
    }

    fn route(&self, addr: &IpAddress) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) {
            return Ok(addr.clone())
        }

        // Route via a gateway.
        match (addr, self.ipv4_gateway) {
            (&IpAddress::Ipv4(_), Some(gateway)) => Ok(gateway.into()),
            _ => Err(Error::Unaddressable)
        }
    }

    fn has_neighbor<'a>(&self, addr: &'a IpAddress, timestamp: u64) -> bool {
        match self.route(addr) {
            Ok(routed_addr) => {
                self.neighbor_cache
                    .lookup_pure(&routed_addr, timestamp)
                    .is_some()
            }
            Err(_) => false
        }
    }

    fn lookup_hardware_addr<Tx>(&mut self, tx_token: Tx, timestamp: u64,
                                src_addr: &IpAddress, dst_addr: &IpAddress) ->
                               Result<(EthernetAddress, Tx)>
        where Tx: TxToken
    {
        let dst_addr = self.route(dst_addr)?;

        match self.neighbor_cache.lookup(&dst_addr, timestamp) {
            NeighborAnswer::Found(hardware_addr) =>
                return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited =>
                return Err(Error::Unaddressable),
            NeighborAnswer::NotFound => (),
        }

        match (src_addr, dst_addr) {
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending ARP request",
                           dst_addr);

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.ethernet_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new(frame.payload_mut()))
                })?;

                Err(Error::Unaddressable)
            }
            _ => unreachable!()
        }
    }

    fn dispatch_ip<Tx, F>(&mut self, tx_token: Tx, timestamp: u64,
                          ip_repr: IpRepr, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(IpRepr, &mut [u8])
    {
        let ip_repr = ip_repr.lower(&self.ip_addrs)?;
        let checksum_caps = self.device_capabilities.checksum.clone();

        let (dst_hardware_addr, tx_token) =
            self.lookup_hardware_addr(tx_token, timestamp,
                                      &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        self.dispatch_ethernet(tx_token, timestamp, ip_repr.total_len(), |mut frame| {
            frame.set_dst_addr(dst_hardware_addr);
            match ip_repr {
                IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                _ => unreachable!()
            }

            ip_repr.emit(frame.payload_mut(), &checksum_caps);

            let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
            f(ip_repr, payload)
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use {Result, Error};

    use super::InterfaceBuilder;
    use iface::{NeighborCache, EthernetInterface};
    use phy::{self, Loopback, ChecksumCapabilities};
    use socket::SocketSet;
    use wire::{ArpOperation, ArpPacket, ArpRepr};
    use wire::{EthernetAddress, EthernetFrame, EthernetProtocol};
    use wire::{IpAddress, IpCidr, IpProtocol, IpRepr};
    use wire::{Ipv4Address, Ipv4Repr};
    use wire::{Icmpv4Repr, Icmpv4DstUnreachable};
    use wire::{UdpPacket, UdpRepr};

    use super::Packet;

    fn create_loopback<'a, 'b>() -> (EthernetInterface<'static, 'b, Loopback>,
                                     SocketSet<'static, 'a, 'b>) {
        // Create a basic device
        let device = Loopback::new();

        let iface = InterfaceBuilder::new(device)
                .ethernet_addr(EthernetAddress::default())
                .neighbor_cache(NeighborCache::new(BTreeMap::new()))
                .ip_addrs([IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)])
                .finalize();

        (iface, SocketSet::new(vec![]))
    }

    #[derive(Debug, PartialEq)]
    struct MockTxToken;

    impl phy::TxToken for MockTxToken {
        fn consume<R, F>(self, _: u64, _: usize, _: F) -> Result<R>
                where F: FnOnce(&mut [u8]) -> Result<R> {
            Err(Error::__Nonexhaustive)
        }
    }

    #[test]
    #[should_panic(expected = "a required option was not set")]
    fn test_builder_initialization_panic() {
        InterfaceBuilder::new(Loopback::new()).finalize();
    }

    #[test]
    fn test_no_icmp_to_broadcast() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 34];

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let frame = {
            let mut frame = EthernetFrame::new(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new(&*frame.into_inner())
        };

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, 0, &frame),
                   Ok(Packet::None));
    }

    #[test]
    fn test_icmp_error_no_payload() {
        static NO_BYTES: [u8; 0] = [];
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 34];

        // Unknown Ipv4 Protocol with no payload
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        // emit the above repr to a frame
        let frame = {
            let mut frame = EthernetFrame::new(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new(&*frame.into_inner())
        };

        // The expected Destination Unreachable response due to the
        // unknown protocol
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::ProtoUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Unknown(12),
                payload_len: 0,
                hop_limit: 64
            },
            data: &NO_BYTES
        };

        let expected_repr = Packet::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64
            },
            icmp_repr
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(iface.inner.process_ipv4(&mut socket_set, 0, &frame),
                   Ok(expected_repr));
    }

    #[test]
    fn test_icmp_error_port_unreachable() {
        static UDP_PAYLOAD: [u8; 12] = [
            0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x2c, 0x20, 0x57,
            0x6f, 0x6c, 0x64, 0x21
        ];
        let (iface, mut socket_set) = create_loopback();

        let mut udp_bytes_unicast = vec![0u8; 20];
        let mut udp_bytes_broadcast = vec![0u8; 20];
        let mut packet_unicast = UdpPacket::new(&mut udp_bytes_unicast);
        let mut packet_broadcast = UdpPacket::new(&mut udp_bytes_broadcast);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload:  &UDP_PAYLOAD
        };

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   64
        });

        // Emit the representations to a packet
        udp_repr.emit(&mut packet_unicast, &ip_repr.src_addr(),
                      &ip_repr.dst_addr(), &ChecksumCapabilities::default());

        let data = packet_unicast.into_inner();

        // The expected Destination Unreachable ICMPv4 error response due
        // to no sockets listening on the destination port.
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.buffer_len(),
                hop_limit: 64
            },
            data: &data
        };
        let expected_repr = Packet::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64
            },
            icmp_repr
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, data),
                   Ok(expected_repr));

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   64
        });

        // Emit the representations to a packet
        udp_repr.emit(&mut packet_broadcast, &ip_repr.src_addr(),
                      &IpAddress::Ipv4(Ipv4Address::BROADCAST),
                      &ChecksumCapabilities::default());

        // Ensure that the port unreachable error does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address and no socket is bound to the port.
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr,
                   packet_broadcast.into_inner()), Ok(Packet::None));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use socket::{UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
        use wire::IpEndpoint;

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (iface, mut socket_set) = create_loopback();

        let rx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 15])]);
        let tx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 15])]);

        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        let mut udp_bytes = vec![0u8; 13];
        let mut packet = UdpPacket::new(&mut udp_bytes);

        let socket_handle = socket_set.add(udp_socket);

        let src_ip = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload:  &UDP_PAYLOAD
        };

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    src_ip,
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   0x40
        });

        {
            // Bind the socket to port 68
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert_eq!(socket.bind(68), Ok(()));
            assert!(!socket.can_recv());
            assert!(socket.can_send());
        }

        udp_repr.emit(&mut packet, &ip_repr.src_addr(), &ip_repr.dst_addr(),
                      &ChecksumCapabilities::default());

        // Packet should be handled by bound UDP socket
        assert_eq!(iface.inner.process_udp(&mut socket_set, ip_repr, packet.into_inner()),
                   Ok(Packet::None));

        {
            // Make sure the payload to the UDP packet processed by process_udp is
            // appended to the bound sockets rx_buffer
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67))));
        }
    }

    #[test]
    fn test_handle_valid_arp_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 42];

        let local_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: local_ip_addr,
        };

        let mut frame = EthernetFrame::new(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for us triggers an ARP Reply
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, 0, frame.into_inner()),
                   Ok(Packet::Arp(ArpRepr::EthernetIpv4 {
                       operation: ArpOperation::Reply,
                       source_hardware_addr: local_hw_addr,
                       source_protocol_addr: local_ip_addr,
                       target_hardware_addr: remote_hw_addr,
                       target_protocol_addr: remote_ip_addr
                   })));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, 0,
            &IpAddress::Ipv4(local_ip_addr), &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    fn test_handle_other_arp_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 42];

        let remote_ip_addr = Ipv4Address([0x7f, 0x00, 0x00, 0x02]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: remote_hw_addr,
            source_protocol_addr: remote_ip_addr,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x03]),
        };

        let mut frame = EthernetFrame::new(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for someone else does not trigger an ARP Reply
        assert_eq!(iface.inner.process_ethernet(&mut socket_set, 0, frame.into_inner()),
                   Ok(Packet::None));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, 0,
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "socket-icmp")]
    fn test_icmpv4_socket() {
        use socket::{IcmpPacketBuffer, IcmpSocket, IcmpSocketBuffer, IcmpEndpoint};
        use wire::Icmpv4Packet;

        let (iface, mut socket_set) = create_loopback();

        let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 24])]);
        let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 24])]);

        let icmpv4_socket = IcmpSocket::new(rx_buffer, tx_buffer);

        let socket_handle = socket_set.add(icmpv4_socket);

        let ident = 0x1234;
        let seq_no = 0x5432;
        let echo_data = &[0xff; 16];

        {
            let mut socket = socket_set.get::<IcmpSocket>(socket_handle);
            // Bind to the ID 0x1234
            assert_eq!(socket.bind(IcmpEndpoint::Ident(ident)), Ok(()));
        }

        // Ensure the ident we bound to and the ident of the packet are the same.
        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new(&mut bytes);
        let echo_repr = Icmpv4Repr::EchoRequest{ ident, seq_no, data: echo_data };
        echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
        let icmp_data = &packet.into_inner()[..];

        let ipv4_repr = Ipv4Repr {
            src_addr:    Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr:    Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            protocol:    IpProtocol::Icmp,
            payload_len: 24,
            hop_limit:   64
        };
        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        // Open a socket and ensure the packet is handled due to the listening
        // socket.
        {
            assert!(!socket_set.get::<IcmpSocket>(socket_handle).can_recv());
        }

        // Confirm we still get EchoReply from `smoltcp` even with the ICMP socket listening
        let echo_reply = Icmpv4Repr::EchoReply{ ident, seq_no, data: echo_data };
        let ipv4_reply = Ipv4Repr {
            src_addr: ipv4_repr.dst_addr,
            dst_addr: ipv4_repr.src_addr,
            ..ipv4_repr
        };
        assert_eq!(iface.inner.process_icmpv4(&mut socket_set, ip_repr, icmp_data),
                   Ok(Packet::Icmpv4((ipv4_reply, echo_reply))));

        {
            let mut socket = socket_set.get::<IcmpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(),
                       Ok((&icmp_data[..],
                           IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02)))));
        }
    }
}
