// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

use managed::{ManagedSlice, ManagedMap};
#[cfg(not(feature = "proto-igmp"))]
use core::marker::PhantomData;

use {Error, Result};
use phy::{Device, DeviceCapabilities, RxToken, TxToken};
use time::{Duration, Instant};
use wire::pretty_print::PrettyPrinter;
use wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use wire::{IpAddress, IpRepr, IpCidr};
#[cfg(feature = "proto-ipv6")]
use wire::{IpProtocol, Ipv6Packet, Ipv6Repr};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Address, Ipv4Packet, Ipv4Repr};
#[cfg(feature = "proto-ipv4")]
use wire::{ArpPacket, ArpRepr, ArpOperation};
#[cfg(feature = "proto-ipv6")]
use wire::{Icmpv6Repr};
#[cfg(feature = "proto-ipv6")]
use wire::{NdiscNeighborFlags, NdiscRepr};

use socket::{SocketSet, PollAt};
use super::{NeighborCache, NeighborAnswer};
use super::Routes;
use super::ip;

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'b, 'c, 'e, DeviceT: for<'d> Device<'d>> {
    device:     DeviceT,

    config:     Config,
    state:      State<'b>,

    ip_config:  ip::Config<'c, 'e>,
    ip_state:   ip::State<'e>,
}

/// Configuration for the interface. This is data that can't change
/// as a result of processing packets (as opposed to State).
/// 
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on config and data.
/// 
/// Similarly, separating config and state allows borrowing them indepentently, which is
/// useful because many components may want immutable access to config, while the packet
/// processing logic has mutable access to State. 
struct Config {
    ethernet_addr:  EthernetAddress,
}

/// State for the interface packet processing logic. This tracks the state of 
/// many protocols, and changes during packet processing.
struct State<'b> {
    neighbor_cache:         NeighborCache<'b>,
    device_capabilities:    DeviceCapabilities,
}

struct Processor<'b, 'c, 'e, 'x> {
    config: &'x Config,
    ip_config: &'x ip::Config<'c, 'e>,
    state: &'x mut State<'b>
}

// These cannot be functions because they would borrow `self` completely,
// and we need them to borrow just the fields.
macro_rules! processor {
    ($iface:expr) => (Processor{
        config: &$iface.config,
        ip_config: &$iface.ip_config,
        state: &mut $iface.state,
    })
}
macro_rules! ip_processor {
    ($iface:expr) => (ip::Processor{
        config: &$iface.ip_config,
        state: &mut $iface.ip_state,
    })
}

/// A builder structure used for creating a Ethernet network
/// interface.
pub struct InterfaceBuilder <'b, 'c, 'e, DeviceT: for<'d> Device<'d>> {
    device:                 DeviceT,
    ethernet_addr:          Option<EthernetAddress>,
    neighbor_cache:         Option<NeighborCache<'b>>,
    ip_addrs:               ManagedSlice<'c, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip:                 bool,
    routes:                 Routes<'e>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups:  ManagedMap<'e, Ipv4Address, ()>,
    #[cfg(not(feature = "proto-igmp"))]
    _ipv4_multicast_groups: PhantomData<&'e ()>,
}

impl<'b, 'c, 'e, DeviceT> InterfaceBuilder<'b, 'c, 'e, DeviceT>
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
    pub fn new(device: DeviceT) -> Self {
        InterfaceBuilder {
            device:              device,
            ethernet_addr:       None,
            neighbor_cache:      None,
            ip_addrs:            ManagedSlice::Borrowed(&mut []),
            #[cfg(feature = "proto-ipv4")]
            any_ip:              false,
            routes:              Routes::new(ManagedMap::Borrowed(&mut [])),
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups:   ManagedMap::Borrowed(&mut []),
            #[cfg(not(feature = "proto-igmp"))]
            _ipv4_multicast_groups:  PhantomData,
        }
    }

    /// Set the Ethernet address the interface will use. See also
    /// [ethernet_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [ethernet_addr]: struct.EthernetInterface.html#method.ethernet_addr
    pub fn ethernet_addr(mut self, addr: EthernetAddress) -> Self {
        Config::check_ethernet_addr(&addr);
        self.ethernet_addr = Some(addr);
        self
    }

    /// Set the IP addresses the interface will use. See also
    /// [ip_addrs].
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    ///
    /// [ip_addrs]: struct.EthernetInterface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> Self
        where T: Into<ManagedSlice<'c, IpCidr>>
    {
        let ip_addrs = ip_addrs.into();
        ip::Config::check_ip_addrs(&ip_addrs);
        self.ip_addrs = ip_addrs;
        self
    }

    /// Enable or disable the AnyIP capability, allowing packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [routes] specifies one of
    /// the interface's [ip_addrs] as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    ///
    /// [routes]: struct.EthernetInterface.html#method.routes
    /// [ip_addrs]: struct.EthernetInterface.html#method.ip_addrs
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(mut self, enabled: bool) -> Self {
        self.any_ip = enabled;
        self
    }

    /// Set the IP routes the interface will use. See also
    /// [routes].
    ///
    /// [routes]: struct.EthernetInterface.html#method.routes
    pub fn routes<T>(mut self, routes: T) -> InterfaceBuilder<'b, 'c, 'e, DeviceT>
        where T: Into<Routes<'e>>
    {
        self.routes = routes.into();
        self
    }

    /// Provide storage for multicast groups.
    ///
    /// Join multicast groups by calling [`join_multicast_group()`] on an `Interface`.
    /// Using [`join_multicast_group()`] will send initial membership reports.
    ///
    /// A previously destroyed interface can be recreated by reusing the multicast group
    /// storage, i.e. providing a non-empty storage to `ipv4_multicast_groups()`.
    /// Note that this way initial membership reports are **not** sent.
    ///
    /// [`join_multicast_group()`]: struct.EthernetInterface.html#method.join_multicast_group
    #[cfg(feature = "proto-igmp")]
    pub fn ipv4_multicast_groups<T>(mut self, ipv4_multicast_groups: T) -> Self
        where T: Into<ManagedMap<'e, Ipv4Address, ()>>
    {
        self.ipv4_multicast_groups = ipv4_multicast_groups.into();
        self
    }

    /// Set the Neighbor Cache the interface will use.
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'b>) -> Self {
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
    pub fn finalize(self) -> Interface<'b, 'c, 'e, DeviceT> {
        match (self.ethernet_addr, self.neighbor_cache) {
            (Some(ethernet_addr), Some(neighbor_cache)) => {
                let caps = self.device.capabilities();
                let mut ip_caps = self.device.capabilities();

                // The IP code needs to know the MTU of the IP packet (not including the Ethernet header)
                ip_caps.max_transmission_unit -= EthernetFrame::<&[u8]>::header_len(); 

                Interface {
                    device: self.device,
                    config: Config {
                        ethernet_addr, 
                    },
                    ip_config: ip::Config{
                        ip_addrs: self.ip_addrs,
                        #[cfg(feature = "proto-ipv4")]
                        any_ip: self.any_ip,
                        routes: self.routes,
                    },
                    state: State {
                        neighbor_cache,
                        device_capabilities: caps,
                    },
                    ip_state: ip::State{
                        device_capabilities: ip_caps,
                        #[cfg(feature = "proto-igmp")]
                        ipv4_multicast_groups: self.ipv4_multicast_groups,
                        #[cfg(not(feature = "proto-igmp"))]
                        _ipv4_multicast_groups:  PhantomData,
                        #[cfg(feature = "proto-igmp")]
                        igmp_report_state: ip::IgmpReportState::Inactive,
                    },
                }
            },
            _ => panic!("a required option was not set"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Packet<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(ip::Packet<'a>),
}

impl<'b, 'c, 'e, DeviceT> Interface<'b, 'c, 'e, DeviceT>
        where DeviceT: for<'d> Device<'d> {
    /// Get the Ethernet address of the interface.
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.config.ethernet_addr
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        self.config.ethernet_addr = addr;
        Config::check_ethernet_addr(&self.config.ethernet_addr);
    }

    /// Get a reference to the inner device.
    pub fn device(&self) -> &DeviceT {
        &self.device
    }

    /// Get a mutable reference to the inner device.
    ///
    /// There are no invariants imposed on the device by the interface itself. Furthermore the
    /// trait implementations, required for references of all lifetimes, guarantees that the
    /// mutable reference can not invalidate the device as such. For some devices, such access may
    /// still allow modifications with adverse effects on the usability as a `phy` device. You
    /// should not use them this way.
    pub fn device_mut(&mut self) -> &mut DeviceT {
        &mut self.device
    }

    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<T: Into<IpAddress>>(&mut self, addr: T, timestamp: Instant) -> Result<bool> {
        match ip_processor!(self).join_multicast_group(addr, timestamp)? {
            None => Ok(false),
            Some(pkt) => { 
                let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                processor!(self).dispatch(tx_token, timestamp, Packet::Ip(pkt))?;
                Ok(true)
            },
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<T: Into<IpAddress>>(&mut self, addr: T, timestamp: Instant) -> Result<bool> {
        match ip_processor!(self).leave_multicast_group(addr, timestamp)? {
            None => Ok(false),
            Some(pkt) => { 
                let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                processor!(self).dispatch(tx_token, timestamp, Packet::Ip(pkt))?;
                Ok(true)
            },
        }
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.ip_state.has_multicast_group(addr)
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.ip_config.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs().iter()
            .filter_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                _ => None,
            }).next()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'c, IpCidr>)>(&mut self, f: F) {
        f(&mut self.ip_config.ip_addrs);
        ip::Config::check_ip_addrs(&self.ip_config.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.ip_config.has_ip_addr(addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_config.ipv4_address()
    }

    pub fn routes(&self) -> &Routes<'e> {
        &self.ip_config.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes<'e> {
        &mut self.ip_config.routes
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
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
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut readiness_may_have_changed = false;
        loop {
            let processed_any = self.socket_ingress(sockets, timestamp)?;

            let l = &mut LowerDispatcher{
                device: &mut self.device,
                processor: processor!(self),
            };
            let emitted_any   = ip_processor!(self).socket_egress(l, sockets, timestamp)?;

            #[cfg(feature = "proto-igmp")]
            ip_processor!(self).igmp_egress(l, timestamp)?;

            if processed_any || emitted_any {
                readiness_may_have_changed = true;
            } else {
                break
            }
        }
        Ok(readiness_may_have_changed)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Instant> {
        sockets.iter().filter_map(|socket| {
            let socket_poll_at = socket.poll_at();
            match socket.meta().poll_at(socket_poll_at, |ip_addr|
                self.state.has_neighbor(&self.ip_config, &ip_addr, timestamp)) {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
            }
        }).min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Duration> {
        match self.poll_at(sockets, timestamp) {
            Some(poll_at) if timestamp < poll_at => {
                Some(poll_at - timestamp)
            }
            Some(_) => {
                Some(Duration::from_millis(0))
            }
            _ => None
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let (rx_token, tx_token) = match self.device.receive() {
                None => break,
                Some(tokens) => tokens,
            };
            let mut p = processor!(self);
            let mut ip = ip_processor!(self);
            rx_token.consume(timestamp, |frame| {
                p.process_ethernet(&mut ip, sockets, timestamp, &frame).map_err(|err| {
                    net_debug!("cannot process ingress packet: {}", err);
                    net_debug!("packet dump follows:\n{}",
                               PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame));
                    err
                }).and_then(|response| {
                    match response {
                        Some(packet) => {
                            processed_any = true;
                            p.dispatch(tx_token, timestamp, packet).map_err(|err| {
                                net_debug!("cannot dispatch response packet: {}", err);
                                err
                            })
                        }
                        None => Ok(())
                    }
                })
            })?;
        }
        Ok(processed_any)
    }
}

impl Config {
    fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }
}

impl<'b> State<'b> {
    fn has_neighbor<'a>(&self, ip_config: &ip::Config, addr: &'a IpAddress, timestamp: Instant) -> bool {
        match ip_config.route(addr, timestamp) {
            Ok(routed_addr) => {
                self.neighbor_cache
                    .lookup_pure(&routed_addr, timestamp)
                    .is_some()
            }
            Err(_) => false
        }
    }
}

impl<'b, 'c, 'e, 'x> Processor<'b, 'c, 'e, 'x> {

    fn process_ethernet<'frame, T: AsRef<[u8]>>
                       (&mut self, ip: &mut ip::Processor, sockets: &mut SocketSet, timestamp: Instant, frame: &'frame T) ->
                       Result<Option<Packet<'frame>>>
    {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast() &&
           !eth_frame.dst_addr().is_multicast() &&
           eth_frame.dst_addr() != self.config.ethernet_addr
        {
            return Ok(None)
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp =>
                self.process_arp(timestamp, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 =>
                self.process_ipv4(ip, sockets, timestamp, &eth_frame).map(|o| o.map(Packet::Ip)),
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 =>
                self.process_ipv6(ip, sockets, timestamp, &eth_frame).map(|o| o.map(Packet::Ip)),
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_arp<'frame, T: AsRef<[u8]>>
                  (&mut self, timestamp: Instant, eth_frame: &EthernetFrame<&'frame T>) ->
                  Result<Option<Packet<'frame>>>
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
                    self.state.neighbor_cache.fill(source_protocol_addr.into(),
                                             source_hardware_addr,
                                             timestamp);
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
                    return Err(Error::Malformed)
                }

                if operation == ArpOperation::Request && self.ip_config.has_ip_addr(target_protocol_addr) {
                    Ok(Some(Packet::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.config.ethernet_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr
                    })))
                } else {
                    Ok(None)
                }
            }

            _ => Err(Error::Unrecognized)
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ipv6<'frame, T: AsRef<[u8]>>
                   (&mut self, ip: &mut ip::Processor, sockets: &mut SocketSet, timestamp: Instant,
                    eth_frame: &EthernetFrame<&'frame T>) ->
                   Result<Option<ip::Packet<'frame>>>
    {
        let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the neighbor cache from IP header of unicast frames.
            let ip_addr = IpAddress::Ipv6(ipv6_repr.src_addr);
            if self.ip_config.in_same_network(&ip_addr) &&
                    self.state.neighbor_cache.lookup_pure(&ip_addr, timestamp).is_none() {
                self.state.neighbor_cache.fill(ip_addr, eth_frame.src_addr(), timestamp);
            }
        }
        
        let lower = &mut LowerProcessor{
            _processor: processor!(self),
        };
        ip.process_ipv6(lower, sockets, timestamp, &ipv6_packet)
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4<'frame, T: AsRef<[u8]>>
                   (&mut self, ip: &mut ip::Processor, sockets: &mut SocketSet, timestamp: Instant,
                    eth_frame: &EthernetFrame<&'frame T>) ->
                   Result<Option<ip::Packet<'frame>>>
    {
        let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        if eth_frame.src_addr().is_unicast() {
            // Fill the neighbor cache from IP header of unicast frames.
            let ip_addr = IpAddress::Ipv4(ipv4_repr.src_addr);
            if self.ip_config.in_same_network(&ip_addr) {
                self.state.neighbor_cache.fill(ip_addr, eth_frame.src_addr(), timestamp);
            }
        }

        let lower = &mut LowerProcessor{
            _processor: processor!(self),
        };
        ip.process_ipv4(lower, sockets, timestamp, &ipv4_packet)
    }


    #[cfg(feature = "proto-ipv6")]
    fn process_ndisc<'frame>(&mut self, timestamp: Instant, ip_repr: Ipv6Repr,
                             repr: NdiscRepr<'frame>) -> Result<Option<ip::Packet<'frame>>> {
        match repr {
            NdiscRepr::NeighborAdvert { lladdr, target_addr, flags } => {
                let ip_addr = ip_repr.src_addr.into();
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        if flags.contains(NdiscNeighborFlags::OVERRIDE) {
                            self.state.neighbor_cache.fill(ip_addr, lladdr, timestamp)
                        } else {
                            if self.state.neighbor_cache.lookup_pure(&ip_addr, timestamp).is_none() {
                                    self.state.neighbor_cache.fill(ip_addr, lladdr, timestamp)
                            }
                        }
                    },
                    _ => (),
                }
                Ok(None)
            }
            NdiscRepr::NeighborSolicit { target_addr, lladdr, .. } => {
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        self.state.neighbor_cache.fill(ip_repr.src_addr.into(), lladdr, timestamp)
                    },
                    _ => (),
                }
                if self.ip_config.has_solicited_node(ip_repr.dst_addr) && self.ip_config.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: target_addr,
                        lladdr: Some(self.config.ethernet_addr)
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len()
                    };
                    Ok(Some(ip::Packet::Icmpv6((ip_repr, advert))))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None)
        }
    }

    fn dispatch<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                    packet: Packet) -> Result<()>
        where Tx: TxToken
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            Packet::Arp(arp_repr) => {
                let dst_hardware_addr =
                    match arp_repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            },
            Packet::Ip(packet) => {
                self.dispatch_ip(tx_token, timestamp, packet)
            },
        }
    }

    fn dispatch_ethernet<Tx, F>(&mut self, tx_token: Tx, timestamp: Instant,
                                buffer_len: usize, f: F) -> Result<()>
        where Tx: TxToken, F: FnOnce(EthernetFrame<&mut [u8]>)
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(timestamp, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer.as_mut());
            frame.set_src_addr(self.config.ethernet_addr);

            f(frame);

            Ok(())
        })
    }

    fn lookup_hardware_addr<Tx>(&mut self, tx_token: Tx, timestamp: Instant,
                                src_addr: &IpAddress, dst_addr: &IpAddress) ->
                               Result<(EthernetAddress, Tx)>
        where Tx: TxToken
    {
        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr =
                match dst_addr {
                    &IpAddress::Unspecified =>
                        None,
                    #[cfg(feature = "proto-ipv4")]
                    &IpAddress::Ipv4(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x01, 0x00,
                            0x5e, b[1] & 0x7F,
                            b[2], b[3],
                        ])),
                    #[cfg(feature = "proto-ipv6")]
                    &IpAddress::Ipv6(_addr) =>
                        Some(EthernetAddress::from_bytes(&[
                            0x33, 0x33,
                            b[12], b[13],
                            b[14], b[15],
                        ])),
                    &IpAddress::__Nonexhaustive =>
                        unreachable!()
                };
            match hardware_addr {
                Some(hardware_addr) =>
                    // Destination is multicast
                    return Ok((hardware_addr, tx_token)),
                None =>
                    // Continue
                    (),
            }
        }

        let dst_addr = self.ip_config.route(dst_addr, timestamp)?;

        match self.state.neighbor_cache.lookup(&dst_addr, timestamp) {
            NeighborAnswer::Found(hardware_addr) =>
                return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited =>
                return Err(Error::Unaddressable),
            NeighborAnswer::NotFound => (),
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending ARP request",
                           dst_addr);

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.config.ethernet_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, timestamp, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;

                Err(Error::Unaddressable)
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!("address {} not in neighbor cache, sending Neighbor Solicitation",
                           dst_addr);

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: src_addr,
                    lladdr: Some(self.config.ethernet_addr),
                });

                let packet = ip::Packet::Icmpv6((
                    Ipv6Repr {
                        src_addr: src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff
                    },
                    solicit,
                ));

                self.dispatch_ip(tx_token, timestamp, packet)?;
                Err(Error::Unaddressable)
            }

            _ => Err(Error::Unaddressable)
        }
    }

    fn dispatch_ip<Tx: TxToken>(&mut self, tx_token: Tx, timestamp: Instant,
                          packet: ip::Packet) -> Result<()> {
        let ip_repr = packet.ip_repr().lower(&self.ip_config.ip_addrs)?;
        let caps = self.state.device_capabilities.clone();

        let (dst_hardware_addr, tx_token) =
            self.lookup_hardware_addr(tx_token, timestamp,
                                      &ip_repr.src_addr(), &ip_repr.dst_addr())?;

        self.dispatch_ethernet(tx_token, timestamp, ip_repr.total_len(), |mut frame| {
            frame.set_dst_addr(dst_hardware_addr);
            match ip_repr {
                #[cfg(feature = "proto-ipv4")]
                IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpRepr::Ipv6(_) => frame.set_ethertype(EthernetProtocol::Ipv6),
                _ => return
            }

            ip_repr.emit(frame.payload_mut(), &caps.checksum);

            let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
            packet.emit_payload(ip_repr, payload, &caps);
        })
    }
}

struct LowerDispatcher<'b, 'c, 'e, 'x, 'y, DeviceT: for<'d> Device<'d>> {
    device: &'y mut DeviceT,
    processor: Processor<'b, 'c, 'e, 'x>,
}

impl<'b, 'c, 'e, 'x, 'y, DeviceT> ip::LowerDispatcher for LowerDispatcher<'b, 'c, 'e, 'x, 'y, DeviceT>
    where DeviceT: for<'d> Device<'d> {
    fn dispatch(&mut self, timestamp: Instant, packet: ip::Packet) -> Result<()> {
        let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
        self.processor.dispatch_ip(tx_token, timestamp, packet)
    }

    fn has_neighbor<'a>(&self, addr: &'a IpAddress, timestamp: Instant) -> bool {
        self.processor.state.has_neighbor(&self.processor.ip_config, addr, timestamp)
    }
}

struct LowerProcessor<'b, 'c, 'e, 'x> {
    _processor: Processor<'b, 'c, 'e, 'x>,
}

impl<'b, 'c, 'e, 'x> ip::LowerProcessor for LowerProcessor<'b, 'c, 'e, 'x> {
    #[cfg(feature = "proto-ipv6")]
    fn process_ndisc<'frame>(&mut self, timestamp: Instant, ip_repr: Ipv6Repr,
                             repr: NdiscRepr<'frame>) -> Result<Option<ip::Packet<'frame>>> {
        self._processor.process_ndisc(timestamp, ip_repr, repr)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "proto-igmp")]
    use std::vec::Vec;
    use std::collections::BTreeMap;
    use {Result, Error};

    use super::InterfaceBuilder;
    use iface::{NeighborCache, EthernetInterface};
    use phy::{self, Loopback, ChecksumCapabilities};
    #[cfg(feature = "proto-igmp")]
    use phy::{Device, RxToken, TxToken};
    use time::Instant;
    use socket::SocketSet;
    #[cfg(feature = "proto-ipv4")]
    use wire::{ArpOperation, ArpPacket, ArpRepr};
    use wire::{EthernetAddress, EthernetFrame, EthernetProtocol};
    use wire::{IpAddress, IpCidr, IpProtocol, IpRepr};
    #[cfg(feature = "proto-ipv4")]
    use wire::{Ipv4Address, Ipv4Repr};
    #[cfg(feature = "proto-igmp")]
    use wire::Ipv4Packet;
    #[cfg(feature = "proto-ipv4")]
    use wire::{Icmpv4Repr, Icmpv4DstUnreachable};
    #[cfg(feature = "proto-igmp")]
    use wire::{IgmpPacket, IgmpRepr, IgmpVersion};
    #[cfg(all(feature = "socket-udp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
    use wire::{UdpPacket, UdpRepr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Ipv6Address, Ipv6Repr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Icmpv6Packet, Icmpv6Repr, Icmpv6ParamProblem};
    #[cfg(feature = "proto-ipv6")]
    use wire::{NdiscNeighborFlags, NdiscRepr};
    #[cfg(feature = "proto-ipv6")]
    use wire::{Ipv6HopByHopHeader, Ipv6Option, Ipv6OptionRepr};

    use super::Packet;
    use super::Processor;
    use super::super::ip;

    // These cannot be functions because they would borrow `self` completely,
    // and we need them to borrow just the fields.
    macro_rules! processor {
        ($iface:expr) => (Processor{
            config: &$iface.config,
            ip_config: &$iface.ip_config,
            state: &mut $iface.state,
        })
    }
    macro_rules! ip_processor {
        ($iface:expr) => (ip::Processor{
            config: &$iface.ip_config,
            state: &mut $iface.ip_state,
        })
    }

    fn create_loopback<'a, 'b, 'c>() -> (EthernetInterface<'static, 'b, 'c, Loopback>,
                                         SocketSet<'static, 'a, 'b>) {
        // Create a basic device
        let device = Loopback::new();
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = InterfaceBuilder::new(device)
            .ethernet_addr(EthernetAddress::default())
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder
            .ipv4_multicast_groups(BTreeMap::new());
        let iface = iface_builder
            .finalize();

        (iface, SocketSet::new(vec![]))
    }

    #[cfg(feature = "proto-igmp")]
    fn recv_all<'b>(iface: &mut EthernetInterface<'static, 'b, 'static, Loopback>, timestamp: Instant) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        while let Some((rx, _tx)) = iface.device.receive() {
            rx.consume(timestamp, |pkt| {
                pkts.push(pkt.iter().cloned().collect());
                Ok(())
            }).unwrap();
        }
        pkts
    }

    #[derive(Debug, PartialEq)]
    struct MockTxToken;

    impl phy::TxToken for MockTxToken {
        fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
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
    fn test_no_icmp_no_unicast() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 54];

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr:    Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });
        #[cfg(feature = "proto-ipv6")]
        let repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr:    Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr:    Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit:   0x40
        });

        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let mut ip = ip_processor!(iface);
        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(processor!(iface).process_ipv6(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
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
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            frame.set_dst_addr(EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            frame.set_src_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_ethertype(EthernetProtocol::Ipv4);
            repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
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

        let expected_repr = ip::Packet::Icmpv4((
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
        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Some(expected_repr)));
    }

    #[test]
    #[cfg(all(feature = "socket-udp", feature = "proto-ipv4"))]
    fn test_icmp_error_port_unreachable() {
        static UDP_PAYLOAD: [u8; 12] = [
            0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x2c, 0x20, 0x57,
            0x6f, 0x6c, 0x64, 0x21
        ];
        let (mut iface, mut socket_set) = create_loopback();

        let mut udp_bytes_unicast = vec![0u8; 20];
        let mut udp_bytes_broadcast = vec![0u8; 20];
        let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
        let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

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
        let expected_repr = ip::Packet::Icmpv4((
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
        assert_eq!(ip_processor!(iface).process_udp(&mut socket_set, ip_repr, false, data),
                   Ok(Some(expected_repr)));

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
        assert_eq!(ip_processor!(iface).process_udp(&mut socket_set, ip_repr,
                   false, packet_broadcast.into_inner()), Ok(None));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata};
        use wire::IpEndpoint;

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (mut iface, mut socket_set) = create_loopback();

        let rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);

        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        let mut udp_bytes = vec![0u8; 13];
        let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

        let socket_handle = socket_set.add(udp_socket);

        #[cfg(feature = "proto-ipv6")]
        let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload:  &UDP_PAYLOAD
        };

        #[cfg(feature = "proto-ipv6")]
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr:    src_ip,
            dst_addr:    Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.buffer_len(),
            hop_limit:   0x40
        });
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
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
        assert_eq!(ip_processor!(iface).process_udp(&mut socket_set, ip_repr, false, packet.into_inner()),
                   Ok(None));

        {
            // Make sure the payload to the UDP packet processed by process_udp is
            // appended to the bound sockets rx_buffer
            let mut socket = socket_set.get::<UdpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67))));
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_ipv4_broadcast() {
        use wire::{Ipv4Packet, Icmpv4Repr, Icmpv4Packet};

        let (mut iface, mut socket_set) = create_loopback();

        let our_ipv4_addr = iface.ipv4_address().unwrap();
        let src_ipv4_addr = Ipv4Address([127, 0, 0, 2]);

        // ICMPv4 echo request
        let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
        let icmpv4_repr = Icmpv4Repr::EchoRequest {
            ident: 0x1234, seq_no: 0xabcd, data: &icmpv4_data
        };

        // Send to IPv4 broadcast address
        let ipv4_repr = Ipv4Repr {
            src_addr:    src_ipv4_addr,
            dst_addr:    Ipv4Address::BROADCAST,
            protocol:    IpProtocol::Icmp,
            hop_limit:   64,
            payload_len: icmpv4_repr.buffer_len(),
        };

        // Emit to ethernet frame
        let mut eth_bytes = vec![0u8;
            EthernetFrame::<&[u8]>::header_len() +
            ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()
        ];
        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(frame.payload_mut()),
                &ChecksumCapabilities::default());
            icmpv4_repr.emit(
                &mut Icmpv4Packet::new_unchecked(
                    &mut frame.payload_mut()[ipv4_repr.buffer_len()..]),
                &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        // Expected ICMPv4 echo reply
        let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
            ident: 0x1234, seq_no: 0xabcd, data: &icmpv4_data };
        let expected_ipv4_repr = Ipv4Repr {
            src_addr: our_ipv4_addr,
            dst_addr: src_ipv4_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmpv4_repr.buffer_len(),
        };
        let expected_packet = ip::Packet::Icmpv4((expected_ipv4_repr, expected_icmpv4_repr));

        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Some(expected_packet)));
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_icmp_reply_size() {
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        use wire::IPV4_MIN_MTU as MIN_MTU;
        #[cfg(feature = "proto-ipv6")]
        use wire::Icmpv6DstUnreachable;
        #[cfg(feature = "proto-ipv6")]
        use wire::IPV6_MIN_MTU as MIN_MTU;

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        const MAX_PAYLOAD_LEN: usize = 528;
        #[cfg(feature = "proto-ipv6")]
        const MAX_PAYLOAD_LEN: usize = 1192;

        let (mut iface, mut socket_set) = create_loopback();

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let src_addr = Ipv4Address([192, 168, 1, 1]);
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let dst_addr = Ipv4Address([192, 168, 1, 2]);
        #[cfg(feature = "proto-ipv6")]
        let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(feature = "proto-ipv6")]
        let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        // UDP packet that if not tructated will cause a icmp port unreachable reply
        // to exeed the minimum mtu bytes in length.
        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; MAX_PAYLOAD_LEN]
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };
        #[cfg(feature = "proto-ipv6")]
        let ip_repr = Ipv6Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };
        let payload = packet.into_inner();

        // Expected packets
        #[cfg(feature = "proto-ipv6")]
        let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: ip_repr,
            data:   &payload[..MAX_PAYLOAD_LEN]
        };
        #[cfg(feature = "proto-ipv6")]
        let expected_ip_repr = Ipv6Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len()
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: ip_repr,
            data:   &payload[..MAX_PAYLOAD_LEN]
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_ip_repr = Ipv4Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len()
        };

        // The expected packet does not exceed the IPV4_MIN_MTU
        assert_eq!(expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(), MIN_MTU);
        // The expected packet and the generated packet are equal
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(ip_processor!(iface).process_udp(&mut socket_set, ip_repr.into(), false, payload),
                   Ok(Some(ip::Packet::Icmpv4((expected_ip_repr, expected_icmp_repr)))));
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(ip_processor!(iface).process_udp(&mut socket_set, ip_repr.into(), false, payload),
                   Ok(Some(ip::Packet::Icmpv6((expected_ip_repr, expected_icmp_repr)))));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
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

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for us triggers an ARP Reply
        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ethernet(&mut ip, &mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(Some(Packet::Arp(ArpRepr::EthernetIpv4 {
                       operation: ArpOperation::Reply,
                       source_hardware_addr: local_hw_addr,
                       source_protocol_addr: local_ip_addr,
                       target_hardware_addr: remote_hw_addr,
                       target_protocol_addr: remote_ip_addr
                   }))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(processor!(iface).lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(local_ip_addr), &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_handle_valid_ndisc_request() {
        let (mut iface, mut socket_set) = create_loopback();

        let mut eth_bytes = vec![0u8; 86];

        let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
        let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: local_ip_addr,
            lladdr: Some(remote_hw_addr),
        });
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: local_ip_addr.solicited_node(),
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: solicit.buffer_len()
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        {
            ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            solicit.emit(&remote_ip_addr.into(), &local_ip_addr.solicited_node().into(),
                         &mut Icmpv6Packet::new_unchecked(
                            &mut frame.payload_mut()[ip_repr.buffer_len()..]),
                         &ChecksumCapabilities::default());
        }

        let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
            flags: NdiscNeighborFlags::SOLICITED,
            target_addr: local_ip_addr,
            lladdr: Some(local_hw_addr)
        });

        let ipv6_expected = Ipv6Repr {
            src_addr: local_ip_addr,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: icmpv6_expected.buffer_len()
        };

        // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ethernet(&mut ip, &mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(Some(Packet::Ip(ip::Packet::Icmpv6((ipv6_expected, icmpv6_expected))))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(processor!(iface).lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv6(local_ip_addr), &IpAddress::Ipv6(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
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

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        {
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
        }

        // Ensure an ARP Request for someone else does not trigger an ARP Reply
        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ethernet(&mut ip, &mut socket_set, Instant::from_millis(0), frame.into_inner()),
                   Ok(None));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(processor!(iface).lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
            &IpAddress::Ipv4(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
    fn test_icmpv4_socket() {
        use socket::{IcmpSocket, IcmpEndpoint, IcmpSocketBuffer, IcmpPacketMetadata};
        use wire::Icmpv4Packet;

        let (mut iface, mut socket_set) = create_loopback();

        let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);
        let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);

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
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
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
        assert_eq!(ip_processor!(iface).process_icmpv4(&mut socket_set, ip_repr, icmp_data),
                   Ok(Some(ip::Packet::Icmpv4((ipv4_reply, echo_reply)))));

        {
            let mut socket = socket_set.get::<IcmpSocket>(socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(),
                       Ok((&icmp_data[..],
                           IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02)))));
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_solicited_node_addrs() {
        let (mut iface, _) = create_loopback();
        let mut new_addrs = vec![IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
                                 IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64)];
        iface.update_ip_addrs(|addrs| {
            new_addrs.extend(addrs.to_vec());
            *addrs = From::from(new_addrs);
        });
        assert!(iface.ip_config.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
        assert!(iface.ip_config.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
        assert!(!iface.ip_config.has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_icmpv6_nxthdr_unknown() {
        let (mut iface, mut socket_set) = create_loopback();

        let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);

        let mut eth_bytes = vec![0; 66];
        let payload = [0x12, 0x34, 0x56, 0x78];

        let ipv6_repr = Ipv6Repr {
            src_addr:    remote_ip_addr,
            dst_addr:    Ipv6Address::LOOPBACK,
            next_header: IpProtocol::HopByHop,
            payload_len: 12,
            hop_limit:   0x40,
        };

        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            let ip_repr = IpRepr::Ipv6(ipv6_repr);
            frame.set_dst_addr(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]));
            frame.set_src_addr(remote_hw_addr);
            frame.set_ethertype(EthernetProtocol::Ipv6);
            ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
            let mut offset = ipv6_repr.buffer_len();
            {
                let mut hbh_pkt =
                    Ipv6HopByHopHeader::new_unchecked(&mut frame.payload_mut()[offset..]);
                hbh_pkt.set_next_header(IpProtocol::Unknown(0x0c));
                hbh_pkt.set_header_len(0);
                offset += 8;
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[..]);
                    Ipv6OptionRepr::PadN(3).emit(&mut pad_pkt);
                }
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[5..]);
                    Ipv6OptionRepr::Pad1.emit(&mut pad_pkt);
                }
            }
            frame.payload_mut()[offset..].copy_from_slice(&payload);
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let reply_icmp_repr = Icmpv6Repr::ParamProblem {
            reason:  Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header:  ipv6_repr,
            data:    &payload[..]
        };

        let reply_ipv6_repr = Ipv6Repr {
            src_addr:    Ipv6Address::LOOPBACK,
            dst_addr:    remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: reply_icmp_repr.buffer_len(),
            hop_limit:   0x40,
        };

        // Ensure the unknown next header causes a ICMPv6 Parameter Problem
        // error message to be sent to the sender.
        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ipv6(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(Some(ip::Packet::Icmpv6((reply_ipv6_repr, reply_icmp_repr)))));

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(processor!(iface).lookup_hardware_addr(MockTxToken, Instant::from_secs(0),
            &IpAddress::Ipv6(Ipv6Address::LOOPBACK),
            &IpAddress::Ipv6(remote_ip_addr)),
            Ok((remote_hw_addr, MockTxToken)));
    }

    #[test]
    #[cfg(feature = "proto-igmp")]
    fn test_handle_igmp() {
        fn recv_igmp<'b>(mut iface: &mut EthernetInterface<'static, 'b, 'static, Loopback>, timestamp: Instant) -> Vec<(Ipv4Repr, IgmpRepr)> {
            let checksum_caps = &iface.device.capabilities().checksum;
            recv_all(&mut iface, timestamp)
                .iter()
                .filter_map(|frame| {
                    let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload()).ok()?;
                    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps).ok()?;
                    let ip_payload = ipv4_packet.payload();
                    let igmp_packet = IgmpPacket::new_checked(ip_payload).ok()?;
                    let igmp_repr = IgmpRepr::parse(&igmp_packet).ok()?;
                    Some((ipv4_repr, igmp_repr))
                })
                .collect::<Vec<_>>()
        }

        let groups = [
            Ipv4Address::new(224, 0, 0, 22),
            Ipv4Address::new(224, 0, 0, 56),
        ];

        let (mut iface, mut socket_set) = create_loopback();

        // Join multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.join_multicast_group(*group, timestamp)
                .unwrap();
        }

        let reports = recv_igmp(&mut iface, timestamp);
        assert_eq!(reports.len(), 2);
        for (i, group_addr) in groups.iter().enumerate() {
            assert_eq!(reports[i].0.protocol, IpProtocol::Igmp);
            assert_eq!(reports[i].0.dst_addr, *group_addr);
            assert_eq!(reports[i].1, IgmpRepr::MembershipReport {
                group_addr: *group_addr,
                version: IgmpVersion::Version2,
            });
        }

        // General query
        let timestamp = Instant::now();
        const GENERAL_QUERY_BYTES: &[u8] = &[
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x01, 0x0a, 0x14,
            0x48, 0x01, 0x21, 0x01, 0x08, 0x00, 0x46, 0xc0,
            0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 0x01, 0x02,
            0x47, 0x43, 0xac, 0x16, 0x63, 0x04, 0xe0, 0x00,
            0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x64,
            0xec, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];
        {
            // Transmit GENERAL_QUERY_BYTES into loopback
            let tx_token = iface.device.transmit().unwrap();
            tx_token.consume(
                timestamp, GENERAL_QUERY_BYTES.len(),
                |buffer| {
                    buffer.copy_from_slice(GENERAL_QUERY_BYTES);
                    Ok(())
                }).unwrap();
        }
        // Trigger processing until all packets received through the
        // loopback have been processed, including responses to
        // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
        // pkts that could be checked.
        iface.socket_ingress(&mut socket_set, timestamp).unwrap();

        // Leave multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.leave_multicast_group(group.clone(), timestamp)
                .unwrap();
        }

        let leaves = recv_igmp(&mut iface, timestamp);
        assert_eq!(leaves.len(), 2);
        for (i, group_addr) in groups.iter().cloned().enumerate() {
            assert_eq!(leaves[i].0.protocol, IpProtocol::Igmp);
            assert_eq!(leaves[i].0.dst_addr, Ipv4Address::MULTICAST_ALL_ROUTERS);
            assert_eq!(leaves[i].1, IgmpRepr::LeaveGroup { group_addr });
        }
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_no_reply() {
        use socket::{RawSocket, RawSocketBuffer, RawPacketMetadata};
        use wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let (mut iface, mut socket_set) = create_loopback();

        let packets = 1;
        let rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; 10]
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to ethernet frame
        let mut eth_bytes = vec![0u8;
            EthernetFrame::<&[u8]>::header_len() +
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(frame.payload_mut()),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut frame.payload_mut()[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_truncated_packet() {
        use socket::{RawSocket, RawSocketBuffer, RawPacketMetadata};
        use wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let (mut iface, mut socket_set) = create_loopback();

        let packets = 1;
        let rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &[0x2a; 49] // 49 > 48, hence packet will be truncated
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to ethernet frame
        let mut eth_bytes = vec![0u8;
            EthernetFrame::<&[u8]>::header_len() +
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(frame.payload_mut()),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut frame.payload_mut()[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let mut ip = ip_processor!(iface);
        let frame = processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame);

        // because the packet could not be handled we should send an Icmp message
        assert!(match frame {  
            Ok(Some(ip::Packet::Icmpv4(_))) => true,
            _ => false,
        });
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
    fn test_raw_socket_with_udp_socket() {
        use socket::{UdpSocket, UdpSocketBuffer, UdpPacketMetadata,
                     RawSocket, RawSocketBuffer, RawPacketMetadata};
        use wire::{IpVersion, IpEndpoint, Ipv4Packet, UdpPacket, UdpRepr};

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (mut iface, mut socket_set) = create_loopback();

        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_socket_handle = socket_set.add(udp_socket);
        {
            // Bind the socket to port 68
            let mut socket = socket_set.get::<UdpSocket>(udp_socket_handle);
            assert_eq!(socket.bind(68), Ok(()));
            assert!(!socket.can_recv());
            assert!(socket.can_send());
        }

        let packets = 1;
        let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * packets]);
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, raw_rx_buffer, raw_tx_buffer);
        socket_set.add(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
            payload: &UDP_PAYLOAD
        };
        let mut bytes = vec![0xff; udp_repr.buffer_len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(&mut packet, &src_addr.into(), &dst_addr.into(), &ChecksumCapabilities::default());
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.buffer_len()
        };

        // Emit to ethernet frame
        let mut eth_bytes = vec![0u8;
            EthernetFrame::<&[u8]>::header_len() +
            ipv4_repr.buffer_len() + udp_repr.buffer_len()
        ];
        let frame = {
            let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(frame.payload_mut()),
                &ChecksumCapabilities::default());
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(
                    &mut frame.payload_mut()[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default());
            EthernetFrame::new_unchecked(&*frame.into_inner())
        };

        let mut ip = ip_processor!(iface);
        assert_eq!(processor!(iface).process_ipv4(&mut ip, &mut socket_set, Instant::from_millis(0), &frame),
                   Ok(None));

        {
            // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
            let mut socket = socket_set.get::<UdpSocket>(udp_socket_handle);
            assert!(socket.can_recv());
            assert_eq!(socket.recv(), Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67))));
        }
    }
}