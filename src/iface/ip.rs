use core::cmp;
use managed::ManagedSlice;
#[cfg(feature = "proto-igmp")]
use managed::ManagedMap;
#[cfg(not(feature = "proto-igmp"))]
use core::marker::PhantomData;

use {Error, Result};
use phy::{DeviceCapabilities};
#[cfg(feature = "proto-igmp")]
use time::Duration;
use time::Instant;
use wire::{IpAddress, IpProtocol, IpRepr, IpCidr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Packet, Ipv6Repr, IPV6_MIN_MTU};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Address, Ipv4Packet, Ipv4Repr, IPV4_MIN_MTU};
#[cfg(feature = "proto-ipv4")]
use wire::{Icmpv4Packet, Icmpv4Repr, Icmpv4DstUnreachable};
#[cfg(feature = "proto-igmp")]
use wire::{IgmpPacket, IgmpRepr, IgmpVersion};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Address, Icmpv6Packet, Icmpv6Repr, Icmpv6ParamProblem};
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use wire::IcmpRepr;
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6HopByHopHeader, Ipv6HopByHopRepr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6OptionRepr, Ipv6OptionFailureType};
#[cfg(all(feature = "proto-ipv6", feature = "socket-udp"))]
use wire::Icmpv6DstUnreachable;
#[cfg(feature = "socket-udp")]
use wire::{UdpPacket, UdpRepr};
#[cfg(feature = "socket-tcp")]
use wire::{TcpPacket, TcpRepr, TcpControl};
#[cfg(all(feature = "proto-ipv6", feature = "ethernet"))]
use wire::{NdiscRepr};

use socket::{Socket, SocketSet, AnySocket};
#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use socket::IcmpSocket;
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use socket::TcpSocket;
use super::Routes;

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
pub(crate) struct Config<'c, 'e> {
    pub(crate) ip_addrs:               ManagedSlice<'c, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    pub(crate) any_ip:                 bool,
    pub(crate) routes:                 Routes<'e>,
}

/// State for the interface packet processing logic. This tracks the state of 
/// many protocols, and changes during packet processing.
pub(crate) struct State<'e> {
    #[cfg(feature = "proto-igmp")]
    pub(crate) ipv4_multicast_groups:  ManagedMap<'e, Ipv4Address, ()>,
    #[cfg(not(feature = "proto-igmp"))]
    pub(crate) _ipv4_multicast_groups: PhantomData<&'e ()>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    pub(crate) igmp_report_state:      IgmpReportState,
    pub(crate) device_capabilities:    DeviceCapabilities,
}

#[cfg(feature = "proto-igmp")]
pub(crate) enum IgmpReportState {
    Inactive,
    ToGeneralQuery {
        version:    IgmpVersion,
        timeout:    Instant,
        interval:   Duration,
        next_index: usize
    },
    ToSpecificQuery {
        version:    IgmpVersion,
        timeout:    Instant,
        group:      Ipv4Address
    },
}

/// This trait contains the callbacks the IP processor needs from lower layers
/// to dispatch outgoing IP packets.
pub(crate) trait LowerDispatcher {
    /// Dispatch an outgoing IP packet.
    fn dispatch(&mut self, timestamp: Instant, packet: Packet) -> Result<()>;

    /// Returns true if the lower interface has a cached link-layer (MAC) address
    /// for the given neighbor IP. This is used to pause socket egress while
    /// neighbor discovery is in progress.
    /// Interfaces without neighbor discovery should make this return always true.
    fn has_neighbor<'a>(&self, addr: &'a IpAddress, timestamp: Instant) -> bool;
}

/// This trait contains the callbacks the IP processor needs from lower layers
/// to process some types of incoming IP packets.
pub(crate) trait LowerProcessor {
    /// Process incoming ipv6 ndisc packets, optionally returning a response packet.
    /// Interfaces without neighbor discovery should make this a no-op.
    #[cfg(all(feature = "proto-ipv6", feature = "ethernet"))]
    fn process_ndisc<'frame>(&mut self, timestamp: Instant, ip_repr: Ipv6Repr,
                             repr: NdiscRepr<'frame>) -> Result<Option<Packet<'frame>>>;
}

pub(crate) struct Processor<'b, 'c, 'e, 'x> {
    pub config: &'x Config<'c, 'e>,
    pub state: &'x mut State<'b>
}

#[derive(Debug, PartialEq)]
pub(crate) enum Packet<'a> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "proto-igmp")]
    Igmp((Ipv4Repr, IgmpRepr)),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6((Ipv6Repr, Icmpv6Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> Packet<'a> {
    pub fn neighbor_addr(&self) -> IpAddress {
        return self.ip_repr().dst_addr()
    }

    pub fn ip_repr(&self) -> IpRepr {
        match &self {
            #[cfg(feature = "proto-ipv4")]
            &Packet::Icmpv4((ipv4_repr, _)) => IpRepr::Ipv4(ipv4_repr.clone()),
            #[cfg(feature = "proto-igmp")]
            &Packet::Igmp((ipv4_repr, _)) => IpRepr::Ipv4(ipv4_repr.clone()),
            #[cfg(feature = "proto-ipv6")]
            &Packet::Icmpv6((ipv6_repr, _)) => IpRepr::Ipv6(ipv6_repr.clone()),
            #[cfg(feature = "socket-raw")]
            &Packet::Raw((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-udp")]
            &Packet::Udp((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-tcp")]
            &Packet::Tcp((ip_repr, _)) => ip_repr.clone(),
        }
    }

    pub fn emit_payload(&self, _ip_repr: IpRepr, payload: &mut [u8], caps: &DeviceCapabilities) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Icmpv4((_, icmpv4_repr)) => 
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "proto-igmp")]
            Packet::Igmp((_, igmp_repr)) =>
                igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload)),
            #[cfg(feature = "proto-ipv6")]
            Packet::Icmpv6((_, icmpv6_repr)) =>
                icmpv6_repr.emit(&_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                         &mut Icmpv6Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "socket-raw")]
            Packet::Raw((_, raw_packet)) =>
                payload.copy_from_slice(raw_packet),
            #[cfg(feature = "socket-udp")]
            Packet::Udp((_, udp_repr)) =>
                udp_repr.emit(&mut UdpPacket::new_unchecked(payload),
                              &_ip_repr.src_addr(), &_ip_repr.dst_addr(), &caps.checksum),
            #[cfg(feature = "socket-tcp")]
            Packet::Tcp((_, mut tcp_repr)) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= _ip_repr.buffer_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(&mut TcpPacket::new_unchecked(payload),
                                &_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                                &caps.checksum);
            }
        }
    }
}



impl<'c, 'e> Config<'c, 'e> {
    pub fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter()
            .filter_map(
                |addr| match addr {
                    &IpCidr::Ipv4(cidr) => Some(cidr.address()),
                    _ => None,
                })
            .next()
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "proto-ipv6")]
    pub fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().find(|cidr| {
            match *cidr {
                &IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK=> {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        }).is_some()
    }

    pub fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs
            .iter()
            .find(|cidr| cidr.contains_addr(addr))
            .is_some()
    }

    pub fn route(&self, addr: &IpAddress, timestamp: Instant) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Ok(*addr)
        }

        // Route via a router.
        match self.routes.lookup(addr, timestamp) {
            Some(router_addr) => Ok(router_addr),
            None => Err(Error::Unaddressable),
        }
    }

}

impl<'e> State<'e> {

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false`.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) =>
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS ||
                self.ipv4_multicast_groups.get(&key).is_some(),
            _ =>
                false,
        }
    }
}

impl<'b, 'c, 'e, 'x> Processor<'b, 'c, 'e, 'x> {

    pub fn socket_egress(&mut self, lower: &mut impl LowerDispatcher, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let _caps = self.state.device_capabilities.clone();

        let mut emitted_any = false;
        for mut socket in sockets.iter_mut() {
            if !socket.meta_mut().egress_permitted(|ip_addr|
                    lower.has_neighbor(&ip_addr, timestamp)) {
                continue
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());


            macro_rules! respond {
                ($response:expr) => ({
                    let response = $response;
                    neighbor_addr = Some(response.neighbor_addr());
                    device_result = lower.dispatch(timestamp, response);
                    device_result
                })
            }

            let socket_result =
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(ref mut socket) =>
                        socket.dispatch(&_caps.checksum, |response|
                            respond!(Packet::Raw(response))),
                    #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
                    Socket::Icmp(ref mut socket) =>
                        socket.dispatch(&_caps, |response| {
                            match response {
                                #[cfg(feature = "proto-ipv4")]
                                (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) =>
                                    respond!(Packet::Icmpv4((ipv4_repr, icmpv4_repr))),
                                #[cfg(feature = "proto-ipv6")]
                                (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) =>
                                    respond!(Packet::Icmpv6((ipv6_repr, icmpv6_repr))),
                                _ => Err(Error::Unaddressable)
                            }
                        }),
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response|
                            respond!(Packet::Udp(response))),
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &_caps, |response|
                            respond!(Packet::Tcp(response))),
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
                (Ok(()), Ok(())) => emitted_any = true
            }
        }
        Ok(emitted_any)
    }

    /// Depending on `igmp_report_state` and the therein contained
    /// timeouts, send IGMP membership reports.
    #[cfg(feature = "proto-igmp")]
    pub fn igmp_egress(&mut self, lower: &mut impl LowerDispatcher, timestamp: Instant) -> Result<bool> {
        match self.state.igmp_report_state {
            IgmpReportState::ToSpecificQuery { version, timeout, group }
                    if timestamp >= timeout => {
                if let Some(pkt) = self.igmp_report_packet(version, group) {
                    // Send initial membership report
                    lower.dispatch(timestamp, pkt)?;
                }

                self.state.igmp_report_state = IgmpReportState::Inactive;
                Ok(true)
            }
            IgmpReportState::ToGeneralQuery { version, timeout, interval, next_index }
                    if timestamp >= timeout => {
                let addr = self.state.ipv4_multicast_groups
                    .iter()
                    .nth(next_index)
                    .map(|(addr, ())| *addr);

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.igmp_report_packet(version, addr) {
                            // Send initial membership report
                            lower.dispatch(timestamp, pkt)?;
                        }

                        let next_timeout = (timeout + interval).max(timestamp);
                        self.state.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version, timeout: next_timeout, interval, next_index: next_index + 1
                        };
                        Ok(true)
                    }

                    None => {
                        self.state.igmp_report_state = IgmpReportState::Inactive;
                        Ok(false)
                    }
                }
            }
            _ => Ok(false)
        }
    }

    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<'any, T: Into<IpAddress>>(&mut self, addr: T, _timestamp: Instant) -> Result<Option<Packet<'any>>> {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let is_not_new = self.state.ipv4_multicast_groups.insert(addr, ())
                    .map_err(|_| Error::Exhausted)?
                    .is_some();
                if is_not_new {
                    Ok(None)
                } else if let Some(pkt) =
                        self.igmp_report_packet(IgmpVersion::Version2, addr) {
                    // Send initial membership report
                    Ok(Some(pkt))
                } else {
                    Ok(None)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable)
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<'any, T: Into<IpAddress>>(&mut self, addr: T, _timestamp: Instant) -> Result<Option<Packet<'any>>> {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.state.ipv4_multicast_groups.remove(&addr)
                    .is_none();
                if was_not_present {
                    Ok(None)
                } else if let Some(pkt) = self.igmp_leave_packet(addr) {
                    // Send group leave packet
                    Ok(Some(pkt))
                } else {
                    Ok(None)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable)
        }
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_report_packet<'any>(&self, version: IgmpVersion, group_addr: Ipv4Address) -> Option<Packet<'any>> {
        let iface_addr = self.config.ipv4_address()?;
        let igmp_repr = IgmpRepr::MembershipReport {
            group_addr,
            version,
        };
        let pkt = Packet::Igmp((Ipv4Repr {
            src_addr:    iface_addr,
            // Send to the group being reported
            dst_addr:    group_addr,
            protocol:    IpProtocol::Igmp,
            payload_len: igmp_repr.buffer_len(),
            hop_limit:   1,
            // TODO: add Router Alert IPv4 header option. See
            // [#183](https://github.com/m-labs/smoltcp/issues/183).
        }, igmp_repr));
        Some(pkt)
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_leave_packet<'any>(&self, group_addr: Ipv4Address) -> Option<Packet<'any>> {
        self.config.ipv4_address().map(|iface_addr| {
            let igmp_repr = IgmpRepr::LeaveGroup { group_addr };
            let pkt = Packet::Igmp((Ipv4Repr {
                src_addr:    iface_addr,
                dst_addr:    Ipv4Address::MULTICAST_ALL_ROUTERS,
                protocol:    IpProtocol::Igmp,
                payload_len: igmp_repr.buffer_len(),
                hop_limit:   1,
            }, igmp_repr));
            pkt
        })
    }

    #[cfg(all(any(feature = "proto-ipv4", feature = "proto-ipv6"), feature = "socket-raw"))]
    fn raw_socket_filter<'frame>(&mut self, sockets: &mut SocketSet, ip_repr: &IpRepr,
                                 ip_payload: &'frame [u8]) -> bool {
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for mut raw_socket in sockets.iter_mut().filter_map(RawSocket::downcast) {
            if !raw_socket.accepts(&ip_repr) { continue }

            match raw_socket.process(&ip_repr, ip_payload, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled_by_raw_socket = true,
                // The socket buffer is full or the packet was truncated
                Err(Error::Exhausted) | Err(Error::Truncated) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }
        handled_by_raw_socket
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn process_ipv6<'frame, T: AsRef<[u8]> + ?Sized>
                   (&mut self, lower: &mut impl LowerProcessor, sockets: &mut SocketSet, timestamp: Instant,
                    ipv6_packet: &Ipv6Packet<&'frame T>) ->
                   Result<Option<Packet<'frame>>>
    {
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(lower, sockets, timestamp, ipv6_repr, ipv6_repr.next_header,
                             handled_by_raw_socket, ip_payload)
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    #[cfg(feature = "proto-ipv6")]
    fn process_nxt_hdr<'frame>
                   (&mut self, lower: &mut impl LowerProcessor, sockets: &mut SocketSet, timestamp: Instant, ipv6_repr: Ipv6Repr,
                    nxt_hdr: IpProtocol, handled_by_raw_socket: bool, ip_payload: &'frame [u8])
                   -> Result<Option<Packet<'frame>>>
    {
        match nxt_hdr {
            IpProtocol::Icmpv6 =>
                self.process_icmpv6(lower, sockets, timestamp, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ipv6_repr.into(), handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop =>
                self.process_hopbyhop(lower, sockets, timestamp, ipv6_repr, handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket =>
                Ok(None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU,
                                                         ipv6_repr.buffer_len());
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
            },
        }
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn process_ipv4<'frame, T: AsRef<[u8]> + ?Sized>
                   (&mut self, _lower: &mut impl LowerProcessor, sockets: &mut SocketSet, timestamp: Instant,
                    ipv4_packet: &Ipv4Packet<&'frame T>) ->
                   Result<Option<Packet<'frame>>>
    {
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed)
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        if !self.config.has_ip_addr(ipv4_repr.dst_addr) &&
           !ipv4_repr.dst_addr.is_broadcast() &&
           !self.state.has_multicast_group(ipv4_repr.dst_addr) {
            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.config.any_ip {
                return Ok(None);
            } else if match self.config.routes.lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), timestamp) {
                Some(router_addr) => !self.config.has_ip_addr(router_addr),
                None => true,
            } {
                return Ok(None);
            }
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp =>
                self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "proto-igmp")]
            IpProtocol::Igmp =>
                self.process_igmp(timestamp, ipv4_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp =>
                self.process_udp(sockets, ip_repr, handled_by_raw_socket, ip_payload),

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp =>
                self.process_tcp(sockets, timestamp, ip_repr, ip_payload),

            _ if handled_by_raw_socket =>
                Ok(None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU,
                                                         ipv4_repr.buffer_len());
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr))
            }
        }
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    #[cfg(feature = "proto-igmp")]
    fn process_igmp<'frame>(&mut self, timestamp: Instant, ipv4_repr: Ipv4Repr,
                            ip_payload: &'frame [u8]) -> Result<Option<Packet<'frame>>> {
        let igmp_packet = IgmpPacket::new_checked(ip_payload)?;
        let igmp_repr = IgmpRepr::parse(&igmp_packet)?;

        // FIXME: report membership after a delay
        match igmp_repr {
            IgmpRepr::MembershipQuery { group_addr, version, max_resp_time } => {
                // General query
                if group_addr.is_unspecified() &&
                        ipv4_repr.dst_addr == Ipv4Address::MULTICAST_ALL_SYSTEMS {
                    // Are we member in any groups?
                    if self.state.ipv4_multicast_groups.iter().next().is_some() {
                        let interval = match version {
                            IgmpVersion::Version1 =>
                                Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = self.state.ipv4_multicast_groups.len() as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.state.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version, timeout: timestamp + interval, interval, next_index: 0
                        };
                    }
                } else {
                    // Group-specific query
                    if self.state.has_multicast_group(group_addr) && ipv4_repr.dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.state.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version, timeout: timestamp + timeout, group: group_addr
                        };
                    }
                }
            },
            // Ignore membership reports
            IgmpRepr::MembershipReport { .. } => (),
            // Ignore hosts leaving groups
            IgmpRepr::LeaveGroup{ .. } => (),
        }

        Ok(None)
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_icmpv6<'frame>(&mut self, lower: &mut impl LowerProcessor, _sockets: &mut SocketSet, timestamp: Instant,
                              ip_repr: IpRepr, ip_payload: &'frame [u8]) -> Result<Option<Packet<'frame>>>
    {
        let icmp_packet = Icmpv6Packet::new_checked(ip_payload)?;
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let icmp_repr = Icmpv6Repr::parse(&ip_repr.src_addr(), &ip_repr.dst_addr(),
                                          &icmp_packet, &checksum_caps)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv6"))]
        for mut icmp_socket in _sockets.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr.into(), &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr.into(), &checksum_caps) {
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
            Icmpv6Repr::EchoRequest { ident, seq_no, data } => {
                match ip_repr {
                    IpRepr::Ipv6(ipv6_repr) => {
                        let icmp_reply_repr = Icmpv6Repr::EchoReply {
                            ident:  ident,
                            seq_no: seq_no,
                            data:   data
                        };
                        Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
                    },
                    _ => Err(Error::Unrecognized),
                }
            }

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => Ok(None),

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(feature = "ethernet")]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => lower.process_ndisc(timestamp, ipv6_repr, repr),
                _ => Ok(None)
            },

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }


    #[cfg(feature = "proto-ipv6")]
    fn process_hopbyhop<'frame>(&mut self, lower: &mut impl LowerProcessor, sockets: &mut SocketSet, timestamp: Instant,
                                ipv6_repr: Ipv6Repr, handled_by_raw_socket: bool,
                                ip_payload: &'frame [u8]) -> Result<Option<Packet<'frame>>>
    {
        let hbh_pkt = Ipv6HopByHopHeader::new_checked(ip_payload)?;
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_pkt)?;
        for result in hbh_repr.options() {
            let opt_repr = result?;
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return Ok(None);
                        },
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return Err(Error::Unrecognized);
                        }
                    }
                }
                _ => return Err(Error::Unrecognized),
            }
        }
        self.process_nxt_hdr(lower, sockets, timestamp, ipv6_repr, hbh_repr.next_header,
                             handled_by_raw_socket, &ip_payload[hbh_repr.buffer_len()..])
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn process_icmpv4<'frame>(&self, _sockets: &mut SocketSet, ip_repr: IpRepr,
                              ip_payload: &'frame [u8]) -> Result<Option<Packet<'frame>>>
    {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &checksum_caps)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
        for mut icmp_socket in _sockets.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr.into(), &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr.into(), &checksum_caps) {
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
            #[cfg(feature = "proto-ipv4")]
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
            },

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => Ok(None),

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn icmpv4_reply<'frame, 'icmp: 'frame>
                   (&self, ipv4_repr: Ipv4Repr, icmp_repr: Icmpv4Repr<'icmp>) ->
                   Option<Packet<'frame>>
    {
        if !ipv4_repr.src_addr.is_unicast() {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if ipv4_repr.dst_addr.is_unicast() {
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr:    ipv4_repr.dst_addr,
                dst_addr:    ipv4_repr.src_addr,
                protocol:    IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Some(Packet::Icmpv4((ipv4_reply_repr, icmp_repr)))
        } else if ipv4_repr.dst_addr.is_broadcast() {
            // Only reply to broadcasts for echo replies and not other ICMP messages
            match icmp_repr {
                Icmpv4Repr::EchoReply {..} => match self.config.ipv4_address() {
                    Some(src_addr) => {
                        let ipv4_reply_repr = Ipv4Repr {
                            src_addr:    src_addr,
                            dst_addr:    ipv4_repr.src_addr,
                            protocol:    IpProtocol::Icmp,
                            payload_len: icmp_repr.buffer_len(),
                            hop_limit:   64
                        };
                        Some(Packet::Icmpv4((ipv4_reply_repr, icmp_repr)))
                    },
                    None => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn icmpv6_reply<'frame, 'icmp: 'frame>
                   (&self, ipv6_repr: Ipv6Repr, icmp_repr: Icmpv6Repr<'icmp>) ->
                   Option<Packet<'frame>>
    {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr:    ipv6_repr.dst_addr,
                dst_addr:    ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit:   64
            };
            Some(Packet::Icmpv6((ipv6_reply_repr, icmp_repr)))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }

    #[cfg(feature = "socket-udp")]
    pub fn process_udp<'frame>(&self, sockets: &mut SocketSet,
                           ip_repr: IpRepr, handled_by_raw_socket: bool, ip_payload: &'frame [u8]) ->
                          Result<Option<Packet<'frame>>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) { continue }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket =>
                Ok(None),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket =>
                Ok(None),
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU,
                                                         ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr))
            },
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => {
                let payload_len = icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU,
                                                         ipv6_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data:   &ip_payload[0..payload_len]
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
            },
            IpRepr::Unspecified { .. } |
            IpRepr::__Nonexhaustive => Err(Error::Unaddressable),
        }
    }

    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(&self, sockets: &mut SocketSet, timestamp: Instant,
                           ip_repr: IpRepr, ip_payload: &'frame [u8]) ->
                          Result<Option<Packet<'frame>>>
    {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.state.device_capabilities.checksum.clone();
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut tcp_socket in sockets.iter_mut().filter_map(TcpSocket::downcast) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) { continue }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map(Packet::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Some(Packet::Tcp(TcpSocket::rst_reply(&ip_repr, &tcp_repr))))
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minumum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    cmp::min(len, mtu - header_len * 2 - 8)
}
