// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

use core::cmp;
use managed::{ManagedMap, ManagedSlice};

use super::socket_set::SocketSet;
use super::{SocketHandle, SocketStorage};
use crate::iface::Routes;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::iface::{NeighborAnswer, NeighborCache};
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};
use crate::wire::*;
use crate::{Error, Result};

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    sockets: SocketSet<'a>,
    inner: InterfaceInner<'a>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for prorcessing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner<'a> {
    caps: DeviceCapabilities,
    now: Instant,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,
    rand: Rand,
}

/// A builder structure used for creating a network interface.
pub struct InterfaceBuilder<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    sockets: SocketSet<'a>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    random_seed: u64,
}

impl<'a, DeviceT> InterfaceBuilder<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    #[cfg_attr(
        feature = "medium-ethernet",
        doc = r##"
# Examples

```
# use std::collections::BTreeMap;
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
# use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};

let device = // ...
# Loopback::new(Medium::Ethernet);
let hw_addr = // ...
# EthernetAddress::default();
let neighbor_cache = // ...
# NeighborCache::new(BTreeMap::new());
let ip_addrs = // ...
# [];
let iface = InterfaceBuilder::new(device, vec![])
        .hardware_addr(hw_addr.into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();
```
    "##
    )]
    pub fn new<SocketsT>(device: DeviceT, sockets: SocketsT) -> Self
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        InterfaceBuilder {
            device: device,
            sockets: SocketSet::new(sockets),

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            hardware_addr: None,
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            neighbor_cache: None,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,

            ip_addrs: ManagedSlice::Borrowed(&mut []),
            #[cfg(feature = "proto-ipv4")]
            any_ip: false,
            routes: Routes::new(ManagedMap::Borrowed(&mut [])),
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups: ManagedMap::Borrowed(&mut []),
            random_seed: 0,
        }
    }

    /// Set the random seed for this interface.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub fn random_seed(mut self, random_seed: u64) -> Self {
        self.random_seed = random_seed;
        self
    }

    /// Set the Hardware address the interface will use. See also
    /// [hardware_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [hardware_addr]: struct.Interface.html#method.hardware_addr
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(mut self, addr: HardwareAddress) -> Self {
        InterfaceInner::check_hardware_addr(&addr);
        self.hardware_addr = Some(addr);
        self
    }

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub fn pan_id(mut self, pan_id: Ieee802154Pan) -> Self {
        self.pan_id = Some(pan_id);
        self
    }

    /// Set the IP addresses the interface will use. See also
    /// [ip_addrs].
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    ///
    /// [ip_addrs]: struct.Interface.html#method.ip_addrs
    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> Self
    where
        T: Into<ManagedSlice<'a, IpCidr>>,
    {
        let ip_addrs = ip_addrs.into();
        InterfaceInner::check_ip_addrs(&ip_addrs);
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
    /// [routes]: struct.Interface.html#method.routes
    /// [ip_addrs]: struct.Interface.html#method.ip_addrs
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(mut self, enabled: bool) -> Self {
        self.any_ip = enabled;
        self
    }

    /// Set the IP routes the interface will use. See also
    /// [routes].
    ///
    /// [routes]: struct.Interface.html#method.routes
    pub fn routes<T>(mut self, routes: T) -> InterfaceBuilder<'a, DeviceT>
    where
        T: Into<Routes<'a>>,
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
    /// [`join_multicast_group()`]: struct.Interface.html#method.join_multicast_group
    #[cfg(feature = "proto-igmp")]
    pub fn ipv4_multicast_groups<T>(mut self, ipv4_multicast_groups: T) -> Self
    where
        T: Into<ManagedMap<'a, Ipv4Address, ()>>,
    {
        self.ipv4_multicast_groups = ipv4_multicast_groups.into();
        self
    }

    /// Set the Neighbor Cache the interface will use.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'a>) -> Self {
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
    pub fn finalize(self) -> Interface<'a, DeviceT> {
        let device_capabilities = self.device.capabilities();

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let (hardware_addr, neighbor_cache) = match device_capabilities.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => (
                Some(
                    self.hardware_addr
                        .expect("hardware_addr required option was not set"),
                ),
                Some(
                    self.neighbor_cache
                        .expect("neighbor_cache required option was not set"),
                ),
            ),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                assert!(
                    self.hardware_addr.is_none(),
                    "hardware_addr is set, but device medium is IP"
                );
                assert!(
                    self.neighbor_cache.is_none(),
                    "neighbor_cache is set, but device medium is IP"
                );
                (None, None)
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => (
                Some(
                    self.hardware_addr
                        .expect("hardware_addr required option was not set"),
                ),
                Some(
                    self.neighbor_cache
                        .expect("neighbor_cache required option was not set"),
                ),
            ),
        };

        let caps = self.device.capabilities();

        #[cfg(feature = "medium-ieee802154")]
        let mut rand = Rand::new(self.random_seed);
        #[cfg(not(feature = "medium-ieee802154"))]
        let rand = Rand::new(self.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        Interface {
            device: self.device,
            sockets: self.sockets,
            inner: InterfaceInner {
                now: Instant::from_secs(0),
                caps,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                hardware_addr,
                ip_addrs: self.ip_addrs,
                #[cfg(feature = "proto-ipv4")]
                any_ip: self.any_ip,
                routes: self.routes,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache,
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: self.ipv4_multicast_groups,
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: self.pan_id,
                rand,
            },
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
enum EthernetPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(IpPacket<'a>),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum IpPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "proto-igmp")]
    Igmp((Ipv4Repr, IgmpRepr)),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6((Ipv6Repr, Icmpv6Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr, &'a [u8])),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>)),
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4((Ipv4Repr, UdpRepr, DhcpRepr<'a>)),
}

impl<'a> IpPacket<'a> {
    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            IpPacket::Icmpv4((ipv4_repr, _)) => IpRepr::Ipv4(*ipv4_repr),
            #[cfg(feature = "proto-igmp")]
            IpPacket::Igmp((ipv4_repr, _)) => IpRepr::Ipv4(*ipv4_repr),
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((ipv6_repr, _)) => IpRepr::Ipv6(*ipv6_repr),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((ip_repr, _, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-dhcpv4")]
            IpPacket::Dhcpv4((ipv4_repr, _, _)) => IpRepr::Ipv4(*ipv4_repr),
        }
    }

    pub(crate) fn emit_payload(
        &self,
        _ip_repr: IpRepr,
        payload: &mut [u8],
        caps: &DeviceCapabilities,
    ) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            IpPacket::Icmpv4((_, icmpv4_repr)) => {
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum)
            }
            #[cfg(feature = "proto-igmp")]
            IpPacket::Igmp((_, igmp_repr)) => {
                igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload))
            }
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6((_, icmpv6_repr)) => icmpv6_repr.emit(
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                &mut Icmpv6Packet::new_unchecked(payload),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw((_, raw_packet)) => payload.copy_from_slice(raw_packet),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udp_repr, inner_payload)) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                inner_payload.len(),
                |buf| buf.copy_from_slice(inner_payload),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((_, mut tcp_repr)) => {
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

                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(payload),
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    &caps.checksum,
                );
            }
            #[cfg(feature = "socket-dhcpv4")]
            IpPacket::Dhcpv4((_, udp_repr, dhcp_repr)) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                dhcp_repr.buffer_len(),
                |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                &caps.checksum,
            ),
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

#[cfg(feature = "proto-igmp")]
enum IgmpReportState {
    Inactive,
    ToGeneralQuery {
        version: IgmpVersion,
        timeout: Instant,
        interval: Duration,
        next_index: usize,
    },
    ToSpecificQuery {
        version: IgmpVersion,
        timeout: Instant,
        group: Ipv4Address,
    },
}

impl<'a, DeviceT> Interface<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Add a socket to the interface, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add_socket<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        self.sockets.add(socket)
    }

    /// Get a socket from the interface by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_socket<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        self.sockets.get(handle)
    }

    /// Get a socket by handle, and the socket context.
    ///
    /// The context is needed for some socket methods.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_socket_and_context<T: AnySocket<'a>>(
        &mut self,
        handle: SocketHandle,
    ) -> (&mut T, &mut InterfaceInner<'a>) {
        (self.sockets.get(handle), &mut self.inner)
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove_socket(&mut self, handle: SocketHandle) -> Socket<'a> {
        self.sockets.remove(handle)
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.device().capabilities().medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.device().capabilities().medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.device().capabilities().medium == Medium::Ethernet
                || self.device().capabilities().medium == Medium::Ieee802154
        );

        self.inner.hardware_addr.unwrap()
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.device().capabilities().medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.device().capabilities().medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.device().capabilities().medium == Medium::Ethernet
                || self.device().capabilities().medium == Medium::Ieee802154
        );

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = Some(addr);
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

    /// Get an iterator to the inner sockets.
    pub fn sockets(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.sockets.iter().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn sockets_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.sockets
            .iter_mut()
            .map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<T: Into<IpAddress>>(
        &mut self,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool> {
        self.inner.now = timestamp;

        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let is_not_new = self
                    .inner
                    .ipv4_multicast_groups
                    .insert(addr, ())
                    .map_err(|_| Error::Exhausted)?
                    .is_some();
                if is_not_new {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_report_packet(IgmpVersion::Version2, addr)
                {
                    // Send initial membership report
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable),
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<T: Into<IpAddress>>(
        &mut self,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool> {
        self.inner.now = timestamp;

        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.inner.ipv4_multicast_groups.remove(&addr).is_none();
                if was_not_present {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_leave_packet(addr) {
                    // Send group leave packet
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            _ => Err(Error::Unaddressable),
        }
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_multicast_group(addr)
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs()
            .iter()
            .filter_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                _ => None,
            })
            .next()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut ManagedSlice<'a, IpCidr>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_address()
    }

    pub fn routes(&self) -> &Routes<'a> {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes<'a> {
        &mut self.inner.routes
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
    pub fn poll(&mut self, timestamp: Instant) -> Result<bool> {
        self.inner.now = timestamp;

        let mut readiness_may_have_changed = false;
        loop {
            let processed_any = self.socket_ingress();
            let emitted_any = self.socket_egress()?;

            #[cfg(feature = "proto-igmp")]
            self.igmp_egress()?;

            if processed_any || emitted_any {
                readiness_may_have_changed = true;
            } else {
                break;
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
    pub fn poll_at(&mut self, timestamp: Instant) -> Option<Instant> {
        self.inner.now = timestamp;

        let inner = &mut self.inner;

        self.sockets
            .iter()
            .filter_map(move |item| {
                let socket_poll_at = item.socket.poll_at(inner);
                match item
                    .meta
                    .poll_at(socket_poll_at, |ip_addr| inner.has_neighbor(&ip_addr))
                {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
                }
            })
            .min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant) -> Option<Duration> {
        match self.poll_at(timestamp) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress(&mut self) -> bool {
        let mut processed_any = false;
        let Self {
            device,
            inner,
            sockets,
            ..
        } = self;
        while let Some((rx_token, tx_token)) = device.receive() {
            if let Err(err) = rx_token.consume(inner.now, |frame| match inner.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => match inner.process_ethernet(sockets, &frame) {
                    Ok(response) => {
                        processed_any = true;
                        if let Some(packet) = response {
                            if let Err(err) = inner.dispatch(tx_token, packet) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                        Ok(())
                    }
                    Err(err) => {
                        net_debug!("cannot process ingress packet: {}", err);
                        #[cfg(not(feature = "defmt"))]
                        net_debug!(
                            "packet dump follows:\n{}",
                            PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame)
                        );
                        Err(err)
                    }
                },
                #[cfg(feature = "medium-ip")]
                Medium::Ip => match inner.process_ip(sockets, &frame) {
                    Ok(response) => {
                        processed_any = true;
                        if let Some(packet) = response {
                            if let Err(err) = inner.dispatch_ip(tx_token, packet) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                        Ok(())
                    }
                    Err(err) => {
                        net_debug!("cannot process ingress packet: {}", err);
                        Err(err)
                    }
                },
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => match inner.process_ieee802154(sockets, &frame) {
                    Ok(response) => {
                        processed_any = true;
                        if let Some(packet) = response {
                            if let Err(err) = inner.dispatch_ieee802154(tx_token, packet) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                        Ok(())
                    }
                    Err(err) => {
                        net_debug!("cannot process ingress packet: {}", err);
                        Err(err)
                    }
                },
            }) {
                net_debug!("Failed to consume RX token: {}", err);
            }
        }

        processed_any
    }

    fn socket_egress(&mut self) -> Result<bool> {
        let Self {
            device,
            inner,
            sockets,
            ..
        } = self;
        let _caps = device.capabilities();

        let mut emitted_any = false;
        for item in sockets.iter_mut() {
            if !item
                .meta
                .egress_permitted(inner.now, |ip_addr| inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());

            macro_rules! respond {
                ($inner:expr, $response:expr) => {{
                    let response = $response;
                    neighbor_addr = Some(response.ip_repr().dst_addr());
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    device_result = $inner.dispatch_ip(tx_token, response);
                    device_result
                }};
            }

            let socket_result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(inner, |inner, response| {
                    respond!(inner, IpPacket::Raw(response))
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => socket.dispatch(inner, |inner, response| match response {
                    #[cfg(feature = "proto-ipv4")]
                    (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => {
                        respond!(inner, IpPacket::Icmpv4((ipv4_repr, icmpv4_repr)))
                    }
                    #[cfg(feature = "proto-ipv6")]
                    (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => {
                        respond!(inner, IpPacket::Icmpv6((ipv6_repr, icmpv6_repr)))
                    }
                    _ => Err(Error::Unaddressable),
                }),
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => socket.dispatch(inner, |inner, response| {
                    respond!(inner, IpPacket::Udp(response))
                }),
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(inner, |inner, response| {
                    respond!(inner, IpPacket::Tcp(response))
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => socket.dispatch(inner, |inner, response| {
                    respond!(inner, IpPacket::Dhcpv4(response))
                }),
            };

            match (device_result, socket_result) {
                (Err(Error::Exhausted), _) => break,   // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (), // nothing to transmit
                (Err(Error::Unaddressable), _) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighboor.
                    item.meta.neighbor_missing(
                        inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                    break;
                }
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!(
                        "{}: cannot dispatch egress packet: {}",
                        item.meta.handle,
                        err
                    );
                    return Err(err);
                }
                (Ok(()), Ok(())) => emitted_any = true,
            }
        }
        Ok(emitted_any)
    }

    /// Depending on `igmp_report_state` and the therein contained
    /// timeouts, send IGMP membership reports.
    #[cfg(feature = "proto-igmp")]
    fn igmp_egress(&mut self) -> Result<bool> {
        match self.inner.igmp_report_state {
            IgmpReportState::ToSpecificQuery {
                version,
                timeout,
                group,
            } if self.inner.now >= timeout => {
                if let Some(pkt) = self.inner.igmp_report_packet(version, group) {
                    // Send initial membership report
                    let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt)?;
                }

                self.inner.igmp_report_state = IgmpReportState::Inactive;
                Ok(true)
            }
            IgmpReportState::ToGeneralQuery {
                version,
                timeout,
                interval,
                next_index,
            } if self.inner.now >= timeout => {
                let addr = self
                    .inner
                    .ipv4_multicast_groups
                    .iter()
                    .nth(next_index)
                    .map(|(addr, ())| *addr);

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.inner.igmp_report_packet(version, addr) {
                            // Send initial membership report
                            let tx_token = self.device.transmit().ok_or(Error::Exhausted)?;
                            self.inner.dispatch_ip(tx_token, pkt)?;
                        }

                        let next_timeout = (timeout + interval).max(self.inner.now);
                        self.inner.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: next_timeout,
                            interval,
                            next_index: next_index + 1,
                        };
                        Ok(true)
                    }

                    None => {
                        self.inner.igmp_report_state = IgmpReportState::Inactive;
                        Ok(false)
                    }
                }
            }
            _ => Ok(false),
        }
    }
}

impl<'a> InterfaceInner<'a> {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> Option<HardwareAddress> {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[cfg(test)]
    pub(crate) fn mock() -> Self {
        Self {
            caps: DeviceCapabilities {
                #[cfg(feature = "medium-ethernet")]
                medium: crate::phy::Medium::Ethernet,
                #[cfg(not(feature = "medium-ethernet"))]
                medium: crate::phy::Medium::Ip,
                checksum: crate::phy::ChecksumCapabilities {
                    #[cfg(feature = "proto-ipv4")]
                    icmpv4: crate::phy::Checksum::Both,
                    #[cfg(feature = "proto-ipv6")]
                    icmpv6: crate::phy::Checksum::Both,
                    ipv4: crate::phy::Checksum::Both,
                    tcp: crate::phy::Checksum::Both,
                    udp: crate::phy::Checksum::Both,
                },
                max_burst_size: None,
                #[cfg(feature = "medium-ethernet")]
                max_transmission_unit: 1514,
                #[cfg(not(feature = "medium-ethernet"))]
                max_transmission_unit: 1500,
            },
            now: Instant::from_millis_const(0),

            ip_addrs: ManagedSlice::Owned(vec![]),
            rand: Rand::new(1234),
            routes: Routes::new(&mut [][..]),

            #[cfg(feature = "proto-ipv4")]
            any_ip: false,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: Some(crate::wire::Ieee802154Pan(0xabcd)),
            #[cfg(feature = "medium-ieee802154")]
            sequence_no: 0,

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            hardware_addr: Some(crate::wire::HardwareAddress::Ethernet(
                crate::wire::EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            )),
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            neighbor_cache: None,

            #[cfg(feature = "proto-igmp")]
            igmp_report_state: IgmpReportState::Inactive,
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups: ManagedMap::Borrowed(&mut []),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    fn get_sequence_number(&mut self) -> u8 {
        let no = self.sequence_no;
        self.sequence_no = self.sequence_no.wrapping_add(1);
        no
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "proto-ipv6")]
    pub fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOOPBACK => {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.as_bytes()[14..] == cidr.address().as_bytes()[14..]
                }
                _ => false,
            }
        })
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_addrs
            .iter()
            .filter_map(|addr| match *addr {
                IpCidr::Ipv4(cidr) => Some(cidr.address()),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .next()
    }

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false`.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) => {
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS
                    || self.ipv4_multicast_groups.get(&key).is_some()
            }
            _ => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        frame: &'frame T,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr.unwrap()
        {
            return Ok(None);
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(self.now, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
                self.process_ipv4(sockets, &ipv4_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
                self.process_ipv6(sockets, &ipv6_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        ip_payload: &'frame T,
    ) -> Result<Option<IpPacket<'frame>>> {
        match IpVersion::of_packet(ip_payload.as_ref()) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = Ipv4Packet::new_checked(ip_payload)?;
                self.process_ipv4(sockets, &ipv4_packet)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = Ipv6Packet::new_checked(ip_payload)?;
                self.process_ipv6(sockets, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    fn process_ieee802154<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        sixlowpan_payload: &'frame T,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ieee802154_frame = Ieee802154Frame::new_checked(sixlowpan_payload)?;
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame)?;

        if ieee802154_repr.frame_type != Ieee802154FrameType::Data {
            return Ok(None);
        }

        // Drop frames when the user has set a PAN id and the PAN id from frame is not equal to this
        // When the user didn't set a PAN id (so it is None), then we accept all PAN id's.
        // We always accept the broadcast PAN id.
        if self.pan_id.is_some()
            && ieee802154_repr.dst_pan_id != self.pan_id
            && ieee802154_repr.dst_pan_id != Some(Ieee802154Pan::BROADCAST)
        {
            net_debug!(
                "dropping {:?} because not our PAN id (or not broadcast)",
                ieee802154_repr
            );
            return Ok(None);
        }

        match ieee802154_frame.payload() {
            Some(payload) => self.process_sixlowpan(sockets, &ieee802154_repr, payload),
            None => Ok(None),
        }
    }

    #[cfg(feature = "proto-sixlowpan")]
    fn process_sixlowpan<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'frame T,
    ) -> Result<Option<IpPacket<'frame>>> {
        // The first header needs to be an IPHC header.
        let iphc_packet = SixlowpanIphcPacket::new_checked(payload)?;
        let iphc_repr = SixlowpanIphcRepr::parse(
            &iphc_packet,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
        )?;

        let payload = iphc_packet.payload();
        let mut ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            hop_limit: iphc_repr.hop_limit,
            next_header: IpProtocol::Unknown(0),
            payload_len: iphc_repr.buffer_len(),
        };

        // Currently we assume the next header is a UDP, so we ignore everything else.
        match iphc_repr.next_header {
            SixlowpanNextHeader::Compressed => {
                match SixlowpanNhcPacket::dispatch(payload)? {
                    SixlowpanNhcPacket::ExtensionHeader(_) => {
                        net_debug!("Extension headers are currently not supported for 6LoWPAN");
                        Ok(None)
                    }
                    #[cfg(not(feature = "socket-udp"))]
                    SixlowpanNhcPacket::UdpHeader(_) => {
                        net_debug!("UDP support is disabled, enable cargo feature `socket-udp`.");
                        Ok(None)
                    }
                    #[cfg(feature = "socket-udp")]
                    SixlowpanNhcPacket::UdpHeader(udp_packet) => {
                        ipv6_repr.next_header = IpProtocol::Udp;
                        // Handle the UDP
                        let udp_repr = SixlowpanUdpRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            udp_packet.checksum(),
                        )?;

                        // Look for UDP sockets that will accept the UDP packet.
                        // If it does not accept the packet, then send an ICMP message.
                        for udp_socket in sockets
                            .iter_mut()
                            .filter_map(|i| UdpSocket::downcast(&mut i.socket))
                        {
                            if !udp_socket.accepts(self, &IpRepr::Ipv6(ipv6_repr), &udp_repr) {
                                continue;
                            }

                            match udp_socket.process(
                                self,
                                &IpRepr::Ipv6(ipv6_repr),
                                &udp_repr,
                                udp_packet.payload(),
                            ) {
                                Ok(()) => return Ok(None),
                                Err(e) => return Err(e),
                            }
                        }

                        let payload_len = icmp_reply_payload_len(
                            payload.len(),
                            IPV6_MIN_MTU,
                            ipv6_repr.buffer_len(),
                        );
                        let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                            reason: Icmpv6DstUnreachable::PortUnreachable,
                            header: ipv6_repr,
                            data: &payload[0..payload_len],
                        };
                        Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
                    }
                }
            }
            SixlowpanNextHeader::Uncompressed(nxt_hdr) => match nxt_hdr {
                IpProtocol::Icmpv6 => {
                    ipv6_repr.next_header = IpProtocol::Icmpv6;
                    self.process_icmpv6(sockets, IpRepr::Ipv6(ipv6_repr), iphc_packet.payload())
                }
                _ => {
                    net_debug!("Headers other than ICMPv6 and compressed headers are currently not supported for 6LoWPAN");
                    Ok(None)
                }
            },
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn process_arp<'frame, T: AsRef<[u8]>>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame T>,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
        let arp_repr = ArpRepr::parse(&arp_packet)?;

        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Only process ARP packets for us.
                if !self.has_ip_addr(target_protocol_addr) {
                    return Ok(None);
                }

                // Only process REQUEST and RESPONSE.
                if let ArpOperation::Unknown(_) = operation {
                    net_debug!("arp: unknown operation code");
                    return Err(Error::Malformed);
                }

                // Discard packets with non-unicast source addresses.
                if !source_protocol_addr.is_unicast() || !source_hardware_addr.is_unicast() {
                    net_debug!("arp: non-unicast source address");
                    return Err(Error::Malformed);
                }

                if !self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
                    net_debug!("arp: source IP address not in same network as us");
                    return Err(Error::Malformed);
                }

                // Fill the ARP cache from any ARP packet aimed at us (both request or response).
                // We fill from requests too because if someone is requesting our address they
                // are probably going to talk to us, so we avoid having to request their address
                // when we later reply to them.
                self.neighbor_cache.as_mut().unwrap().fill(
                    source_protocol_addr.into(),
                    source_hardware_addr.into(),
                    timestamp,
                );

                if operation == ArpOperation::Request {
                    let src_hardware_addr = match self.hardware_addr {
                        Some(HardwareAddress::Ethernet(addr)) => addr,
                        _ => unreachable!(),
                    };

                    Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    })))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &'frame [u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .iter_mut()
            .filter_map(|i| RawSocket::downcast(&mut i.socket))
        {
            if !raw_socket.accepts(ip_repr) {
                continue;
            }

            match raw_socket.process(self, ip_repr, ip_payload) {
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
    fn process_ipv6<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_packet: &Ipv6Packet<&'frame T>,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ipv6_repr = Ipv6Repr::parse(ipv6_packet)?;

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed);
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(
            sockets,
            ipv6_repr,
            ipv6_repr.next_header,
            handled_by_raw_socket,
            ip_payload,
        )
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    #[cfg(feature = "proto-ipv6")]
    fn process_nxt_hdr<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        match nxt_hdr {
            IpProtocol::Icmpv6 => self.process_icmpv6(sockets, ipv6_repr.into(), ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp => {
                self.process_udp(sockets, ipv6_repr.into(), handled_by_raw_socket, ip_payload)
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop => {
                self.process_hopbyhop(sockets, ipv6_repr, handled_by_raw_socket, ip_payload)
            }

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket => Ok(None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
            }
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ipv4_packet: &Ipv4Packet<&'frame T>,
    ) -> Result<Option<IpPacket<'frame>>> {
        let ipv4_repr = Ipv4Repr::parse(ipv4_packet, &self.caps.checksum)?;

        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return Err(Error::Malformed);
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        #[cfg(feature = "socket-dhcpv4")]
        {
            if ipv4_repr.protocol == IpProtocol::Udp && self.hardware_addr.is_some() {
                // First check for source and dest ports, then do `UdpRepr::parse` if they match.
                // This way we avoid validating the UDP checksum twice for all non-DHCP UDP packets (one here, one in `process_udp`)
                let udp_packet = UdpPacket::new_checked(ip_payload)?;
                if udp_packet.src_port() == DHCP_SERVER_PORT
                    && udp_packet.dst_port() == DHCP_CLIENT_PORT
                {
                    if let Some(dhcp_socket) = sockets
                        .iter_mut()
                        .filter_map(|i| Dhcpv4Socket::downcast(&mut i.socket))
                        .next()
                    {
                        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
                        let udp_repr =
                            UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &self.caps.checksum)?;
                        let udp_payload = udp_packet.payload();

                        match dhcp_socket.process(self, &ipv4_repr, &udp_repr, udp_payload) {
                            // The packet is valid and handled by socket.
                            Ok(()) => return Ok(None),
                            // The packet is malformed, or the socket buffer is full.
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }

        if !self.has_ip_addr(ipv4_repr.dst_addr)
            && !self.has_multicast_group(ipv4_repr.dst_addr)
            && !self.is_broadcast_v4(ipv4_repr.dst_addr)
        {
            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
            // If AnyIP is enabled, also check if the packet is routed locally.
            if !self.any_ip
                || !ipv4_repr.dst_addr.is_unicast()
                || self
                    .routes
                    .lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), self.now)
                    .map_or(true, |router_addr| !self.has_ip_addr(router_addr))
            {
                return Ok(None);
            }
        }

        match ipv4_repr.protocol {
            IpProtocol::Icmp => self.process_icmpv4(sockets, ip_repr, ip_payload),

            #[cfg(feature = "proto-igmp")]
            IpProtocol::Igmp => self.process_igmp(ipv4_repr, ip_payload),

            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp => {
                self.process_udp(sockets, ip_repr, handled_by_raw_socket, ip_payload)
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ip_repr, ip_payload),

            _ if handled_by_raw_socket => Ok(None),

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr))
            }
        }
    }

    /// Checks if an incoming packet has a broadcast address for the interfaces
    /// associated ipv4 addresses.
    #[cfg(feature = "proto-ipv4")]
    fn is_subnet_broadcast(&self, address: Ipv4Address) -> bool {
        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is broadcast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        address.is_broadcast() || self.is_subnet_broadcast(address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.is_unicast() && !self.is_subnet_broadcast(address)
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    #[cfg(feature = "proto-igmp")]
    fn process_igmp<'frame>(
        &mut self,
        ipv4_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let igmp_packet = IgmpPacket::new_checked(ip_payload)?;
        let igmp_repr = IgmpRepr::parse(&igmp_packet)?;

        // FIXME: report membership after a delay
        match igmp_repr {
            IgmpRepr::MembershipQuery {
                group_addr,
                version,
                max_resp_time,
            } => {
                // General query
                if group_addr.is_unspecified()
                    && ipv4_repr.dst_addr == Ipv4Address::MULTICAST_ALL_SYSTEMS
                {
                    // Are we member in any groups?
                    if self.ipv4_multicast_groups.iter().next().is_some() {
                        let interval = match version {
                            IgmpVersion::Version1 => Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = self.ipv4_multicast_groups.len() as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: self.now + interval,
                            interval,
                            next_index: 0,
                        };
                    }
                } else {
                    // Group-specific query
                    if self.has_multicast_group(group_addr) && ipv4_repr.dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version,
                            timeout: self.now + timeout,
                            group: group_addr,
                        };
                    }
                }
            }
            // Ignore membership reports
            IgmpRepr::MembershipReport { .. } => (),
            // Ignore hosts leaving groups
            IgmpRepr::LeaveGroup { .. } => (),
        }

        Ok(None)
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_icmpv6<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let icmp_packet = Icmpv6Packet::new_checked(ip_payload)?;
        let icmp_repr = Icmpv6Repr::parse(
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            &icmp_packet,
            &self.caps.checksum,
        )?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv6"))]
        for icmp_socket in _sockets
            .iter_mut()
            .filter_map(|i| IcmpSocket::downcast(&mut i.socket))
        {
            if !icmp_socket.accepts(self, &ip_repr, &icmp_repr.into()) {
                continue;
            }

            match icmp_socket.process(self, &ip_repr, &icmp_repr.into()) {
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
            Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => {
                    let icmp_reply_repr = Icmpv6Repr::EchoReply {
                        ident,
                        seq_no,
                        data,
                    };
                    Ok(self.icmpv6_reply(ipv6_repr, icmp_reply_repr))
                }
                _ => Err(Error::Unrecognized),
            },

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => Ok(None),

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => self.process_ndisc(ipv6_repr, repr),
                _ => Ok(None),
            },

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => Ok(None),

            // FIXME: do something correct here?
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(all(
        any(feature = "medium-ethernet", feature = "medium-ieee802154"),
        feature = "proto-ipv6"
    ))]
    fn process_ndisc<'frame>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: NdiscRepr<'frame>,
    ) -> Result<Option<IpPacket<'frame>>> {
        match repr {
            NdiscRepr::NeighborAdvert {
                lladdr,
                target_addr,
                flags,
            } => {
                let ip_addr = ip_repr.src_addr.into();
                if let Some(lladdr) = lladdr {
                    let lladdr = lladdr.parse(self.caps.medium)?;
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return Err(Error::Malformed);
                    }
                    if flags.contains(NdiscNeighborFlags::OVERRIDE)
                        || !self
                            .neighbor_cache
                            .as_mut()
                            .unwrap()
                            .lookup(&ip_addr, self.now)
                            .found()
                    {
                        self.neighbor_cache
                            .as_mut()
                            .unwrap()
                            .fill(ip_addr, lladdr, self.now)
                    }
                }
                Ok(None)
            }
            NdiscRepr::NeighborSolicit {
                target_addr,
                lladdr,
                ..
            } => {
                if let Some(lladdr) = lladdr {
                    let lladdr = lladdr.parse(self.caps.medium)?;
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return Err(Error::Malformed);
                    }
                    self.neighbor_cache.as_mut().unwrap().fill(
                        ip_repr.src_addr.into(),
                        lladdr,
                        self.now,
                    );
                }

                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr,
                        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                        lladdr: Some(self.hardware_addr.unwrap().into()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Ok(Some(IpPacket::Icmpv6((ip_repr, advert))))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
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
                        }
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return Err(Error::Unrecognized);
                        }
                    }
                }
            }
        }
        self.process_nxt_hdr(
            sockets,
            ipv6_repr,
            hbh_repr.next_header,
            handled_by_raw_socket,
            &ip_payload[hbh_repr.buffer_len()..],
        )
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_icmpv4<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let icmp_packet = Icmpv4Packet::new_checked(ip_payload)?;
        let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &self.caps.checksum)?;

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
        for icmp_socket in _sockets
            .iter_mut()
            .filter_map(|i| IcmpSocket::downcast(&mut i.socket))
        {
            if !icmp_socket.accepts(self, &ip_repr, &icmp_repr.into()) {
                continue;
            }

            match icmp_socket.process(self, &ip_repr, &icmp_repr.into()) {
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
            Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                match ip_repr {
                    IpRepr::Ipv4(ipv4_repr) => Ok(self.icmpv4_reply(ipv4_repr, icmp_reply_repr)),
                    _ => Err(Error::Unrecognized),
                }
            }

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
    fn icmpv4_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv4_repr: Ipv4Repr,
        icmp_repr: Icmpv4Repr<'icmp>,
    ) -> Option<IpPacket<'frame>> {
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if self.is_unicast_v4(ipv4_repr.dst_addr) {
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr: ipv4_repr.dst_addr,
                dst_addr: ipv4_repr.src_addr,
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
        } else if self.is_broadcast_v4(ipv4_repr.dst_addr) {
            // Only reply to broadcasts for echo replies and not other ICMP messages
            match icmp_repr {
                Icmpv4Repr::EchoReply { .. } => match self.ipv4_address() {
                    Some(src_addr) => {
                        let ipv4_reply_repr = Ipv4Repr {
                            src_addr: src_addr,
                            dst_addr: ipv4_repr.src_addr,
                            protocol: IpProtocol::Icmp,
                            payload_len: icmp_repr.buffer_len(),
                            hop_limit: 64,
                        };
                        Some(IpPacket::Icmpv4((ipv4_reply_repr, icmp_repr)))
                    }
                    None => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn icmpv6_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv6_repr: Ipv6Repr,
        icmp_repr: Icmpv6Repr<'icmp>,
    ) -> Option<IpPacket<'frame>> {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr: ipv6_repr.dst_addr,
                dst_addr: ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(IpPacket::Icmpv6((ipv6_reply_repr, icmp_repr)))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }

    #[cfg(feature = "socket-udp")]
    fn process_udp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &self.caps.checksum)?;
        let udp_payload = udp_packet.payload();

        for udp_socket in sockets
            .iter_mut()
            .filter_map(|i| UdpSocket::downcast(&mut i.socket))
        {
            if !udp_socket.accepts(self, &ip_repr, &udp_repr) {
                continue;
            }

            match udp_socket.process(self, &ip_repr, &udp_repr, udp_payload) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e),
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket => Ok(None),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket => Ok(None),
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                Ok(self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr))
            }
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                Ok(self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr))
            }
            IpRepr::Unspecified { .. } => Err(Error::Unaddressable),
        }
    }

    #[cfg(feature = "socket-tcp")]
    fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Option<IpPacket<'frame>>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &self.caps.checksum)?;

        for tcp_socket in sockets
            .iter_mut()
            .filter_map(|i| TcpSocket::downcast(&mut i.socket))
        {
            if !tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                continue;
            }

            match tcp_socket.process(self, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map(IpPacket::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e),
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Some(IpPacket::Tcp(TcpSocket::rst_reply(
                &ip_repr, &tcp_repr,
            ))))
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(&mut self, tx_token: Tx, packet: EthernetPacket) -> Result<()>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => self.dispatch_ip(tx_token, packet),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch_ethernet<Tx, F>(&mut self, tx_token: Tx, buffer_len: usize, f: F) -> Result<()>
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

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Result<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Ok(*addr);
        }

        // Route via a router.
        match self.routes.lookup(addr, timestamp) {
            Some(router_addr) => Ok(router_addr),
            None => Err(Error::Unaddressable),
        }
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Ok(_routed_addr) => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self
                    .neighbor_cache
                    .as_ref()
                    .unwrap()
                    .lookup(&_routed_addr, self.now)
                    .found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self
                    .neighbor_cache
                    .as_ref()
                    .unwrap()
                    .lookup(&_routed_addr, self.now)
                    .found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            Err(_) => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<(HardwareAddress, Tx)>
    where
        Tx: TxToken,
    {
        if dst_addr.is_broadcast() {
            let hardware_addr = match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr = match *dst_addr {
                IpAddress::Unspecified => unreachable!(),
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_addr) => {
                    HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x01,
                        0x00,
                        0x5e,
                        b[1] & 0x7F,
                        b[2],
                        b[3],
                    ]))
                }
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x33, 0x33, b[12], b[13], b[14], b[15],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self.route(dst_addr, self.now)?;

        match self
            .neighbor_cache
            .as_mut()
            .unwrap()
            .lookup(&dst_addr, self.now)
        {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(Error::Unaddressable),
            _ => (), // XXX
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr =
                    if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                        addr
                    } else {
                        return Err(Error::Malformed);
                    };

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.hardware_addr.unwrap().into()),
                });

                let packet = IpPacket::Icmpv6((
                    Ipv6Repr {
                        src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    solicit,
                ));

                self.dispatch_ip(tx_token, packet)?;
            }

            _ => (),
        }
        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.as_mut().unwrap().limit_rate(self.now);
        Err(Error::Unaddressable)
    }

    fn flush_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        if let Some(cache) = self.neighbor_cache.as_mut() {
            cache.flush()
        }
    }

    fn dispatch_ip<Tx: TxToken>(&mut self, tx_token: Tx, packet: IpPacket) -> Result<()> {
        let ip_repr = packet.ip_repr().lower(&self.ip_addrs)?;

        match self.caps.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                let (dst_hardware_addr, tx_token) = match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    #[cfg(feature = "medium-ieee802154")]
                    (HardwareAddress::Ieee802154(_), _) => unreachable!(),
                };

                let caps = self.caps.clone();
                self.dispatch_ethernet(tx_token, ip_repr.total_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    match ip_repr {
                        #[cfg(feature = "proto-ipv4")]
                        IpRepr::Ipv4(_) => frame.set_ethertype(EthernetProtocol::Ipv4),
                        #[cfg(feature = "proto-ipv6")]
                        IpRepr::Ipv6(_) => frame.set_ethertype(EthernetProtocol::Ipv6),
                        _ => return,
                    }

                    ip_repr.emit(frame.payload_mut(), &caps.checksum);

                    let payload = &mut frame.payload_mut()[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &caps);
                })
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                let tx_len = ip_repr.total_len();
                tx_token.consume(self.now, tx_len, |mut tx_buffer| {
                    debug_assert!(tx_buffer.as_ref().len() == tx_len);

                    ip_repr.emit(&mut tx_buffer, &self.caps.checksum);

                    let payload = &mut tx_buffer[ip_repr.buffer_len()..];
                    packet.emit_payload(ip_repr, payload, &self.caps);

                    Ok(())
                })
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => self.dispatch_ieee802154(tx_token, packet),
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    fn dispatch_ieee802154<Tx: TxToken>(&mut self, tx_token: Tx, packet: IpPacket) -> Result<()> {
        let ip_repr = packet.ip_repr().lower(&self.ip_addrs)?;

        match self.caps.medium {
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                let (dst_hardware_addr, tx_token) = match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                )? {
                    (HardwareAddress::Ieee802154(addr), tx_token) => (addr, tx_token),
                    _ => unreachable!(),
                };

                let ack_request = dst_hardware_addr.is_unicast();

                let ack_request = match packet {
                    IpPacket::Icmpv6(_) => false,
                    _ => ack_request,
                };

                let mut tx_len = 0;

                let ll_src_addr =
                    if let Some(HardwareAddress::Ieee802154(addr)) = self.hardware_addr {
                        Some(addr)
                    } else {
                        return Err(Error::Malformed);
                    };

                let ieee_repr = Ieee802154Repr {
                    frame_type: Ieee802154FrameType::Data,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request,
                    sequence_number: Some(self.get_sequence_number()),
                    pan_id_compression: true,
                    frame_version: Ieee802154FrameVersion::Ieee802154_2003,
                    dst_pan_id: self.pan_id,
                    dst_addr: Some(dst_hardware_addr),
                    src_pan_id: self.pan_id,
                    src_addr: ll_src_addr,
                };

                let (src_addr, dst_addr) = match (ip_repr.src_addr(), ip_repr.dst_addr()) {
                    (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => (src_addr, dst_addr),
                    _ => return Err(Error::Unaddressable),
                };

                #[allow(unreachable_patterns)]
                let (next_header, hop_limit) = match &packet {
                    #[cfg(feature = "socket-udp")]
                    IpPacket::Udp(_) => (SixlowpanNextHeader::Compressed, 64),
                    IpPacket::Icmpv6((_, repr)) => (
                        SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
                        match repr {
                            Icmpv6Repr::Ndisc(_) => 255,
                            _ => 64,
                        },
                    ),
                    _ => return Err(Error::Unrecognized),
                };

                let iphc_repr = SixlowpanIphcRepr {
                    src_addr,
                    ll_src_addr,
                    dst_addr,
                    ll_dst_addr: Some(dst_hardware_addr),
                    next_header,
                    hop_limit,
                };

                tx_len += ieee_repr.buffer_len();
                tx_len += iphc_repr.buffer_len();

                #[allow(unreachable_patterns)]
                match &packet {
                    #[cfg(feature = "socket-udp")]
                    IpPacket::Udp((_, udp_repr, payload)) => {
                        let udp_repr = SixlowpanUdpRepr(*udp_repr);
                        tx_len += udp_repr.header_len() + payload.len();
                    }
                    IpPacket::Icmpv6((_, icmp)) => {
                        tx_len += icmp.buffer_len();
                    }
                    _ => return Err(Error::Unrecognized),
                }

                tx_token.consume(self.now, tx_len, |mut tx_buffer| {
                    // 1. Create the header of 802.15.4
                    let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buffer);
                    ieee_repr.emit(&mut ieee_packet);

                    let mut start = ieee_repr.buffer_len();

                    // 2. Create the header for 6LoWPAN IPHC
                    let mut iphc_packet =
                        SixlowpanIphcPacket::new_unchecked(&mut tx_buffer[start..tx_len]);
                    iphc_repr.emit(&mut iphc_packet);
                    start += iphc_repr.buffer_len();

                    #[allow(unreachable_patterns)]
                    match packet {
                        #[cfg(feature = "socket-udp")]
                        IpPacket::Udp((_, udp_repr, payload)) => {
                            // 3. Create the header for 6LoWPAN UDP
                            let mut udp_packet =
                                SixlowpanUdpPacket::new_unchecked(&mut tx_buffer[start..tx_len]);

                            SixlowpanUdpRepr(udp_repr).emit(
                                &mut udp_packet,
                                &iphc_repr.src_addr,
                                &iphc_repr.dst_addr,
                                payload.len(),
                                |buf| buf.copy_from_slice(payload),
                            );
                        }
                        #[cfg(feature = "proto-ipv6")]
                        IpPacket::Icmpv6((_, icmp_repr)) => {
                            // 3. Create the header for ICMPv6
                            let mut icmp_packet =
                                Icmpv6Packet::new_unchecked(&mut tx_buffer[start..tx_len]);

                            icmp_repr.emit(
                                &iphc_repr.src_addr.into(),
                                &iphc_repr.dst_addr.into(),
                                &mut icmp_packet,
                                &self.caps.checksum,
                            );
                        }
                        _ => return Err(Error::Unrecognized),
                    }

                    Ok(())
                })
            }
            _ => Err(Error::NotSupported),
        }
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_report_packet<'any>(
        &self,
        version: IgmpVersion,
        group_addr: Ipv4Address,
    ) -> Option<IpPacket<'any>> {
        let iface_addr = self.ipv4_address()?;
        let igmp_repr = IgmpRepr::MembershipReport {
            group_addr,
            version,
        };
        let pkt = IpPacket::Igmp((
            Ipv4Repr {
                src_addr: iface_addr,
                // Send to the group being reported
                dst_addr: group_addr,
                protocol: IpProtocol::Igmp,
                payload_len: igmp_repr.buffer_len(),
                hop_limit: 1,
                // TODO: add Router Alert IPv4 header option. See
                // [#183](https://github.com/m-labs/smoltcp/issues/183).
            },
            igmp_repr,
        ));
        Some(pkt)
    }

    #[cfg(feature = "proto-igmp")]
    fn igmp_leave_packet<'any>(&self, group_addr: Ipv4Address) -> Option<IpPacket<'any>> {
        self.ipv4_address().map(|iface_addr| {
            let igmp_repr = IgmpRepr::LeaveGroup { group_addr };
            IpPacket::Igmp((
                Ipv4Repr {
                    src_addr: iface_addr,
                    dst_addr: Ipv4Address::MULTICAST_ALL_ROUTERS,
                    protocol: IpProtocol::Igmp,
                    payload_len: igmp_repr.buffer_len(),
                    hop_limit: 1,
                },
                igmp_repr,
            ))
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    #[cfg(feature = "proto-igmp")]
    use std::vec::Vec;

    use super::*;

    use crate::iface::Interface;
    #[cfg(feature = "medium-ethernet")]
    use crate::iface::NeighborCache;
    use crate::phy::{ChecksumCapabilities, Loopback};
    #[cfg(feature = "proto-igmp")]
    use crate::time::Instant;
    use crate::{Error, Result};

    #[allow(unused)]
    fn fill_slice(s: &mut [u8], val: u8) {
        for x in s.iter_mut() {
            *x = val
        }
    }

    fn create_loopback<'a>() -> Interface<'a, Loopback> {
        #[cfg(feature = "medium-ethernet")]
        return create_loopback_ethernet();
        #[cfg(not(feature = "medium-ethernet"))]
        return create_loopback_ip();
    }

    #[cfg(all(feature = "medium-ip"))]
    #[allow(unused)]
    fn create_loopback_ip<'a>() -> Interface<'a, Loopback> {
        // Create a basic device
        let device = Loopback::new(Medium::Ip);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = InterfaceBuilder::new(device, vec![]).ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        iface_builder.finalize()
    }

    #[cfg(all(feature = "medium-ethernet"))]
    fn create_loopback_ethernet<'a>() -> Interface<'a, Loopback> {
        // Create a basic device
        let device = Loopback::new(Medium::Ethernet);
        let ip_addrs = [
            #[cfg(feature = "proto-ipv4")]
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64),
        ];

        let iface_builder = InterfaceBuilder::new(device, vec![])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(NeighborCache::new(BTreeMap::new()))
            .ip_addrs(ip_addrs);
        #[cfg(feature = "proto-igmp")]
        let iface_builder = iface_builder.ipv4_multicast_groups(BTreeMap::new());
        iface_builder.finalize()
    }

    #[cfg(feature = "proto-igmp")]
    fn recv_all(iface: &mut Interface<'_, Loopback>, timestamp: Instant) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        while let Some((rx, _tx)) = iface.device.receive() {
            rx.consume(timestamp, |pkt| {
                pkts.push(pkt.to_vec());
                Ok(())
            })
            .unwrap();
        }
        pkts
    }

    #[derive(Debug, PartialEq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct MockTxToken;

    impl TxToken for MockTxToken {
        fn consume<R, F>(self, _: Instant, _: usize, _: F) -> Result<R>
        where
            F: FnOnce(&mut [u8]) -> Result<R>,
        {
            Err(Error::Unaddressable)
        }
    }

    #[test]
    #[should_panic(expected = "hardware_addr required option was not set")]
    #[cfg(all(feature = "medium-ethernet"))]
    fn test_builder_initialization_panic() {
        InterfaceBuilder::new(Loopback::new(Medium::Ethernet), vec![]).finalize();
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_no_icmp_no_unicast_ipv4() {
        let mut iface = create_loopback();

        // Unknown Ipv4 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            dst_addr: Ipv4Address::BROADCAST,
            protocol: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(
            iface.inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_no_icmp_no_unicast_ipv6() {
        let mut iface = create_loopback();

        // Unknown Ipv6 Protocol
        //
        // Because the destination is the broadcast address
        // this should not trigger and Destination Unreachable
        // response. See RFC 1122 § 3.2.2.
        let repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 54];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv6Packet::new_unchecked(&bytes);

        // Ensure that the unknown protocol frame does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address
        assert_eq!(
            iface.inner.process_ipv6(&mut iface.sockets, &frame),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_icmp_error_no_payload() {
        static NO_BYTES: [u8; 0] = [];
        let mut iface = create_loopback();

        // Unknown Ipv4 Protocol with no payload
        let repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol: IpProtocol::Unknown(0x0c),
            payload_len: 0,
            hop_limit: 0x40,
        });

        let mut bytes = vec![0u8; 34];
        repr.emit(&mut bytes, &ChecksumCapabilities::default());
        let frame = Ipv4Packet::new_unchecked(&bytes);

        // The expected Destination Unreachable response due to the
        // unknown protocol
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::ProtoUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Unknown(12),
                payload_len: 0,
                hop_limit: 64,
            },
            data: &NO_BYTES,
        };

        let expected_repr = IpPacket::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            },
            icmp_repr,
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(
            iface.inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(Some(expected_repr))
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_local_subnet_broadcasts() {
        let mut iface = create_loopback();
        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 1, 23]), 24));
            });
        });

        assert!(iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 1, 255])),);
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 1, 254])),);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 16));
            });
        });
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 23, 255])),);
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 23, 254])),);
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 255, 254])),);
        assert!(iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 168, 255, 255])),);

        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address([192, 168, 23, 24]), 8));
            });
        });
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 23, 1, 255])),);
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 23, 1, 254])),);
        assert!(!iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 255, 255, 254])),);
        assert!(iface
            .inner
            .is_subnet_broadcast(Ipv4Address([192, 255, 255, 255])),);
    }

    #[test]
    #[cfg(all(feature = "socket-udp", feature = "proto-ipv4"))]
    fn test_icmp_error_port_unreachable() {
        static UDP_PAYLOAD: [u8; 12] = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21,
        ];
        let mut iface = create_loopback();

        let mut udp_bytes_unicast = vec![0u8; 20];
        let mut udp_bytes_broadcast = vec![0u8; 20];
        let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
        let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
            protocol: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        });

        // Emit the representations to a packet
        udp_repr.emit(
            &mut packet_unicast,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        let data = packet_unicast.into_inner();

        // The expected Destination Unreachable ICMPv4 error response due
        // to no sockets listening on the destination port.
        let icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
                hop_limit: 64,
            },
            data: data,
        };
        let expected_repr = IpPacket::Icmpv4((
            Ipv4Repr {
                src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
                dst_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
                protocol: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            },
            icmp_repr,
        ));

        // Ensure that the unknown protocol triggers an error response.
        // And we correctly handle no payload.
        assert_eq!(
            iface
                .inner
                .process_udp(&mut iface.sockets, ip_repr, false, data),
            Ok(Some(expected_repr))
        );

        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x02]),
            dst_addr: Ipv4Address::BROADCAST,
            protocol: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        });

        // Emit the representations to a packet
        udp_repr.emit(
            &mut packet_broadcast,
            &ip_repr.src_addr(),
            &IpAddress::Ipv4(Ipv4Address::BROADCAST),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        // Ensure that the port unreachable error does not trigger an
        // ICMP error response when the destination address is a
        // broadcast address and no socket is bound to the port.
        assert_eq!(
            iface.inner.process_udp(
                &mut iface.sockets,
                ip_repr,
                false,
                packet_broadcast.into_inner()
            ),
            Ok(None)
        );
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_handle_udp_broadcast() {
        use crate::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
        use crate::wire::IpEndpoint;

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let mut iface = create_loopback();

        let rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);

        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        let mut udp_bytes = vec![0u8; 13];
        let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

        let socket_handle = iface.add_socket(udp_socket);

        #[cfg(feature = "proto-ipv6")]
        let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };

        #[cfg(feature = "proto-ipv6")]
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: src_ip,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 0x40,
        });
        #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
        let ip_repr = IpRepr::Ipv4(Ipv4Repr {
            src_addr: src_ip,
            dst_addr: Ipv4Address::BROADCAST,
            protocol: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 0x40,
        });

        // Bind the socket to port 68
        let socket = iface.get_socket::<UdpSocket>(socket_handle);
        assert_eq!(socket.bind(68), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());

        udp_repr.emit(
            &mut packet,
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );

        // Packet should be handled by bound UDP socket
        assert_eq!(
            iface
                .inner
                .process_udp(&mut iface.sockets, ip_repr, false, packet.into_inner()),
            Ok(None)
        );

        // Make sure the payload to the UDP packet processed by process_udp is
        // appended to the bound sockets rx_buffer
        let socket = iface.get_socket::<UdpSocket>(socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67)))
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_handle_ipv4_broadcast() {
        use crate::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet};

        let mut iface = create_loopback();

        let our_ipv4_addr = iface.ipv4_address().unwrap();
        let src_ipv4_addr = Ipv4Address([127, 0, 0, 2]);

        // ICMPv4 echo request
        let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
        let icmpv4_repr = Icmpv4Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &icmpv4_data,
        };

        // Send to IPv4 broadcast address
        let ipv4_repr = Ipv4Repr {
            src_addr: src_ipv4_addr,
            dst_addr: Ipv4Address::BROADCAST,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: icmpv4_repr.buffer_len(),
        };

        // Emit to ip frame
        let mut bytes = vec![0u8; ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            icmpv4_repr.emit(
                &mut Icmpv4Packet::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        // Expected ICMPv4 echo reply
        let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &icmpv4_data,
        };
        let expected_ipv4_repr = Ipv4Repr {
            src_addr: our_ipv4_addr,
            dst_addr: src_ipv4_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmpv4_repr.buffer_len(),
        };
        let expected_packet = IpPacket::Icmpv4((expected_ipv4_repr, expected_icmpv4_repr));

        assert_eq!(
            iface.inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(Some(expected_packet))
        );
    }

    #[test]
    #[cfg(feature = "socket-udp")]
    fn test_icmp_reply_size() {
        #[cfg(feature = "proto-ipv6")]
        use crate::wire::Icmpv6DstUnreachable;
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        use crate::wire::IPV4_MIN_MTU as MIN_MTU;
        #[cfg(feature = "proto-ipv6")]
        use crate::wire::IPV6_MIN_MTU as MIN_MTU;

        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        const MAX_PAYLOAD_LEN: usize = 528;
        #[cfg(feature = "proto-ipv6")]
        const MAX_PAYLOAD_LEN: usize = 1192;

        let mut iface = create_loopback();

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
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + MAX_PAYLOAD_LEN];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            MAX_PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
        };
        #[cfg(feature = "proto-ipv6")]
        let ip_repr = Ipv6Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            next_header: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
        };
        let payload = packet.into_inner();

        // Expected packets
        #[cfg(feature = "proto-ipv6")]
        let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
            reason: Icmpv6DstUnreachable::PortUnreachable,
            header: ip_repr,
            data: &payload[..MAX_PAYLOAD_LEN],
        };
        #[cfg(feature = "proto-ipv6")]
        let expected_ip_repr = Ipv6Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len(),
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
            reason: Icmpv4DstUnreachable::PortUnreachable,
            header: ip_repr,
            data: &payload[..MAX_PAYLOAD_LEN],
        };
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        let expected_ip_repr = Ipv4Repr {
            src_addr: dst_addr,
            dst_addr: src_addr,
            protocol: IpProtocol::Icmp,
            hop_limit: 64,
            payload_len: expected_icmp_repr.buffer_len(),
        };

        // The expected packet does not exceed the IPV4_MIN_MTU
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(
            expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
            MIN_MTU
        );
        // The expected packet does not exceed the IPV4_MIN_MTU
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(
            expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
            MIN_MTU
        );
        // The expected packet and the generated packet are equal
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        assert_eq!(
            iface
                .inner
                .process_udp(&mut iface.sockets, ip_repr.into(), false, payload),
            Ok(Some(IpPacket::Icmpv4((
                expected_ip_repr,
                expected_icmp_repr
            ))))
        );
        #[cfg(feature = "proto-ipv6")]
        assert_eq!(
            iface
                .inner
                .process_udp(&mut iface.sockets, ip_repr.into(), false, payload),
            Ok(Some(IpPacket::Icmpv6((
                expected_ip_repr,
                expected_icmp_repr
            ))))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_valid_arp_request() {
        let mut iface = create_loopback_ethernet();

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
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);

        // Ensure an ARP Request for us triggers an ARP Reply
        assert_eq!(
            iface
                .inner
                .process_ethernet(&mut iface.sockets, frame.into_inner()),
            Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: local_hw_addr,
                source_protocol_addr: local_ip_addr,
                target_hardware_addr: remote_hw_addr,
                target_protocol_addr: remote_ip_addr
            })))
        );

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(local_ip_addr),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn test_handle_valid_ndisc_request() {
        let mut iface = create_loopback_ethernet();

        let mut eth_bytes = vec![0u8; 86];

        let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
        let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
        let local_hw_addr = EthernetAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

        let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
            target_addr: local_ip_addr,
            lladdr: Some(remote_hw_addr.into()),
        });
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: local_ip_addr.solicited_node(),
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: solicit.buffer_len(),
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        solicit.emit(
            &remote_ip_addr.into(),
            &local_ip_addr.solicited_node().into(),
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.buffer_len()..]),
            &ChecksumCapabilities::default(),
        );

        let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
            flags: NdiscNeighborFlags::SOLICITED,
            target_addr: local_ip_addr,
            lladdr: Some(local_hw_addr.into()),
        });

        let ipv6_expected = Ipv6Repr {
            src_addr: local_ip_addr,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: icmpv6_expected.buffer_len(),
        };

        // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
        assert_eq!(
            iface
                .inner
                .process_ethernet(&mut iface.sockets, frame.into_inner()),
            Ok(Some(EthernetPacket::Ip(IpPacket::Icmpv6((
                ipv6_expected,
                icmpv6_expected
            )))))
        );

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv6(local_ip_addr),
                &IpAddress::Ipv6(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_handle_other_arp_request() {
        let mut iface = create_loopback_ethernet();

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
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);

        // Ensure an ARP Request for someone else does not trigger an ARP Reply
        assert_eq!(
            iface
                .inner
                .process_ethernet(&mut iface.sockets, frame.into_inner()),
            Ok(None)
        );

        // Ensure the address of the requestor was NOT entered in the cache
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Err(Error::Unaddressable)
        );
    }

    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn test_arp_flush_after_update_ip() {
        let mut iface = create_loopback_ethernet();

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
            target_protocol_addr: Ipv4Address([0x7f, 0x00, 0x00, 0x01]),
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
        assert_eq!(
            iface
                .inner
                .process_ethernet(&mut iface.sockets, frame.into_inner()),
            Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: local_hw_addr,
                source_protocol_addr: local_ip_addr,
                target_hardware_addr: remote_hw_addr,
                target_protocol_addr: remote_ip_addr
            })))
        );

        // Ensure the address of the requestor was entered in the cache
        assert_eq!(
            iface.inner.lookup_hardware_addr(
                MockTxToken,
                &IpAddress::Ipv4(local_ip_addr),
                &IpAddress::Ipv4(remote_ip_addr)
            ),
            Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
        );

        // Update IP addrs to trigger ARP cache flush
        let local_ip_addr_new = Ipv4Address([0x7f, 0x00, 0x00, 0x01]);
        iface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(local_ip_addr_new, 24));
            });
        });

        // ARP cache flush after address change
        assert!(!iface.inner.has_neighbor(&IpAddress::Ipv4(remote_ip_addr)));
    }

    #[test]
    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
    fn test_icmpv4_socket() {
        use crate::socket::{IcmpEndpoint, IcmpPacketMetadata, IcmpSocket, IcmpSocketBuffer};
        use crate::wire::Icmpv4Packet;

        let mut iface = create_loopback();

        let rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);
        let tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 24]);

        let icmpv4_socket = IcmpSocket::new(rx_buffer, tx_buffer);

        let socket_handle = iface.add_socket(icmpv4_socket);

        let ident = 0x1234;
        let seq_no = 0x5432;
        let echo_data = &[0xff; 16];

        let socket = iface.get_socket::<IcmpSocket>(socket_handle);
        // Bind to the ID 0x1234
        assert_eq!(socket.bind(IcmpEndpoint::Ident(ident)), Ok(()));

        // Ensure the ident we bound to and the ident of the packet are the same.
        let mut bytes = [0xff; 24];
        let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
        let echo_repr = Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data: echo_data,
        };
        echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
        let icmp_data = &packet.into_inner()[..];

        let ipv4_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            protocol: IpProtocol::Icmp,
            payload_len: 24,
            hop_limit: 64,
        };
        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        // Open a socket and ensure the packet is handled due to the listening
        // socket.
        assert!(!iface.get_socket::<IcmpSocket>(socket_handle).can_recv());

        // Confirm we still get EchoReply from `smoltcp` even with the ICMP socket listening
        let echo_reply = Icmpv4Repr::EchoReply {
            ident,
            seq_no,
            data: echo_data,
        };
        let ipv4_reply = Ipv4Repr {
            src_addr: ipv4_repr.dst_addr,
            dst_addr: ipv4_repr.src_addr,
            ..ipv4_repr
        };
        assert_eq!(
            iface
                .inner
                .process_icmpv4(&mut iface.sockets, ip_repr, icmp_data),
            Ok(Some(IpPacket::Icmpv4((ipv4_reply, echo_reply))))
        );

        let socket = iface.get_socket::<IcmpSocket>(socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((
                icmp_data,
                IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02))
            ))
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_solicited_node_addrs() {
        let mut iface = create_loopback();
        let mut new_addrs = vec![
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64),
        ];
        iface.update_ip_addrs(|addrs| {
            new_addrs.extend(addrs.to_vec());
            *addrs = From::from(new_addrs);
        });
        assert!(iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002)));
        assert!(iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff)));
        assert!(!iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003)));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn test_icmpv6_nxthdr_unknown() {
        let mut iface = create_loopback();

        let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let payload = [0x12, 0x34, 0x56, 0x78];

        let ipv6_repr = Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: Ipv6Address::LOOPBACK,
            next_header: IpProtocol::HopByHop,
            payload_len: 12,
            hop_limit: 0x40,
        };

        let mut bytes = vec![0; 52];
        let frame = {
            let ip_repr = IpRepr::Ipv6(ipv6_repr);
            ip_repr.emit(&mut bytes, &ChecksumCapabilities::default());
            let mut offset = ipv6_repr.buffer_len();
            {
                let mut hbh_pkt = Ipv6HopByHopHeader::new_unchecked(&mut bytes[offset..]);
                hbh_pkt.set_next_header(IpProtocol::Unknown(0x0c));
                hbh_pkt.set_header_len(0);
                offset += 8;
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut *hbh_pkt.options_mut());
                    Ipv6OptionRepr::PadN(3).emit(&mut pad_pkt);
                }
                {
                    let mut pad_pkt = Ipv6Option::new_unchecked(&mut hbh_pkt.options_mut()[5..]);
                    Ipv6OptionRepr::Pad1.emit(&mut pad_pkt);
                }
            }
            bytes[offset..].copy_from_slice(&payload);
            Ipv6Packet::new_unchecked(&bytes)
        };

        let reply_icmp_repr = Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: ipv6_repr,
            data: &payload[..],
        };

        let reply_ipv6_repr = Ipv6Repr {
            src_addr: Ipv6Address::LOOPBACK,
            dst_addr: remote_ip_addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: reply_icmp_repr.buffer_len(),
            hop_limit: 0x40,
        };

        // Ensure the unknown next header causes a ICMPv6 Parameter Problem
        // error message to be sent to the sender.
        assert_eq!(
            iface.inner.process_ipv6(&mut iface.sockets, &frame),
            Ok(Some(IpPacket::Icmpv6((reply_ipv6_repr, reply_icmp_repr))))
        );
    }

    #[test]
    #[cfg(feature = "proto-igmp")]
    fn test_handle_igmp() {
        fn recv_igmp(
            iface: &mut Interface<'_, Loopback>,
            timestamp: Instant,
        ) -> Vec<(Ipv4Repr, IgmpRepr)> {
            let caps = iface.device.capabilities();
            let checksum_caps = &caps.checksum;
            recv_all(iface, timestamp)
                .iter()
                .filter_map(|frame| {
                    let ipv4_packet = match caps.medium {
                        #[cfg(feature = "medium-ethernet")]
                        Medium::Ethernet => {
                            let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                            Ipv4Packet::new_checked(eth_frame.payload()).ok()?
                        }
                        #[cfg(feature = "medium-ip")]
                        Medium::Ip => Ipv4Packet::new_checked(&frame[..]).ok()?,
                        #[cfg(feature = "medium-ieee802154")]
                        Medium::Ieee802154 => todo!(),
                    };
                    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, checksum_caps).ok()?;
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

        let mut iface = create_loopback();

        // Join multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.join_multicast_group(*group, timestamp).unwrap();
        }

        let reports = recv_igmp(&mut iface, timestamp);
        assert_eq!(reports.len(), 2);
        for (i, group_addr) in groups.iter().enumerate() {
            assert_eq!(reports[i].0.protocol, IpProtocol::Igmp);
            assert_eq!(reports[i].0.dst_addr, *group_addr);
            assert_eq!(
                reports[i].1,
                IgmpRepr::MembershipReport {
                    group_addr: *group_addr,
                    version: IgmpVersion::Version2,
                }
            );
        }

        // General query
        let timestamp = Instant::now();
        const GENERAL_QUERY_BYTES: &[u8] = &[
            0x46, 0xc0, 0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 0x01, 0x02, 0x47, 0x43, 0xac, 0x16,
            0x63, 0x04, 0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x64, 0xec, 0x8f,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        {
            // Transmit GENERAL_QUERY_BYTES into loopback
            let tx_token = iface.device.transmit().unwrap();
            tx_token
                .consume(timestamp, GENERAL_QUERY_BYTES.len(), |buffer| {
                    buffer.copy_from_slice(GENERAL_QUERY_BYTES);
                    Ok(())
                })
                .unwrap();
        }
        // Trigger processing until all packets received through the
        // loopback have been processed, including responses to
        // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
        // pkts that could be checked.
        iface.socket_ingress();

        // Leave multicast groups
        let timestamp = Instant::now();
        for group in &groups {
            iface.leave_multicast_group(*group, timestamp).unwrap();
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
        use crate::socket::{RawPacketMetadata, RawSocket, RawSocketBuffer};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let mut iface = create_loopback();

        let packets = 1;
        let rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        iface.add_socket(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        const PAYLOAD_LEN: usize = 10;

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + PAYLOAD_LEN];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + PAYLOAD_LEN,
        };

        // Emit to frame
        let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + PAYLOAD_LEN];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                PAYLOAD_LEN,
                |buf| fill_slice(buf, 0x2a),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        assert_eq!(
            iface.inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(None)
        );
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw"))]
    fn test_raw_socket_truncated_packet() {
        use crate::socket::{RawPacketMetadata, RawSocket, RawSocketBuffer};
        use crate::wire::{IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        let mut iface = create_loopback();

        let packets = 1;
        let rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        iface.add_socket(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        const PAYLOAD_LEN: usize = 49; // 49 > 48, hence packet will be truncated

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + PAYLOAD_LEN];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );

        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + PAYLOAD_LEN,
        };

        // Emit to frame
        let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + PAYLOAD_LEN];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                PAYLOAD_LEN,
                |buf| fill_slice(buf, 0x2a),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        let frame = iface.inner.process_ipv4(&mut iface.sockets, &frame);

        // because the packet could not be handled we should send an Icmp message
        assert!(match frame {
            Ok(Some(IpPacket::Icmpv4(_))) => true,
            _ => false,
        });
    }

    #[test]
    #[cfg(all(feature = "proto-ipv4", feature = "socket-raw", feature = "socket-udp"))]
    fn test_raw_socket_with_udp_socket() {
        use crate::socket::{
            RawPacketMetadata, RawSocket, RawSocketBuffer, UdpPacketMetadata, UdpSocket,
            UdpSocketBuffer,
        };
        use crate::wire::{IpEndpoint, IpVersion, Ipv4Packet, UdpPacket, UdpRepr};

        static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let mut iface = create_loopback();

        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 15]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        let udp_socket_handle = iface.add_socket(udp_socket);

        // Bind the socket to port 68
        let socket = iface.get_socket::<UdpSocket>(udp_socket_handle);
        assert_eq!(socket.bind(68), Ok(()));
        assert!(!socket.can_recv());
        assert!(socket.can_send());

        let packets = 1;
        let raw_rx_buffer =
            RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
        let raw_tx_buffer = RawSocketBuffer::new(
            vec![RawPacketMetadata::EMPTY; packets],
            vec![0; 48 * packets],
        );
        let raw_socket = RawSocket::new(
            IpVersion::Ipv4,
            IpProtocol::Udp,
            raw_rx_buffer,
            raw_tx_buffer,
        );
        iface.add_socket(raw_socket);

        let src_addr = Ipv4Address([127, 0, 0, 2]);
        let dst_addr = Ipv4Address([127, 0, 0, 1]);

        let udp_repr = UdpRepr {
            src_port: 67,
            dst_port: 68,
        };
        let mut bytes = vec![0xff; udp_repr.header_len() + UDP_PAYLOAD.len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
        udp_repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        let ipv4_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            hop_limit: 64,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        };

        // Emit to frame
        let mut bytes =
            vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + UDP_PAYLOAD.len()];
        let frame = {
            ipv4_repr.emit(
                &mut Ipv4Packet::new_unchecked(&mut bytes),
                &ChecksumCapabilities::default(),
            );
            udp_repr.emit(
                &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
                &src_addr.into(),
                &dst_addr.into(),
                UDP_PAYLOAD.len(),
                |buf| buf.copy_from_slice(&UDP_PAYLOAD),
                &ChecksumCapabilities::default(),
            );
            Ipv4Packet::new_unchecked(&bytes)
        };

        assert_eq!(
            iface.inner.process_ipv4(&mut iface.sockets, &frame),
            Ok(None)
        );

        // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
        let socket = iface.get_socket::<UdpSocket>(udp_socket_handle);
        assert!(socket.can_recv());
        assert_eq!(
            socket.recv(),
            Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_addr.into(), 67)))
        );
    }
}
