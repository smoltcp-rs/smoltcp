// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

#[cfg(test)]
mod tests;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;

use core::cmp;
use managed::{ManagedMap, ManagedSlice};

#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
use super::socket_set::SocketSet;
use crate::iface::Routes;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::iface::{NeighborAnswer, NeighborCache};
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
#[cfg(feature = "socket-dns")]
use crate::socket::dns;
use crate::socket::*;
use crate::time::{Duration, Instant};
use crate::wire::*;
use crate::{Error, Result};

pub(crate) struct FragmentsBuffer<'a> {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(crate) ipv4_fragments: PacketAssemblerSet<'a, Ipv4FragKey>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments: PacketAssemblerSet<'a, SixlowpanFragKey>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments_cache_timeout: Duration,
    #[cfg(not(any(
        feature = "proto-ipv4-fragmentation",
        feature = "proto-sixlowpan-fragmentation"
    )))]
    _lifetime: core::marker::PhantomData<&'a ()>,
}

pub(crate) struct OutPackets<'a> {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_out_packet: Ipv4OutPacket<'a>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_out_packet: SixlowpanOutPacket<'a>,

    #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
    _lifetime: core::marker::PhantomData<&'a ()>,
}

impl<'a> OutPackets<'a> {
    #[cfg(any(
        feature = "proto-ipv4-fragmentation",
        feature = "proto-sixlowpan-fragmentation"
    ))]
    /// Returns `true` when all the data of the outgoing buffers are transmitted.
    fn all_transmitted(&self) -> bool {
        #[cfg(feature = "proto-ipv4-fragmentation")]
        if !self.ipv4_out_packet.is_empty() {
            return false;
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if !self.sixlowpan_out_packet.is_empty() {
            return false;
        }

        true
    }
}

#[allow(unused)]
#[cfg(feature = "proto-ipv4")]
pub(crate) struct Ipv4OutPacket<'a> {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    buffer: ManagedSlice<'a, u8>,
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    sent_bytes: usize,

    /// The IPv4 representation.
    repr: Ipv4Repr,
    /// The destination hardware address.
    dst_hardware_addr: EthernetAddress,
    /// The offset of the next fragment.
    frag_offset: u16,
    /// The identifier of the stream.
    ident: u16,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
impl<'a> Ipv4OutPacket<'a> {
    pub(crate) fn new(buffer: ManagedSlice<'a, u8>) -> Self {
        Self {
            buffer,
            packet_len: 0,
            sent_bytes: 0,
            repr: Ipv4Repr {
                src_addr: Ipv4Address::default(),
                dst_addr: Ipv4Address::default(),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            },
            dst_hardware_addr: EthernetAddress::default(),
            frag_offset: 0,
            ident: 0,
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    fn reset(&mut self) {
        self.packet_len = 0;
        self.sent_bytes = 0;
        self.repr = Ipv4Repr {
            src_addr: Ipv4Address::default(),
            dst_addr: Ipv4Address::default(),
            next_header: IpProtocol::Unknown(0),
            payload_len: 0,
            hop_limit: 0,
        };
        self.dst_hardware_addr = EthernetAddress::default();
    }
}

#[allow(unused)]
#[cfg(feature = "proto-sixlowpan")]
pub(crate) struct SixlowpanOutPacket<'a> {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    buffer: ManagedSlice<'a, u8>,
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    sent_bytes: usize,

    /// The datagram size that is used for the fragmentation headers.
    datagram_size: u16,
    /// The datagram tag that is used for the fragmentation headers.
    datagram_tag: u16,
    datagram_offset: usize,

    /// The size of the FRAG_N packets.
    fragn_size: usize,

    /// The link layer IEEE802.15.4 source address.
    ll_dst_addr: Ieee802154Address,
    /// The link layer IEEE802.15.4 source address.
    ll_src_addr: Ieee802154Address,
}

#[cfg(feature = "proto-sixlowpan-fragmentation")]
impl<'a> SixlowpanOutPacket<'a> {
    pub(crate) fn new(buffer: ManagedSlice<'a, u8>) -> Self {
        Self {
            buffer,
            packet_len: 0,
            datagram_size: 0,
            datagram_tag: 0,
            datagram_offset: 0,
            sent_bytes: 0,
            fragn_size: 0,
            ll_dst_addr: Ieee802154Address::Absent,
            ll_src_addr: Ieee802154Address::Absent,
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    fn reset(&mut self) {
        self.packet_len = 0;
        self.datagram_size = 0;
        self.datagram_tag = 0;
        self.sent_bytes = 0;
        self.fragn_size = 0;
        self.ll_dst_addr = Ieee802154Address::Absent;
        self.ll_src_addr = Ieee802154Address::Absent;
    }
}

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}
use check;

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a> {
    inner: InterfaceInner<'a>,
    fragments: FragmentsBuffer<'a>,
    out_packets: OutPackets<'a>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner<'a> {
    caps: DeviceCapabilities,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_id: u16,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context: &'a [SixlowpanAddressContext<'a>],
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,
}

/// A builder structure used for creating a network interface.
pub struct InterfaceBuilder<'a> {
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache<'a>>,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes<'a>,
    /// Does not share storage with `ipv6_multicast_groups` to avoid IPv6 size overhead.
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: ManagedMap<'a, Ipv4Address, ()>,
    random_seed: u64,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_fragments: PacketAssemblerSet<'a, Ipv4FragKey>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_out_buffer: ManagedSlice<'a, u8>,

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments: PacketAssemblerSet<'a, SixlowpanFragKey>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_reassembly_buffer_timeout: Duration,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_out_buffer: ManagedSlice<'a, u8>,

    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context: &'a [SixlowpanAddressContext<'a>],
}

impl<'a> InterfaceBuilder<'a> {
    /// Create a builder used for creating a network interface using the
    /// given device and address.
    #[cfg_attr(
        all(feature = "medium-ethernet", not(feature = "proto-sixlowpan")),
        doc = r##"
# Examples

```
# use std::collections::BTreeMap;
#[cfg(feature = "proto-ipv4-fragmentation")]
use smoltcp::iface::FragmentsCache;
use smoltcp::iface::{InterfaceBuilder, NeighborCache};
# use smoltcp::phy::{Loopback, Medium};
use smoltcp::wire::{EthernetAddress, IpCidr, IpAddress};

let mut device = // ...
# Loopback::new(Medium::Ethernet);
let hw_addr = // ...
# EthernetAddress::default();
let neighbor_cache = // ...
# NeighborCache::new(BTreeMap::new());
# #[cfg(feature = "proto-ipv4-fragmentation")]
# let ipv4_frag_cache = // ...
# FragmentsCache::new(vec![], BTreeMap::new());
let ip_addrs = // ...
# [];
let builder = InterfaceBuilder::new()
        .hardware_addr(hw_addr.into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs);

# #[cfg(feature = "proto-ipv4-fragmentation")]
let builder = builder
    .ipv4_reassembly_buffer(ipv4_frag_cache)
    .ipv4_fragmentation_buffer(vec![]);

let iface = builder.finalize(&mut device);
```
    "##
    )]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        InterfaceBuilder {
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

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_fragments: PacketAssemblerSet::new(&mut [][..], &mut [][..]),
            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_out_buffer: ManagedSlice::Borrowed(&mut [][..]),

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_fragments: PacketAssemblerSet::new(&mut [][..], &mut [][..]),
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_reassembly_buffer_timeout: Duration::from_secs(60),
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_out_buffer: ManagedSlice::Borrowed(&mut [][..]),

            #[cfg(feature = "proto-sixlowpan")]
            sixlowpan_address_context: &[],
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
    pub fn routes<T>(mut self, routes: T) -> InterfaceBuilder<'a>
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

    /// Set the IPv4 reassembly buffer the interface will use.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub fn ipv4_reassembly_buffer(mut self, storage: PacketAssemblerSet<'a, Ipv4FragKey>) -> Self {
        self.ipv4_fragments = storage;
        self
    }

    /// Set the IPv4 fragments buffer the interface will use.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub fn ipv4_fragmentation_buffer<T>(mut self, storage: T) -> Self
    where
        T: Into<ManagedSlice<'a, u8>>,
    {
        self.ipv4_out_buffer = storage.into();
        self
    }

    /// Set the address contexts the interface will use.
    #[cfg(feature = "proto-sixlowpan")]
    pub fn sixlowpan_address_context(
        mut self,
        sixlowpan_address_context: &'a [SixlowpanAddressContext<'a>],
    ) -> Self {
        self.sixlowpan_address_context = sixlowpan_address_context;
        self
    }

    /// Set the 6LoWPAN reassembly buffer the interface will use.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_reassembly_buffer(
        mut self,
        storage: PacketAssemblerSet<'a, SixlowpanFragKey>,
    ) -> Self {
        self.sixlowpan_fragments = storage;
        self
    }

    /// Set the timeout value the 6LoWPAN reassembly buffer will use.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_reassembly_buffer_timeout(mut self, timeout: Duration) -> Self {
        if timeout > Duration::from_secs(60) {
            net_debug!("RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds");
        }
        self.sixlowpan_reassembly_buffer_timeout = timeout;
        self
    }

    /// Set the 6LoWPAN fragments buffer the interface will use.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn sixlowpan_fragmentation_buffer<T>(mut self, storage: T) -> Self
    where
        T: Into<ManagedSlice<'a, u8>>,
    {
        self.sixlowpan_out_buffer = storage.into();
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
    pub fn finalize<D>(self, device: &mut D) -> Interface<'a>
    where
        D: Device + ?Sized,
    {
        let caps = device.capabilities();

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let (hardware_addr, neighbor_cache) = match caps.medium {
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

        let mut rand = Rand::new(self.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = rand.rand_u16();
            if tag != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-ipv4")]
        let mut ipv4_id;

        #[cfg(feature = "proto-ipv4")]
        loop {
            ipv4_id = rand.rand_u16();
            if ipv4_id != 0 {
                break;
            }
        }

        Interface {
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_fragments: self.ipv4_fragments,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments: self.sixlowpan_fragments,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments_cache_timeout: self.sixlowpan_reassembly_buffer_timeout,

                #[cfg(not(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                )))]
                _lifetime: core::marker::PhantomData,
            },
            out_packets: OutPackets {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_out_packet: Ipv4OutPacket::new(self.ipv4_out_buffer),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_out_packet: SixlowpanOutPacket::new(self.sixlowpan_out_buffer),

                #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
                _lifetime: core::marker::PhantomData,
            },
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
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_id,
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: &[],
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
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
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
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPacket::Udp((ip_repr, _, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-dhcpv4")]
            IpPacket::Dhcpv4((ipv4_repr, _, _)) => IpRepr::Ipv4(*ipv4_repr),
        }
    }

    pub(crate) fn emit_payload(
        &self,
        _ip_repr: &IpRepr,
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
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
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
                    max_segment_size -= _ip_repr.header_len();
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
    // Since the entire network layer packet must fit within the minimum
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

impl<'a> Interface<'a> {
    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner<'a> {
        &mut self.inner
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
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
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = Some(addr);
    }

    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool>
    where
        D: Device + ?Sized,
    {
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
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt, None)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
            _ => Err(Error::Unaddressable),
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool>
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.inner.ipv4_multicast_groups.remove(&addr).is_none();
                if was_not_present {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_leave_packet(addr) {
                    // Send group leave packet
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt, None)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
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
            .find_map(|cidr| match cidr.address() {
                IpAddress::Ipv4(addr) => Some(addr),
                #[allow(unreachable_patterns)]
                _ => None,
            })
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
    pub fn poll<D>(
        &mut self,
        timestamp: Instant,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> Result<bool>
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        self.fragments
            .ipv4_fragments
            .remove_when(|frag| Ok(timestamp >= frag.expires_at()?))?;

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        self.fragments
            .sixlowpan_fragments
            .remove_when(|frag| Ok(timestamp >= frag.expires_at()?))?;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        match self.ipv4_egress(device) {
            Ok(true) => return Ok(true),
            Err(e) => {
                net_debug!("failed to transmit: {}", e);
                return Err(e);
            }
            _ => (),
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        match self.sixlowpan_egress(device) {
            Ok(true) => return Ok(true),
            Err(e) => {
                net_debug!("failed to transmit: {}", e);
                return Err(e);
            }
            _ => (),
        }

        let mut readiness_may_have_changed = false;

        loop {
            let processed_any = self.socket_ingress(device, sockets);
            let emitted_any = self.socket_egress(device, sockets);

            #[cfg(feature = "proto-igmp")]
            self.igmp_egress(device)?;

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
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if !self.out_packets.all_transmitted() {
            return Some(Instant::from_millis(0));
        }

        let inner = &mut self.inner;

        sockets
            .items()
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
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let mut processed_any = false;
        let Self {
            inner,
            fragments: ref mut _fragments,
            out_packets: _out_packets,
        } = self;

        while let Some((rx_token, tx_token)) = device.receive() {
            let res = rx_token.consume(inner.now, |frame| {
                match inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some(packet) = inner.process_ethernet(sockets, &frame, _fragments) {
                            if let Err(err) = inner.dispatch(tx_token, packet, Some(_out_packets)) {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => {
                        if let Some(packet) = inner.process_ip(sockets, &frame, _fragments) {
                            if let Err(err) =
                                inner.dispatch_ip(tx_token, packet, Some(_out_packets))
                            {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        if let Some(packet) = inner.process_ieee802154(sockets, &frame, _fragments)
                        {
                            if let Err(err) =
                                inner.dispatch_ip(tx_token, packet, Some(_out_packets))
                            {
                                net_debug!("Failed to send response: {}", err);
                            }
                        }
                    }
                }
                processed_any = true;
                Ok(())
            });

            if let Err(err) = res {
                net_debug!("Failed to consume RX token: {}", err);
            }
        }

        processed_any
    }

    fn socket_egress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let Self {
            inner,
            out_packets: _out_packets,
            ..
        } = self;
        let _caps = device.capabilities();

        let mut emitted_any = false;
        for item in sockets.items_mut() {
            if !item
                .meta
                .egress_permitted(inner.now, |ip_addr| inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut respond = |inner: &mut InterfaceInner, response: IpPacket| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                let t = device.transmit().ok_or_else(|| {
                    net_debug!("failed to transmit IP: {}", Error::Exhausted);
                    Error::Exhausted
                })?;

                #[cfg(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                ))]
                inner.dispatch_ip(t, response, Some(_out_packets))?;

                #[cfg(not(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                )))]
                inner.dispatch_ip(t, response, None)?;

                emitted_any = true;

                Ok(())
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(inner, |inner, response| {
                    respond(inner, IpPacket::Raw(response))
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => socket.dispatch(inner, |inner, response| match response {
                    #[cfg(feature = "proto-ipv4")]
                    (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => {
                        respond(inner, IpPacket::Icmpv4((ipv4_repr, icmpv4_repr)))
                    }
                    #[cfg(feature = "proto-ipv6")]
                    (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => {
                        respond(inner, IpPacket::Icmpv6((ipv6_repr, icmpv6_repr)))
                    }
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }),
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => socket.dispatch(inner, |inner, response| {
                    respond(inner, IpPacket::Udp(response))
                }),
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(inner, |inner, response| {
                    respond(inner, IpPacket::Tcp(response))
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => socket.dispatch(inner, |inner, response| {
                    respond(inner, IpPacket::Dhcpv4(response))
                }),
                #[cfg(feature = "socket-dns")]
                Socket::Dns(ref mut socket) => socket.dispatch(inner, |inner, response| {
                    respond(inner, IpPacket::Udp(response))
                }),
            };

            match result {
                Err(Error::Exhausted) => break, // Device buffer full.
                Err(Error::Unaddressable) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                    break;
                }
                Err(err) => {
                    net_debug!(
                        "{}: cannot dispatch egress packet: {}",
                        item.meta.handle,
                        err
                    );
                }
                Ok(()) => {}
            }
        }
        emitted_any
    }

    /// Depending on `igmp_report_state` and the therein contained
    /// timeouts, send IGMP membership reports.
    #[cfg(feature = "proto-igmp")]
    fn igmp_egress<D>(&mut self, device: &mut D) -> Result<bool>
    where
        D: Device + ?Sized,
    {
        match self.inner.igmp_report_state {
            IgmpReportState::ToSpecificQuery {
                version,
                timeout,
                group,
            } if self.inner.now >= timeout => {
                if let Some(pkt) = self.inner.igmp_report_packet(version, group) {
                    // Send initial membership report
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    self.inner.dispatch_ip(tx_token, pkt, None)?;
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
                            let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                            self.inner.dispatch_ip(tx_token, pkt, None)?;
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

    /// Process fragments that still need to be sent for IPv4 packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    fn ipv4_egress<D>(&mut self, device: &mut D) -> Result<bool>
    where
        D: Device + ?Sized,
    {
        // Reset the buffer when we transmitted everything.
        if self.out_packets.ipv4_out_packet.finished() {
            self.out_packets.ipv4_out_packet.reset();
        }

        if self.out_packets.ipv4_out_packet.is_empty() {
            return Ok(false);
        }

        let Ipv4OutPacket {
            packet_len,
            sent_bytes,
            ..
        } = &self.out_packets.ipv4_out_packet;

        if *packet_len > *sent_bytes {
            match device.transmit() {
                Some(tx_token) => self
                    .inner
                    .dispatch_ipv4_out_packet(tx_token, &mut self.out_packets.ipv4_out_packet),
                None => Err(Error::Exhausted),
            }
            .map(|_| true)
        } else {
            Ok(false)
        }
    }

    /// Process fragments that still need to be sent for 6LoWPAN packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn sixlowpan_egress<D>(&mut self, device: &mut D) -> Result<bool>
    where
        D: Device + ?Sized,
    {
        // Reset the buffer when we transmitted everything.
        if self.out_packets.sixlowpan_out_packet.finished() {
            self.out_packets.sixlowpan_out_packet.reset();
        }

        if self.out_packets.sixlowpan_out_packet.is_empty() {
            return Ok(false);
        }

        let SixlowpanOutPacket {
            packet_len,
            sent_bytes,
            ..
        } = &self.out_packets.sixlowpan_out_packet;

        if *packet_len > *sent_bytes {
            match device.transmit() {
                Some(tx_token) => self.inner.dispatch_ieee802154_out_packet(
                    tx_token,
                    &mut self.out_packets.sixlowpan_out_packet,
                ),
                None => Err(Error::Exhausted),
            }
            .map(|_| true)
        } else {
            Ok(false)
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

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&mut self, dst_addr: IpAddress) -> Option<IpAddress> {
        let v = dst_addr.version();
        for cidr in self.ip_addrs.iter() {
            let addr = cidr.address();
            if addr.version() == v {
                return Some(addr);
            }
        }
        None
    }

    #[cfg(feature = "proto-ipv4")]
    #[allow(unused)]
    pub(crate) fn get_source_address_ipv4(
        &mut self,
        _dst_addr: Ipv4Address,
    ) -> Option<Ipv4Address> {
        for cidr in self.ip_addrs.iter() {
            #[allow(irrefutable_let_patterns)] // if only ipv4 is enabled
            if let IpCidr::Ipv4(cidr) = cidr {
                return Some(cidr.address());
            }
        }
        None
    }

    #[cfg(feature = "proto-ipv6")]
    #[allow(unused)]
    pub(crate) fn get_source_address_ipv6(
        &mut self,
        _dst_addr: Ipv6Address,
    ) -> Option<Ipv6Address> {
        for cidr in self.ip_addrs.iter() {
            #[allow(irrefutable_let_patterns)] // if only ipv6 is enabled
            if let IpCidr::Ipv6(cidr) = cidr {
                return Some(cidr.address());
            }
        }
        None
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

            ip_addrs: ManagedSlice::Owned(vec![
                #[cfg(feature = "proto-ipv4")]
                IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 1), 24)),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(Ipv6Cidr::new(
                    Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                    64,
                )),
            ]),
            rand: Rand::new(1234),
            routes: Routes::new(&mut [][..]),

            #[cfg(feature = "proto-ipv4")]
            any_ip: false,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: Some(crate::wire::Ieee802154Pan(0xabcd)),
            #[cfg(feature = "medium-ieee802154")]
            sequence_no: 1,

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            tag: 1,

            #[cfg(feature = "proto-sixlowpan")]
            sixlowpan_address_context: &[],

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_id: 1,

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

    #[cfg(feature = "proto-ipv4-fragmentation")]
    fn get_ipv4_ident(&mut self) -> u16 {
        let ipv4_id = self.ipv4_id;
        self.ipv4_id = self.ipv4_id.wrapping_add(1);
        ipv4_id
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn get_sixlowpan_fragment_tag(&mut self) -> u16 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        tag
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
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[cfg(feature = "proto-ipv6")]
            IpCidr::Ipv6(_) => None,
        })
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
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        ip_payload: &'frame T,
        _fragments: &'frame mut FragmentsBuffer<'a>,
    ) -> Option<IpPacket<'frame>> {
        match IpVersion::of_packet(ip_payload.as_ref()) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(ip_payload));

                #[cfg(feature = "proto-ipv4-fragmentation")]
                {
                    self.process_ipv4(sockets, &ipv4_packet, Some(&mut _fragments.ipv4_fragments))
                }

                #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                {
                    self.process_ipv4(sockets, &ipv4_packet, None)
                }
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(ip_payload));
                self.process_ipv6(sockets, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => None,
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
            .items_mut()
            .filter_map(|i| raw::Socket::downcast_mut(&mut i.socket))
        {
            if raw_socket.accepts(ip_repr) {
                raw_socket.process(self, ip_repr, ip_payload);
                handled_by_raw_socket = true;
            }
        }
        handled_by_raw_socket
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

    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    fn process_udp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        udp_repr: UdpRepr,
        handled_by_raw_socket: bool,
        udp_payload: &'frame [u8],
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        #[cfg(feature = "socket-udp")]
        for udp_socket in sockets
            .items_mut()
            .filter_map(|i| udp::Socket::downcast_mut(&mut i.socket))
        {
            if udp_socket.accepts(self, &ip_repr, &udp_repr) {
                udp_socket.process(self, &ip_repr, &udp_repr, udp_payload);
                return None;
            }
        }

        #[cfg(feature = "socket-dns")]
        for dns_socket in sockets
            .items_mut()
            .filter_map(|i| dns::Socket::downcast_mut(&mut i.socket))
        {
            if dns_socket.accepts(&ip_repr, &udp_repr) {
                dns_socket.process(self, &ip_repr, &udp_repr, udp_payload);
                return None;
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr)
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
                self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr)
            }
        }
    }

    #[cfg(feature = "socket-tcp")]
    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| tcp::Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(IpPacket::Tcp);
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Some(IpPacket::Tcp(tcp::Socket::rst_reply(&ip_repr, &tcp_repr)))
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
        _out_packet: Option<&mut OutPackets<'_>>,
    ) -> Result<()>
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
            EthernetPacket::Ip(packet) => self.dispatch_ip(tx_token, packet, _out_packet),
        }
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

                self.dispatch_ip(tx_token, packet, None)?;
            }

            #[allow(unreachable_patterns)]
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

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        packet: IpPacket,
        _out_packet: Option<&mut OutPackets<'_>>,
    ) -> Result<()> {
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.caps.medium, Medium::Ieee802154) {
            let (dst_hardware_addr, tx_token) = match self.lookup_hardware_addr(
                tx_token,
                &ip_repr.src_addr(),
                &ip_repr.dst_addr(),
            )? {
                (HardwareAddress::Ieee802154(addr), tx_token) => (addr, tx_token),
                _ => unreachable!(),
            };

            return self.dispatch_ieee802154(
                dst_hardware_addr,
                &ip_repr,
                tx_token,
                packet,
                _out_packet,
            );
        }

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ipv4_id = self.get_ipv4_ident();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        #[cfg(feature = "medium-ethernet")]
        let (dst_hardware_addr, tx_token) =
            match self.lookup_hardware_addr(tx_token, &ip_repr.src_addr(), &ip_repr.dst_addr())? {
                (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                #[cfg(feature = "medium-ieee802154")]
                (HardwareAddress::Ieee802154(_), _) => unreachable!(),
            };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = if let Some(HardwareAddress::Ethernet(addr)) = self.hardware_addr {
                addr
            } else {
                return Err(Error::Malformed);
            };

            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }

            Ok(())
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, mut tx_buffer: &mut [u8]| {
            repr.emit(&mut tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps);
        };

        let total_ip_len = ip_repr.buffer_len();

        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ref mut repr) => {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                if total_ip_len > self.caps.max_transmission_unit {
                    #[cfg(feature = "proto-ipv4-fragmentation")]
                    {
                        net_debug!("start fragmentation");

                        let Ipv4OutPacket {
                            buffer,
                            packet_len,
                            sent_bytes,
                            repr: out_packet_repr,
                            frag_offset,
                            ident,
                            dst_hardware_addr: dst_address,
                        } = &mut _out_packet.unwrap().ipv4_out_packet;

                        // Calculate how much we will send now (including the Ethernet header).
                        let tx_len = self.caps.max_transmission_unit;

                        let ip_header_len = repr.buffer_len();
                        let first_frag_ip_len = self.caps.ip_mtu();

                        if buffer.len() < first_frag_ip_len {
                            net_debug!("Fragmentation buffer is too small");
                            return Err(Error::Exhausted);
                        }

                        *dst_address = dst_hardware_addr;

                        // Save the total packet len (without the Ethernet header, but with the first
                        // IP header).
                        *packet_len = total_ip_len;

                        // Save the IP header for other fragments.
                        *out_packet_repr = *repr;

                        // Save how much bytes we will send now.
                        *sent_bytes = first_frag_ip_len;

                        // Modify the IP header
                        repr.payload_len = first_frag_ip_len - repr.buffer_len();

                        // Emit the IP header to the buffer.
                        emit_ip(&ip_repr, buffer);
                        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..]);
                        *ident = ipv4_id;
                        ipv4_packet.set_ident(ipv4_id);
                        ipv4_packet.set_more_frags(true);
                        ipv4_packet.set_dont_frag(false);
                        ipv4_packet.set_frag_offset(0);

                        if caps.checksum.ipv4.tx() {
                            ipv4_packet.fill_checksum();
                        }

                        // Transmit the first packet.
                        tx_token.consume(self.now, tx_len, |mut tx_buffer| {
                            #[cfg(feature = "medium-ethernet")]
                            if matches!(self.caps.medium, Medium::Ethernet) {
                                emit_ethernet(&ip_repr, tx_buffer)?;
                                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                            }

                            // Change the offset for the next packet.
                            *frag_offset = (first_frag_ip_len - ip_header_len) as u16;

                            // Copy the IP header and the payload.
                            tx_buffer[..first_frag_ip_len]
                                .copy_from_slice(&buffer[..first_frag_ip_len]);

                            Ok(())
                        })
                    }

                    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                    {
                        net_debug!("Enable the `proto-ipv4-fragmentation` feature for fragmentation support.");
                        Ok(())
                    }
                } else {
                    // No fragmentation is required.
                    tx_token.consume(self.now, total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer)?;
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                        Ok(())
                    })
                }
            }
            // We don't support IPv6 fragmentation yet.
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) => tx_token.consume(self.now, total_len, |mut tx_buffer| {
                #[cfg(feature = "medium-ethernet")]
                if matches!(self.caps.medium, Medium::Ethernet) {
                    emit_ethernet(&ip_repr, tx_buffer)?;
                    tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                }

                emit_ip(&ip_repr, tx_buffer);
                Ok(())
            }),
        }
    }
}
