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

#[cfg(feature = "proto-igmp")]
mod igmp;

#[cfg(feature = "proto-rpl")]
mod rpl;

use core::cmp;
use core::result::Result;
use heapless::{LinearMap, Vec};

#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::socket_set::SocketSet;
use crate::iface::Routes;
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
#[cfg(feature = "socket-dns")]
use crate::socket::dns;
use crate::socket::*;
use crate::time::{Duration, Instant};
use crate::wire::*;

#[cfg(feature = "proto-rpl")]
use crate::iface::rpl::{Rank, Rpl};

const MAX_IP_ADDR_COUNT: usize = 5;
#[cfg(feature = "proto-igmp")]
const MAX_IPV4_MULTICAST_GROUPS: usize = 4;
const FRAGMENTATION_BUFFER_SIZE: usize = 1500;
#[cfg(feature = "proto-sixlowpan")]
const SIXLOWPAN_ADDRESS_CONTEXT_COUNT: usize = 4;

pub(crate) struct FragmentsBuffer {
    #[cfg(feature = "proto-sixlowpan")]
    decompress_buf: [u8; sixlowpan::MAX_DECOMPRESSED_LEN],
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(crate) ipv4_fragments: PacketAssemblerSet<Ipv4FragKey>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments: PacketAssemblerSet<SixlowpanFragKey>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_fragments_cache_timeout: Duration,
}

pub(crate) struct OutPackets {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_out_packet: Ipv4OutPacket,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    sixlowpan_out_packet: SixlowpanOutPacket,
}

impl OutPackets {
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
#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Ipv4OutPacket {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    sent_bytes: usize,

    /// The IPv4 representation.
    repr: Ipv4Repr,
    /// The destination hardware address.
    #[cfg(feature = "medium-ethernet")]
    dst_hardware_addr: EthernetAddress,
    /// The offset of the next fragment.
    frag_offset: u16,
    /// The identifier of the stream.
    ident: u16,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
impl Ipv4OutPacket {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
            packet_len: 0,
            sent_bytes: 0,
            repr: Ipv4Repr {
                src_addr: Ipv4Address::default(),
                dst_addr: Ipv4Address::default(),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            },
            #[cfg(feature = "medium-ethernet")]
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
        #[cfg(feature = "medium-ethernet")]
        {
            self.dst_hardware_addr = EthernetAddress::default();
        }
    }
}

#[allow(unused)]
#[cfg(feature = "proto-sixlowpan")]
pub(crate) struct SixlowpanOutPacket {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
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
impl SixlowpanOutPacket {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
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
pub struct Interface {
    inner: InterfaceInner,
    fragments: FragmentsBuffer,
    out_packets: OutPackets,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: Option<NeighborCache>,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    hardware_addr: Option<HardwareAddress>,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_id: u16,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context: Vec<SixlowpanAddressContext, SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    ip_addrs: Vec<IpCidr, MAX_IP_ADDR_COUNT>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: LinearMap<Ipv4Address, (), MAX_IPV4_MULTICAST_GROUPS>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,

    #[cfg(feature = "proto-rpl")]
    rpl: Rpl,
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub hardware_addr: Option<HardwareAddress>,

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub pan_id: Option<Ieee802154Pan>,

    /// Set the RPL configuration the interface will use.
    #[cfg(feature = "proto-rpl")]
    pub rpl: super::RplConfig,
}

impl Config {
    pub fn new() -> Self {
        Config {
            random_seed: 0,
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            hardware_addr: None,
            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,
            #[cfg(feature = "proto-rpl")]
            rpl: super::RplConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
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
    #[cfg(feature = "proto-sixlowpan")]
    Forward((Ipv6Repr, Option<Ipv6HopByHopRepr<'a>>, &'a [u8])),
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
            #[cfg(feature = "proto-sixlowpan")]
            IpPacket::Forward((ipv6_repr, _, _)) => IpRepr::Ipv6(*ipv6_repr),
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
            #[cfg(feature = "proto-sixlowpan")]
            IpPacket::Forward(_) => {
                todo!();
            }
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

impl Interface {
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
    pub fn new<D>(config: Config, device: &mut D) -> Self
    where
        D: Device + ?Sized,
    {
        let caps = device.capabilities();

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        let hardware_addr = match caps.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => Some(
                config
                    .hardware_addr
                    .expect("hardware_addr required option was not set"),
            ),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                assert!(
                    config.hardware_addr.is_none(),
                    "hardware_addr is set, but device medium is IP"
                );
                None
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => Some(
                config
                    .hardware_addr
                    .expect("hardware_addr required option was not set"),
            ),
        };

        let mut rand = Rand::new(config.random_seed);

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
                #[cfg(feature = "proto-sixlowpan")]
                decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],

                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_fragments: PacketAssemblerSet::new(),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments: PacketAssemblerSet::new(),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_fragments_cache_timeout: Duration::from_secs(60),
            },
            out_packets: OutPackets {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_out_packet: Ipv4OutPacket::new(),
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                sixlowpan_out_packet: SixlowpanOutPacket::new(),
            },
            inner: InterfaceInner {
                now: Instant::from_secs(0),
                caps,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                hardware_addr,
                ip_addrs: Vec::new(),
                #[cfg(feature = "proto-ipv4")]
                any_ip: false,
                routes: Routes::new(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: Some(NeighborCache::new()),
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: LinearMap::new(),
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: config.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_id,
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: Vec::new(),
                rand,
                #[cfg(feature = "proto-rpl")]
                rpl: Rpl::new(config.rpl, Instant::from_secs(0)),
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&self) -> &InterfaceInner {
        &self.inner
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context_mut(&mut self) -> &mut InterfaceInner {
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

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.inner.ipv6_addr()
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr, MAX_IP_ADDR_COUNT>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// AnyIP allowins packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [`routes`](Self::routes) specifies one of
    /// the interface's [`ip_addrs`](Self::ip_addrs) as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    #[cfg(feature = "proto-ipv4")]
    pub fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Get whether AnyIP is enabled.
    ///
    /// See [`set_any_ip`](Self::set_any_ip) for details on AnyIP
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(&self) -> bool {
        self.inner.any_ip
    }

    /// Get the 6LoWPAN address contexts.
    #[cfg(feature = "proto-sixlowpan")]
    pub fn sixlowpan_address_context(
        &self,
    ) -> &Vec<SixlowpanAddressContext, SIXLOWPAN_ADDRESS_CONTEXT_COUNT> {
        &self.inner.sixlowpan_address_context
    }

    /// Get a mutable reference to the 6LoWPAN address contexts.
    #[cfg(feature = "proto-sixlowpan")]
    pub fn sixlowpan_address_context_mut(
        &mut self,
    ) -> &mut Vec<SixlowpanAddressContext, SIXLOWPAN_ADDRESS_CONTEXT_COUNT> {
        &mut self.inner.sixlowpan_address_context
    }

    /// Get the packet reassembly timeout.
    ///
    /// Currently used only for 6LoWPAN, will be used for IPv4 in the future as well.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.sixlowpan_fragments_cache_timeout
    }

    /// Set the packet reassembly timeout.
    ///
    /// Currently used only for 6LoWPAN, will be used for IPv4 in the future as well.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        if timeout > Duration::from_secs(60) {
            net_debug!("RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds");
        }
        self.fragments.sixlowpan_fragments_cache_timeout = timeout;
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    pub fn poll<D>(
        &mut self,
        timestamp: Instant,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        #[cfg(feature = "proto-rpl")]
        self.poll_rpl(device);

        #[cfg(feature = "proto-ipv4-fragmentation")]
        self.fragments.ipv4_fragments.remove_expired(timestamp);

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        self.fragments.sixlowpan_fragments.remove_expired(timestamp);

        #[cfg(feature = "proto-ipv4-fragmentation")]
        if self.ipv4_egress(device) {
            return true;
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if self.sixlowpan_egress(device) {
            return true;
        }

        let mut readiness_may_have_changed = false;

        loop {
            let mut did_something = false;
            did_something |= self.socket_ingress(device, sockets);
            did_something |= self.socket_egress(device, sockets);

            #[cfg(feature = "proto-igmp")]
            {
                did_something |= self.igmp_egress(device);
            }

            if did_something {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }

        readiness_may_have_changed
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

        #[cfg(feature = "proto-rpl")]
        let min = Some(self.poll_at_rpl());

        #[cfg(not(feature = "proto-rpl"))]
        let min = None;

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        if !self.out_packets.all_transmitted() {
            return Some(Instant::from_millis(0));
        }

        let inner = &mut self.inner;

        let result = sockets
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
            .min();

        if result.is_none() {
            min
        } else {
            result.min(min)
        }
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

    #[cfg(feature = "proto-rpl")]
    fn poll_rpl<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        let InterfaceInner { rpl, now, rand, .. } = &mut self.inner;

        rpl.dio_timer.start(*now, rand);

        if rpl.has_parent()
            && rpl.parent_last_heard.unwrap_or(*now) < *now - rpl.dio_timer.max_expiration() * 2
        {
            rpl.parent_address = None;
            rpl.parent_rank = None;
            rpl.parent_preference = None;
            rpl.rank = Rank::INFINITE;

            return self.transmit_rpl_dio(device);
        }

        // This is for transmitting DIS messages.
        if rpl.should_send_dis(*now) {
            rpl.set_dis_expiration(*now + Duration::from_secs(60));
            return self.transmit_rpl_dis(device);
        }

        // This is for transmitting DIO messages periodically.
        if (rpl.has_parent() || rpl.is_root) && rpl.dio_timer.poll(*now, rand) {
            return self.transmit_rpl_dio(device);
        }

        false
    }

    #[cfg(feature = "proto-rpl")]
    pub fn poll_at_rpl(&mut self) -> Instant {
        if self.inner.rpl.has_parent() || self.inner.rpl.is_root {
            self.inner.rpl.dio_timer.poll_at()
        } else {
            self.inner.rpl.dis_expiration
        }
    }

    fn socket_ingress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let mut processed_any = false;

        while let Some((rx_token, tx_token)) = device.receive(self.inner.now) {
            rx_token.consume(|frame| {
                match self.inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some(packet) =
                            self.inner
                                .process_ethernet(sockets, &frame, &mut self.fragments)
                        {
                            if let Err(err) =
                                self.inner
                                    .dispatch(tx_token, packet, Some(&mut self.out_packets))
                            {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => {
                        if let Some(packet) =
                            self.inner.process_ip(sockets, &frame, &mut self.fragments)
                        {
                            if let Err(err) = self.inner.dispatch_ip(
                                tx_token,
                                packet,
                                Some(&mut self.out_packets),
                            ) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        if let Some(packet) =
                            self.inner
                                .process_ieee802154(sockets, &frame, &mut self.fragments)
                        {
                            if let Err(err) = self.inner.dispatch_ip(
                                tx_token,
                                packet,
                                Some(&mut self.out_packets),
                            ) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                }
                processed_any = true;
            });
        }

        processed_any
    }

    fn socket_egress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let _caps = device.capabilities();

        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;
        for item in sockets.items_mut() {
            if !item
                .meta
                .egress_permitted(self.inner.now, |ip_addr| self.inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut respond = |inner: &mut InterfaceInner, response: IpPacket| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                let t = device.transmit(inner.now).ok_or_else(|| {
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                #[cfg(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                ))]
                inner
                    .dispatch_ip(t, response, Some(&mut self.out_packets))
                    .map_err(EgressError::Dispatch)?;

                #[cfg(not(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-sixlowpan-fragmentation"
                )))]
                inner
                    .dispatch_ip(t, response, None)
                    .map_err(EgressError::Dispatch)?;

                emitted_any = true;

                Ok(())
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut self.inner, |inner, response| {
                    respond(inner, IpPacket::Raw(response))
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, response| match response {
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
                    })
                }
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => socket.dispatch(&mut self.inner, |inner, response| {
                    respond(inner, IpPacket::Udp(response))
                }),
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(&mut self.inner, |inner, response| {
                    respond(inner, IpPacket::Tcp(response))
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => socket.dispatch(&mut self.inner, |inner, response| {
                    respond(inner, IpPacket::Dhcpv4(response))
                }),
                #[cfg(feature = "socket-dns")]
                Socket::Dns(ref mut socket) => socket
                    .dispatch(&mut self.inner, |inner, response| {
                        respond(inner, IpPacket::Udp(response))
                    }),
            };

            match result {
                Err(EgressError::Exhausted) => break, // Device buffer full.
                Err(EgressError::Dispatch(_)) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    //item.meta.neighbor_missing(
                    //self.inner.now,
                    //neighbor_addr.expect("non-IP response packet"),
                    //);
                }
                Ok(()) => {}
            }
        }
        emitted_any
    }

    /// Process fragments that still need to be sent for IPv4 packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    fn ipv4_egress<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        // Reset the buffer when we transmitted everything.
        if self.out_packets.ipv4_out_packet.finished() {
            self.out_packets.ipv4_out_packet.reset();
        }

        if self.out_packets.ipv4_out_packet.is_empty() {
            return false;
        }

        let Ipv4OutPacket {
            packet_len,
            sent_bytes,
            ..
        } = &self.out_packets.ipv4_out_packet;

        if *packet_len > *sent_bytes {
            if let Some(tx_token) = device.transmit(self.inner.now) {
                self.inner
                    .dispatch_ipv4_out_packet(tx_token, &mut self.out_packets.ipv4_out_packet);
                return true;
            }
        }
        false
    }

    /// Process fragments that still need to be sent for 6LoWPAN packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn sixlowpan_egress<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        // Reset the buffer when we transmitted everything.
        if self.out_packets.sixlowpan_out_packet.finished() {
            self.out_packets.sixlowpan_out_packet.reset();
        }

        if self.out_packets.sixlowpan_out_packet.is_empty() {
            return false;
        }

        let SixlowpanOutPacket {
            packet_len,
            sent_bytes,
            ..
        } = &self.out_packets.sixlowpan_out_packet;

        if *packet_len > *sent_bytes {
            if let Some(tx_token) = device.transmit(self.inner.now) {
                self.inner.dispatch_ieee802154_out_packet(
                    tx_token,
                    &mut self.out_packets.sixlowpan_out_packet,
                );
                return true;
            }
        }
        false
    }

    #[cfg(feature = "proto-rpl")]
    fn transmit_rpl_dis<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        let dis = RplRepr::DodagInformationSolicitation {
            options: heapless::Vec::new(),
        };

        net_trace!("Sending {}", dis);

        let icmp_rpl = Icmpv6Repr::Rpl(dis);

        // TODO(thvdveld): remove unwrap
        let ipv6_repr = Ipv6Repr {
            src_addr: self.inner.ipv6_addr().unwrap(),
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp_rpl.buffer_len(),
            hop_limit: 64,
        };

        if let Some(tx_token) = device.transmit(self.inner.now) {
            match self.inner.dispatch_ip(
                tx_token,
                IpPacket::Icmpv6((ipv6_repr, icmp_rpl)),
                Some(&mut self.out_packets),
            ) {
                Ok(()) => return true,
                Err(e) => {
                    net_debug!("Failed to send DIS: {e:?}");
                    return false;
                }
            }
        }

        false
    }

    #[cfg(feature = "proto-rpl")]
    fn transmit_rpl_dio<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        let mut options = heapless::Vec::new();
        options.push(self.inner.rpl.dodag_configuration()).unwrap();

        let dio = RplRepr::DodagInformationObject {
            rpl_instance_id: self.inner.rpl.instance_id,
            version_number: self.inner.rpl.version_number.value(),
            rank: self.inner.rpl.rank.raw_value(),
            grounded: self.inner.rpl.grounded,
            mode_of_operation: self.inner.rpl.mode_of_operation.into(),
            dodag_preference: self.inner.rpl.dodag_preference,
            dtsn: self.inner.rpl.dtsn.value(),
            dodag_id: self.inner.rpl.dodag_id.unwrap(),
            options,
        };
        net_trace!("Sending {}", dio);

        let icmp_rpl = Icmpv6Repr::Rpl(dio);

        // TODO(thvdveld): remove unwrap
        let ipv6_repr = Ipv6Repr {
            src_addr: self.inner.ipv6_addr().unwrap(),
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp_rpl.buffer_len(),
            hop_limit: 64,
        };

        if let Some(tx_token) = device.transmit(self.inner.now) {
            match self.inner.dispatch_ip(
                tx_token,
                IpPacket::Icmpv6((ipv6_repr, icmp_rpl)),
                Some(&mut self.out_packets),
            ) {
                Ok(()) => return true,
                Err(e) => {
                    net_debug!("Failed to send DIS: {e:?}");
                    return false;
                }
            }
        }

        false
    }
}

impl InterfaceInner {
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
                #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ip"))]
                medium: crate::phy::Medium::Ip,
                #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ieee802154"))]
                medium: crate::phy::Medium::Ieee802154,

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

            ip_addrs: Vec::from_slice(&[
                #[cfg(feature = "proto-ipv4")]
                IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 1), 24)),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(Ipv6Cidr::new(
                    Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                    64,
                )),
            ])
            .unwrap(),
            rand: Rand::new(1234),
            routes: Routes::new(),

            #[cfg(feature = "proto-ipv4")]
            any_ip: false,

            #[cfg(feature = "medium-ieee802154")]
            pan_id: Some(crate::wire::Ieee802154Pan(0xabcd)),
            #[cfg(feature = "medium-ieee802154")]
            sequence_no: 1,

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            tag: 1,

            #[cfg(feature = "proto-sixlowpan")]
            sixlowpan_address_context: Vec::new(),

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_id: 1,

            #[cfg(feature = "medium-ethernet")]
            hardware_addr: Some(crate::wire::HardwareAddress::Ethernet(
                crate::wire::EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            )),
            #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ieee802154"))]
            hardware_addr: Some(crate::wire::HardwareAddress::Ieee802154(
                crate::wire::Ieee802154Address::Extended([
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x2, 0x2,
                ]),
            )),

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            neighbor_cache: None,

            #[cfg(feature = "proto-igmp")]
            igmp_report_state: IgmpReportState::Inactive,
            #[cfg(feature = "proto-igmp")]
            ipv4_multicast_groups: LinearMap::new(),

            #[cfg(feature = "proto-rpl")]
            rpl: Rpl::new(crate::iface::RplConfig::default(), Instant::now()),
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
            panic!("Ethernet address {addr} is not unicast")
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
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv6(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    #[cfg(not(feature = "proto-igmp"))]
    fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        false
    }

    #[cfg(feature = "proto-rpl")]
    pub fn rpl(&self) -> &Rpl {
        &self.rpl
    }

    #[cfg(feature = "proto-rpl")]
    pub fn rpl_mut(&mut self) -> &mut Rpl {
        &mut self.rpl
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        ip_payload: &'frame T,
        _fragments: &'frame mut FragmentsBuffer,
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
                self.process_ipv6(sockets, None, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &[u8],
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
        _out_packet: Option<&mut OutPackets>,
    ) -> Result<(), DispatchError>
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

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        // Send directly.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        // Route via a router.
        self.routes.lookup(addr, timestamp)
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Some(_routed_addr) => match self.caps.medium {
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
            None => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
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

        let dst_addr = self
            .route(dst_addr, self.now)
            .ok_or(DispatchError::NoRoute)?;

        match self
            .neighbor_cache
            .as_mut()
            .unwrap()
            .lookup(&dst_addr, self.now)
        {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr = self.hardware_addr.unwrap().ethernet_or_panic();

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                if let Err(e) =
                    self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                        frame.set_dst_addr(EthernetAddress::BROADCAST);
                        frame.set_ethertype(EthernetProtocol::Arp);

                        arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                    })
                {
                    net_debug!("Failed to dispatch ARP request: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
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

                if let Err(e) = self.dispatch_ip(tx_token, packet, None) {
                    net_debug!("Failed to dispatch NDISC solicit: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[allow(unreachable_patterns)]
            _ => (),
        }

        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.as_mut().unwrap().limit_rate(self.now);
        Err(DispatchError::NeighborPending)
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
        _out_packet: Option<&mut OutPackets>,
    ) -> Result<(), DispatchError> {
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.caps.medium, Medium::Ieee802154) {
            // TODO(thvdveld): make the following part nicer!
            let (addr, tx_token) = if ip_repr.dst_addr().is_multicast() {
                (Ieee802154Address::BROADCAST, tx_token)
            } else {
                #[cfg(feature = "proto-rpl")]
                {
                    let addr = if let Some(addr) = self.rpl.parent_address {
                        if let Some((n, _)) =
                            self.rpl.neighbor_table.get_neighbor_from_ip_addr(&addr)
                        {
                            n.link_layer_addr().ieee802154_or_panic()
                        } else {
                            unreachable!()
                        }
                    } else {
                        net_trace!("No parent yet, so cannot send it.");
                        return Err(DispatchError::NoRoute);
                    };

                    (addr, tx_token)
                }

                #[cfg(not(feature = "proto-rpl"))]
                {
                    let (addr, tx_token) = self.lookup_hardware_addr(
                        tx_token,
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                    )?;
                    let addr = addr.ieee802154_or_panic();

                    (addr, tx_token)
                }
            };

            self.dispatch_ieee802154(addr, tx_token, packet, _out_packet);
            return Ok(());
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
        let (dst_hardware_addr, tx_token) = match self.caps.medium {
            Medium::Ethernet => {
                match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    #[cfg(feature = "medium-ieee802154")]
                    (HardwareAddress::Ieee802154(_), _) => unreachable!(),
                }
            }
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.unwrap().ethernet_or_panic();
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
                            #[cfg(feature = "medium-ethernet")]
                                dst_hardware_addr: dst_address,
                        } = &mut _out_packet.unwrap().ipv4_out_packet;

                        // Calculate how much we will send now (including the Ethernet header).
                        let tx_len = self.caps.max_transmission_unit;

                        let ip_header_len = repr.buffer_len();
                        let first_frag_ip_len = self.caps.ip_mtu();

                        if buffer.len() < first_frag_ip_len {
                            net_debug!(
                                "Fragmentation buffer is too small, at least {} needed. Dropping",
                                first_frag_ip_len
                            );
                            return Ok(());
                        }

                        #[cfg(feature = "medium-ethernet")]
                        {
                            *dst_address = dst_hardware_addr;
                        }

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
                        tx_token.consume(tx_len, |mut tx_buffer| {
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
                    tx_token.consume(total_len, |mut tx_buffer| {
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
            IpRepr::Ipv6(_) => tx_token.consume(total_len, |mut tx_buffer| {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
