/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides two levels
of functionality.

 * First, it provides functions to extract fields from sequences of octets,
   and to insert fields into sequences of octets. This happens `Packet` family of
   structures, e.g. [EthernetFrame] or [Ipv4Packet].
 * Second, in cases where the space of valid field values is much smaller than the space
   of possible field values, it provides a compact, high-level representation
   of packet data that can be parsed from and emitted into a sequence of octets.
   This happens through the `Repr` family of structs and enums, e.g. [ArpRepr] or [Ipv4Repr].

[EthernetFrame]: struct.EthernetFrame.html
[Ipv4Packet]: struct.Ipv4Packet.html
[ArpRepr]: enum.ArpRepr.html
[Ipv4Repr]: struct.Ipv4Repr.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.

In the `Repr` family of data structures, the `Repr::parse()` method never panics
as long as `Packet::new_checked()` (or `Packet::check_len()`) has succeeded, and
the `Repr::emit()` method never panics as long as the underlying buffer is exactly
`Repr::buffer_len()` octets long.

# Examples

To emit an IP packet header into an octet buffer, and then parse it back:

```rust
# #[cfg(feature = "proto-ipv4")]
# {
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    next_header: IpProtocol::Tcp,
    payload_len: 10,
    hop_limit:   64,
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
}
{ // parsing
    let packet = Ipv4Packet::new_checked(&buffer)
                            .expect("truncated packet");
    let parsed = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())
                          .expect("malformed packet");
    assert_eq!(repr, parsed);
}
# }
```
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

#[cfg(all(feature = "proto-ipv4", feature = "medium-ethernet"))]
mod arp;
#[cfg(feature = "proto-dhcpv4")]
pub(crate) mod dhcpv4;
#[cfg(feature = "proto-dns")]
pub(crate) mod dns;
#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
mod icmp;
#[cfg(feature = "proto-ipv4")]
mod icmpv4;
#[cfg(feature = "proto-ipv6")]
mod icmpv6;
#[cfg(feature = "medium-ieee802154")]
pub mod ieee802154;
#[cfg(feature = "proto-igmp")]
mod igmp;
pub(crate) mod ip;
#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-ipv6")]
mod ipv6fragment;
#[cfg(feature = "proto-ipv6-hop-by-hop")]
mod ipv6hopbyhop;
#[cfg(feature = "proto-ipv6")]
mod ipv6option;
#[cfg(feature = "proto-ipv6")]
mod ipv6routing;
#[cfg(feature = "proto-ipv6")]
mod mld;
#[cfg(all(
    feature = "proto-ipv6",
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
mod ndisc;
#[cfg(all(
    feature = "proto-ipv6",
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
mod ndiscoption;
#[cfg(all(feature = "proto-sixlowpan", feature = "medium-ieee802154"))]
mod sixlowpan;
mod tcp;
mod udp;

use core::fmt;

use crate::phy::Medium;

pub use self::pretty_print::PrettyPrinter;

#[cfg(feature = "medium-ethernet")]
pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

#[cfg(all(feature = "proto-ipv4", feature = "medium-ethernet"))]
pub use self::arp::{
    Hardware as ArpHardware, Operation as ArpOperation, Packet as ArpPacket, Repr as ArpRepr,
};

#[cfg(all(feature = "proto-sixlowpan", feature = "medium-ieee802154"))]
pub use self::sixlowpan::{
    frag::{Key as SixlowpanFragKey, Packet as SixlowpanFragPacket, Repr as SixlowpanFragRepr},
    iphc::{Packet as SixlowpanIphcPacket, Repr as SixlowpanIphcRepr},
    nhc::{
        ExtHeaderPacket as SixlowpanExtHeaderPacket, ExtHeaderRepr as SixlowpanExtHeaderRepr,
        NhcPacket as SixlowpanNhcPacket, UdpNhcPacket as SixlowpanUdpNhcPacket,
        UdpNhcRepr as SixlowpanUdpNhcRepr,
    },
    AddressContext as SixlowpanAddressContext, NextHeader as SixlowpanNextHeader, SixlowpanPacket,
};

#[cfg(feature = "medium-ieee802154")]
pub use self::ieee802154::{
    Address as Ieee802154Address, AddressingMode as Ieee802154AddressingMode,
    Frame as Ieee802154Frame, FrameType as Ieee802154FrameType,
    FrameVersion as Ieee802154FrameVersion, Pan as Ieee802154Pan, Repr as Ieee802154Repr,
};

pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint,
    ListenEndpoint as IpListenEndpoint, Protocol as IpProtocol, Repr as IpRepr,
    Version as IpVersion,
};

#[cfg(feature = "proto-ipv4")]
pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, Key as Ipv4FragKey, Packet as Ipv4Packet,
    Repr as Ipv4Repr, HEADER_LEN as IPV4_HEADER_LEN, MIN_MTU as IPV4_MIN_MTU,
};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, Packet as Ipv6Packet, Repr as Ipv6Repr,
    HEADER_LEN as IPV6_HEADER_LEN, MIN_MTU as IPV6_MIN_MTU,
};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6option::{
    FailureType as Ipv6OptionFailureType, Ipv6Option, Repr as Ipv6OptionRepr,
    Type as Ipv6OptionType,
};

#[cfg(feature = "proto-ipv6-hop-by-hop")]
pub use self::ipv6hopbyhop::{Header as Ipv6HopByHopHeader, Repr as Ipv6HopByHopRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6fragment::{Header as Ipv6FragmentHeader, Repr as Ipv6FragmentRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6routing::{
    Header as Ipv6RoutingHeader, Repr as Ipv6RoutingRepr, Type as Ipv6RoutingType,
};

#[cfg(feature = "proto-ipv4")]
pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, Repr as Icmpv4Repr,
    TimeExceeded as Icmpv4TimeExceeded,
};

#[cfg(feature = "proto-igmp")]
pub use self::igmp::{IgmpVersion, Packet as IgmpPacket, Repr as IgmpRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, Repr as Icmpv6Repr, TimeExceeded as Icmpv6TimeExceeded,
};

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
pub use self::icmp::Repr as IcmpRepr;

#[cfg(all(
    feature = "proto-ipv6",
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
pub use self::ndisc::{
    NeighborFlags as NdiscNeighborFlags, Repr as NdiscRepr, RouterFlags as NdiscRouterFlags,
};

#[cfg(all(
    feature = "proto-ipv6",
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
pub use self::ndiscoption::{
    NdiscOption, PrefixInfoFlags as NdiscPrefixInfoFlags,
    PrefixInformation as NdiscPrefixInformation, RedirectedHeader as NdiscRedirectedHeader,
    Repr as NdiscOptionRepr, Type as NdiscOptionType,
};

#[cfg(feature = "proto-ipv6")]
pub use self::mld::{AddressRecord as MldAddressRecord, Repr as MldRepr};

pub use self::udp::{Packet as UdpPacket, Repr as UdpRepr, HEADER_LEN as UDP_HEADER_LEN};

pub use self::tcp::{
    Control as TcpControl, Packet as TcpPacket, Repr as TcpRepr, SeqNumber as TcpSeqNumber,
    TcpOption, HEADER_LEN as TCP_HEADER_LEN,
};

#[cfg(feature = "proto-dhcpv4")]
pub use self::dhcpv4::{
    DhcpOption, DhcpOptionWriter, MessageType as DhcpMessageType, Packet as DhcpPacket,
    Repr as DhcpRepr, CLIENT_PORT as DHCP_CLIENT_PORT,
    MAX_DNS_SERVER_COUNT as DHCP_MAX_DNS_SERVER_COUNT, SERVER_PORT as DHCP_SERVER_PORT,
};

#[cfg(feature = "proto-dns")]
pub use self::dns::{Packet as DnsPacket, Repr as DnsRepr, Type as DnsQueryType};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by smoltcp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Error;

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Representation of an hardware address, such as an Ethernet address or an IEEE802.15.4 address.
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HardwareAddress {
    #[cfg(feature = "medium-ethernet")]
    Ethernet(EthernetAddress),
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154(Ieee802154Address),
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl HardwareAddress {
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.as_bytes(),
        }
    }

    /// Query wether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.is_unicast(),
        }
    }

    /// Query wether the address is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.is_broadcast(),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn ethernet_or_panic(&self) -> EthernetAddress {
        match self {
            HardwareAddress::Ethernet(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("HardwareAddress is not Ethernet."),
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    pub(crate) fn ieee802154_or_panic(&self) -> Ieee802154Address {
        match self {
            HardwareAddress::Ieee802154(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("HardwareAddress is not Ethernet."),
        }
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

#[cfg(feature = "medium-ieee802154")]
impl From<Ieee802154Address> for HardwareAddress {
    fn from(addr: Ieee802154Address) -> Self {
        HardwareAddress::Ieee802154(addr)
    }
}

#[cfg(not(feature = "medium-ieee802154"))]
pub const MAX_HARDWARE_ADDRESS_LEN: usize = 6;
#[cfg(feature = "medium-ieee802154")]
pub const MAX_HARDWARE_ADDRESS_LEN: usize = 8;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RawHardwareAddress {
    len: u8,
    data: [u8; MAX_HARDWARE_ADDRESS_LEN],
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl RawHardwareAddress {
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HARDWARE_ADDRESS_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self {
            len: addr.len() as u8,
            data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn parse(&self, medium: Medium) -> Result<HardwareAddress> {
        match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                if self.len() < 6 {
                    return Err(Error);
                }
                Ok(HardwareAddress::Ethernet(EthernetAddress::from_bytes(
                    self.as_bytes(),
                )))
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                if self.len() < 8 {
                    return Err(Error);
                }
                Ok(HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(
                    self.as_bytes(),
                )))
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => unreachable!(),
        }
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl core::fmt::Display for RawHardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for RawHardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

#[cfg(feature = "medium-ieee802154")]
impl From<Ieee802154Address> for RawHardwareAddress {
    fn from(addr: Ieee802154Address) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl From<HardwareAddress> for RawHardwareAddress {
    fn from(addr: HardwareAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IpPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4PacketRepr<'a>),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6PacketRepr<'a>),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv4")]
pub struct Ipv4PacketRepr<'a> {
    hdr: Ipv4Repr,
    payload: IpPayload<'a>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv6")]
pub struct Ipv6PacketRepr<'a> {
    hdr: Ipv6Repr,
    #[cfg(feature = "proto-ipv6-hop-by-hop")]
    hop_by_hop: Option<Ipv6HopByHopRepr<'a>>,
    payload: IpPayload<'a>,
}

impl<'a> IpPacket<'a> {
    pub fn new(hdr: IpRepr, payload: IpPayload<'a>) -> Self {
        // Check that the packet we make makes sense.
        match (hdr.version(), &payload) {
            #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
            (IpVersion::Ipv4, &IpPayload::Icmpv6(..)) => unreachable!(),
            #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
            (IpVersion::Ipv6, &IpPayload::Icmpv4(..)) => unreachable!(),
            #[cfg(all(feature = "proto-ipv6", feature = "socket-dhcpv4"))]
            (IpVersion::Ipv6, &IpPayload::Dhcpv4(..)) => unreachable!(),
            _ => (),
        }

        match hdr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(hdr) => Self::Ipv4(Ipv4PacketRepr { hdr, payload }),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(hdr) => Self::Ipv6(Ipv6PacketRepr {
                hdr,
                #[cfg(feature = "proto-ipv6-hop-by-hop")]
                hop_by_hop: None,
                payload,
            }),
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IpPayload<'a> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4(Icmpv4Repr<'a>),
    #[cfg(feature = "proto-igmp")]
    Igmp(IgmpRepr),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6(Icmpv6Repr<'a>),
    #[cfg(feature = "socket-raw")]
    Raw(&'a [u8]),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    Udp(UdpRepr, &'a [u8]),
    #[cfg(feature = "socket-tcp")]
    Tcp(TcpRepr<'a>),
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4(UdpRepr, DhcpRepr<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn header(&self) -> IpRepr {
        match &self {
            #[cfg(feature = "proto-ipv4")]
            Self::Ipv4(Ipv4PacketRepr { hdr, .. }) => IpRepr::Ipv4(*hdr),
            #[cfg(feature = "proto-ipv6")]
            Self::Ipv6(Ipv6PacketRepr { hdr, .. }) => IpRepr::Ipv6(*hdr),
        }
    }

    pub fn set_header(&mut self, header: IpRepr) {
        match (self, header) {
            #[cfg(feature = "proto-ipv4")]
            (IpPacket::Ipv4(Ipv4PacketRepr { hdr, .. }), IpRepr::Ipv4(new_header)) => {
                *hdr = new_header
            }
            #[cfg(feature = "proto-ipv6")]
            (IpPacket::Ipv6(Ipv6PacketRepr { hdr, .. }), IpRepr::Ipv6(new_header)) => {
                *hdr = new_header
            }
            _ => unreachable!(),
        }
    }

    pub fn payload(&self) -> &IpPayload {
        match &self {
            #[cfg(feature = "proto-ipv4")]
            Self::Ipv4(Ipv4PacketRepr { payload, .. }) => payload,
            #[cfg(feature = "proto-ipv6")]
            Self::Ipv6(Ipv6PacketRepr { payload, .. }) => payload,
        }
    }

    pub fn payload_mut(&mut self) -> &'a mut IpPayload {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Self::Ipv4(Ipv4PacketRepr { payload, .. }) => payload,
            #[cfg(feature = "proto-ipv6")]
            Self::Ipv6(Ipv6PacketRepr { payload, .. }) => payload,
        }
    }

    pub fn emit(&self, mut buffer: &mut [u8], caps: &crate::phy::DeviceCapabilities) {
        let hdr = self.header();
        match hdr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ip) => {
                ip.emit(
                    &mut Ipv4Packet::new_unchecked(&mut buffer[..]),
                    &caps.checksum,
                );
                buffer = &mut buffer[ip.buffer_len()..];
            }
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ip) => {
                ip.emit(&mut Ipv6Packet::new_unchecked(&mut buffer[..]));
                buffer = &mut buffer[ip.buffer_len()..];
            }
        }
        match self.payload() {
            #[cfg(feature = "proto-ipv4")]
            IpPayload::Icmpv4(icmpv4_repr) => {
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(buffer), &caps.checksum)
            }
            #[cfg(feature = "proto-igmp")]
            IpPayload::Igmp(igmp_repr) => igmp_repr.emit(&mut IgmpPacket::new_unchecked(buffer)),
            #[cfg(feature = "proto-ipv6")]
            IpPayload::Icmpv6(icmpv6_repr) => icmpv6_repr.emit(
                &hdr.src_addr(),
                &hdr.dst_addr(),
                &mut Icmpv6Packet::new_unchecked(buffer),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-raw")]
            IpPayload::Raw(raw_packet) => buffer.copy_from_slice(raw_packet),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayload::Udp(udp_repr, inner_payload) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(buffer),
                &hdr.src_addr(),
                &hdr.dst_addr(),
                inner_payload.len(),
                |buf| buf.copy_from_slice(inner_payload),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-tcp")]
            IpPayload::Tcp(mut tcp_repr) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= hdr.header_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(buffer),
                    &hdr.src_addr(),
                    &hdr.dst_addr(),
                    &caps.checksum,
                );
            }
            #[cfg(feature = "socket-dhcpv4")]
            IpPayload::Dhcpv4(udp_repr, dhcp_repr) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(buffer),
                &hdr.src_addr(),
                &hdr.dst_addr(),
                dhcp_repr.buffer_len(),
                |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                &caps.checksum,
            ),
        }
    }
}
