use core::fmt;
use core::convert::From;

use {Error, Result};
use phy::ChecksumCapabilities;
#[cfg(feature = "proto-ipv4")]
use super::{Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use super::{Ipv6Address, Ipv6Cidr, Ipv6Packet, Ipv6Repr};

/// Internet protocol version.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    Unspecified,
    #[cfg(feature = "proto-ipv4")]
    Ipv4,
    #[cfg(feature = "proto-ipv6")]
    Ipv6,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// This function never returns `Ok(IpVersion::Unspecified)`; instead,
    /// unknown versions result in `Err(Error::Unrecognized)`.
    pub fn of_packet(data: &[u8]) -> Result<Version> {
        match data[0] >> 4 {
            #[cfg(feature = "proto-ipv4")]
            4 => Ok(Version::Ipv4),
            #[cfg(feature = "proto-ipv6")]
            6 => Ok(Version::Ipv6),
            _ => Err(Error::Unrecognized)
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Version::Unspecified => write!(f, "IPv?"),
            #[cfg(feature = "proto-ipv4")]
            &Version::Ipv4 => write!(f, "IPv4"),
            #[cfg(feature = "proto-ipv6")]
            &Version::Ipv6 => write!(f, "IPv6"),
            &Version::__Nonexhaustive => unreachable!()
        }
    }
}

enum_with_unknown! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Protocol::HopByHop    => write!(f, "Hop-by-Hop"),
            &Protocol::Icmp        => write!(f, "ICMP"),
            &Protocol::Tcp         => write!(f, "TCP"),
            &Protocol::Udp         => write!(f, "UDP"),
            &Protocol::Ipv6Route   => write!(f, "IPv6-Route"),
            &Protocol::Ipv6Frag    => write!(f, "IPv6-Frag"),
            &Protocol::Icmpv6      => write!(f, "ICMPv6"),
            &Protocol::Ipv6NoNxt   => write!(f, "IPv6-NoNxt"),
            &Protocol::Ipv6Opts    => write!(f, "IPv6-Opts"),
            &Protocol::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// An internetworking address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An unspecified address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Unspecified,
    /// An IPv4 address.
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Address),
    /// An IPv6 address.
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Address),
    #[doc(hidden)]
    __Nonexhaustive
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    #[cfg(feature = "proto-ipv4")]
    pub fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Create an address wrapping an IPv6 address with the given octets.
    #[cfg(feature = "proto-ipv6")]
    pub fn v6(a0: u16, a1: u16, a2: u16, a3: u16,
              a4: u16, a5: u16, a6: u16, a7: u16) -> Address {
        Address::Ipv6(Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            &Address::Unspecified     => false,
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr)      => addr.is_unicast(),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(addr)      => addr.is_unicast(),
            &Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            &Address::Unspecified     => false,
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr)      => addr.is_broadcast(),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(_)         => false,
            &Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            &Address::Unspecified     => true,
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr)      => addr.is_unspecified(),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(addr)      => addr.is_unspecified(),
            &Address::__Nonexhaustive => unreachable!()
        }
    }

    /// Return an unspecified address that has the same IP version as `self`.
    pub fn to_unspecified(&self) -> Address {
        match self {
            &Address::Unspecified     => Address::Unspecified,
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(_)         => Address::Ipv4(Ipv4Address::UNSPECIFIED),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(_)         => Address::Ipv6(Ipv6Address::UNSPECIFIED),
            &Address::__Nonexhaustive => unreachable!()
        }
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Unspecified
    }
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Address::Unspecified     => write!(f, "*"),
            #[cfg(feature = "proto-ipv4")]
            &Address::Ipv4(addr)      => write!(f, "{}", addr),
            #[cfg(feature = "proto-ipv6")]
            &Address::Ipv6(addr)      => write!(f, "{}", addr),
            &Address::__Nonexhaustive => unreachable!()
        }
    }
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Cidr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Cidr),
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given address is unspecified, or
    /// the given prefix length is invalid for the given address.
    pub fn new(addr: Address, prefix_len: u8) -> Cidr {
        match addr {
            #[cfg(feature = "proto-ipv4")]
            Address::Ipv4(addr) => Cidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)),
            #[cfg(feature = "proto-ipv6")]
            Address::Ipv6(addr) => Cidr::Ipv6(Ipv6Cidr::new(addr, prefix_len)),
            Address::Unspecified =>
                panic!("a CIDR block cannot be based on an unspecified address"),
            Address::__Nonexhaustive =>
                unreachable!()
        }
    }

    /// Return the IP address of this CIDR block.
    pub fn address(&self) -> Address {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Cidr::Ipv4(cidr)      => Address::Ipv4(cidr.address()),
            #[cfg(feature = "proto-ipv6")]
            &Cidr::Ipv6(cidr)      => Address::Ipv6(cidr.address()),
            &Cidr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the prefix length of this CIDR block.
    pub fn prefix_len(&self) -> u8 {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Cidr::Ipv4(cidr)      => cidr.prefix_len(),
            #[cfg(feature = "proto-ipv6")]
            &Cidr::Ipv6(cidr)      => cidr.prefix_len(),
            &Cidr::__Nonexhaustive => unreachable!()
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        match (self, addr) {
            #[cfg(feature = "proto-ipv4")]
            (&Cidr::Ipv4(ref cidr), &Address::Ipv4(ref addr)) =>
                cidr.contains_addr(addr),
            #[cfg(feature = "proto-ipv6")]
            (&Cidr::Ipv6(ref cidr), &Address::Ipv6(ref addr)) =>
                cidr.contains_addr(addr),
            #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv4"))]
            (&Cidr::Ipv4(_), &Address::Ipv6(_)) | (&Cidr::Ipv6(_), &Address::Ipv4(_)) =>
                false,
            (_, &Address::Unspecified) =>
                // a fully unspecified address covers both IPv4 and IPv6,
                // and no CIDR block can do that.
                false,
            (&Cidr::__Nonexhaustive, _) |
            (_, &Address::__Nonexhaustive) =>
                unreachable!()
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            #[cfg(feature = "proto-ipv4")]
            (&Cidr::Ipv4(ref cidr), &Cidr::Ipv4(ref other)) =>
                cidr.contains_subnet(other),
            #[cfg(feature = "proto-ipv6")]
            (&Cidr::Ipv6(ref cidr), &Cidr::Ipv6(ref other)) =>
                cidr.contains_subnet(other),
            #[cfg(all(feature = "proto-ipv6", feature = "proto-ipv4"))]
            (&Cidr::Ipv4(_), &Cidr::Ipv6(_)) | (&Cidr::Ipv6(_), &Cidr::Ipv4(_)) =>
                false,
            (&Cidr::__Nonexhaustive, _) |
            (_, &Cidr::__Nonexhaustive) =>
                unreachable!()
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "proto-ipv4")]
            &Cidr::Ipv4(cidr)      => write!(f, "{}", cidr),
            #[cfg(feature = "proto-ipv6")]
            &Cidr::Ipv6(cidr)      => write!(f, "{}", cidr),
            &Cidr::__Nonexhaustive => unreachable!()
        }
    }
}

/// An internet endpoint address.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16
}

impl Endpoint {
    /// An endpoint with unspecified address and port.
    pub const UNSPECIFIED: Endpoint = Endpoint { addr: Address::Unspecified, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr: addr, port: port }
    }

    /// Query whether the endpoint has a specified address and port.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl From<u16> for Endpoint {
    fn from(port: u16) -> Endpoint {
        Endpoint { addr: Address::Unspecified, port: port }
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint { addr: addr.into(), port: port }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains a concrete
/// high-level representation for some IP protocol version, or an unspecified representation,
/// which permits the `IpAddress::Unspecified` addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repr {
    Unspecified {
        src_addr:    Address,
        dst_addr:    Address,
        protocol:    Protocol,
        payload_len: usize,
        hop_limit:   u8
    },
    #[cfg(feature = "proto-ipv4")]
    Ipv4(Ipv4Repr),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(Ipv6Repr),
    #[doc(hidden)]
    __Nonexhaustive
}

#[cfg(feature = "proto-ipv4")]
impl From<Ipv4Repr> for Repr {
    fn from(repr: Ipv4Repr) -> Repr {
        Repr::Ipv4(repr)
    }
}

#[cfg(feature = "proto-ipv6")]
impl From<Ipv6Repr> for Repr {
    fn from(repr: Ipv6Repr) -> Repr {
        Repr::Ipv6(repr)
    }
}

impl Repr {
    /// Return the protocol version.
    pub fn version(&self) -> Version {
        match self {
            &Repr::Unspecified { .. } => Version::Unspecified,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(_) => Version::Ipv4,
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(_) => Version::Ipv6,
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the source address.
    pub fn src_addr(&self) -> Address {
        match self {
            &Repr::Unspecified { src_addr, .. } => src_addr,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) => Address::Ipv6(repr.src_addr),
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the destination address.
    pub fn dst_addr(&self) -> Address {
        match self {
            &Repr::Unspecified { dst_addr, .. } => dst_addr,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) => Address::Ipv6(repr.dst_addr),
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the protocol.
    pub fn protocol(&self) -> Protocol {
        match self {
            &Repr::Unspecified { protocol, .. } => protocol,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) => repr.protocol,
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) => repr.next_header,
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the payload length.
    pub fn payload_len(&self) -> usize {
        match self {
            &Repr::Unspecified { payload_len, .. } => payload_len,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) => repr.payload_len,
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) => repr.payload_len,
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Set the payload length.
    pub fn set_payload_len(&mut self, length: usize) {
        match self {
            &mut Repr::Unspecified { ref mut payload_len, .. } =>
                *payload_len = length,
            #[cfg(feature = "proto-ipv4")]
            &mut Repr::Ipv4(Ipv4Repr { ref mut payload_len, .. }) =>
                *payload_len = length,
            #[cfg(feature = "proto-ipv6")]
            &mut Repr::Ipv6(Ipv6Repr { ref mut payload_len, .. }) =>
                *payload_len = length,
            &mut Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the TTL value.
    pub fn hop_limit(&self) -> u8 {
        match self {
            &Repr::Unspecified { hop_limit, .. }    => hop_limit,
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(Ipv4Repr { hop_limit, .. }) => hop_limit,
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(Ipv6Repr { hop_limit, ..})  => hop_limit,
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Convert an unspecified representation into a concrete one, or return
    /// `Err(Error::Unaddressable)` if not possible.
    ///
    /// # Panics
    /// This function panics if source and destination addresses belong to different families,
    /// or the destination address is unspecified, since this indicates a logic error.
    pub fn lower(&self, fallback_src_addrs: &[Cidr]) -> Result<Repr> {
        macro_rules! resolve_unspecified {
            ($reprty:path, $ipty:path, $iprepr:expr, $fallbacks:expr) => {
                if $iprepr.src_addr.is_unspecified() {
                    for cidr in $fallbacks {
                        match cidr.address() {
                            $ipty(addr) => {
                                $iprepr.src_addr = addr;
                                return Ok($reprty($iprepr));
                            },
                            _ => ()
                        }
                    }
                    Err(Error::Unaddressable)
                } else {
                    Ok($reprty($iprepr))
                }
            }
        }

        match self {
            #[cfg(feature = "proto-ipv4")]
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv4(_),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv4(src_ipv4_addr) = src_addr {
                    Some(src_ipv4_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv4(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Ok(Repr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr.ok_or(Error::Unaddressable)?,
                    dst_addr, protocol, payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv6")]
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Unspecified,
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } |
            &Repr::Unspecified {
                src_addr: src_addr @ Address::Ipv6(_),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } if src_addr.is_unspecified() => {
                let mut src_addr = if let Address::Ipv6(src_ipv6_addr) = src_addr {
                    Some(src_ipv6_addr)
                } else {
                    None
                };
                for cidr in fallback_src_addrs {
                    if let Address::Ipv6(addr) = cidr.address() {
                        src_addr = Some(addr);
                        break;
                    }
                }
                Ok(Repr::Ipv6(Ipv6Repr {
                    src_addr:    src_addr.ok_or(Error::Unaddressable)?,
                    next_header: protocol,
                    dst_addr, payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv4")]
            &Repr::Unspecified {
                src_addr: Address::Ipv4(src_addr),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Ok(Repr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    protocol:    protocol,
                    payload_len: payload_len, hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv6")]
            &Repr::Unspecified {
                src_addr: Address::Ipv6(src_addr),
                dst_addr: Address::Ipv6(dst_addr),
                protocol, payload_len, hop_limit
            } => {
                Ok(Repr::Ipv6(Ipv6Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    next_header: protocol,
                    payload_len: payload_len,
                    hop_limit:   hop_limit
                }))
            }

            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(mut repr) =>
                resolve_unspecified!(Repr::Ipv4, Address::Ipv4, repr, fallback_src_addrs),

            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(mut repr) =>
                resolve_unspecified!(Repr::Ipv6, Address::Ipv6, repr, fallback_src_addrs),

            &Repr::Unspecified { .. } =>
                panic!("source and destination IP address families do not match"),

            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::Unspecified { .. } =>
                panic!("unspecified IP representation"),
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) =>
                repr.buffer_len(),
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) =>
                repr.buffer_len(),
            &Repr::__Nonexhaustive =>
                unreachable!()
        }
    }

    /// Emit this high-level representation into a buffer.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T, _checksum_caps: &ChecksumCapabilities) {
        match self {
            &Repr::Unspecified { .. } =>
                panic!("unspecified IP representation"),
            #[cfg(feature = "proto-ipv4")]
            &Repr::Ipv4(repr) =>
                repr.emit(&mut Ipv4Packet::new(buffer), &_checksum_caps),
            #[cfg(feature = "proto-ipv6")]
            &Repr::Ipv6(repr) =>
                repr.emit(&mut Ipv6Packet::new(buffer)),
            &Repr::__Nonexhaustive =>
                unreachable!()
        }
    }

    /// Return the total length of a packet that will be emitted from this
    /// high-level representation.
    ///
    /// This is the same as `repr.buffer_len() + repr.payload_len()`.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn total_len(&self) -> usize {
        self.buffer_len() + self.payload_len()
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }
        
        // Add the last remaining odd byte, if any.
        if let Some(&value) = data.first() {
            accum += (value as u32) << 8;
        }
        
        propagate_carries(accum)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    /// Compute an IP pseudo header checksum.
    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address,
                         protocol: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&Address::Ipv4(src_addr), &Address::Ipv4(dst_addr)) => {
                let mut proto_len = [0u8; 4];
                proto_len[1] = protocol.into();
                NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            },

            #[cfg(feature = "proto-ipv6")]
            (&Address::Ipv6(src_addr), &Address::Ipv6(dst_addr)) => {
                let mut proto_len = [0u8; 8];
                proto_len[7] = protocol.into();
                NetworkEndian::write_u32(&mut proto_len[0..4], length);
                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            }

            _ => panic!("Unexpected pseudo header addresses: {}, {}",
                        src_addr, dst_addr)
        }
    }

    // We use this in pretty printer implementations.
    pub(crate) fn format_checksum(f: &mut fmt::Formatter, correct: bool) -> fmt::Result {
        if !correct {
            write!(f, " (checksum incorrect)")
        } else {
            Ok(())
        }
    }
}

use super::pretty_print::PrettyIndent;

pub fn pretty_print_ip_payload<T: Into<Repr>>(f: &mut fmt::Formatter, indent: &mut PrettyIndent,
                                              ip_repr: T, payload: &[u8]) -> fmt::Result {
    #[cfg(feature = "proto-ipv4")]
    use wire::Icmpv4Packet;
    #[cfg(feature = "proto-ipv4")]
    use super::pretty_print::PrettyPrint;
    use wire::{TcpPacket, TcpRepr, UdpPacket, UdpRepr};
    use wire::ip::checksum::format_checksum;

    let checksum_caps = ChecksumCapabilities::ignored();
    let repr = ip_repr.into();
    match repr.protocol() {
        #[cfg(feature = "proto-ipv4")]
        Protocol::Icmp => {
            indent.increase(f)?;
            Icmpv4Packet::<&[u8]>::pretty_print(&payload.as_ref(), f, indent)
        }
        Protocol::Udp => {
            indent.increase(f)?;
            match UdpPacket::<&[u8]>::new_checked(payload.as_ref()) {
                Err(err) => write!(f, "{}({})", indent, err),
                Ok(udp_packet) => {
                    match UdpRepr::parse(&udp_packet, &repr.src_addr(),
                                         &repr.dst_addr(), &checksum_caps) {
                        Err(err) => write!(f, "{}{} ({})", indent, udp_packet, err),
                        Ok(udp_repr) => {
                            write!(f, "{}{}", indent, udp_repr)?;
                            let valid = udp_packet.verify_checksum(&repr.src_addr(),
                                                                   &repr.dst_addr());
                            format_checksum(f, valid)
                        }
                    }
                }
            }
        }
        Protocol::Tcp => {
            indent.increase(f)?;
            match TcpPacket::<&[u8]>::new_checked(payload.as_ref()) {
                Err(err) => write!(f, "{}({})", indent, err),
                Ok(tcp_packet) => {
                    match TcpRepr::parse(&tcp_packet, &repr.src_addr(),
                                         &repr.dst_addr(), &checksum_caps) {
                        Err(err) => write!(f, "{}{} ({})", indent, tcp_packet, err),
                        Ok(tcp_repr) => {
                            write!(f, "{}{}", indent, tcp_repr)?;
                            let valid = tcp_packet.verify_checksum(&repr.src_addr(),
                                                                   &repr.dst_addr());
                            format_checksum(f, valid)
                        }
                    }
                }
            }
        }
        _ => Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(unused)]

    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_1: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 1]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_2: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 2]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_3: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 3]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_IP_ADDR_4: IpAddress = IpAddress::Ipv6(Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0, 0, 0, 0, 0, 4]));
    #[cfg(feature = "proto-ipv6")]
    pub(crate) const MOCK_UNSPECIFIED: IpAddress = IpAddress::Ipv6(Ipv6Address::UNSPECIFIED);

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_1: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_2: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 2]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_3: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 3]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_IP_ADDR_4: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 4]));
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    pub(crate) const MOCK_UNSPECIFIED: IpAddress = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);


    use super::*;
    use wire::{IpAddress, IpProtocol,IpCidr};
    #[cfg(feature = "proto-ipv4")]
    use wire::{Ipv4Address, Ipv4Repr};

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn ip_repr_lower() {
        let ip_addr_a = Ipv4Address::new(1, 2, 3, 4);
        let ip_addr_b = Ipv4Address::new(5, 6, 7, 8);
        let proto = IpProtocol::Icmp;
        let payload_len = 10;

        assert_eq!(
            Repr::Unspecified{
                src_addr:  IpAddress::Ipv4(ip_addr_a),
                dst_addr:  IpAddress::Ipv4(ip_addr_b),
                protocol:  proto,
                hop_limit: 0x2a,
                payload_len,
            }.lower(&[]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 0x2a,
                payload_len
            }))
        );

        assert_eq!(
            Repr::Unspecified{
                src_addr:  IpAddress::Unspecified,
                dst_addr:  IpAddress::Ipv4(ip_addr_b),
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }.lower(&[]),
            Err(Error::Unaddressable)
        );

        assert_eq!(
            Repr::Unspecified{
                src_addr:  IpAddress::Unspecified,
                dst_addr:  IpAddress::Ipv4(ip_addr_b),
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }.lower(&[IpCidr::new(IpAddress::Ipv4(ip_addr_a), 24)]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }))
        );

        assert_eq!(
            Repr::Unspecified{
                src_addr:  IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
                dst_addr:  IpAddress::Ipv4(ip_addr_b),
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }.lower(&[IpCidr::new(IpAddress::Ipv4(ip_addr_a), 24)]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }))
        );

        assert_eq!(
            Repr::Unspecified{
                src_addr:  IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
                dst_addr:  IpAddress::Ipv4(ip_addr_b),
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }.lower(&[]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  Ipv4Address::UNSPECIFIED,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }))
        );

        assert_eq!(
            Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 255,
                payload_len
            }).lower(&[]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 255,
                payload_len
            }))
        );

        assert_eq!(
            Repr::Ipv4(Ipv4Repr{
                src_addr:  Ipv4Address::UNSPECIFIED,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 255,
                payload_len
            }).lower(&[]),
            Err(Error::Unaddressable)
        );

        assert_eq!(
            Repr::Ipv4(Ipv4Repr{
                src_addr:  Ipv4Address::UNSPECIFIED,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }).lower(&[IpCidr::new(IpAddress::Ipv4(ip_addr_a), 24)]),
            Ok(Repr::Ipv4(Ipv4Repr{
                src_addr:  ip_addr_a,
                dst_addr:  ip_addr_b,
                protocol:  proto,
                hop_limit: 64,
                payload_len
            }))
        );
    }

    #[test]
    fn endpoint_unspecified() {
        assert!(!Endpoint::UNSPECIFIED.is_specified());
    }
}
