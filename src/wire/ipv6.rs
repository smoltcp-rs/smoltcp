#![deny(missing_docs)]

use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use crate::{Error, Result};
use crate::wire::ip::pretty_print_ip_payload;
#[cfg(feature = "proto-ipv4")]
use crate::wire::ipv4;

pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv6. See [RFC 8200 § 5].
///
/// [RFC 8200 § 5]: https://tools.ietf.org/html/rfc8200#section-5
pub const MIN_MTU: usize = 1280;

/// A sixteen-octet IPv6 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 16]);

impl Address {
    /// The [unspecified address].
    ///
    /// [unspecified address]: https://tools.ietf.org/html/rfc4291#section-2.5.2
    pub const UNSPECIFIED: Address = Address([0x00; 16]);

    /// The link-local [all routers multicast address].
    ///
    /// [all routers multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const LINK_LOCAL_ALL_NODES: Address =
        Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// The link-local [all nodes multicast address].
    ///
    /// [all nodes multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const LINK_LOCAL_ALL_ROUTERS: Address =
        Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);

    /// The [loopback address].
    ///
    /// [loopback address]: https://tools.ietf.org/html/rfc4291#section-2.5.3
    pub const LOOPBACK: Address =
        Address([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// Construct an IPv6 address from parts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(a0: u16, a1: u16, a2: u16, a3: u16,
               a4: u16, a5: u16, a6: u16, a7: u16) -> Address {
        let mut addr = [0u8; 16];
        NetworkEndian::write_u16(&mut addr[0..2], a0);
        NetworkEndian::write_u16(&mut addr[2..4], a1);
        NetworkEndian::write_u16(&mut addr[4..6], a2);
        NetworkEndian::write_u16(&mut addr[6..8], a3);
        NetworkEndian::write_u16(&mut addr[8..10], a4);
        NetworkEndian::write_u16(&mut addr[10..12], a5);
        NetworkEndian::write_u16(&mut addr[12..14], a6);
        NetworkEndian::write_u16(&mut addr[14..16], a7);
        Address(addr)
    }

    /// Construct an IPv6 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not sixteen octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Construct an IPv6 address from a sequence of words, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 words long.
    pub fn from_parts(data: &[u16]) -> Address {
        assert!(data.len() >= 8);
        let mut bytes = [0; 16];
        for (word_idx, chunk) in bytes.chunks_mut(2).enumerate() {
            NetworkEndian::write_u16(chunk, data[word_idx]);
        }
        Address(bytes)
    }

    /// Write a IPv6 address to the given slice.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 words long.
    pub fn write_parts(&self, data: &mut [u16]) {
        assert!(data.len() >= 8);
        for (i, chunk) in self.0.chunks(2).enumerate() {
            data[i] = NetworkEndian::read_u16(chunk);
        }
    }

    /// Return an IPv6 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the IPv6 address is an [unicast address].
    ///
    /// [unicast address]: https://tools.ietf.org/html/rfc4291#section-2.5
    pub fn is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    /// Query whether the IPv6 address is a [multicast address].
    ///
    /// [multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Query whether the IPv6 address is the [unspecified address].
    ///
    /// [unspecified address]: https://tools.ietf.org/html/rfc4291#section-2.5.2
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0x00; 16]
    }

    /// Query whether the IPv6 address is in the [link-local] scope.
    ///
    /// [link-local]: https://tools.ietf.org/html/rfc4291#section-2.5.6
    pub fn is_link_local(&self) -> bool {
        self.0[0..8] == [0xfe, 0x80, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00]
    }

    /// Query whether the IPv6 address is the [loopback address].
    ///
    /// [loopback address]: https://tools.ietf.org/html/rfc4291#section-2.5.3
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    /// Query whether the IPv6 address is an [IPv4 mapped IPv6 address].
    ///
    /// [IPv4 mapped IPv6 address]: https://tools.ietf.org/html/rfc4291#section-2.5.5.2
    pub fn is_ipv4_mapped(&self) -> bool {
        self.0[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
    }

    #[cfg(feature = "proto-ipv4")]
    /// Convert an IPv4 mapped IPv6 address to an IPv4 address.
    pub fn as_ipv4(&self) -> Option<ipv4::Address> {
        if self.is_ipv4_mapped() {
            Some(ipv4::Address::new(self.0[12], self.0[13], self.0[14], self.0[15]))
        } else {
            None
        }
    }

    /// Helper function used to mask an addres given a prefix.
    ///
    /// # Panics
    /// This function panics if `mask` is greater than 128.
    pub(super) fn mask(&self, mask: u8) -> [u8; 16] {
        assert!(mask <= 128);
        let mut bytes = [0u8; 16];
        let idx = (mask as usize) / 8;
        let modulus = (mask as usize) % 8;
        let (first, second) = self.0.split_at(idx);
        bytes[0..idx].copy_from_slice(&first);
        if idx < 16 {
            let part = second[0];
            bytes[idx] = part & (!(0xff >> modulus) as u8);
        }
        bytes
    }

    /// The solicited node for the given unicast address.
    ///
    /// # Panics
    /// This function panics if the given address is not
    /// unicast.
    pub fn solicited_node(&self) -> Address {
        assert!(self.is_unicast());
        let mut bytes = [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes[14..].copy_from_slice(&self.0[14..]);
        Address(bytes)
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv6Addr> for Address {
    fn from(x: ::std::net::Ipv6Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv6Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv6Addr {
        x.into()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_ipv4_mapped() {
            return write!(f, "::ffff:{}.{}.{}.{}", self.0[12], self.0[13], self.0[14], self.0[15])
        }

        // The string representation of an IPv6 address should
        // collapse a series of 16 bit sections that evaluate
        // to 0 to "::"
        //
        // See https://tools.ietf.org/html/rfc4291#section-2.2
        // for details.
        enum State {
            Head,
            HeadBody,
            Tail,
            TailBody
        }
        let mut words = [0u16; 8];
        self.write_parts(&mut words);
        let mut state = State::Head;
        for word in words.iter() {
            state = match (*word, &state) {
                // Once a u16 equal to zero write a double colon and
                // skip to the next non-zero u16.
                (0, &State::Head) | (0, &State::HeadBody) => {
                    write!(f, "::")?;
                    State::Tail
                },
                // Continue iterating without writing any characters until
                // we hit anothing non-zero value.
                (0, &State::Tail) => State::Tail,
                // When the state is Head or Tail write a u16 in hexadecimal
                // without the leading colon if the value is not 0.
                (_, &State::Head) => {
                    write!(f, "{:x}", word)?;
                    State::HeadBody
                },
                (_, &State::Tail) => {
                    write!(f, "{:x}", word)?;
                    State::TailBody
                },
                // Write the u16 with a leading colon when parsing a value
                // that isn't the first in a section
                (_, &State::HeadBody) | (_, &State::TailBody) => {
                    write!(f, ":{:x}", word)?;
                    state
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "proto-ipv4")]
/// Convert the given IPv4 address into a IPv4-mapped IPv6 address
impl From<ipv4::Address> for Address {
    fn from(address: ipv4::Address) -> Self {
        let octets = address.0;
        Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                octets[0], octets[1], octets[2], octets[3]])
    }
}

/// A specification of an IPv6 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Cidr {
    address:    Address,
    prefix_len: u8,
}

impl Cidr {
    /// The [solicited node prefix].
    ///
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Cidr =
        Cidr {
            address: Address([0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00]),
            prefix_len: 104
        };

    /// Create an IPv6 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 128.
    pub fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 128);
        Cidr { address, prefix_len }
    }

    /// Return the address of this IPv6 CIDR block.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv6 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Query whether the subnetwork described by this IPv6 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        // right shift by 128 is not legal
        if self.prefix_len == 0 { return true }

        let shift = 128 - self.prefix_len;
        self.address.mask(shift) == addr.mask(shift)
    }

    /// Query whether the subnetwork described by this IPV6 CIDR block contains
    /// the subnetwork described by the given IPv6 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// A read/write wrapper around an Internet Protocol version 6 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

// Ranges and constants describing the IPv6 header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc2460#section-3 for details.
mod field {
    use crate::wire::field::*;
    // 4-bit version number, 8-bit traffic class, and the
    // 20-bit flow label.
    pub const VER_TC_FLOW: Field = 0..4;
    // 16-bit value representing the length of the payload.
    // Note: Options are included in this length.
    pub const LENGTH:      Field = 4..6;
    // 8-bit value identifying the type of header following this
    // one. Note: The same numbers are used in IPv4.
    pub const NXT_HDR:     usize = 6;
    // 8-bit value decremented by each node that forwards this
    // packet. The packet is discarded when the value is 0.
    pub const HOP_LIMIT:   usize = 7;
    // IPv6 address of the source node.
    pub const SRC_ADDR:    Field = 8..24;
    // IPv6 address of the destination node.
    pub const DST_ADDR:    Field = 24..40;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with an IPv6 packet structure.
    #[inline]
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_payload_len].
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end || len < self.total_len() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the header length.
    #[inline]
    pub fn header_len(&self) -> usize {
        // This is not a strictly necessary function, but it makes
        // code more readable.
        field::DST_ADDR.end
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_TC_FLOW.start] >> 4
    }

    /// Return the traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        let data = self.buffer.as_ref();
        ((NetworkEndian::read_u16(&data[0..2]) & 0x0ff0) >> 4) as u8
    }

    /// Return the flow label field.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u24(&data[1..4]) & 0x000fffff
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the payload length added to the known header length.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.payload_len() as usize
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::NXT_HDR])
    }

    /// Return the hop limit field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HOP_LIMIT]
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SRC_ADDR])
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DST_ADDR])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        let range = self.header_len()..self.total_len();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // Make sure to retain the lower order bits which contain
        // the higher order bits of the traffic class
        data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the traffic class field.
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // Put the higher order 4-bits of value in the lower order
        // 4-bits of the first byte
        data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
        // Put the lower order 4-bits of value in the higher order
        // 4-bits of the second byte
        data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the flow label field.
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        // Retain the lower order 4-bits of the traffic class
        let raw = (((data[1] & 0xf0) as u32) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut data[1..4], raw);
    }

    /// Set the payload length field.
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value);
    }

    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// Set the hop limit field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HOP_LIMIT] = value;
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(value.as_bytes());
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(value.as_bytes());
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..self.total_len();
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv6 ({})", err)?;
                Ok(())
            }
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Protocol version 6 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// IPv6 address of the source node.
    pub src_addr:    Address,
    /// IPv6 address of the destination node.
    pub dst_addr:    Address,
    /// Protocol contained in the next header.
    pub next_header: Protocol,
    /// Length of the payload including the extension headers.
    pub payload_len: usize,
    /// The 8-bit hop limit field.
    pub hop_limit:   u8
}

impl Repr {
    /// Parse an Internet Protocol version 6 packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr> {
        // Ensure basic accessors will work
        packet.check_len()?;
        if packet.version() != 6 { return Err(Error::Malformed); }
        Ok(Repr {
            src_addr:    packet.src_addr(),
            dst_addr:    packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len: packet.payload_len() as usize,
            hop_limit:   packet.hop_limit()
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // This function is not strictly necessary, but it can make client code more readable.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 6 packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        // Make no assumptions about the original state of the packet buffer.
        // Make sure to set every byte.
        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_len(self.payload_len as u16);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv6 src={} dst={} nxt_hdr={} hop_limit={}",
               self.src_addr, self.dst_addr, self.next_header, self.hop_limit)
    }
}

use crate::wire::pretty_print::{PrettyPrint, PrettyIndent};

// TODO: This is very similar to the implementation for IPv4. Make
// a way to have less copy and pasted code here.
impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &dyn AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        let (ip_repr, payload) = match Packet::new_checked(buffer) {
            Err(err) => return write!(f, "{}({})", indent, err),
            Ok(ip_packet) => {
                match Repr::parse(&ip_packet) {
                    Err(_) => return Ok(()),
                    Ok(ip_repr) => {
                        write!(f, "{}{}", indent, ip_repr)?;
                        (ip_repr, ip_packet.payload())
                    }
                }
            }
        };

        pretty_print_ip_payload(f, indent, ip_repr, payload)
    }
}

#[cfg(test)]
mod test {
    use crate::Error;
    use super::{Address, Cidr};
    use super::{Packet, Protocol, Repr};
    use crate::wire::pretty_print::{PrettyPrinter};

    #[cfg(feature = "proto-ipv4")]
    use crate::wire::ipv4::Address as Ipv4Address;

    static LINK_LOCAL_ADDR: Address = Address([0xfe, 0x80, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x01]);
    #[test]
    fn test_basic_multicast() {
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_unspecified());
        assert!(Address::LINK_LOCAL_ALL_ROUTERS.is_multicast());
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_link_local());
        assert!(!Address::LINK_LOCAL_ALL_ROUTERS.is_loopback());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_unspecified());
        assert!(Address::LINK_LOCAL_ALL_NODES.is_multicast());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_link_local());
        assert!(!Address::LINK_LOCAL_ALL_NODES.is_loopback());
    }

    #[test]
    fn test_basic_link_local() {
        assert!(!LINK_LOCAL_ADDR.is_unspecified());
        assert!(!LINK_LOCAL_ADDR.is_multicast());
        assert!(LINK_LOCAL_ADDR.is_link_local());
        assert!(!LINK_LOCAL_ADDR.is_loopback());
    }

    #[test]
    fn test_basic_loopback() {
        assert!(!Address::LOOPBACK.is_unspecified());
        assert!(!Address::LOOPBACK.is_multicast());
        assert!(!Address::LOOPBACK.is_link_local());
        assert!(Address::LOOPBACK.is_loopback());
    }

    #[test]
    fn test_address_format() {
        assert_eq!("ff02::1",
                   format!("{}", Address::LINK_LOCAL_ALL_NODES));
        assert_eq!("fe80::1",
                   format!("{}", LINK_LOCAL_ADDR));
        assert_eq!("fe80::7f00:0:1",
                   format!("{}", Address::new(0xfe80, 0, 0, 0, 0, 0x7f00, 0x0000, 0x0001)));
        assert_eq!("::",
                   format!("{}", Address::UNSPECIFIED));
        assert_eq!("::1",
                   format!("{}", Address::LOOPBACK));

        #[cfg(feature = "proto-ipv4")]
        assert_eq!("::ffff:192.168.1.1",
                   format!("{}", Address::from(Ipv4Address::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_new() {
        assert_eq!(Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                   Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
                   Address::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(Address::new(0, 0, 0, 0, 0, 0, 0, 1),
                   Address::LOOPBACK);
        assert_eq!(Address::new(0, 0, 0, 0, 0, 0, 0, 0),
                   Address::UNSPECIFIED);
        assert_eq!(Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                   LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_from_parts() {
        assert_eq!(Address::from_parts(&[0xff02, 0, 0, 0, 0, 0, 0, 1]),
                   Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(Address::from_parts(&[0xff02, 0, 0, 0, 0, 0, 0, 2]),
                   Address::LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(Address::from_parts(&[0, 0, 0, 0, 0, 0, 0, 1]),
                   Address::LOOPBACK);
        assert_eq!(Address::from_parts(&[0, 0, 0, 0, 0, 0, 0, 0]),
                   Address::UNSPECIFIED);
        assert_eq!(Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 1]),
                   LINK_LOCAL_ADDR);
    }

    #[test]
    fn test_write_parts() {
        let mut bytes = [0u16; 8];
        {
            Address::LOOPBACK.write_parts(&mut bytes);
            assert_eq!(Address::LOOPBACK, Address::from_parts(&bytes));
        }
        {
            Address::LINK_LOCAL_ALL_ROUTERS.write_parts(&mut bytes);
            assert_eq!(Address::LINK_LOCAL_ALL_ROUTERS, Address::from_parts(&bytes));
        }
        {
            LINK_LOCAL_ADDR.write_parts(&mut bytes);
            assert_eq!(LINK_LOCAL_ADDR, Address::from_parts(&bytes));
        }
    }

    #[test]
    fn test_mask() {
        let addr = Address::new(0x0123, 0x4567, 0x89ab, 0, 0, 0, 0, 1);
        assert_eq!(addr.mask(11), [0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(15), [0x01, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(26), [0x01, 0x23, 0x45, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(128), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(addr.mask(127), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_is_ipv4_mapped() {
        assert_eq!(false, Address::UNSPECIFIED.is_ipv4_mapped());
        assert_eq!(true, Address::from(Ipv4Address::new(192, 168, 1, 1)).is_ipv4_mapped());
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_as_ipv4() {
        assert_eq!(None, Address::UNSPECIFIED.as_ipv4());

        let ipv4 = Ipv4Address::new(192, 168, 1, 1);
        assert_eq!(Some(ipv4), Address::from(ipv4).as_ipv4());
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn test_from_ipv4_address() {
        assert_eq!(Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]),
            Address::from(Ipv4Address::new(192, 168, 1, 1)));
        assert_eq!(Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 222, 1, 41, 90]),
            Address::from(Ipv4Address::new(222, 1, 41, 90)));
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(LINK_LOCAL_ADDR, 64);

        let inside_subnet = [
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]
        ];

        let outside_subnet = [
            [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        ];

        let subnets = [
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             65),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
             128),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78],
             96)
        ];

        let not_subnets = [
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             63),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             64),
            ([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
             65),
            ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
             128)
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_bytes(a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets.iter().map(
            |&(a, p)| Cidr::new(Address(a), p)) {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets.iter().map(
            |&(a, p)| Cidr::new(Address(a), p)) {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(LINK_LOCAL_ADDR, 0);
        assert!(cidr_without_prefix.contains_addr(&Address::LOOPBACK));
    }

    #[test]
    #[should_panic(expected = "length")]
    fn test_from_bytes_too_long() {
        let _ = Address::from_bytes(&[0u8; 15]);
    }

    #[test]
    #[should_panic(expected = "data.len() >= 8")]
    fn test_from_parts_too_long() {
        let _ = Address::from_parts(&[0u16; 7]);
    }

    static REPR_PACKET_BYTES: [u8; 52] = [0x60, 0x00, 0x00, 0x00,
                                          0x00, 0x0c, 0x11, 0x40,
                                          0xfe, 0x80, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01,
                                          0xff, 0x02, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x01,
                                          0x00, 0x01, 0x00, 0x02,
                                          0x00, 0x0c, 0x02, 0x4e,
                                          0xff, 0xff, 0xff, 0xff];
    static REPR_PAYLOAD_BYTES: [u8; 12] = [0x00, 0x01, 0x00, 0x02,
                                           0x00, 0x0c, 0x02, 0x4e,
                                           0xff, 0xff, 0xff, 0xff];

    fn packet_repr() -> Repr {
        Repr {
            src_addr:    Address([0xfe, 0x80, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x01]),
            dst_addr:    Address::LINK_LOCAL_ALL_NODES,
            next_header: Protocol::Udp,
            payload_len: 12,
            hop_limit:   64
        }
    }

    #[test]
    fn test_packet_deconstruction() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0);
        assert_eq!(packet.flow_label(), 0);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(packet.payload_len() as usize, REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Address([0xfe, 0x80, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x01]));
        assert_eq!(packet.dst_addr(), Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let mut bytes = [0xff; 52];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        // Version, Traffic Class, and Flow Label are not
        // byte aligned. make sure the setters and getters
        // do not interfere with each other.
        packet.set_version(6);
        assert_eq!(packet.version(), 6);
        packet.set_traffic_class(0x99);
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0x99);
        packet.set_flow_label(0x54321);
        assert_eq!(packet.traffic_class(), 0x99);
        assert_eq!(packet.flow_label(), 0x54321);
        packet.set_payload_len(0xc);
        packet.set_next_header(Protocol::Udp);
        packet.set_hop_limit(0xfe);
        packet.set_src_addr(Address::LINK_LOCAL_ALL_ROUTERS);
        packet.set_dst_addr(Address::LINK_LOCAL_ALL_NODES);
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        let mut expected_bytes = [
            0x69, 0x95, 0x43, 0x21, 0x00, 0x0c, 0x11, 0xfe,
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];
        let start = expected_bytes.len() - REPR_PAYLOAD_BYTES.len();
        expected_bytes[start..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(&packet.into_inner()[..], &expected_bytes[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(Packet::new_unchecked(&bytes).payload().len(),
                   REPR_PAYLOAD_BYTES.len());
        assert_eq!(Packet::new_unchecked(&mut bytes).payload_mut().len(),
                   REPR_PAYLOAD_BYTES.len());
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_payload_len(0x80);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(),
                   Error::Truncated);
    }

    #[test]
    fn test_repr_parse_valid() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_repr_parse_bad_version() {
        let mut bytes = vec![0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(4);
        packet.set_payload_len(0);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error::Malformed));
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = vec![0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(39);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error::Truncated));
    }

    #[test]
    fn test_repr_parse_smaller_than_payload() {
        let mut bytes = vec![0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(1);
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(Repr::parse(&packet), Err(Error::Truncated));
    }

    #[test]
    fn test_basic_repr_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xff; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet);
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&packet.into_inner()[..], &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_pretty_print() {
        assert_eq!(format!("{}", PrettyPrinter::<Packet<&'static [u8]>>::new("\n", &&REPR_PACKET_BYTES[..])),
                   "\nIPv6 src=fe80::1 dst=ff02::1 nxt_hdr=UDP hop_limit=64\n \\ UDP src=1 dst=2 len=4");
    }
}
