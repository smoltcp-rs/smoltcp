use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::ip::checksum;
use super::IpAddress;

pub use super::IpProtocol as Protocol;

/// A four-octet IPv4 address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 4]);

impl Address {
    // pub const UNSPECIFIED: Address = Address([0x00; 4]);
    // pub const BROADCAST:   Address = Address([0xff; 4]);

    /// Construct an IPv4 address from parts.
    pub fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address([a0, a1, a2, a3])
    }

    /// Construct an IPv4 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not four octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() ||
          self.is_multicast() ||
          self.is_unspecified())
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; 4]
    }

    /// Query whether the address is a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query whether the address falls into the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    /// Query whether the address falls into the "loopback" range.
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    use wire::field::*;

    pub const VER_IHL:  usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH:   Field = 2..4;
    pub const IDENT:    Field = 4..6;
    pub const FLG_OFF:  Field = 6..8;
    pub const TTL:      usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Wrap a buffer with an IPv4 packet. Returns an error if the buffer
    /// is too small to contain one.
    pub fn new(buffer: T) -> Result<Packet<T>, Error> {
        let len = buffer.as_ref().len();
        if len < field::DST_ADDR.end {
            Err(Error::Truncated)
        } else {
            let packet = Packet { buffer: buffer };
            if len < packet.header_len() as usize {
                Err(Error::Truncated)
            } else {
                Ok(packet)
            }
        }
    }

    /// Consumes the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline]
    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline]
    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the protocol field.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
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

    /// Validate the header checksum.
    pub fn verify_checksum(&self) -> bool {
        let data = self.buffer.as_ref();
        checksum::data(&data[..self.header_len() as usize]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[range..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_ttl(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_addr:    Address,
    pub dst_addr:    Address,
    pub protocol:    Protocol,
    pub payload_len: usize
}

impl Repr {
    /// Parse an Internet Protocol version 4 packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr, Error> {
        // Version 4 is expected.
        if packet.version() != 4 { return Err(Error::Malformed) }
        // Valid checksum is expected.
        if !packet.verify_checksum() { return Err(Error::Checksum) }
        // We do not support any IP options.
        if packet.header_len() > 20 { return Err(Error::Unrecognized) }
        // We do not support fragmentation.
        if packet.more_frags() || packet.frag_offset() != 0 { return Err(Error::Fragmented) }
        // Since the packet is not fragmented, it must include the entire payload.
        let payload_len = packet.total_len() as usize - packet.header_len() as usize;
        if packet.payload().len() < payload_len  { return Err(Error::Truncated) }

        // All DSCP values are acceptable, since they are of no concern to receiving endpoint.
        // All ECN values are acceptable, since ECN requires opt-in from both endpoints.
        // All TTL values are acceptable, since we do not perform routing.
        Ok(Repr {
            src_addr:    packet.src_addr(),
            dst_addr:    packet.dst_addr(),
            protocol:    packet.protocol(),
            payload_len: payload_len
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // We never emit any options.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(4);
        packet.set_header_len(field::DST_ADDR.end as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);
        let total_len = packet.header_len() as u16 + self.payload_len as u16;
        packet.set_total_len(total_len);
        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_ttl(64);
        packet.set_protocol(self.protocol);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);
        packet.fill_checksum();
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                try!(write!(f, "IPv4 ({})", err));
                try!(write!(f, " src={} dst={} proto={} ttl={}",
                            self.src_addr(), self.dst_addr(), self.protocol(), self.ttl()));
                if self.version() != 4 {
                    try!(write!(f, " ver={}", self.version()))
                }
                if self.header_len() != 20 {
                    try!(write!(f, " hlen={}", self.header_len()))
                }
                if self.dscp() != 0 {
                    try!(write!(f, " dscp={}", self.dscp()))
                }
                if self.ecn() != 0 {
                    try!(write!(f, " ecn={}", self.ecn()))
                }
                try!(write!(f, " tlen={}", self.total_len()));
                if self.dont_frag() {
                    try!(write!(f, " df"))
                }
                if self.more_frags() {
                    try!(write!(f, " mf"))
                }
                if self.frag_offset() != 0 {
                    try!(write!(f, " off={}", self.frag_offset()))
                }
                if self.more_frags() || self.frag_offset() != 0 {
                    try!(write!(f, " id={}", self.ident()))
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv4 src={} dst={} proto={}",
               self.src_addr, self.dst_addr, self.protocol)
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        let (ip_repr, payload) = match Packet::new(buffer) {
            Err(err) => return write!(f, "{}({})\n", indent, err),
            Ok(ip_packet) => {
                try!(write!(f, "{}{}\n", indent, ip_packet));
                match Repr::parse(&ip_packet) {
                    Err(_) => return Ok(()),
                    Ok(ip_repr) => (ip_repr, &ip_packet.payload()[..ip_repr.payload_len])
                }
            }
        };

        indent.increase();
        match ip_repr.protocol {
            Protocol::Icmp =>
                super::Icmpv4Packet::<&[u8]>::pretty_print(&payload, f, indent),
            Protocol::Udp => {
                match super::UdpPacket::new(payload) {
                    Err(err) => write!(f, "{}({})\n", indent, err),
                    Ok(udp_packet) => {
                        match super::UdpRepr::parse(&udp_packet,
                                                    &IpAddress::from(ip_repr.src_addr),
                                                    &IpAddress::from(ip_repr.dst_addr)) {
                            Err(err) => write!(f, "{}{} ({})\n", indent, udp_packet, err),
                            Ok(udp_repr) => write!(f, "{}{}\n", indent, udp_repr)
                        }
                    }
                }
            }
            Protocol::Tcp => {
                match super::TcpPacket::new(payload) {
                    Err(err) => write!(f, "{}({})\n", indent, err),
                    Ok(tcp_packet) => {
                        match super::TcpRepr::parse(&tcp_packet,
                                                    &IpAddress::from(ip_repr.src_addr),
                                                    &IpAddress::from(ip_repr.dst_addr)) {
                            Err(err) => write!(f, "{}{} ({})\n", indent, tcp_packet, err),
                            Ok(tcp_repr) => write!(f, "{}{}\n", indent, tcp_repr)
                        }
                    }
                }
            }
            _ => Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 30] =
        [0x45, 0x00, 0x00, 0x1e,
         0x01, 0x02, 0x62, 0x03,
         0x1a, 0x01, 0xd5, 0x6e,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 10] =
        [0xaa, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert_eq!(packet.more_frags(), true);
        assert_eq!(packet.dont_frag(), true);
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.ttl(), 0x1a);
        assert_eq!(packet.protocol(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Address([0x11, 0x12, 0x13, 0x14]));
        assert_eq!(packet.dst_addr(), Address([0x21, 0x22, 0x23, 0x24]));
        assert_eq!(packet.verify_checksum(), true);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0; 30];
        let mut packet = Packet::new(&mut bytes).unwrap();
        packet.set_version(4);
        packet.set_header_len(20);
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_ttl(0x1a);
        packet.set_protocol(Protocol::Icmp);
        packet.set_src_addr(Address([0x11, 0x12, 0x13, 0x14]));
        packet.set_dst_addr(Address([0x21, 0x22, 0x23, 0x24]));
        packet.fill_checksum();
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }

    static REPR_PACKET_BYTES: [u8; 24] =
        [0x45, 0x00, 0x00, 0x18,
         0x00, 0x00, 0x40, 0x00,
         0x40, 0x01, 0xd2, 0x79,
         0x11, 0x12, 0x13, 0x14,
         0x21, 0x22, 0x23, 0x24,
         0xaa, 0x00, 0x00, 0xff];

    static REPR_PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    fn packet_repr() -> Repr {
        Repr {
            src_addr:    Address([0x11, 0x12, 0x13, 0x14]),
            dst_addr:    Address([0x21, 0x22, 0x23, 0x24]),
            protocol:    Protocol::Icmp,
            payload_len: 4
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new(&REPR_PACKET_BYTES[..]).unwrap();
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new(&mut bytes).unwrap();
        repr.emit(&mut packet);
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&packet.into_inner()[..], &REPR_PACKET_BYTES[..]);
    }
}
