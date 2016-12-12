use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};
use Error;

pub use super::InternetProtocolType as ProtocolType;

/// A four-octet IPv4 address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 4]);

impl Address {
    pub const BROADCAST: Address = Address([255; 4]);

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
    #![allow(non_snake_case)]

    use wire::field::*;

    pub const VER_IHL:  usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH:   Field = 2..4;
    pub const IDENT:    Field = 4..6;
    pub const FLG_OFF1: usize = 6;
    pub const FLG_OFF0: usize = 7;
    pub const TTL:      usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

fn checksum(data: &[u8]) -> u16 {
    let mut accum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        if i == field::CHECKSUM.start { continue }
        let word = NetworkEndian::read_u16(&data[i..i + 2]) as u32;
        accum += word;
    }
    !(((accum >> 16) as u16) + (accum as u16))
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Wrap a buffer with an IPv4 packet. Returns an error if the buffer
    /// is too small to contain one.
    pub fn new(buffer: T) -> Result<Packet<T>, Error> {
        let len = buffer.as_ref().len();
        if len < field::VER_IHL {
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
    #[inline(always)]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] & 0x04
    }

    /// Return the header length, in octets.
    #[inline(always)]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] >> 4) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x3f
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 6
    }

    /// Return the total length field.
    #[inline(always)]
    pub fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline(always)]
    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline(always)]
    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::FLG_OFF1] & 0x02 != 0
    }

    /// Return the "more fragments" flag.
    #[inline(always)]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::FLG_OFF1] & 0x04 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline(always)]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        let chunks = (((data[field::FLG_OFF1] >> 3) as u16) << 8) |
                        data[field::FLG_OFF0] as u16;
        chunks * 8
    }

    /// Return the time to live field.
    #[inline(always)]
    pub fn ttl(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the protocol field.
    #[inline(always)]
    pub fn protocol(&self) -> ProtocolType {
        let data = self.buffer.as_ref();
        ProtocolType::from(data[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline(always)]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the source address field.
    #[inline(always)]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SRC_ADDR])
    }

    /// Return the destination address field.
    #[inline(always)]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DST_ADDR])
    }

    /// Return a pointer to the payload.
    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        let range = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[range..]
    }

    /// Validate the header checksum.
    pub fn verify_checksum(&self) -> bool {
        let checksum = {
            let data = self.buffer.as_ref();
            checksum(&data[..self.header_len() as usize])
        };
        self.checksum() == checksum
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline(always)]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x04) | (value & 0x04);
    }

    /// Set the header length, in octets.
    #[inline(always)]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x40) | ((value / 4) << 4);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x3f) | (value & 0x3f)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & 0x3f) | (value << 6)
    }

    /// Set the total length field.
    #[inline(always)]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline(always)]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value)
    }

    /// Set the "don't fragment" flag.
    #[inline(always)]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = data[field::FLG_OFF1];
        data[field::FLG_OFF1] = if value { raw | 0x02 } else { raw & !0x02 };
    }

    /// Set the "more fragments" flag.
    #[inline(always)]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = data[field::FLG_OFF1];
        data[field::FLG_OFF1] = if value { raw | 0x04 } else { raw & !0x04 };
    }

    /// Set the fragment offset, in octets.
    #[inline(always)]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let chunks = value / 8;
        let raw = data[field::FLG_OFF1] & 0x7;
        data[field::FLG_OFF1] = raw | (((chunks >> 8) << 3) as u8);
        data[field::FLG_OFF0] = chunks as u8;
    }

    /// Set the time to live field.
    #[inline(always)]
    pub fn set_ttl(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the protocol field.
    #[inline(always)]
    pub fn set_protocol(&mut self, value: ProtocolType) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline(always)]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline(always)]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Set the destination address field.
    #[inline(always)]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Return a mutable pointer to the payload.
    #[inline(always)]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        let checksum = {
            let data = self.buffer.as_ref();
            checksum(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 30] =
        [0x54, 0x00, 0x00, 0x1e,
         0x01, 0x02, 0x16, 0x03,
         0x1a, 0x01, 0x12, 0x6f,
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
        assert_eq!(packet.protocol(), ProtocolType::Icmp);
        assert_eq!(packet.checksum(), 0x126f);
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
        packet.set_protocol(ProtocolType::Icmp);
        packet.set_src_addr(Address([0x11, 0x12, 0x13, 0x14]));
        packet.set_dst_addr(Address([0x21, 0x22, 0x23, 0x24]));
        packet.fill_checksum();
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }
}
