use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};

pub use super::IpProtocol as Protocol;

/// A sixteen-octet IPv6 address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 16]);

impl Address {
    /// An unspecified address.
    pub const UNSPECIFIED: Address = Address([0x00; 16]);

    /// Link local all routers multicast address.
    pub const LINK_LOCAL_ALL_NODES: Address =
        Address([0xff, 0x02, 0x00, 0x0, 0x00, 0x00, 0x00, 0x0,
                 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x1]);

    /// Link local all nodes multicast address.
    pub const LINK_LOCAL_ALL_ROUTERS: Address =
        Address([0xff, 0x02, 0x00, 0x0, 0x00, 0x00, 0x00, 0x0,
                 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x2]);

    /// Loopback address.
    pub const LOOPBACK: Address =
        Address([0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x0,
                 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x1]);

    /// Construct an IPv6 address from parts.
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
        for word_idx in 0..8 {
            let byte_idx = word_idx * 2;
            NetworkEndian::write_u16(&mut bytes[byte_idx..(byte_idx + 2)], data[word_idx]);
        }
        Address(bytes)
    }

    /// Write a IPv6 address to the given slice.
    ///
    /// # Panics
    /// The function panics if `data` is not 8 words long.
    pub fn write_parts(&self, data: &mut [u16]) {
        assert!(data.len() >= 8);
        for i in 0..8 {
            let byte_idx = i * 2;
            data[i] = NetworkEndian::read_u16(&self.0[byte_idx..(byte_idx + 2)]);
        }
    }

    /// Return an IPv6 address as a sequence of octets, in big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the IPv6 address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    /// Query whether the IPv6 address is a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Query whether the IPv6 address is the "unspecified" address.
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0x00; 16]
    }

    /// Query whether the IPv6 address is in the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..8] == [0xfe, 0x80, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00]
    }

    /// Query whether the IPv6 address is the "loopback" address.
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
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
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

/// A specification of an IPv6 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cidr {
    address:    Address,
    prefix_len: u8,
}

impl Cidr {
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
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

#[cfg(test)]
mod test {
    use super::{Address, Cidr};

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
    #[should_panic(expected = "destination and source slices have different lengths")]
    fn from_bytes_too_long() {
        let _ = Address::from_bytes(&[0u8; 15]);
    }

    #[test]
    #[should_panic(expected = "data.len() >= 8")]
    fn from_parts_too_long() {
        let _ = Address::from_parts(&[0u16; 7]);
    }
}
