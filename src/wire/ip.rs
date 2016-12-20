use core::fmt;

use super::Ipv4Address;

enum_with_unknown! {
    /// Internetworking protocol.
    pub enum Protocol(u8) {
        Icmp = 0x01,
        Tcp  = 0x06,
        Udp  = 0x11
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Protocol::Icmp => write!(f, "ICMP"),
            &Protocol::Tcp  => write!(f, "TCP"),
            &Protocol::Udp  => write!(f, "UDP"),
            &Protocol::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// An internetworking address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An invalid address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Invalid,
    /// An IPv4 address.
    Ipv4(Ipv4Address)
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    pub const fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address([a0, a1, a2, a3]))
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            &Address::Invalid    => false,
            &Address::Ipv4(addr) => addr.is_unicast()
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            &Address::Invalid    => false,
            &Address::Ipv4(addr) => addr.is_unspecified()
        }
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Invalid
    }
}

impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Address::Invalid    => write!(f, "(invalid)"),
            &Address::Ipv4(addr) => write!(f, "{}", addr)
        }
    }
}

/// An internet endpoint address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16
}

impl Endpoint {
    pub const INVALID: Endpoint = Endpoint { addr: Address::Invalid, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr: addr, port: port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(data: &[u8]) -> u16 {
        let mut accum: u32 = 0;
        for i in (0..data.len()).step_by(2) {
            let word;
            if i + 2 <= data.len() {
                word = NetworkEndian::read_u16(&data[i..i + 2]) as u32
            } else {
                word = (data[i] as u32) << 8
            }
            accum += word;
        }
        (((accum >> 16) as u16) + (accum as u16))
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        (((accum >> 16) as u16) + (accum as u16))
    }

    /// Compute an IP pseudo header checksum.
    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address,
                         protocol: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
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

            _ => panic!("Unexpected pseudo header ")
        }
    }
}
