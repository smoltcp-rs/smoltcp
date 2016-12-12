//! Network interface logic.
//!
//! The `iface` module deals with the *network interfaces*. It filters incoming frames,
//! provides lookup and caching of hardware addresses, and handles management packets.
use core::fmt;
use wire;

mod arp_cache;
mod ethernet;

pub use self::arp_cache::Cache as ArpCache;
pub use self::arp_cache::SliceCache as SliceArpCache;
pub use self::ethernet::Interface as EthernetInterface;

/// An internetworking protocol address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum ProtocolAddress {
    /// An invalid address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Invalid,
    /// An IPv4 address.
    Ipv4(wire::Ipv4Address)
}

impl ProtocolAddress {
    /// Create a protocol address wrapping an IPv4 address with the given octets.
    pub const fn ipv4(octets: [u8; 4]) -> ProtocolAddress {
        ProtocolAddress::Ipv4(wire::Ipv4Address(octets))
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            &ProtocolAddress::Invalid    => false,
            &ProtocolAddress::Ipv4(addr) => addr.is_unicast()
        }
    }
}

impl Default for ProtocolAddress {
    fn default() -> ProtocolAddress {
        ProtocolAddress::Invalid
    }
}

impl From<wire::Ipv4Address> for ProtocolAddress {
    fn from(addr: wire::Ipv4Address) -> Self {
        ProtocolAddress::Ipv4(addr)
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ProtocolAddress::Invalid    => write!(f, "(invalid)"),
            &ProtocolAddress::Ipv4(addr) => write!(f, "{}", addr)
        }
    }
}
