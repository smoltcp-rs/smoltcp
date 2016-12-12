//! Network interface logic.
//!
//! The `iface` module deals with the *network interfaces*. It filters incoming frames,
//! provides lookup and caching of hardware addresses, and handles management packets.
use wire;

mod arp_cache;
mod ethernet;

pub use self::arp_cache::Cache as ArpCache;
pub use self::arp_cache::SliceCache as SliceArpCache;
pub use self::ethernet::Interface as EthernetInterface;

/// An internetworking protocol address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum ProtocolAddress {
    Invalid,
    Ipv4(wire::Ipv4Address)
}

impl ProtocolAddress {
    pub const fn ipv4(bytes: [u8; 4]) -> ProtocolAddress {
        ProtocolAddress::Ipv4(wire::Ipv4Address(bytes))
    }
}

impl Default for ProtocolAddress {
    fn default() -> ProtocolAddress {
        ProtocolAddress::Invalid
    }
}
