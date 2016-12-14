//! Network interface logic.
//!
//! The `iface` module deals with the *network interfaces*. It filters incoming frames,
//! provides lookup and caching of hardware addresses, and handles management packets.

mod arp_cache;
mod ethernet;

pub use self::arp_cache::Cache as ArpCache;
pub use self::arp_cache::SliceCache as SliceArpCache;
pub use self::ethernet::Interface as EthernetInterface;
