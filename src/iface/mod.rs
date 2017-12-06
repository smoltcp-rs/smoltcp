//! Network interface logic.
//!
//! The `iface` module deals with the *network interfaces*. It filters incoming frames,
//! provides lookup and caching of hardware addresses, and handles management packets.

mod neighbor;
mod ethernet;

pub use self::neighbor::Neighbor as Neighbor;
pub(crate) use self::neighbor::Answer as NeighborAnswer;
pub use self::neighbor::Cache as NeighborCache;
pub use self::ethernet::Interface as EthernetInterface;
pub use self::ethernet::Packet as EthernetPacket;
