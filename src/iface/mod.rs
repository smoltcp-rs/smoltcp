/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(feature = "ethernet")]
mod neighbor;
mod route;
mod interface;

#[cfg(feature = "ethernet")]
pub use self::neighbor::Neighbor as Neighbor;
#[cfg(feature = "ethernet")]
pub(crate) use self::neighbor::Answer as NeighborAnswer;
#[cfg(feature = "ethernet")]
pub use self::neighbor::Cache as NeighborCache;
pub use self::route::{Route, Routes};

pub use self::interface::{Interface, InterfaceBuilder};
