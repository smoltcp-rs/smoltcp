/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod interface;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;
mod socket_meta;
mod socket_set;

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub(crate) use self::neighbor::Answer as NeighborAnswer;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub use self::neighbor::Cache as NeighborCache;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub use self::neighbor::Neighbor;
pub use self::route::{Route, Routes};
pub use socket_set::{SocketHandle, SocketStorage};

pub use self::interface::{Interface, InterfaceBuilder, InterfaceInner as Context};
