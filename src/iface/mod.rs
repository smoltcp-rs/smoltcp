/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "medium-ieee802154"
))]
mod interface;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub(crate) use self::neighbor::Answer as NeighborAnswer;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub use self::neighbor::Cache as NeighborCache;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
pub use self::neighbor::Neighbor;
pub use self::route::{Route, Routes};

#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "medium-ieee802154"
))]
pub use self::interface::{Interface, InterfaceBuilder};
