/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
mod fragmentation;
mod interface;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;
#[cfg(feature = "proto-rpl")]
mod rpl;
mod socket_meta;
mod socket_set;

pub use self::interface::{Config, Interface, InterfaceInner as Context};
pub use self::route::{Route, RouteTableFull, Routes};
pub use socket_set::{SocketHandle, SocketSet, SocketStorage};

#[cfg(feature = "proto-rpl")]
pub use self::rpl::RplBuilder;
