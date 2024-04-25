/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod fragmentation;
mod interface;
mod multicast;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;
#[cfg(feature = "proto-rpl")]
mod rpl;
mod socket_meta;
mod socket_set;

mod packet;

#[cfg(feature = "proto-igmp")]
pub use self::interface::MulticastError;
pub use self::interface::{Config, Interface, InterfaceInner as Context};

pub use self::route::{Route, RouteTableFull, Routes};
pub use self::socket_set::{SocketHandle, SocketSet, SocketStorage};

#[cfg(feature = "proto-rpl")]
pub use self::rpl::{
    Config as RplConfig, ModeOfOperation as RplModeOfOperation, RootConfig as RplRootConfig,
    RplInstanceId, TrickleTimer,
};

#[cfg(feature = "proto-rpl")]
use self::rpl::Rpl;

pub use multicast::MulticastMetadata;
