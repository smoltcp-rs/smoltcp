/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod neighbor;
mod route;
mod ethernet;

pub use self::neighbor::Neighbor as Neighbor;
pub(crate) use self::neighbor::Answer as NeighborAnswer;
pub use self::neighbor::Cache as NeighborCache;
pub use self::route::{Route, Routes};
pub use self::ethernet::{Interface as EthernetInterface,
                         InterfaceBuilder as EthernetInterfaceBuilder};
