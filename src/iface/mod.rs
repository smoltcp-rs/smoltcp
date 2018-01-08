/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod neighbor;
mod ethernet;

pub use self::neighbor::Neighbor as Neighbor;
pub(crate) use self::neighbor::Answer as NeighborAnswer;
pub use self::neighbor::Cache as NeighborCache;
pub use self::ethernet::{Interface as EthernetInterface,
                         InterfaceBuilder as EthernetInterfaceBuilder};

use Result;
use phy::{DeviceCapabilities, ChecksumCapabilities};
use wire::{IpRepr, Ipv4Repr, UdpRepr, TcpRepr, Icmpv4Repr};

pub trait PacketFilter {
    fn process_udp(&mut self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> Result<()>;
    fn process_tcp<'frame>(&mut self, timestamp: u64, ip_repr: &IpRepr, tcp_repr: &TcpRepr<'frame>) ->
        Result<Option<(IpRepr, TcpRepr<'static>)>>;
    fn process_icmpv4(&mut self, ip_repr: &IpRepr, icmp_repr: &Icmpv4Repr, cksum: &ChecksumCapabilities) -> Result<bool>;
    fn process_raw(&mut self, ip_repr: &IpRepr, payload: &[u8],checksum_caps: &ChecksumCapabilities) -> Result<bool>;

    fn egress<E>(&mut self, caps: &DeviceCapabilities, timestamp: u64, emitter: &mut E) -> Result<bool>
        where E: PacketEmitter;

    fn poll_at(&self, timestamp: u64) -> Option<u64> { None }
}

pub trait PacketEmitter {
    fn emit_tcp(&mut self, (IpRepr, TcpRepr), timestamp: u64) -> Result<()>;
    fn emit_udp(&mut self, (IpRepr, UdpRepr), timestamp: u64) -> Result<()>;
    fn emit_icmpv4(&mut self, (Ipv4Repr, Icmpv4Repr), timestamp: u64) -> Result<()>;
    fn emit_raw(&mut self, (IpRepr, &[u8]), timestamp: u64) -> Result<()>;
}
