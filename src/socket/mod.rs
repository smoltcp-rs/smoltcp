//! Communication between endpoints.
//!
//! The `socket` module deals with *network endpoints* and *buffering*.
//! It provides interfaces for accessing buffers of data, and protocol state machines
//! for filling and emptying these buffers.
//!
//! The programming interface implemented here differs greatly from the common Berkeley socket
//! interface. Specifically, in the Berkeley interface the buffering is implicit:
//! the operating system decides on the good size for a buffer and manages it.
//! The interface implemented by this module uses explicit buffering: you decide on the good
//! size for a buffer, allocate it, and let the networking stack use it.
//!
//! Every socket implementation allows selecting transmit and receive buffers separately;
//! this means that, for example, a socket that never receives data does not have to allocate
//! any storage to receive buffers.

use Error;
use wire::{InternetAddress as Address, InternetProtocolType as ProtocolType};

mod udp;

pub use self::udp::Buffer as UdpBuffer;
pub use self::udp::NullBuffer as UdpNullBuffer;
pub use self::udp::UnitaryBuffer as UdpUnitaryBuffer;
pub use self::udp::UdpSocket as UdpSocket;

/// A packet representation.
///
/// This interface abstracts the various types of packets layered under the IP protocol,
/// and serves as an accessory to [trait Socket](trait.Socket.html).
pub trait PacketRepr {
    /// Return the length required to serialize this high-level representation.
    fn len(&self) -> usize;

    /// Emit this high-level representation into a sequence of octets.
    fn emit(&self, src_addr: &Address, dst_addr: &Address, payload: &mut [u8]);
}

/// A network socket.
///
/// This interface abstracts the various types of sockets based on the IP protocol.
/// It is necessarily implemented as a trait, and not as an enumeration, to allow using different
/// buffering strategies in sockets assigned to the same interface.
///
/// The `collect` and `dispatch` functions are fundamentally asymmetric and thus differ in
/// their use of the [trait PacketRepr](trait.PacketRepr.html). When `collect` is called,
/// the packet length is already known and no allocation is required; on the other hand,
/// `collect` would have to downcast a `&PacketRepr` to e.g. an `&UdpRepr` through `Any`,
/// which is rather inelegant. Conversely, when `dispatch` is called, the packet length is
/// not yet known and the packet storage has to be allocated; but the `&PacketRepr` is sufficient
/// since the lower layers treat the packet as an opaque octet sequence.
pub trait Socket {
    /// Process a packet received from a network interface.
    ///
    /// This function checks if the packet contained in the payload matches the socket endpoint,
    /// and if it does, copies it into the internal buffer, otherwise, `Err(Error::Rejected)`
    /// is returned.
    ///
    /// This function is used internally by the networking stack.
    fn collect(&mut self, src_addr: &Address, dst_addr: &Address,
               protocol: ProtocolType, payload: &[u8])
        -> Result<(), Error>;

    /// Prepare a packet to be transmitted to a network interface.
    ///
    /// This function checks if the internal buffer is empty, and if it is not, calls `f` with
    /// the representation of the packet to be transmitted, otherwise, `Err(Error::Exhausted)`
    /// is returned.
    ///
    /// This function is used internally by the networking stack.
    fn dispatch(&mut self, f: &mut FnMut(&Address, &Address,
                                         ProtocolType, &PacketRepr) -> Result<(), Error>)
        -> Result<(), Error>;
}
