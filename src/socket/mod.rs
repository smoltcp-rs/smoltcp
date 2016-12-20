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

use Error;
use wire::{IpAddress, IpProtocol};

mod udp;
mod tcp;

pub use self::udp::PacketBuffer as UdpPacketBuffer;
pub use self::udp::SocketBuffer as UdpSocketBuffer;
pub use self::udp::UdpSocket as UdpSocket;

pub use self::tcp::SocketBuffer as TcpSocketBuffer;
pub use self::tcp::Incoming as TcpIncoming;
pub use self::tcp::Listener as TcpListener;

/// A packet representation.
///
/// This interface abstracts the various types of packets layered under the IP protocol,
/// and serves as an accessory to [trait Socket](trait.Socket.html).
pub trait PacketRepr {
    /// Return the length of the buffer required to serialize this high-level representation.
    fn buffer_len(&self) -> usize;

    /// Emit this high-level representation into a sequence of octets.
    fn emit(&self, src_addr: &IpAddress, dst_addr: &IpAddress, payload: &mut [u8]);
}

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value down to a concrete socket, use
/// the [AsSocket](trait.AsSocket.html) trait, and call e.g. `socket.as_socket::<UdpSocket<_>>()`.
///
/// The `collect` and `dispatch` functions are fundamentally asymmetric and thus differ in
/// their use of the [trait PacketRepr](trait.PacketRepr.html). When `collect` is called,
/// the packet length is already known and no allocation is required; on the other hand,
/// `collect` would have to downcast a `&PacketRepr` to e.g. an `&UdpRepr` through `Any`,
/// which is rather inelegant. Conversely, when `dispatch` is called, the packet length is
/// not yet known and the packet storage has to be allocated; but the `&PacketRepr` is sufficient
/// since the lower layers treat the packet as an opaque octet sequence.
pub enum Socket<'a, 'b: 'a> {
    Udp(UdpSocket<'a, 'b>),
    TcpServer(TcpListener<'a>),
    #[doc(hidden)]
    __Nonexhaustive
}

impl<'a, 'b> Socket<'a, 'b> {
    /// Process a packet received from a network interface.
    ///
    /// This function checks if the packet contained in the payload matches the socket endpoint,
    /// and if it does, copies it into the internal buffer, otherwise, `Err(Error::Rejected)`
    /// is returned.
    ///
    /// This function is used internally by the networking stack.
    pub fn collect(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress,
                   protocol: IpProtocol, payload: &[u8])
            -> Result<(), Error> {
        match self {
            &mut Socket::Udp(ref mut socket) =>
                socket.collect(src_addr, dst_addr, protocol, payload),
            &mut Socket::TcpServer(ref mut socket) =>
                socket.collect(src_addr, dst_addr, protocol, payload),
            &mut Socket::__Nonexhaustive => unreachable!()
        }
    }

    /// Prepare a packet to be transmitted to a network interface.
    ///
    /// This function checks if the internal buffer is empty, and if it is not, calls `f` with
    /// the representation of the packet to be transmitted, otherwise, `Err(Error::Exhausted)`
    /// is returned.
    ///
    /// This function is used internally by the networking stack.
    pub fn dispatch(&mut self, f: &mut FnMut(&IpAddress, &IpAddress,
                                             IpProtocol, &PacketRepr) -> Result<(), Error>)
            -> Result<(), Error> {
        match self {
            &mut Socket::Udp(ref mut socket) =>
                socket.dispatch(f),
            &mut Socket::TcpServer(_) =>
                Err(Error::Exhausted),
            &mut Socket::__Nonexhaustive => unreachable!()
        }
    }
}

/// A conversion trait for network sockets.
///
/// This trait is used to concisely downcast [Socket](trait.Socket.html) values to their
/// concrete types.
pub trait AsSocket<T> {
    fn as_socket(&mut self) -> &mut T;
}

impl<'a, 'b> AsSocket<UdpSocket<'a, 'b>> for Socket<'a, 'b> {
    fn as_socket(&mut self) -> &mut UdpSocket<'a, 'b> {
        match self {
            &mut Socket::Udp(ref mut socket) => socket,
            _ => panic!(".as_socket::<UdpSocket> called on wrong socket type")
        }
    }
}

impl<'a, 'b> AsSocket<TcpListener<'a>> for Socket<'a, 'b> {
    fn as_socket(&mut self) -> &mut TcpListener<'a> {
        match self {
            &mut Socket::TcpServer(ref mut socket) => socket,
            _ => panic!(".as_socket::<TcpListener> called on wrong socket type")
        }
    }
}
