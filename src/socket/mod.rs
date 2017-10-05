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

use core::marker::PhantomData;
use wire::IpRepr;

#[cfg(feature = "socket-raw")] mod raw;
#[cfg(feature = "socket-udp")] mod udp;
#[cfg(feature = "socket-tcp")] mod tcp;
mod set;

#[cfg(feature = "socket-raw")]
pub use self::raw::{PacketBuffer as RawPacketBuffer,
                    SocketBuffer as RawSocketBuffer,
                    RawSocket};

#[cfg(feature = "socket-udp")]
pub use self::udp::{PacketBuffer as UdpPacketBuffer,
                    SocketBuffer as UdpSocketBuffer,
                    UdpSocket};

#[cfg(feature = "socket-tcp")]
pub use self::tcp::{SocketBuffer as TcpSocketBuffer,
                    State as TcpState,
                    TcpSocket};

pub use self::set::{Set as SocketSet, Item as SocketSetItem, Handle as SocketHandle};
pub use self::set::{Iter as SocketSetIter, IterMut as SocketSetIterMut};

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value down to a concrete socket, use
/// the [AsSocket](trait.AsSocket.html) trait, and call e.g. `socket.as_socket::<UdpSocket<_>>()`.
///
/// The `process` and `dispatch` functions are fundamentally asymmetric and thus differ in
/// their use of the [trait PacketRepr](trait.PacketRepr.html). When `process` is called,
/// the packet length is already known and no allocation is required; on the other hand,
/// `process` would have to downcast a `&PacketRepr` to e.g. an `&UdpRepr` through `Any`,
/// which is rather inelegant. Conversely, when `dispatch` is called, the packet length is
/// not yet known and the packet storage has to be allocated; but the `&PacketRepr` is sufficient
/// since the lower layers treat the packet as an opaque octet sequence.
#[derive(Debug)]
pub enum Socket<'a, 'b: 'a> {
    #[cfg(feature = "socket-raw")]
    Raw(RawSocket<'a, 'b>),
    #[cfg(feature = "socket-udp")]
    Udp(UdpSocket<'a, 'b>),
    #[cfg(feature = "socket-tcp")]
    Tcp(TcpSocket<'a>),
    #[doc(hidden)]
    __Nonexhaustive(PhantomData<(&'a (), &'b ())>)
}

macro_rules! dispatch_socket {
    ($self_:expr, |$socket:ident [$( $mut_:tt )*]| $code:expr) => ({
        match $self_ {
            #[cfg(feature = "socket-raw")]
            &$( $mut_ )* Socket::Raw(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "socket-udp")]
            &$( $mut_ )* Socket::Udp(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "socket-tcp")]
            &$( $mut_ )* Socket::Tcp(ref $( $mut_ )* $socket) => $code,
            &$( $mut_ )* Socket::__Nonexhaustive(_) => unreachable!()
        }
    })
}

impl<'a, 'b> Socket<'a, 'b> {
    /// Return the socket handle.
    pub fn handle(&self) -> SocketHandle {
        dispatch_socket!(self, |socket []| socket.handle())
    }

    pub(crate) fn set_handle(&mut self, handle: SocketHandle) {
        dispatch_socket!(self, |socket [mut]| socket.set_handle(handle))
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        dispatch_socket!(self, |socket []| socket.poll_at())
    }
}

/// A conversion trait for network sockets.
///
/// This trait is used to concisely downcast [Socket](trait.Socket.html) values to their
/// concrete types.
pub trait AsSocket<T> {
    fn as_socket(&mut self) -> &mut T;
    fn try_as_socket(&mut self) -> Option<&mut T>;
}

macro_rules! as_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a, 'b> AsSocket<$socket> for Socket<'a, 'b> {
            fn as_socket(&mut self) -> &mut $socket {
                match self {
                    &mut Socket::$variant(ref mut socket) => socket,
                    _ => panic!(concat!(".as_socket::<",
                                        stringify!($socket),
                                        "> called on wrong socket type"))
                }
            }

            fn try_as_socket(&mut self) -> Option<&mut $socket> {
                match self {
                    &mut Socket::$variant(ref mut socket) => Some(socket),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(feature = "socket-raw")]
as_socket!(RawSocket<'a, 'b>, Raw);
#[cfg(feature = "socket-udp")]
as_socket!(UdpSocket<'a, 'b>, Udp);
#[cfg(feature = "socket-tcp")]
as_socket!(TcpSocket<'a>, Tcp);
