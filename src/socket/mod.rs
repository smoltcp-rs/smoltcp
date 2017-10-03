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
mod socket_ref;

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

pub use self::socket_ref::Ref as SocketRef;
pub(crate) use self::socket_ref::Session as SocketSession;

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value down to a concrete socket, use
/// the [FromSocket](trait.FromSocket.html) trait, and call e.g. `UdpSocket::from_socket(socket)`.
/// Users are expected to work with references to concrete socket types directly
/// via [SocketSet::get](struct.SocketSet.html#method.get)
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
    /// Return the debug identifier.
    pub fn debug_id(&self) -> usize {
        dispatch_socket!(self, |socket []| socket.debug_id())
    }

    /// Set the debug identifier.
    ///
    /// The debug identifier is a number printed in socket trace messages.
    /// It could as well be used by the user code.
    pub fn set_debug_id(&mut self, id: usize) {
        dispatch_socket!(self, |socket [mut]| socket.set_debug_id(id))
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        dispatch_socket!(self, |socket []| socket.poll_at())
    }
}

/// A conversion trait for network sockets.
pub trait FromSocket<'a, 'b>: SocketSession + Sized {
    fn downcast_socket<'c>(&'c mut Socket<'a, 'b>) -> Option<&'c mut Self>;

    fn from_socket_ref<'c>(socket_ref: SocketRef<'c, Socket<'a, 'b>>)
                           -> Option<SocketRef<'c, Self>> {
        SocketRef::from_socket_ref(socket_ref)
    }
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a, 'b> FromSocket<'a, 'b> for $socket {
            fn downcast_socket<'c>(socket: &'c mut Socket<'a, 'b>)
                               -> Option<&'c mut $socket> {
                match *socket {
                    Socket::$variant(ref mut socket) => Some(socket),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(feature = "socket-raw")]
from_socket!(RawSocket<'a, 'b>, Raw);
#[cfg(feature = "socket-udp")]
from_socket!(UdpSocket<'a, 'b>, Udp);
#[cfg(feature = "socket-tcp")]
from_socket!(TcpSocket<'a>, Tcp);
