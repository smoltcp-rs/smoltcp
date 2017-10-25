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

#[cfg(feature = "proto-raw")] mod raw;
#[cfg(feature = "proto-udp")] mod udp;
#[cfg(feature = "proto-tcp")] mod tcp;
mod set;
mod ref_;

#[cfg(feature = "proto-raw")]
pub use self::raw::{PacketBuffer as RawPacketBuffer,
                    SocketBuffer as RawSocketBuffer,
                    RawSocket};

#[cfg(feature = "proto-udp")]
pub use self::udp::{PacketBuffer as UdpPacketBuffer,
                    SocketBuffer as UdpSocketBuffer,
                    UdpSocket};

#[cfg(feature = "proto-tcp")]
pub use self::tcp::{SocketBuffer as TcpSocketBuffer,
                    State as TcpState,
                    TcpSocket};

pub use self::set::{Set as SocketSet, Item as SocketSetItem, Handle as SocketHandle};
pub use self::set::{Iter as SocketSetIter, IterMut as SocketSetIterMut};

pub use self::ref_::Ref as SocketRef;
pub(crate) use self::ref_::Session as SocketSession;

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value to a concrete socket, use the [AnySocket] trait,
/// e.g. to get `UdpSocket`, call `UdpSocket::downcast(socket)`.
///
/// It is usually more convenient to use [SocketSet::get] instead.
///
/// [AnySocket]: trait.AnySocket.html
/// [SocketSet::get]: struct.SocketSet.html#method.get
#[derive(Debug)]
pub enum Socket<'a, 'b: 'a> {
    #[cfg(feature = "proto-raw")]
    Raw(RawSocket<'a, 'b>),
    #[cfg(feature = "proto-udp")]
    Udp(UdpSocket<'a, 'b>),
    #[cfg(feature = "proto-tcp")]
    Tcp(TcpSocket<'a>),
    #[doc(hidden)]
    __Nonexhaustive(PhantomData<(&'a (), &'b ())>)
}

macro_rules! dispatch_socket {
    ($self_:expr, |$socket:ident [$( $mut_:tt )*]| $code:expr) => ({
        match $self_ {
            #[cfg(feature = "proto-raw")]
            &$( $mut_ )* Socket::Raw(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "proto-udp")]
            &$( $mut_ )* Socket::Udp(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "proto-tcp")]
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

impl<'a, 'b> SocketSession for Socket<'a, 'b> {
    fn finish(&mut self) {
        dispatch_socket!(self, |socket [mut]| socket.finish())
    }
}

/// A conversion trait for network sockets.
pub trait AnySocket<'a, 'b>: SocketSession + Sized {
    fn downcast<'c>(socket_ref: SocketRef<'c, Socket<'a, 'b>>) ->
                   Option<SocketRef<'c, Self>>;
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a, 'b> AnySocket<'a, 'b> for $socket {
            fn downcast<'c>(ref_: SocketRef<'c, Socket<'a, 'b>>) ->
                           Option<SocketRef<'c, Self>> {
                SocketRef::map(ref_, |socket| {
                    match *socket {
                        Socket::$variant(ref mut socket) => Some(socket),
                        _ => None,
                    }
                })
            }
        }
    }
}

#[cfg(feature = "proto-raw")]
from_socket!(RawSocket<'a, 'b>, Raw);
#[cfg(feature = "proto-udp")]
from_socket!(UdpSocket<'a, 'b>, Udp);
#[cfg(feature = "proto-tcp")]
from_socket!(TcpSocket<'a>, Tcp);
