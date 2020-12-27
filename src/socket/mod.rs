/*! Communication between endpoints.

The `socket` module deals with *network endpoints* and *buffering*.
It provides interfaces for accessing buffers of data, and protocol state machines
for filling and emptying these buffers.

The programming interface implemented here differs greatly from the common Berkeley socket
interface. Specifically, in the Berkeley interface the buffering is implicit:
the operating system decides on the good size for a buffer and manages it.
The interface implemented by this module uses explicit buffering: you decide on the good
size for a buffer, allocate it, and let the networking stack use it.
*/

use core::marker::PhantomData;
use crate::time::Instant;

mod meta;
#[cfg(feature = "socket-raw")]
mod raw;
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
mod icmp;
#[cfg(feature = "socket-udp")]
mod udp;
#[cfg(feature = "socket-tcp")]
mod tcp;
mod set;
mod ref_;

#[cfg(feature = "async")]
mod waker;

pub(crate) use self::meta::Meta as SocketMeta;
#[cfg(feature = "async")]
pub(crate) use self::waker::WakerRegistration;

#[cfg(feature = "socket-raw")]
pub use self::raw::{RawPacketMetadata,
                    RawSocketBuffer,
                    RawSocket};

#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
pub use self::icmp::{IcmpPacketMetadata,
                     IcmpSocketBuffer,
                     Endpoint as IcmpEndpoint,
                     IcmpSocket};

#[cfg(feature = "socket-udp")]
pub use self::udp::{UdpPacketMetadata,
                    UdpSocketBuffer,
                    UdpSocket};

#[cfg(feature = "socket-tcp")]
pub use self::tcp::{SocketBuffer as TcpSocketBuffer,
                    State as TcpState,
                    TcpSocket};

pub use self::set::{Set as SocketSet, Item as SocketSetItem, Handle as SocketHandle};
pub use self::set::{Iter as SocketSetIter, IterMut as SocketSetIterMut};

pub use self::ref_::Ref as SocketRef;
pub(crate) use self::ref_::Session as SocketSession;

/// Gives an indication on the next time the socket should be polled.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PollAt {
    /// The socket needs to be polled immidiately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}

impl PollAt {
    #[cfg(feature = "socket-tcp")]
    fn is_ingress(&self) -> bool {
        match *self {
            PollAt::Ingress => true,
            _ => false,
        }
    }
}

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
    #[cfg(feature = "socket-raw")]
    Raw(RawSocket<'a, 'b>),
    #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
    Icmp(IcmpSocket<'a, 'b>),
    #[cfg(feature = "socket-udp")]
    Udp(UdpSocket<'a, 'b>),
    #[cfg(feature = "socket-tcp")]
    Tcp(TcpSocket<'a>),
    #[doc(hidden)]
    __Nonexhaustive(PhantomData<(&'a (), &'b ())>)
}

macro_rules! dispatch_socket {
    ($self_:expr, |$socket:ident| $code:expr) => {
        dispatch_socket!(@inner $self_, |$socket| $code);
    };
    (mut $self_:expr, |$socket:ident| $code:expr) => {
        dispatch_socket!(@inner mut $self_, |$socket| $code);
    };
    (@inner $( $mut_:ident )* $self_:expr, |$socket:ident| $code:expr) => {
        match $self_ {
            #[cfg(feature = "socket-raw")]
            &$( $mut_ )* Socket::Raw(ref $( $mut_ )* $socket) => $code,
            #[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
            &$( $mut_ )* Socket::Icmp(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "socket-udp")]
            &$( $mut_ )* Socket::Udp(ref $( $mut_ )* $socket) => $code,
            #[cfg(feature = "socket-tcp")]
            &$( $mut_ )* Socket::Tcp(ref $( $mut_ )* $socket) => $code,
            &$( $mut_ )* Socket::__Nonexhaustive(_) => unreachable!()
        }
    };
}

impl<'a, 'b> Socket<'a, 'b> {
    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta().handle
    }

    pub(crate) fn meta(&self) -> &SocketMeta {
        dispatch_socket!(self, |socket| &socket.meta)
    }

    pub(crate) fn meta_mut(&mut self) -> &mut SocketMeta {
        dispatch_socket!(mut self, |socket| &mut socket.meta)
    }

    pub(crate) fn poll_at(&self) -> PollAt {
        dispatch_socket!(self, |socket| socket.poll_at())
    }
}

impl<'a, 'b> SocketSession for Socket<'a, 'b> {
    fn finish(&mut self) {
        dispatch_socket!(mut self, |socket| socket.finish())
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
                match SocketRef::into_inner(ref_) {
                    &mut Socket::$variant(ref mut socket) => Some(SocketRef::new(socket)),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(feature = "socket-raw")]
from_socket!(RawSocket<'a, 'b>, Raw);
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
from_socket!(IcmpSocket<'a, 'b>, Icmp);
#[cfg(feature = "socket-udp")]
from_socket!(UdpSocket<'a, 'b>, Udp);
#[cfg(feature = "socket-tcp")]
from_socket!(TcpSocket<'a>, Tcp);
