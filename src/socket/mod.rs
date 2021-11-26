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

use crate::iface::Context;
use crate::time::Instant;

#[cfg(feature = "socket-dhcpv4")]
mod dhcpv4;
#[cfg(feature = "socket-icmp")]
mod icmp;
#[cfg(feature = "socket-raw")]
mod raw;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(feature = "socket-udp")]
mod udp;

#[cfg(feature = "async")]
mod waker;

#[cfg(feature = "socket-dhcpv4")]
pub use self::dhcpv4::{Config as Dhcpv4Config, Dhcpv4Socket, Event as Dhcpv4Event};
#[cfg(feature = "socket-icmp")]
pub use self::icmp::{Endpoint as IcmpEndpoint, IcmpPacketMetadata, IcmpSocket, IcmpSocketBuffer};
#[cfg(feature = "socket-raw")]
pub use self::raw::{RawPacketMetadata, RawSocket, RawSocketBuffer};
#[cfg(feature = "socket-tcp")]
pub use self::tcp::{SocketBuffer as TcpSocketBuffer, State as TcpState, TcpSocket};
#[cfg(feature = "socket-udp")]
pub use self::udp::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};

#[cfg(feature = "async")]
pub(crate) use self::waker::WakerRegistration;

/// Gives an indication on the next time the socket should be polled.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum PollAt {
    /// The socket needs to be polled immidiately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
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
pub enum Socket<'a> {
    #[cfg(feature = "socket-raw")]
    Raw(RawSocket<'a>),
    #[cfg(feature = "socket-icmp")]
    Icmp(IcmpSocket<'a>),
    #[cfg(feature = "socket-udp")]
    Udp(UdpSocket<'a>),
    #[cfg(feature = "socket-tcp")]
    Tcp(TcpSocket<'a>),
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4(Dhcpv4Socket),
}

impl<'a> Socket<'a> {
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        match self {
            #[cfg(feature = "socket-raw")]
            Socket::Raw(s) => s.poll_at(cx),
            #[cfg(feature = "socket-icmp")]
            Socket::Icmp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-udp")]
            Socket::Udp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-tcp")]
            Socket::Tcp(s) => s.poll_at(cx),
            #[cfg(feature = "socket-dhcpv4")]
            Socket::Dhcpv4(s) => s.poll_at(cx),
        }
    }
}

/// A conversion trait for network sockets.
pub trait AnySocket<'a>: Sized {
    fn upcast(self) -> Socket<'a>;
    fn downcast<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>;
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a> AnySocket<'a> for $socket {
            fn upcast(self) -> Socket<'a> {
                Socket::$variant(self)
            }

            fn downcast<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }
        }
    };
}

#[cfg(feature = "socket-raw")]
from_socket!(RawSocket<'a>, Raw);
#[cfg(feature = "socket-icmp")]
from_socket!(IcmpSocket<'a>, Icmp);
#[cfg(feature = "socket-udp")]
from_socket!(UdpSocket<'a>, Udp);
#[cfg(feature = "socket-tcp")]
from_socket!(TcpSocket<'a>, Tcp);
#[cfg(feature = "socket-dhcpv4")]
from_socket!(Dhcpv4Socket, Dhcpv4);
