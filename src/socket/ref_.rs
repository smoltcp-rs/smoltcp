use core::ops::{Deref, DerefMut};

#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
use socket::IcmpSocket;
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use socket::TcpSocket;

/// A trait for tracking a socket usage session.
///
/// Allows implementation of custom drop logic that runs only if the socket was changed
/// in specific ways. For example, drop logic for UDP would check if the local endpoint
/// has changed, and if yes, notify the socket set.
#[doc(hidden)]
pub trait Session {
    fn finish(&mut self) {}
}

#[cfg(feature = "socket-raw")]
impl<'a, 'b> Session for RawSocket<'a, 'b> {}
#[cfg(all(feature = "socket-icmp", any(feature = "proto-ipv4", feature = "proto-ipv6")))]
impl<'a, 'b> Session for IcmpSocket<'a, 'b> {}
#[cfg(feature = "socket-udp")]
impl<'a, 'b> Session for UdpSocket<'a, 'b> {}
#[cfg(feature = "socket-tcp")]
impl<'a> Session for TcpSocket<'a> {}

/// A smart pointer to a socket.
///
/// Allows the network stack to efficiently determine if the socket state was changed in any way.
pub struct Ref<'a, T: Session + 'a> {
    socket:   &'a mut T,
    consumed: bool,
}

impl<'a, T: Session + 'a> Ref<'a, T> {
    /// Wrap a pointer to a socket to make a smart pointer.
    ///
    /// Calling this function is only necessary if your code is using [into_inner].
    ///
    /// [into_inner]: #method.into_inner
    pub fn new(socket: &'a mut T) -> Self {
        Ref { socket, consumed: false }
    }

    /// Unwrap a smart pointer to a socket.
    ///
    /// The finalization code is not run. Prompt operation of the network stack depends
    /// on wrapping the returned pointer back and dropping it.
    ///
    /// Calling this function is only necessary to achieve composability if you *must*
    /// map a `&mut SocketRef<'a, XSocket>` to a `&'a mut XSocket` (note the lifetimes);
    /// be sure to call [new] afterwards.
    ///
    /// [new_unchecked]: #method.new_unchecked
    pub fn into_inner(mut ref_: Self) -> &'a mut T {
        ref_.consumed = true;
        ref_.socket
    }
}

impl<'a, T: Session> Deref for Ref<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.socket
    }
}

impl<'a, T: Session> DerefMut for Ref<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.socket
    }
}

impl<'a, T: Session> Drop for Ref<'a, T> {
    fn drop(&mut self) {
        if !self.consumed {
            Session::finish(self.socket);
        }
    }
}
