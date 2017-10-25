use core::ops::{Deref, DerefMut};

#[cfg(feature = "proto-raw")]
use socket::RawSocket;
#[cfg(feature = "proto-udp")]
use socket::UdpSocket;
#[cfg(feature = "proto-tcp")]
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

#[cfg(feature = "proto-raw")]
impl<'a, 'b> Session for RawSocket<'a, 'b> {}
#[cfg(feature = "proto-udp")]
impl<'a, 'b> Session for UdpSocket<'a, 'b> {}
#[cfg(feature = "proto-tcp")]
impl<'a> Session for TcpSocket<'a> {}

/// A smart pointer to a socket.
///
/// Allows the network stack to efficiently determine if the socket state was changed in any way.
pub struct Ref<'a, T: Session + 'a> {
    socket:   &'a mut T,
    consumed: bool,
}

impl<'a, T: Session> Ref<'a, T> {
    pub(crate) fn new(socket: &'a mut T) -> Self {
        Ref { socket, consumed: false }
    }
}

impl<'a, T: Session + 'a> Ref<'a, T> {
    pub(crate) fn map<U, F>(mut ref_: Self, f: F) -> Option<Ref<'a, U>>
            where U: Session + 'a, F: FnOnce(&'a mut T) -> Option<&'a mut U> {
        if let Some(socket) = f(ref_.socket) {
            ref_.consumed = true;
            Some(Ref::new(socket))
        } else {
            None
        }
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
