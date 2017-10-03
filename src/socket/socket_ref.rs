use core::ops::{Deref, DerefMut};
use socket::{FromSocket, Socket, SocketHandle};
#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-tcp")]
use socket::TcpSocket;

/// A trait for tracking a socket usage sessions.
///
/// Allows implementation of custom on-drop logic.
pub trait Session {
    fn finish(&mut self) {}
}

#[cfg(feature = "socket-raw")]
impl<'a, 'b> Session for RawSocket<'a, 'b> {}
#[cfg(feature = "socket-udp")]
impl<'a, 'b> Session for UdpSocket<'a, 'b> {}
#[cfg(feature = "socket-tcp")]
impl<'a> Session for TcpSocket<'a> {}

impl<'a, 'b> Session for Socket<'a, 'b> {
    fn finish(&mut self) {
        match *self {
            #[cfg(feature = "socket-raw")]
            Socket::Raw(ref mut raw_socket) => {
                raw_socket.finish();
            }
            #[cfg(feature = "socket-udp")]
            Socket::Udp(ref mut udp_socket) => {
                udp_socket.finish();
            }
            #[cfg(feature = "socket-tcp")]
            Socket::Tcp(ref mut tcp_socket) => {
                tcp_socket.finish();
            }
            Socket::__Nonexhaustive(_) => unreachable!(),
        }
    }
}

/// A tracking smart-pointer to a socket.
///
/// Implements `Deref` and `DerefMut` to the socket it contains.
pub struct Ref<'a, T: Session + 'a> {
    socket: &'a mut T,
    handle: SocketHandle,
    fused: bool,
}

impl<'a, T: Session> Ref<'a, T> {
    pub(crate) fn new(socket: &'a mut T, handle: SocketHandle) -> Self {
        Ref {
            socket,
            handle,
            fused: true,
        }
    }
}

impl<'a, 'b, 'c, T: FromSocket<'b, 'c>> Ref<'a, T> {
    pub(crate) fn from_socket_ref(mut socket_ref: Ref<'a, Socket<'b, 'c>>)
                                  -> Option<Ref<'a, T>> {
        if let Some(socket) = T::downcast_socket(socket_ref.socket) {
            socket_ref.fused = false;
            Some(Ref::new(socket, socket_ref.handle))
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
        if self.fused {
            Session::finish(self.socket);
        }
    }
}
