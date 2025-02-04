use core::fmt;
use managed::ManagedSlice;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'a> {
    inner: Option<Item<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

#[cfg(test)]
pub(crate) fn new_handle(index: usize) -> SocketHandle {
    SocketHandle(index)
}

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: ManagedSlice<'a, SocketStorage<'a>>,
    first_empty_index: usize,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let sockets = sockets.into();
        SocketSet {
            sockets,
            first_empty_index: 0,
        }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a>(index: usize, slot: &mut SocketStorage<'a>, socket: Socket<'a>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        if self.first_empty_index < self.sockets.len() {
            let handle = put(
                self.first_empty_index,
                &mut self.sockets[self.first_empty_index],
                socket,
            );

            for i in (self.first_empty_index + 1)..self.sockets.len() {
                if self.sockets[i].inner.is_none() {
                    self.first_empty_index = i;
                    return handle;
                }
            }

            self.first_empty_index = self.sockets.len();
            return handle;
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                self.first_empty_index = sockets.len();
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].inner.take() {
            Some(item) => {
                if handle.0 < self.first_empty_index {
                    self.first_empty_index = handle.0;
                }

                item.socket
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }
}

#[cfg(test)]
#[cfg(all(feature = "socket-tcp", any(feature = "std", feature = "alloc")))]
pub(crate) mod test {
    use crate::iface::socket_set::new_handle;
    use crate::iface::SocketSet;
    use crate::socket::tcp;
    use crate::socket::tcp::Socket;
    use std::ptr;

    fn gen_owned_socket() -> Socket<'static> {
        let rx = tcp::SocketBuffer::new(vec![0; 1]);
        let tx = tcp::SocketBuffer::new(vec![0; 1]);
        Socket::new(rx, tx)
    }

    fn gen_owned_socket_set(size: usize) -> SocketSet<'static> {
        let mut socket_set = SocketSet::new(Vec::with_capacity(size));
        for _ in 0..size {
            socket_set.add(gen_owned_socket());
        }

        socket_set
    }

    #[test]
    fn test_add() {
        let socket_set = gen_owned_socket_set(5);
        assert_eq!(socket_set.first_empty_index, 5);
    }

    #[test]
    fn test_remove() {
        let mut socket_set = gen_owned_socket_set(10);

        let removed_socket = socket_set.remove(new_handle(5));
        for socket in socket_set.iter() {
            assert!(!ptr::eq(socket.1, &removed_socket));
        }

        assert_eq!(socket_set.first_empty_index, 5);
    }

    #[test]
    fn test_remove_add_integrity() {
        let mut socket_set = gen_owned_socket_set(10);

        for remove_index in 0..10 {
            let removed_socket = socket_set.remove(new_handle(remove_index));
            for socket in socket_set.iter() {
                assert!(!ptr::eq(socket.1, &removed_socket));
            }

            let new_socket = gen_owned_socket();
            let handle = socket_set.add(new_socket);
            assert_eq!(handle.0, remove_index);
        }

        assert_eq!(socket_set.first_empty_index, 10);
    }

    #[test]
    fn test_full_reconstruct() {
        let mut socket_set = gen_owned_socket_set(10);

        for index in 0..10 {
            socket_set.remove(new_handle(index));
        }

        assert_eq!(socket_set.first_empty_index, 0);

        for _ in 0..10 {
            socket_set.add(gen_owned_socket());
        }

        assert_eq!(socket_set.first_empty_index, 10);
    }
}
