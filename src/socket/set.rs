use core::fmt;
use managed::ManagedSlice;

use crate::socket::{AnySocket, Socket};

use super::meta::Meta;

/// An item of a socket set.
///
/// The only reason this struct is public is to allow the socket set storage
/// to be allocated externally.
#[derive(Debug)]
pub struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// A handle, identifying a socket in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Handle(usize);

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.
#[derive(Debug)]
pub struct Set<'a> {
    sockets: ManagedSlice<'a, Option<Item<'a>>>,
}

impl<'a> Set<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> Set<'a>
    where
        SocketsT: Into<ManagedSlice<'a, Option<Item<'a>>>>,
    {
        let sockets = sockets.into();
        Set { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> Handle {
        fn put<'a>(index: usize, slot: &mut Option<Item<'a>>, socket: Socket<'a>) -> Handle {
            net_trace!("[{}]: adding", index);
            let handle = Handle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = Some(Item { socket, meta });
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                return put(index, slot, socket);
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(None);
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&mut self, handle: Handle) -> &mut T {
        match self.sockets[handle.0].as_mut() {
            Some(item) => {
                T::downcast(&mut item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: Handle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Iterate every socket in this set.
    pub fn iter(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.as_ref())
    }

    /// Iterate every socket in this set.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.as_mut())
    }
}
