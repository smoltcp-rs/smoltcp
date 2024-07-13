use core::fmt;

use managed::{ManagedSlice, SlotVec};

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};

/// Opaque struct with space for storing one handle.
///
/// A handle, identifying a socket in an Interface.
///
/// The [`new`] method can be used to bind a unique index id to a handle,
/// which is usually the index generated when it is added to a socket set
/// so that it can be retrieved from the socket set. Of course, external
/// relationships can also be provided to index the corresponding socket.
///
/// For simplicity, we do not set the field `handle_id` as a generic input.
/// When customizing the [`AnySocketSet`] implementation, external relations
/// need to decide the conversion themselves.
///
/// [`new`]: SocketHandle::new
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug)]
pub struct SocketStorage<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// A set of sockets trait.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.
pub trait AnySocketSet<'a> {
    /// Returns an iterator over the items in the socket set, immutable version..
    fn items<'s>(&'s self) -> impl Iterator<Item = &'s SocketStorage<'a>>
    where
        'a: 's;

    /// Returns an iterator over the items in the socket set, mutable version.
    fn items_mut<'s>(&'s mut self) -> impl Iterator<Item = &'s mut SocketStorage<'a>>
    where
        'a: 's;
}

impl SocketHandle {
    pub fn new(handle_id: usize) -> Self {
        Self(handle_id)
    }
}

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl<'a> SocketStorage<'a> {
    pub fn new(handle: SocketHandle, socket: Socket<'a>) -> Self {
        let mut meta = Meta::default();
        meta.handle = handle;
        Self { meta, socket }
    }
}

/// An extensible set of sockets which implements default [`AnySocketSet`].
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: SlotVec<'a, SocketStorage<'a>>,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, Option<SocketStorage<'a>>>>,
    {
        let sockets = SlotVec::new(sockets.into());
        SocketSet { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        let index = self
            .sockets
            .push_with(|index| {
                net_trace!("[{}]: adding", index);
                let handle = SocketHandle::new(index);
                let socket = socket.upcast();
                SocketStorage::new(handle, socket)
            })
            .expect("adding a socket to a full SocketSet");
        self.sockets[index].meta.handle
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        let item = self
            .sockets
            .get(handle.0)
            .expect("handle does not refer to a valid socket");
        T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        let item = self
            .sockets
            .get_mut(handle.0)
            .expect("handle does not refer to a valid socket");
        T::downcast_mut(&mut item.socket).expect("handle refers to a socket of a wrong type")
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        self.sockets
            .remove(handle.0)
            .map(|item| item.socket)
            .expect("handle does not refer to a valid socket")
    }

    /// Checks the handle refers to a valid socket.
    ///
    /// Returns true if the handle refers to a valid socket,
    /// or false if matches any of the following:
    /// - the handle does not belong to this socket set,
    /// - the handle refers to a socket has the wrong type.
    pub fn check<T: AnySocket<'a>>(&self, handle: SocketHandle) -> bool {
        self.sockets
            .get(handle.0)
            .and_then(|item| T::downcast(&item.socket))
            .is_some()
    }
}

/// A default implementation for [`AnySocketSet`].
impl<'a> AnySocketSet<'a> for SocketSet<'a> {
    fn items<'s>(&'s self) -> impl Iterator<Item = &'s SocketStorage<'a>>
    where
        'a: 's,
    {
        self.sockets.iter()
    }

    fn items_mut<'s>(&'s mut self) -> impl Iterator<Item = &'s mut SocketStorage<'a>>
    where
        'a: 's,
    {
        self.sockets.iter_mut()
    }
}
