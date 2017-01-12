use managed::ManagedSlice;
use core::slice;

use super::Socket;

/// A handle, identifying a socket in a set.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Handle {
    index: usize
}

/// An extensible set of sockets, with stable numeric identifiers.
#[derive(Debug)]
pub struct Set<'a, 'b: 'a, 'c: 'a + 'b> {
    sockets: ManagedSlice<'a, Option<Socket<'b, 'c>>>
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Set<'a, 'b, 'c> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> Set<'a, 'b, 'c>
            where SocketsT: Into<ManagedSlice<'a, Option<Socket<'b, 'c>>>> {
        let sockets = sockets.into();
        Set {
            sockets: sockets
        }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add(&mut self, socket: Socket<'b, 'c>) -> Handle {
        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(socket);
                return Handle { index: index }
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => {
                panic!("adding a socket to a full SocketSet")
            }
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(Some(socket));
                Handle { index: sockets.len() - 1 }
            }
        }
    }

    /// Get a socket from the set by its handle.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn get(&self, handle: Handle) -> &Socket<'b, 'c> {
        self.sockets[handle.index]
            .as_ref()
            .expect("handle does not refer to a valid socket")
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn get_mut(&mut self, handle: Handle) -> &mut Socket<'b, 'c> {
        self.sockets[handle.index]
            .as_mut()
            .expect("handle does not refer to a valid socket")
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: Handle) {
        assert!(self.sockets[handle.index].is_some());
        self.sockets[handle.index] = None
    }

    /// Iterate every socket in this set.
    pub fn iter<'d>(&'d self) -> Iter<'d, 'b, 'c> {
        Iter { lower: self.sockets.iter() }
    }

    /// Iterate every socket in this set, as mutable.
    pub fn iter_mut<'d>(&'d mut self) -> IterMut<'d, 'b, 'c> {
        IterMut { lower: self.sockets.iter_mut() }
    }
}

/// Immutable socket set iterator.
///
/// This struct is created by the [iter](struct.SocketSet.html#method.iter)
/// on [socket sets](struct.SocketSet.html).
pub struct Iter<'a, 'b: 'a, 'c: 'a + 'b> {
    lower: slice::Iter<'a, Option<Socket<'b, 'c>>>
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Iterator for Iter<'a, 'b, 'c> {
    type Item = &'a Socket<'b, 'c>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(socket_opt) = self.lower.next() {
            if let Some(socket) = socket_opt.as_ref() {
                return Some(socket)
            }
        }
        None
    }
}

/// Mutable socket set iterator.
///
/// This struct is created by the [iter_mut](struct.SocketSet.html#method.iter_mut)
/// on [socket sets](struct.SocketSet.html).
pub struct IterMut<'a, 'b: 'a, 'c: 'a + 'b> {
    lower: slice::IterMut<'a, Option<Socket<'b, 'c>>>
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Iterator for IterMut<'a, 'b, 'c> {
    type Item = &'a mut Socket<'b, 'c>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(socket_opt) = self.lower.next() {
            if let Some(socket) = socket_opt.as_mut() {
                return Some(socket)
            }
        }
        None
    }
}
