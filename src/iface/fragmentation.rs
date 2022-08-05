#![allow(unused)]

use core::fmt;

use managed::{ManagedMap, ManagedSlice};

use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::Error;
use crate::Result;

/// Holds different fragments of one packet, used for assembling fragmented packets.
///
/// The buffer used for the `PacketAssembler` should either be dynamically sized (ex: Vec<u8>)
/// or should be statically allocated based upon the MTU of the type of packet being
/// assembled (ex: 1280 for a IPv6 frame).
#[derive(Debug)]
pub struct PacketAssembler<'a> {
    buffer: ManagedSlice<'a, u8>,
    assembler: AssemblerState,
}

/// Holds the state of the assembling of one packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq)]
enum AssemblerState {
    NotInit,
    Assembling {
        assembler: Assembler,
        total_size: Option<usize>,
        expires_at: Instant,
        offset_correction: isize,
    },
}

impl fmt::Display for AssemblerState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AssemblerState::NotInit => write!(f, "Not init")?,
            AssemblerState::Assembling {
                assembler,
                total_size,
                expires_at,
                offset_correction,
            } => {
                write!(f, "{} expires at {}", assembler, expires_at)?;
            }
        }
        Ok(())
    }
}

impl<'a> PacketAssembler<'a> {
    /// Create a new empty buffer for fragments.
    pub fn new<S>(storage: S) -> Self
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        let s = storage.into();
        PacketAssembler {
            buffer: s,
            assembler: AssemblerState::NotInit,
        }
    }

    /// Start with saving fragments.
    /// We initialize the assembler with the total size of the final packet.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerBufferTooSmall`] when the buffer is too small for holding all the
    /// fragments of a packet.
    pub(crate) fn start(
        &mut self,
        total_size: Option<usize>,
        expires_at: Instant,
        offset_correction: isize,
    ) -> Result<()> {
        match &mut self.buffer {
            ManagedSlice::Borrowed(b) => {
                if let Some(total_size) = total_size {
                    if b.len() < total_size {
                        return Err(Error::PacketAssemblerBufferTooSmall);
                    }
                }
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(b) => {
                if let Some(total_size) = total_size {
                    b.resize(total_size, 0);
                }
            }
        }

        self.assembler = AssemblerState::Assembling {
            assembler: Assembler::new(if let Some(total_size) = total_size {
                total_size
            } else {
                usize::MAX
            }),
            total_size,
            expires_at,
            offset_correction,
        };

        Ok(())
    }

    /// Set the total size of the packet assembler.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the assembler was not initialized (try initializing the
    /// assembler with [Self::start]).
    pub(crate) fn set_total_size(&mut self, size: usize) -> Result<()> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling {
                ref mut total_size, ..
            } => {
                *total_size = Some(size);
                Ok(())
            }
        }
    }

    /// Return the instant when the assembler expires.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the assembler was not initialized (try initializing the
    /// assembler with [Self::start]).
    pub(crate) fn expires_at(&self) -> Result<Instant> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling { expires_at, .. } => Ok(expires_at),
        }
    }

    /// Add a fragment into the packet that is being reassembled.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the assembler was not initialized (try initializing the
    /// assembler with [Self::start]).
    /// - Returns [`Error::PacketAssemblerBufferTooSmall`] when trying to add data into the buffer at a non-existing
    /// place.
    /// - Returns [`Error::PacketAssemblerOverlap`] when there was an overlap when adding data.
    pub(crate) fn add(&mut self, data: &[u8], offset: usize) -> Result<bool> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling {
                ref mut assembler,
                total_size,
                offset_correction,
                ..
            } => {
                let offset = offset as isize + offset_correction;
                let offset = if offset <= 0 { 0 } else { offset as usize };

                match &mut self.buffer {
                    ManagedSlice::Borrowed(b) => {
                        if offset + data.len() > b.len() {
                            return Err(Error::PacketAssemblerBufferTooSmall);
                        }
                    }
                    #[cfg(any(feature = "std", feature = "alloc"))]
                    ManagedSlice::Owned(b) => {
                        if offset + data.len() > b.len() {
                            b.resize(offset + data.len(), 0);
                        }
                    }
                }

                let len = data.len();
                self.buffer[offset..][..len].copy_from_slice(data);

                net_debug!(
                    "frag assembler: receiving {} octests at offset {}",
                    len,
                    offset
                );

                match assembler.add(offset, data.len()) {
                    Ok(overlap) => {
                        net_debug!("assembler: {}", self.assembler);

                        if overlap {
                            net_debug!("packet was added, but there was an overlap.");
                        }
                        self.is_complete()
                    }
                    // NOTE(thvdveld): hopefully we wont get too many holes errors I guess?
                    Err(_) => Err(Error::PacketAssemblerTooManyHoles),
                }
            }
        }
    }

    /// Get an immutable slice of the underlying packet data.
    /// This will mark the assembler state as [`AssemblerState::NotInit`] such that it can be reused.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the assembler was not initialized (try initializing the
    /// assembler with [`Self::start`]).
    /// - Returns [`Error::PacketAssemblerIncomplete`] when not all the fragments have been collected.
    pub(crate) fn assemble(&mut self) -> Result<&'_ [u8]> {
        let b = match self.assembler {
            AssemblerState::NotInit => return Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling { total_size, .. } => {
                if self.is_complete()? {
                    // NOTE: we can unwrap because `is_complete` already checks this.
                    let total_size = total_size.unwrap();
                    let a = &self.buffer[..total_size];
                    self.assembler = AssemblerState::NotInit;
                    a
                } else {
                    return Err(Error::PacketAssemblerIncomplete);
                }
            }
        };
        Ok(b)
    }

    /// Returns `true` when all fragments have been received, otherwise `false`.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the assembler was not initialized (try initializing the
    /// assembler with [`Self::start`]).
    pub(crate) fn is_complete(&self) -> Result<bool> {
        match &self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling {
                assembler,
                total_size,
                ..
            } => match (total_size, assembler.peek_front()) {
                (Some(total_size), Some(front)) => Ok(front == *total_size),
                _ => Ok(false),
            },
        }
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.assembler == AssemblerState::NotInit
    }

    /// Mark this assembler as [`AssemblerState::NotInit`].
    /// This is then cleaned up by the [`PacketAssemblerSet`].
    pub fn mark_discarded(&mut self) {
        self.assembler = AssemblerState::NotInit;
    }

    /// Returns `true` when the [`AssemblerState`] is discarded.
    pub fn is_discarded(&self) -> bool {
        matches!(self.assembler, AssemblerState::NotInit)
    }
}

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
pub struct PacketAssemblerSet<'a, Key: Eq + Ord + Clone + Copy> {
    packet_buffer: ManagedSlice<'a, PacketAssembler<'a>>,
    index_buffer: ManagedMap<'a, Key, usize>,
}

impl<'a, K: Eq + Ord + Clone + Copy> PacketAssemblerSet<'a, K> {
    /// Create a new set of packet assemblers.
    ///
    /// # Panics
    ///
    /// This will panic when:
    ///   - The packet buffer and index buffer don't have the same size or are empty (when they are
    ///   both borrowed).
    ///   - The packet buffer is empty (when only the packet buffer is borrowed).
    ///   - The index buffer is empty (when only the index buffer is borrowed).
    pub fn new<FB, IB>(packet_buffer: FB, index_buffer: IB) -> Self
    where
        FB: Into<ManagedSlice<'a, PacketAssembler<'a>>>,
        IB: Into<ManagedMap<'a, K, usize>>,
    {
        let packet_buffer = packet_buffer.into();
        let index_buffer = index_buffer.into();

        match (&packet_buffer, &index_buffer) {
            (ManagedSlice::Borrowed(f), ManagedMap::Borrowed(i)) => {
                if f.len() != i.len() {
                    panic!("The amount of places in the index buffer must be the same as the amount of possible fragments assemblers.");
                }
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            (ManagedSlice::Borrowed(f), ManagedMap::Owned(_)) => {
                if f.is_empty() {
                    panic!("The packet buffer cannot be empty.");
                }
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            (ManagedSlice::Owned(_), ManagedMap::Borrowed(i)) => {
                if i.is_empty() {
                    panic!("The index buffer cannot be empty.");
                }
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            (ManagedSlice::Owned(_), ManagedMap::Owned(_)) => (),
        }

        Self {
            packet_buffer,
            index_buffer,
        }
    }

    /// Reserve a [`PacketAssembler`], which is linked to a specific key.
    /// Returns the reserved fragments assembler.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerSetFull`] when every [`PacketAssembler`] in the buffer is used (only
    /// when the non allocating version of is used).
    pub(crate) fn reserve_with_key(&mut self, key: &K) -> Result<&mut PacketAssembler<'a>> {
        // Check how many WIP reassemblies we have.
        // The limit is currently set to 255.
        if self.index_buffer.len() == u8::MAX as usize {
            return Err(Error::PacketAssemblerSetFull);
        }

        if self.packet_buffer.len() == self.index_buffer.len() {
            match &mut self.packet_buffer {
                ManagedSlice::Borrowed(_) => return Err(Error::PacketAssemblerSetFull),
                #[cfg(any(feature = "std", feature = "alloc"))]
                ManagedSlice::Owned(b) => (),
            }
        }

        let i = self
            .get_free_packet_assembler()
            .ok_or(Error::PacketAssemblerSetFull)?;

        // NOTE(thvdveld): this should not fail because we already checked the available space.
        match self.index_buffer.insert(*key, i) {
            Ok(_) => Ok(&mut self.packet_buffer[i]),
            Err(_) => unreachable!(),
        }
    }

    /// Return the first free packet assembler available from the cache.
    fn get_free_packet_assembler(&mut self) -> Option<usize> {
        match &mut self.packet_buffer {
            ManagedSlice::Borrowed(_) => (),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(b) => b.push(PacketAssembler::new(alloc::vec![])),
        }

        self.packet_buffer
            .iter()
            .enumerate()
            .find(|(_, b)| b.is_free())
            .map(|(i, _)| i)
    }

    /// Return a mutable slice to a packet assembler.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerSetKeyNotFound`] when the key was not found in the set.
    pub(crate) fn get_packet_assembler_mut(&mut self, key: &K) -> Result<&mut PacketAssembler<'a>> {
        if let Some(i) = self.index_buffer.get(key) {
            Ok(&mut self.packet_buffer[*i as usize])
        } else {
            Err(Error::PacketAssemblerSetKeyNotFound)
        }
    }

    /// Return the assembled packet from a packet assembler.
    /// This also removes it from the set.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerSetKeyNotFound`] when the `key` was not found.
    /// - Returns [`Error::PacketAssemblerIncomplete`] when the fragments assembler was empty or not fully assembled.
    pub(crate) fn get_assembled_packet(&mut self, key: &K) -> Result<&[u8]> {
        if let Some(i) = self.index_buffer.get(key) {
            let p = self.packet_buffer[*i as usize].assemble()?;
            self.index_buffer.remove(key);
            Ok(p)
        } else {
            Err(Error::PacketAssemblerSetKeyNotFound)
        }
    }

    /// Remove all [`PacketAssembler`]s that are marked as discarded.
    pub fn remove_discarded(&mut self) {
        loop {
            let mut key = None;
            for (k, i) in self.index_buffer.iter() {
                if matches!(
                    self.packet_buffer[*i as usize].assembler,
                    AssemblerState::NotInit
                ) {
                    key = Some(*k);
                    break;
                }
            }

            if let Some(k) = key {
                self.index_buffer.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Mark all [`PacketAssembler`]s as discarded for which `f` returns `Ok(true)`.
    /// This does not remove them from the buffer.
    pub fn mark_discarded_when<F>(&mut self, f: F) -> Result<()>
    where
        F: Fn(&mut PacketAssembler<'_>) -> Result<bool>,
    {
        for (_, i) in &mut self.index_buffer.iter() {
            let frag = &mut self.packet_buffer[*i as usize];
            if f(frag)? {
                frag.mark_discarded();
            }
        }

        Ok(())
    }

    /// Remove all [`PacketAssembler`]s for which `f` returns `Ok(true)`.
    pub fn remove_when<F>(&mut self, f: F) -> Result<()>
    where
        F: Fn(&mut PacketAssembler<'_>) -> Result<bool>,
    {
        self.mark_discarded_when(f)?;
        self.remove_discarded();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key {
        id: usize,
    }

    #[test]
    fn packet_assembler_not_init() {
        let mut p_assembler = PacketAssembler::new(vec![]);
        let data = b"Hello World!";
        assert_eq!(
            p_assembler.add(&data[..], data.len()),
            Err(Error::PacketAssemblerNotInit)
        );

        assert_eq!(
            p_assembler.is_complete(),
            Err(Error::PacketAssemblerNotInit)
        );
        assert_eq!(p_assembler.assemble(), Err(Error::PacketAssemblerNotInit));
    }

    #[test]
    fn packet_assembler_buffer_too_small() {
        let mut storage = [0u8; 1];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        assert_eq!(
            p_assembler.start(Some(2), Instant::from_secs(0), 0),
            Err(Error::PacketAssemblerBufferTooSmall)
        );
        assert_eq!(p_assembler.start(Some(1), Instant::from_secs(0), 0), Ok(()));

        let data = b"Hello World!";
        assert_eq!(
            p_assembler.add(&data[..], data.len()),
            Err(Error::PacketAssemblerBufferTooSmall)
        );
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut storage = [0u8; 5];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        p_assembler
            .start(Some(5), Instant::from_secs(0), 0)
            .unwrap();
        let data = b"Rust";

        p_assembler.add(&data[..], 0).unwrap();

        assert_eq!(p_assembler.add(&data[..], 1), Ok(true));
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut storage = [0u8; 12];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        let data = b"Hello World!";

        p_assembler
            .start(Some(data.len()), Instant::from_secs(0), 0)
            .unwrap();

        p_assembler.add(b"Hello ", 0).unwrap();
        assert_eq!(
            p_assembler.assemble(),
            Err(Error::PacketAssemblerIncomplete)
        );

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();

        assert_eq!(p_assembler.assemble(), Ok(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_out_of_order_assemble() {
        let mut storage = [0u8; 12];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        let data = b"Hello World!";

        p_assembler
            .start(Some(data.len()), Instant::from_secs(0), 0)
            .unwrap();

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();
        assert_eq!(
            p_assembler.assemble(),
            Err(Error::PacketAssemblerIncomplete)
        );

        p_assembler.add(b"Hello ", 0).unwrap();

        assert_eq!(p_assembler.assemble(), Ok(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_set() {
        let key = Key { id: 1 };

        let mut set = PacketAssemblerSet::<'_, _>::new(vec![], std::collections::BTreeMap::new());

        if let Err(e) = set.get_packet_assembler_mut(&key) {
            assert_eq!(e, Error::PacketAssemblerSetKeyNotFound);
        }

        assert!(set.reserve_with_key(&key).is_ok());
    }

    #[test]
    fn packet_assembler_set_borrowed() {
        let mut buf = [0u8, 127];
        let mut packet_assembler_cache = [PacketAssembler::<'_>::new(&mut buf[..])];
        let mut packet_index_cache = [None];

        let key = Key { id: 1 };

        let mut set =
            PacketAssemblerSet::new(&mut packet_assembler_cache[..], &mut packet_index_cache[..]);

        if let Err(e) = set.get_packet_assembler_mut(&key) {
            assert_eq!(e, Error::PacketAssemblerSetKeyNotFound);
        }

        assert!(set.reserve_with_key(&key).is_ok());
    }

    #[test]
    fn packet_assembler_set_assembling_many() {
        let mut buf = [0u8, 127];
        let mut packet_assembler_cache = [PacketAssembler::new(&mut buf[..])];
        let mut packet_index_cache = [None];

        let mut set =
            PacketAssemblerSet::new(&mut packet_assembler_cache[..], &mut packet_index_cache[..]);

        let key = Key { id: 0 };
        set.reserve_with_key(&key).unwrap();
        set.get_packet_assembler_mut(&key)
            .unwrap()
            .start(Some(0), Instant::from_secs(0), 0)
            .unwrap();
        set.get_assembled_packet(&key).unwrap();

        let key = Key { id: 1 };
        set.reserve_with_key(&key).unwrap();
        set.get_packet_assembler_mut(&key)
            .unwrap()
            .start(Some(0), Instant::from_secs(0), 0)
            .unwrap();
        set.get_assembled_packet(&key).unwrap();

        let key = Key { id: 2 };
        set.reserve_with_key(&key).unwrap();
        set.get_packet_assembler_mut(&key)
            .unwrap()
            .start(Some(0), Instant::from_secs(0), 0)
            .unwrap();
        set.get_assembled_packet(&key).unwrap();
    }
}
