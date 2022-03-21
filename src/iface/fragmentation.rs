#![allow(unused)]

use managed::{ManagedMap, ManagedSlice};

use crate::storage::Assembler;
use crate::time::Instant;
use crate::Error;
use crate::Result;

pub trait PacketAssemblerInfo: PartialEq {
    /// Calculate a new offset based on some other information.
    fn calc_offset(&self, offset: usize) -> usize;
}

#[derive(Debug, PartialEq)]
pub struct NoInfo;

impl PacketAssemblerInfo for NoInfo {
    #[inline]
    fn calc_offset(&self, offset: usize) -> usize {
        offset
    }
}

/// Holds different fragments of one packet, used for assembling fragmented packets.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketAssembler<'a, Info: PacketAssemblerInfo = NoInfo> {
    buffer: ManagedSlice<'a, u8>,
    assembler: AssemblerState<Info>,
}

/// Holds the state of the assembling of one packet.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum AssemblerState<Info: PacketAssemblerInfo = NoInfo> {
    NotInit,
    Assembling {
        assembler: Assembler,
        total_size: usize,
        info: Info,
        last_updated: Instant,
        started_on: Instant,
    },
}

impl<'a, Info: PacketAssemblerInfo> PacketAssembler<'a, Info> {
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
    /// - Returns [`Error::PacketAssemblerBufferTooSmall`] when the buffer is too smal for holding all the
    /// fragments of a packet.
    pub(crate) fn start(
        &mut self,
        total_size: usize,
        info: Info,
        start_time: Instant,
    ) -> Result<()> {
        match &mut self.buffer {
            ManagedSlice::Borrowed(b) if b.len() < total_size => {
                return Err(Error::PacketAssemblerBufferTooSmall);
            }
            ManagedSlice::Borrowed(_) => (),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(b) => {
                b.resize(total_size, 0);
            }
        }

        self.assembler = AssemblerState::Assembling {
            assembler: Assembler::new(total_size),
            total_size,
            info,
            last_updated: start_time,
            started_on: start_time,
        };

        Ok(())
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
    pub(crate) fn add(&mut self, data: &[u8], offset: usize, now: Instant) -> Result<bool> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling {
                ref mut assembler,
                total_size,
                ref info,
                ref mut last_updated,
                ..
            } => {
                let offset = info.calc_offset(offset);

                if offset + data.len() > total_size {
                    return Err(Error::PacketAssemblerBufferTooSmall);
                }

                let len = data.len();
                self.buffer[offset..][..len].copy_from_slice(data);

                match assembler.add(offset, data.len()) {
                    Ok(false) => {
                        *last_updated = now;
                        self.is_complete()
                    }
                    Ok(true) => Err(Error::PacketAssemblerOverlap),
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
            } => {
                if let Some(front) = assembler.peek_front() {
                    Ok(front == *total_size)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.assembler == AssemblerState::NotInit
    }

    /// Returns the [`Instant`] when the packet assembler was started.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the packet assembler was not initialized.
    pub fn start_time(&self) -> Result<Instant> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling { started_on, .. } => Ok(started_on),
        }
    }

    /// Returns the [`Instant`] when the packet assembler was last updated.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerNotInit`] when the packet assembler was not initialized.
    pub fn last_update_time(&self) -> Result<Instant> {
        match self.assembler {
            AssemblerState::NotInit => Err(Error::PacketAssemblerNotInit),
            AssemblerState::Assembling { last_updated, .. } => Ok(last_updated),
        }
    }

    /// Mark this assembler as [`AssemblerState::NotInit`].
    /// This is then cleaned up by the [`PacketAssemblerSet`].
    pub fn mark_discarded(&mut self) {
        self.assembler = AssemblerState::NotInit;
    }
}

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketAssemblerSet<'a, Key: Eq + Ord + Clone + Copy, Info: PacketAssemblerInfo> {
    packet_buffer: ManagedSlice<'a, PacketAssembler<'a, Info>>,
    index_buffer: ManagedMap<'a, Key, u8>,
}

impl<'a, K: Eq + Ord + Clone + Copy, Info: PacketAssemblerInfo> PacketAssemblerSet<'a, K, Info> {
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
        FB: Into<ManagedSlice<'a, PacketAssembler<'a, Info>>>,
        IB: Into<ManagedMap<'a, K, u8>>,
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
    pub(crate) fn reserve_with_key(&mut self, key: &K) -> Result<&mut PacketAssembler<'a, Info>> {
        if self.packet_buffer.len() == self.index_buffer.len() {
            match &mut self.packet_buffer {
                ManagedSlice::Borrowed(_) => return Err(Error::PacketAssemblerSetFull),
                #[cfg(any(feature = "std", feature = "alloc"))]
                ManagedSlice::Owned(b) => {
                    b.resize_with(self.index_buffer.len() + 1, || {
                        PacketAssembler::new(Vec::new())
                    });
                }
            }
        }

        let i = self
            .get_free_packet_assembler()
            .ok_or(Error::PacketAssemblerSetFull)?;

        // NOTE(thvdveld): this should not fail because we already checked the available space.
        match self.index_buffer.insert(*key, i as u8) {
            Ok(_) => Ok(&mut self.packet_buffer[i]),
            Err(_) => unreachable!(),
        }
    }

    /// Return the first free packet assembler available from the cache.
    fn get_free_packet_assembler(&self) -> Option<usize> {
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
    pub(crate) fn get_packet_assembler_mut(
        &mut self,
        key: &K,
    ) -> Result<&mut PacketAssembler<'a, Info>> {
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

    /// Remove all [`PacketAssembler`]s that are marked as discared.
    pub fn remove_discarded(&mut self) {
        loop {
            let mut key = None;
            for (k, i) in self.index_buffer.iter() {
                if self.packet_buffer[*i as usize].assembler == AssemblerState::NotInit {
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

    /// Remove all [`PacketAssembler`]s for which `f` returns `Ok(true)`.
    pub fn remove_when(
        &mut self,
        f: impl Fn(&mut PacketAssembler<'_, Info>) -> Result<bool>,
    ) -> Result<()> {
        for (_, i) in &mut self.index_buffer.iter() {
            let frag = &mut self.packet_buffer[*i as usize];
            if f(frag)? {
                frag.mark_discarded();
            }
        }
        self.remove_discarded();

        Ok(())
    }
}

#[cfg(feature = "proto-sixlowpan")]
pub mod sixlowpan {
    #[derive(Debug, PartialEq)]
    pub struct SixlowpanAssemblerInfo {
        header_size: usize,
    }

    impl SixlowpanAssemblerInfo {
        pub fn new(header_size: usize) -> Self {
            SixlowpanAssemblerInfo { header_size }
        }
    }

    impl super::PacketAssemblerInfo for SixlowpanAssemblerInfo {
        #[inline]
        fn calc_offset(&self, offset: usize) -> usize {
            match offset {
                0 => 0,
                offset => offset - self.header_size,
            }
        }
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
        let mut p_assembler = PacketAssembler::<NoInfo>::new(vec![]);
        let data = b"Hello World!";
        assert_eq!(
            p_assembler.add(&data[..], data.len(), Instant::now()),
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
        let mut p_assembler = PacketAssembler::<NoInfo>::new(&mut storage[..]);

        assert_eq!(
            p_assembler.start(2, NoInfo, Instant::now()),
            Err(Error::PacketAssemblerBufferTooSmall)
        );
        assert_eq!(p_assembler.start(1, NoInfo, Instant::now()), Ok(()));

        let data = b"Hello World!";
        assert_eq!(
            p_assembler.add(&data[..], data.len(), Instant::now()),
            Err(Error::PacketAssemblerBufferTooSmall)
        );
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut storage = [0u8; 5];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        p_assembler.start(5, NoInfo, Instant::now()).unwrap();
        let data = b"Rust";

        p_assembler.add(&data[..], 0, Instant::now()).unwrap();

        assert_eq!(
            p_assembler.add(&data[..], 1, Instant::now()),
            Err(Error::PacketAssemblerOverlap),
        );
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut storage = [0u8; 12];
        let mut p_assembler = PacketAssembler::new(&mut storage[..]);

        let data = b"Hello World!";

        p_assembler
            .start(data.len(), NoInfo, Instant::now())
            .unwrap();

        p_assembler.add(b"Hello ", 0, Instant::now()).unwrap();
        assert_eq!(
            p_assembler.assemble(),
            Err(Error::PacketAssemblerIncomplete)
        );

        p_assembler
            .add(b"World!", b"Hello ".len(), Instant::now())
            .unwrap();

        assert_eq!(p_assembler.assemble(), Ok(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_set() {
        let key = Key { id: 1 };

        let mut set =
            PacketAssemblerSet::<'_, _, NoInfo>::new(vec![], std::collections::BTreeMap::new());

        if let Err(e) = set.get_packet_assembler_mut(&key) {
            assert_eq!(e, Error::PacketAssemblerSetKeyNotFound);
        }

        assert!(set.reserve_with_key(&key).is_ok());
    }

    #[test]
    fn packet_assembler_set_borrowed() {
        let mut buf = [0u8, 127];
        let mut packet_assembler_cache = [PacketAssembler::<'_, NoInfo>::new(&mut buf[..])];
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
            .start(0, NoInfo, Instant::now())
            .unwrap();
        set.get_assembled_packet(&key).unwrap();

        let key = Key { id: 1 };
        set.reserve_with_key(&key).unwrap();
        set.get_packet_assembler_mut(&key)
            .unwrap()
            .start(0, NoInfo, Instant::now())
            .unwrap();
        set.get_assembled_packet(&key).unwrap();

        let key = Key { id: 2 };
        set.reserve_with_key(&key).unwrap();
        set.get_packet_assembler_mut(&key)
            .unwrap()
            .start(0, NoInfo, Instant::now())
            .unwrap();
        set.get_assembled_packet(&key).unwrap();
    }
}
