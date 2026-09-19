#![allow(unused)]

use core::fmt;

use managed::{ManagedMap, ManagedSlice};

use crate::config::{FRAGMENTATION_BUFFER_SIZE, REASSEMBLY_BUFFER_COUNT, REASSEMBLY_BUFFER_SIZE};
use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::wire::*;

use core::result::Result;

#[cfg(feature = "alloc")]
type Buffer = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
type Buffer = [u8; REASSEMBLY_BUFFER_SIZE];

/// Problem when assembling: something was out of bounds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerError;

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerError")
    }
}

impl core::error::Error for AssemblerError {}

/// Packet assembler is full
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerFullError;

impl fmt::Display for AssemblerFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerFullError")
    }
}

impl core::error::Error for AssemblerFullError {}

/// Holds different fragments of one packet, used for assembling fragmented packets.
///
/// The buffer used for the `PacketAssembler` should either be dynamically sized (ex: Vec<u8>)
/// or should be statically allocated based upon the MTU of the type of packet being
/// assembled (ex: 1280 for a IPv6 frame).
#[derive(Debug)]
pub struct PacketAssembler<K> {
    key: Option<K>,
    buffer: Buffer,

    assembler: Assembler,
    total_size: Option<usize>,
    expires_at: Instant,

    /// The largest datagram this slot may assemble, stamped from the set
    /// when the slot is handed out.
    max_len: usize,

    /// What the FIRST fragment of an IPv6 datagram said, kept because the
    /// reassembled packet's header comes from it (RFC 8200 section 4.5) and
    /// the fragment that completes the datagram is usually not that one.
    ///
    /// It lives here rather than in a table beside the set so that it is
    /// cleared by the same `reset` that frees the slot; a side table would be
    /// one more thing to keep in step with expiry and eviction.
    #[cfg(feature = "proto-ipv6-fragmentation")]
    ipv6_first_fragment: Option<Ipv6FirstFragment>,
}

/// The fields of an IPv6 datagram that only its first fragment carries.
#[cfg(feature = "proto-ipv6-fragmentation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Ipv6FirstFragment {
    /// The upper-layer protocol, from the first fragment's Fragment header.
    pub next_header: IpProtocol,
    /// The hop limit the reassembled packet is presented with.
    pub hop_limit: u8,
}

impl<K> PacketAssembler<K> {
    /// Create a new empty buffer for fragments.
    pub const fn new() -> Self {
        Self {
            key: None,

            #[cfg(feature = "alloc")]
            buffer: Buffer::new(),
            #[cfg(not(feature = "alloc"))]
            buffer: [0u8; REASSEMBLY_BUFFER_SIZE],

            assembler: Assembler::new(),
            total_size: None,
            expires_at: Instant::ZERO,
            max_len: REASSEMBLY_MAX_LEN_DEFAULT,

            #[cfg(feature = "proto-ipv6-fragmentation")]
            ipv6_first_fragment: None,
        }
    }

    /// Record what this datagram's first fragment carried, if it has arrived.
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fn set_ipv6_first_fragment(&mut self, first: Ipv6FirstFragment) {
        self.ipv6_first_fragment = Some(first);
    }

    /// What this datagram's first fragment carried, or `None` while it has
    /// not arrived yet.
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fn ipv6_first_fragment(&self) -> Option<Ipv6FirstFragment> {
        self.ipv6_first_fragment
    }

    pub(crate) fn reset(&mut self) {
        self.key = None;
        self.assembler.clear();
        self.total_size = None;
        #[cfg(feature = "proto-ipv6-fragmentation")]
        {
            self.ipv6_first_fragment = None;
        }
        self.expires_at = Instant::ZERO;
    }

    /// Set the total size of the packet assembler.
    pub(crate) fn set_total_size(&mut self, size: usize) -> Result<(), AssemblerError> {
        if let Some(old_size) = self.total_size
            && old_size != size
        {
            return Err(AssemblerError);
        }

        if size > self.max_len {
            return Err(AssemblerError);
        }

        #[cfg(not(feature = "alloc"))]
        if self.buffer.len() < size {
            return Err(AssemblerError);
        }

        #[cfg(feature = "alloc")]
        if self.buffer.len() < size {
            self.buffer.resize(size, 0);
        }

        self.total_size = Some(size);
        Ok(())
    }

    /// Return the instant when the assembler expires.
    pub(crate) fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub(crate) fn add_with(
        &mut self,
        offset: usize,
        f: impl Fn(&mut [u8]) -> Result<usize, AssemblerError>,
    ) -> Result<(), AssemblerError> {
        if self.buffer.len() < offset {
            return Err(AssemblerError);
        }

        let len = f(&mut self.buffer[offset..])?;
        assert!(offset + len <= self.buffer.len());

        net_debug!(
            "frag assembler: receiving {} octets at offset {}",
            len,
            offset
        );

        self.assembler
            .add(offset, len)
            .map_err(|_| AssemblerError)?;
        Ok(())
    }

    /// Add a fragment into the packet that is being reassembled.
    ///
    /// # Errors
    ///
    /// - Returns [`AssemblerError`] when trying to add data into the buffer at a non-existing
    ///   place, or when the range cannot be recorded because the assembler
    ///   already holds [`ASSEMBLER_MAX_SEGMENT_COUNT`] discontiguous ranges.
    ///
    /// [`ASSEMBLER_MAX_SEGMENT_COUNT`]: crate::config::ASSEMBLER_MAX_SEGMENT_COUNT
    pub(crate) fn add(&mut self, data: &[u8], offset: usize) -> Result<(), AssemblerError> {
        // Before any growth: under `alloc` the buffer resizes to whatever a
        // fragment's offset asks for, so without this one datagram could
        // make the slot hold `max_len` octets on the strength of a single
        // packet claiming a far offset.
        if offset + data.len() > self.max_len {
            return Err(AssemblerError);
        }

        #[cfg(not(feature = "alloc"))]
        if self.buffer.len() < offset + data.len() {
            return Err(AssemblerError);
        }

        #[cfg(feature = "alloc")]
        if self.buffer.len() < offset + data.len() {
            self.buffer.resize(offset + data.len(), 0);
        }

        let len = data.len();
        self.buffer[offset..][..len].copy_from_slice(data);

        net_debug!(
            "frag assembler: receiving {} octets at offset {}",
            len,
            offset
        );

        self.assembler
            .add(offset, data.len())
            .map_err(|_| AssemblerError)?;
        Ok(())
    }

    /// Get an immutable slice of the underlying packet data, if reassembly complete.
    /// This will mark the assembler as empty, so that it can be reused.
    pub(crate) fn assemble(&mut self) -> Option<&'_ [u8]> {
        if !self.is_complete() {
            return None;
        }

        // NOTE: we can unwrap because `is_complete` already checks this.
        let total_size = self.total_size.unwrap();
        self.reset();
        Some(&self.buffer[..total_size])
    }

    /// Whether a fragment at `offset` of `len` octets would land on top of
    /// one already received (RFC 5722).
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fn overlaps(&self, offset: usize, len: usize) -> bool {
        self.assembler.overlaps(offset, len)
    }

    /// Returns `true` when all fragments have been received, otherwise `false`.
    pub(crate) fn is_complete(&self) -> bool {
        self.total_size == Some(self.assembler.peek_front())
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.key.is_none()
    }
}

/// The largest datagram reassembly will produce unless an embedder lowers
/// it: the most an IP header can describe.
pub const REASSEMBLY_MAX_LEN_DEFAULT: usize = u16::MAX as usize;

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
pub struct PacketAssemblerSet<K: Eq + Copy> {
    assemblers: [PacketAssembler<K>; REASSEMBLY_BUFFER_COUNT],
    max_len: usize,
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    const NEW_PA: PacketAssembler<K> = PacketAssembler::new();

    /// Create a new set of packet assemblers.
    pub fn new() -> Self {
        Self {
            assemblers: [Self::NEW_PA; REASSEMBLY_BUFFER_COUNT],
            max_len: REASSEMBLY_MAX_LEN_DEFAULT,
        }
    }

    /// The largest datagram any slot of this set will assemble.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Bound the largest datagram any slot of this set will assemble.
    ///
    /// Applies to slots handed out from now on; a datagram already being
    /// assembled keeps the bound it started under, so lowering this never
    /// strands a slot holding more than it is allowed to.
    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// Get a [`PacketAssembler`] for a specific key.
    ///
    /// If it doesn't exist, it is created, with the `expires_at` timestamp.
    ///
    /// If the assembler set is full, in which case an error is returned.
    pub(crate) fn get(
        &mut self,
        key: &K,
        expires_at: Instant,
    ) -> Result<&mut PacketAssembler<K>, AssemblerFullError> {
        let mut empty_slot = None;
        for slot in &mut self.assemblers {
            if slot.key.as_ref() == Some(key) {
                return Ok(slot);
            }
            if slot.is_free() {
                empty_slot = Some(slot)
            }
        }

        let slot = empty_slot.ok_or(AssemblerFullError)?;
        // Hand the slot over clean. Under `alloc` its buffer still carries
        // the previous datagram's high-water mark, so without this a single
        // large datagram would pin `max_len` octets per slot for the life of
        // the interface; and clearing keeps stale octets of one datagram
        // from ever being read as part of the next.
        #[cfg(feature = "alloc")]
        {
            slot.buffer.clear();
            slot.buffer.shrink_to(REASSEMBLY_BUFFER_SIZE);
        }
        slot.key = Some(*key);
        slot.expires_at = expires_at;
        slot.max_len = self.max_len;
        Ok(slot)
    }

    /// Remove all [`PacketAssembler`]s that are expired.
    pub fn remove_expired(&mut self, timestamp: Instant) {
        for frag in &mut self.assemblers {
            if !frag.is_free() && frag.expires_at < timestamp {
                frag.reset();
            }
        }
    }
}

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

#[cfg(feature = "_proto-fragmentation")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum FragKey {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    Ipv4(Ipv4FragKey),
    #[cfg(feature = "proto-ipv6-fragmentation")]
    Ipv6(Ipv6FragKey),
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    Sixlowpan(SixlowpanFragKey),
}

/// The reassembly state the IPv6 receive path needs, borrowed field by field
/// rather than as a whole [`FragmentsBuffer`].
///
/// The 6LoWPAN path is why. It decompresses into `FragmentsBuffer`'s
/// `decompress_buf` and hands the resulting slice to `process_ipv6`, so that
/// slice keeps an immutable borrow of one field alive for as long as the
/// packet it produces — which leaves no way to pass `&mut FragmentsBuffer`
/// alongside it. The assembler is a disjoint field, so it can still be
/// handed over on its own.
pub(crate) struct Ipv6Reassembly<'a> {
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub assembler: &'a mut PacketAssemblerSet<FragKey>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub timeout: Duration,
    /// Keeps the lifetime and the type inhabited when IPv6 reassembly is
    /// compiled out, so that callers need no `cfg` on the argument they pass.
    #[cfg(not(feature = "proto-ipv6-fragmentation"))]
    pub _borrow: core::marker::PhantomData<&'a mut ()>,
}

impl<'a> From<&'a mut FragmentsBuffer> for Ipv6Reassembly<'a> {
    fn from(_frag: &'a mut FragmentsBuffer) -> Self {
        Self {
            #[cfg(feature = "proto-ipv6-fragmentation")]
            timeout: _frag.reassembly_timeout,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            assembler: &mut _frag.assembler,
            #[cfg(not(feature = "proto-ipv6-fragmentation"))]
            _borrow: core::marker::PhantomData,
        }
    }
}

pub(crate) struct FragmentsBuffer {
    #[cfg(feature = "proto-sixlowpan")]
    pub decompress_buf: [u8; MAX_DECOMPRESSED_LEN],

    #[cfg(feature = "_proto-fragmentation")]
    pub assembler: PacketAssemblerSet<FragKey>,

    #[cfg(feature = "_proto-fragmentation")]
    pub reassembly_timeout: Duration,
}

#[cfg(not(feature = "_proto-fragmentation"))]
pub(crate) struct Fragmenter {}

#[cfg(not(feature = "_proto-fragmentation"))]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "_proto-fragmentation")]
pub(crate) struct Fragmenter {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    pub buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    pub packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    pub sent_bytes: usize,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub ipv4: Ipv4Fragmenter,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub sixlowpan: SixlowpanFragmenter,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The IPv4 representation.
    pub repr: Ipv4Repr,
    /// The destination hardware address.
    #[cfg(feature = "medium-ethernet")]
    pub dst_hardware_addr: EthernetAddress,
    /// The offset of the next fragment.
    pub frag_offset: u16,
    /// The identifier of the stream.
    pub ident: u16,
}

#[cfg(feature = "proto-sixlowpan-fragmentation")]
pub(crate) struct SixlowpanFragmenter {
    /// The datagram size that is used for the fragmentation headers.
    pub datagram_size: u16,
    /// The datagram tag that is used for the fragmentation headers.
    pub datagram_tag: u16,
    pub datagram_offset: usize,

    /// The size of the FRAG_N packets.
    pub fragn_size: usize,

    /// The link layer IEEE802.15.4 source address.
    pub ll_dst_addr: Ieee802154Address,
    /// The link layer IEEE802.15.4 source address.
    pub ll_src_addr: Ieee802154Address,
}

#[cfg(feature = "_proto-fragmentation")]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
            packet_len: 0,
            sent_bytes: 0,

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4: Ipv4Fragmenter {
                repr: Ipv4Repr {
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: Ipv4Address::new(0, 0, 0, 0),
                    next_header: IpProtocol::Unknown(0),
                    payload_len: 0,
                    hop_limit: 0,
                },
                #[cfg(feature = "medium-ethernet")]
                dst_hardware_addr: EthernetAddress::default(),
                frag_offset: 0,
                ident: 0,
            },

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan: SixlowpanFragmenter {
                datagram_size: 0,
                datagram_tag: 0,
                datagram_offset: 0,
                fragn_size: 0,
                ll_dst_addr: Ieee802154Address::Absent,
                ll_src_addr: Ieee802154Address::Absent,
            },
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    pub(crate) fn reset(&mut self) {
        self.packet_len = 0;
        self.sent_bytes = 0;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        {
            self.ipv4.repr = Ipv4Repr {
                src_addr: Ipv4Address::new(0, 0, 0, 0),
                dst_addr: Ipv4Address::new(0, 0, 0, 0),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            };
            #[cfg(feature = "medium-ethernet")]
            {
                self.ipv4.dst_hardware_addr = EthernetAddress::default();
            }
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        {
            self.sixlowpan.datagram_size = 0;
            self.sixlowpan.datagram_tag = 0;
            self.sixlowpan.fragn_size = 0;
            self.sixlowpan.ll_dst_addr = Ieee802154Address::Absent;
            self.sixlowpan.ll_src_addr = Ieee802154Address::Absent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ASSEMBLER_MAX_SEGMENT_COUNT;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key {
        id: usize,
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        p_assembler.set_total_size(5).unwrap();

        let data = b"Rust";
        p_assembler.add(&data[..], 0).unwrap();
        p_assembler.add(&data[..], 1).unwrap();

        assert_eq!(p_assembler.assemble(), Some(&b"RRust"[..]))
    }

    /// `Assembler::add` refuses a range once `ASSEMBLER_MAX_SEGMENT_COUNT`
    /// discontiguous ranges are already recorded. That refusal used to be
    /// dropped on the floor: the bytes were copied into the buffer, the range
    /// was not recorded, and the datagram could then never complete — it sat
    /// in its slot until the reassembly timeout, with nothing reported.
    #[test]
    fn packet_assembler_reports_a_range_it_could_not_record() {
        let mut p_assembler = PacketAssembler::<Key>::new();
        p_assembler.set_total_size(64).unwrap();

        // One byte every other offset: each is its own contig, so the budget
        // is spent after ASSEMBLER_MAX_SEGMENT_COUNT of them.
        let mut offset = 0;
        for _ in 0..ASSEMBLER_MAX_SEGMENT_COUNT {
            p_assembler.add(&[0xff], offset).unwrap();
            offset += 2;
        }

        assert_eq!(p_assembler.add(&[0xff], offset), Err(AssemblerError));
    }

    /// The bound is what multiplies by the slot count to give the worst
    /// case, so it has to stop the growth rather than notice it afterwards.
    #[test]
    fn a_bounded_set_refuses_to_grow_past_its_ceiling() {
        let mut set = PacketAssemblerSet::<Key>::new();
        assert_eq!(set.max_len(), REASSEMBLY_MAX_LEN_DEFAULT);
        set.set_max_len(64);

        let assr = set.get(&Key { id: 1 }, Instant::ZERO).unwrap();
        assert_eq!(assr.add(&[0xff; 8], 56), Ok(()), "the last octet it may");
        assert_eq!(
            assr.add(&[0xff; 8], 57),
            Err(AssemblerError),
            "one past, refused before anything is copied or resized"
        );
        assert_eq!(assr.set_total_size(65), Err(AssemblerError));
    }

    /// A slot handed out for a new datagram starts clean: under `alloc` the
    /// previous datagram's high-water mark would otherwise be pinned for
    /// the life of the interface.
    #[test]
    #[cfg(feature = "alloc")]
    fn a_reused_slot_gives_its_buffer_back() {
        // Which slot `get` hands out is its own business — it happens to
        // pick the last free one — so this looks at the whole set.
        fn widest(set: &PacketAssemblerSet<Key>) -> usize {
            set.assemblers
                .iter()
                .map(|slot| slot.buffer.capacity())
                .max()
                .unwrap()
        }

        let mut set = PacketAssemblerSet::<Key>::new();

        let assr = set.get(&Key { id: 1 }, Instant::ZERO).unwrap();
        assr.set_total_size(8192).unwrap();
        assr.add(&[0xff; 8192], 0).unwrap();
        assert!(assr.assemble().is_some());
        assert!(
            widest(&set) >= 8192,
            "the datagram grew a buffer: {}",
            widest(&set)
        );

        // Every slot handed out again, so every buffer is given back.
        for id in 0..REASSEMBLY_BUFFER_COUNT {
            let _ = set.get(&Key { id }, Instant::ZERO).unwrap();
        }
        assert!(
            widest(&set) <= REASSEMBLY_BUFFER_SIZE,
            "a slot still holds {} octets",
            widest(&set)
        );
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler.add(b"Hello ", 0).unwrap();
        assert_eq!(p_assembler.assemble(), None);

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();

        assert_eq!(p_assembler.assemble(), Some(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_out_of_order_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler.add(b"World!", b"Hello ".len()).unwrap();
        assert_eq!(p_assembler.assemble(), None);

        p_assembler.add(b"Hello ", 0).unwrap();

        assert_eq!(p_assembler.assemble(), Some(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_set() {
        let key = Key { id: 1 };

        let mut set = PacketAssemblerSet::new();

        assert!(set.get(&key, Instant::ZERO).is_ok());
    }

    #[test]
    fn packet_assembler_set_full() {
        let mut set = PacketAssemblerSet::new();
        for i in 0..REASSEMBLY_BUFFER_COUNT {
            set.get(&Key { id: i }, Instant::ZERO).unwrap();
        }
        assert!(set.get(&Key { id: 4 }, Instant::ZERO).is_err());
    }

    #[test]
    fn packet_assembler_set_assembling_many() {
        let mut set = PacketAssemblerSet::new();

        let key = Key { id: 0 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert_eq!(assr.assemble(), None);
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        // Test that `.assemble()` effectively deletes it.
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert_eq!(assr.assemble(), None);
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 1 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble().unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(2).unwrap();
        assr.add(&[0x00], 0).unwrap();
        assert_eq!(assr.assemble(), None);
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.add(&[0x01], 1).unwrap();
        assert_eq!(assr.assemble(), Some(&[0x00, 0x01][..]));
    }
}
