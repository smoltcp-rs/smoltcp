#![allow(unused)]

use core::fmt;

use managed::{ManagedMap, ManagedSlice};

use crate::config::{FRAGMENTATION_BUFFER_SIZE, REASSEMBLY_BUFFER_COUNT, REASSEMBLY_BUFFER_SIZE};
use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::wire::*;

use crate::iface::interface::DispatchError;
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "proto-ipv4")]
use crate::wire::ipv4::{ALIGNMENT_32_BITS, HEADER_LEN, MAX_OPTIONS_SIZE, Packet, Repr};
use core::result::Result;

// Special option type octets.
const OPTION_TYPE_PADDING: u8 = 0x00;
const OPTION_TYPE_NO_OPERATION: u8 = 0x01;

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

#[cfg(feature = "std")]
impl std::error::Error for AssemblerError {}

/// Packet assembler is full
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerFullError;

impl fmt::Display for AssemblerFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerFullError")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AssemblerFullError {}

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
        }
    }

    pub(crate) fn reset(&mut self) {
        self.key = None;
        self.assembler.clear();
        self.total_size = None;
        self.expires_at = Instant::ZERO;
    }

    /// Set the total size of the packet assembler.
    pub(crate) fn set_total_size(&mut self, size: usize) -> Result<(), AssemblerError> {
        if let Some(old_size) = self.total_size
            && old_size != size
        {
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

        self.assembler.add(offset, len);
        Ok(())
    }

    /// Add a fragment into the packet that is being reassembled.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::PacketAssemblerBufferTooSmall`] when trying to add data into the buffer at a non-existing
    ///   place.
    pub(crate) fn add(&mut self, data: &[u8], offset: usize) -> Result<(), AssemblerError> {
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

        self.assembler.add(offset, data.len());
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

    /// Returns `true` when all fragments have been received, otherwise `false`.
    pub(crate) fn is_complete(&self) -> bool {
        self.total_size == Some(self.assembler.peek_front())
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.key.is_none()
    }
}

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
pub struct PacketAssemblerSet<K: Eq + Copy> {
    assemblers: [PacketAssembler<K>; REASSEMBLY_BUFFER_COUNT],
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    const NEW_PA: PacketAssembler<K> = PacketAssembler::new();

    /// Create a new set of packet assemblers.
    pub fn new() -> Self {
        Self {
            assemblers: [Self::NEW_PA; REASSEMBLY_BUFFER_COUNT],
        }
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
        slot.key = Some(*key);
        slot.expires_at = expires_at;
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
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    Sixlowpan(SixlowpanFragKey),
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
    /// The header options.
    pub options_buffer: [u8; MAX_OPTIONS_SIZE],
    /// Actual length of the options.
    pub options_len: usize,
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
                options_buffer: [0u8; MAX_OPTIONS_SIZE],
                options_len: 0,
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

#[cfg(feature = "proto-ipv4-fragmentation")]
#[derive(PartialEq)]
enum OptionCopyBehavior {
    // This option is copied for every fragment
    Copy,
    // This option is discarded after the first fragment
    DontCopy,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
#[derive(PartialEq)]
enum OptionLengthType {
    // This option has an octet specifying the length of the option
    HasLength,
    // This option has no length octet and is of single octet length
    NoLength,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
impl Ipv4Fragmenter {
    /// Determines two characteristics of the option from the type octet.
    /// Returns (OptionCopyBehavior, OptionLengthType)
    fn parse_option_type_octet(type_octet: u8) -> (OptionCopyBehavior, OptionLengthType) {
        let copy_behavior = match (type_octet & 0x80) {
            0x80 => OptionCopyBehavior::Copy,
            _ => OptionCopyBehavior::DontCopy,
        };
        let length_type = match type_octet {
            OPTION_TYPE_PADDING | OPTION_TYPE_NO_OPERATION => OptionLengthType::NoLength,
            _ => OptionLengthType::HasLength,
        };
        (copy_behavior, length_type)
    }

    /// Filters the original option set and overwrites it in the repr for use with subsequent packet fragments.
    /// Returns Ok(()) if no error occurs during filtering.
    pub(crate) fn filter_options(&mut self) -> Result<(), DispatchError> {
        // Exit nicely if no options are present, there is just nothing to filter.
        if self.options_len == 0 {
            return Ok(());
        }
        // Check for a proper length. There must be enough bytes for at least one operable option.
        if self.options_len < ALIGNMENT_32_BITS
            || !self.options_len.is_multiple_of(ALIGNMENT_32_BITS)
            || self.options_len > MAX_OPTIONS_SIZE
        {
            return Err(DispatchError::CannotFragment);
        }
        // Initialize read and write pointers.
        let source: &[u8; MAX_OPTIONS_SIZE] = &self.options_buffer;
        let mut i_read: usize = 0;
        let dest: &mut [u8; MAX_OPTIONS_SIZE] = &mut [0u8; MAX_OPTIONS_SIZE];
        let mut i_write: usize = 0;
        // Iterate through the options.
        while i_read < self.options_len {
            // Parse the type octet to get our instructions for this option.
            let type_octet = source[i_read];
            let (copy_behavior, length_type) = Self::parse_option_type_octet(type_octet);
            match length_type {
                OptionLengthType::HasLength => {
                    // Nothing prevents defining an option that has a length octet with a value that indicates zero length data,
                    // so we allow for the presence of a length octet prior to the last octet.
                    if i_read + 1 >= self.options_len {
                        // This is the last octet, and there is no more room for a length octet.
                        return Err(DispatchError::CannotFragment);
                    }
                    // Parse the length octet.
                    let length = source[i_read + 1] as usize;
                    // Safely copy the option based on its length.
                    if copy_behavior == OptionCopyBehavior::Copy {
                        // Prevent a length from overflowing the end.
                        if i_write + length > dest.len() || i_read + length > source.len() {
                            return Err(DispatchError::CannotFragment);
                        }
                        dest[i_write..i_write + length]
                            .copy_from_slice(&source[i_read..i_read + length]);
                        // Advance the write pointer.
                        i_write += length;
                    }
                    // Advance the read pointer.
                    i_read += length;
                }
                OptionLengthType::NoLength => {
                    // Advance past any single octets. They are not operable option bytes.
                    // Padding is inserted once the writing of all options is complete.
                    // Only option types 0x0 and 0x1 have the length bit unset. All other option types have the
                    // length bit set. Therefore, no operable option types have both the copy bit set
                    // and the length bit unset. See the IANA option number list at:
                    // https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
                    i_read += 1;
                }
            }
        }
        // If necessary, safely pad the remainder of the alignment in the destination.
        while !i_write.is_multiple_of(ALIGNMENT_32_BITS) && i_write < MAX_OPTIONS_SIZE {
            dest[i_write] = OPTION_TYPE_PADDING;
            i_write += 1;
        }
        // Apply the filtered options.
        Ok(self.options_buffer.copy_from_slice(dest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::ChecksumCapabilities;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::ipv4::{Packet, Repr};

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key {
        id: usize,
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        p_assembler.set_total_size(5).unwrap();

        let data = b"Rust";
        p_assembler.add(&data[..], 0);
        p_assembler.add(&data[..], 1);

        assert_eq!(p_assembler.assemble(), Some(&b"RRust"[..]))
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

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_no_options_present() {
        const PACKET_BYTES: [u8; 30] = [
            0x45, 0x21, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x4d, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xff,
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_ok());
        assert_eq!(repr, frag.ipv4.repr);
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_one_persisted_option_present() {
        const PACKET_BYTES: [u8; 34] = [
            0x46, 0x21, 0x00, 0x22, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xf1, 0xea, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x88, 0x04, 0x5a, 0x5a, // Stream Identifier option
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        frag.ipv4.filter_options();
        // The stream id remains. Each fragment header is identical.
        assert_eq!(repr, frag.ipv4.repr);
        assert_eq!(frag.ipv4.options_len, 4);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
        // Repeat as if on next fragment.
        assert!(frag.ipv4.filter_options().is_ok());
        // The stream id remains. Each fragment header is identical.
        assert_eq!(repr, frag.ipv4.repr);
        assert_eq!(frag.ipv4.options_len, 4);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_one_discarded_option_present_with_noop_padding() {
        const PACKET_BYTES: [u8; 38] = [
            0x47, 0x21, 0x00, 0x26, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xc2, 0x39, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x07, 0x07, 0x04, 0x01, 0x02, 0x03, 0x04, // Route Record
            0x01, // Padding
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_ok());
        assert_ne!(repr, frag.ipv4.repr);
        // The route record is discarded in all further fragments.
        assert_eq!(frag.ipv4.options_len, 0);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_one_discarded_and_one_persisted_with_middle_padding() {
        const PACKET_BYTES: [u8; 42] = [
            0x48, 0x21, 0x00, 0x2a, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xde, 0xd6, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x07, 0x07, 0x04, 0x01, 0x02, 0x03, 0x04, // Route Record
            0x01, // Padding
            0x88, 0x04, 0x5a, 0x5a, // Stream Identifier option (4 bytes)
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_ok());
        assert_ne!(repr, frag.ipv4.repr);
        // The route record is discarded and only the stream id persists to all fragments.
        assert_eq!(frag.ipv4.options_len, 4); // stream id only in options
        assert_eq!(frag.ipv4.options_buffer[0..4], [0x88, 0x04, 0x5a, 0x5a]);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_max_options_present() {
        const PACKET_BYTES: [u8; 70] = [
            0x4F, 0x21, 0x00, 0x46, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0x14, 0xff, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x07, 0x23, 0x20, // Route Record
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x88, 0x04, 0x5a,
            0x5a, // Stream Identifier option (4 bytes)
            0x01, // Padding
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_ok());
        assert_ne!(repr, frag.ipv4.repr);
        // The route record is discarded and only the stream id persists to all fragments.
        assert_eq!(frag.ipv4.options_len, 4); // stream id only in options
        assert_eq!(frag.ipv4.options_buffer[0..4], [0x88, 0x04, 0x5a, 0x5a]);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_bad_option_at_end_does_not_cause_panic() {
        const PACKET_BYTES: [u8; 70] = [
            0x4F, 0x21, 0x00, 0x46, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0x14, 0x7f, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x07, 0x23, 0x20, // Route Record
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x88, 0x04, 0x5a,
            0x5a, // Stream Identifier option (4 bytes)
            0x81, // Bad octet that indicates a length octet is following, but we are at the end
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_err());
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_one_discarded_and_one_persisted_with_padding_required_of_different_length() {
        const PACKET_BYTES: [u8; 46] = [
            0x49, 0x21, 0x00, 0x2e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xac, 0x9d, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0x07, 0x07, 0x04, 0x01, 0x02, 0x03, 0x04, // Route Record
            0x83, 0x07, 0x04, 0x05, 0x06, 0x07, 0x08, // Loose Source
            0x00, 0x00, // Padding (two octets)
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_ok());
        assert_ne!(repr, frag.ipv4.repr);
        // The route record is discarded and only the loose source option persists to all fragments.
        // Only one octet of padding is needed.
        assert_eq!(frag.ipv4.options_len, 8);
        assert_eq!(frag.ipv4.repr.payload_len, 10);
        assert_eq!(
            frag.ipv4.options_buffer[0..8],
            [0x83, 0x07, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00]
        );
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    #[test]
    fn filter_options_length_octet_overflow() {
        const PACKET_BYTES: [u8; 70] = [
            0x4F, 0x21, 0x00, 0x46, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xcb, 0x25, 0x11, 0x12,
            0x13, 0x14, 0x21, 0x22, 0x23, 0x24, // Fixed header
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xaa, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // Payload (10 bytes)
        ];
        let mut packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        let mut frag = Fragmenter::new();
        frag.ipv4.repr = repr;
        assert!(frag.ipv4.filter_options().is_err());
    }
}
