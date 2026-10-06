#![allow(dead_code)]

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;
use core::iter;
use core::iter::Iterator;

use super::{Error, Result};
#[cfg(feature = "proto-ipv4")]
use crate::wire::Ipv4Address;
#[cfg(feature = "proto-ipv6")]
use crate::wire::Ipv6Address;

enum_with_unknown! {
    /// DNS OpCodes
    pub enum Opcode(u8) {
        Query  = 0x00,
        Status = 0x01,
    }
}
enum_with_unknown! {
    /// DNS OpCodes
    pub enum Rcode(u8) {
        NoError  = 0x00,
        FormErr  = 0x01,
        ServFail = 0x02,
        NXDomain = 0x03,
        NotImp   = 0x04,
        Refused  = 0x05,
        YXDomain = 0x06,
        YXRRSet  = 0x07,
        NXRRSet  = 0x08,
        NotAuth  = 0x09,
        NotZone  = 0x0a,
    }
}

enum_with_unknown! {
    /// DNS record types
    pub enum Type(u16) {
        A     = 0x0001,
        Ns    = 0x0002,
        Cname = 0x0005,
        Soa   = 0x0006,
        Ptr   = 0x000c,
        Aaaa  = 0x001c,
        Srv   = 0x0021,
    }
}

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Flags: u16 {
        const RESPONSE            = 0b1000_0000_0000_0000;
        const AUTHORITATIVE       = 0b0000_0100_0000_0000;
        const TRUNCATED           = 0b0000_0010_0000_0000;
        const RECURSION_DESIRED   = 0b0000_0001_0000_0000;
        const RECURSION_AVAILABLE = 0b0000_0000_1000_0000;
        const AUTHENTIC_DATA      = 0b0000_0000_0010_0000;
        const CHECK_DISABLED      = 0b0000_0000_0001_0000;
    }
}

mod field {
    use crate::wire::field::*;

    pub const ID: Field = 0..2;
    pub const FLAGS: Field = 2..4;
    pub const QDCOUNT: Field = 4..6;
    pub const ANCOUNT: Field = 6..8;
    pub const NSCOUNT: Field = 8..10;
    pub const ARCOUNT: Field = 10..12;

    pub const HEADER_END: usize = 12;
}

// DNS class IN (Internet)
const CLASS_IN: u16 = 1;

/// A DNS name borrowed either from a DNS message or a canonical standalone buffer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Name<'a> {
    message: &'a [u8],
    raw_name: &'a [u8],
}

impl<'a> Name<'a> {
    /// Creates a DNS name view over `raw_name`, using `message` as the base for compression
    /// pointers.
    pub fn new(message: &'a [u8], raw_name: &'a [u8]) -> Result<Self> {
        let name = Self { message, raw_name };

        for label in name.labels() {
            let _ = label?;
        }

        Ok(name)
    }

    /// Parses exactly one DNS name from `raw_name`, rejecting any trailing bytes.
    pub fn parse(message: &'a [u8], raw_name: &'a [u8]) -> Result<Self> {
        let (rest, _) = parse_name_part(raw_name, |_| ())?;
        if !rest.is_empty() {
            return Err(Error);
        }

        Self::new(message, raw_name)
    }

    /// Returns the raw wire-format name slice.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw_name
    }

    /// Returns whether this name is the DNS root (`.`).
    pub const fn is_root(&self) -> bool {
        self.raw_name.len() == 1 && self.raw_name[0] == 0
    }

    /// Returns an iterator over the labels in this name, following compression pointers if present.
    pub fn labels(&self) -> NameIter<'a> {
        NameIter {
            packet: self.message,
            bytes: self.raw_name,
        }
    }

    /// Returns the size of this name when written in canonical, uncompressed wire format.
    pub const fn wire_len(&self) -> Result<usize> {
        let packet = self.message;
        let mut bytes = self.raw_name;
        let mut offset = 0;
        let mut packet_limit = packet.len();
        let mut len = 1;

        loop {
            if offset >= bytes.len() {
                return Err(Error);
            }

            match bytes[offset] {
                0x00 => return Ok(len),
                x if x & 0xC0 == 0x00 => {
                    let label_len = (x & 0x3F) as usize;
                    if bytes.len() - offset < 1 + label_len {
                        return Err(Error);
                    }

                    len += 1 + label_len;
                    offset += 1 + label_len;
                }
                x if x & 0xC0 == 0xC0 => {
                    if bytes.len() - offset < 2 {
                        return Err(Error);
                    }

                    let ptr = ((x & 0x3F) as usize) << 8 | bytes[offset + 1] as usize;
                    if packet_limit <= ptr {
                        return Err(Error);
                    }

                    bytes = packet;
                    offset = ptr;
                    packet_limit = ptr;
                }
                _ => return Err(Error),
            }
        }
    }

    /// Writes this name into `buffer` in canonical, uncompressed wire format.
    pub fn write_uncompressed(&self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.wire_len()?;
        if buffer.len() < len {
            return Err(Error);
        }

        let mut offset = 0;
        for label in self.labels() {
            let label = label?;
            buffer[offset] = label.len() as u8;
            offset += 1;

            let next = offset + label.len();
            buffer[offset..next].copy_from_slice(label);
            offset = next;
        }

        buffer[offset] = 0;
        Ok(len)
    }

    /// Compares this name with another name label-by-label.
    pub fn labels_eq(&self, other: Name<'_>) -> Result<bool> {
        let mut lhs = self.labels();
        let mut rhs = other.labels();

        loop {
            let pair = (lhs.next().transpose()?, rhs.next().transpose()?);
            match pair {
                (None, None) => return Ok(true),
                (Some(lhs_label), Some(rhs_label)) if lhs_label == rhs_label => {
                    continue;
                }
                _ => return Ok(false),
            }
        }
    }

    /// Encodes `labels` into `buffer` and returns a canonical name view over the encoded bytes.
    pub fn from_labels<T>(buffer: &'a mut [u8], labels: impl IntoIterator<Item = T>) -> Result<Self>
    where
        T: AsRef<[u8]>,
    {
        let mut offset = 0;

        for label in labels {
            let label = label.as_ref();

            if label.len() > 63 {
                return Err(Error);
            }

            let next = offset + 1 + label.len();
            if next + 1 > buffer.len() {
                return Err(Error);
            }

            buffer[offset] = label.len() as u8;
            offset += 1;

            buffer[offset..offset + label.len()].copy_from_slice(label);
            offset += label.len();
        }

        if offset >= buffer.len() {
            return Err(Error);
        }

        buffer[offset] = 0;
        offset += 1;

        Self::from_const(&buffer[..offset])
    }

    /// Encodes a dotted presentation-form name into `buffer` and returns a canonical name view.
    ///
    /// Names with and without a trailing dot are treated the same. DNS search path expansion is
    /// not supported.
    pub fn from_str(buffer: &'a mut [u8], name: &str) -> Result<Self> {
        let name = name.as_bytes();
        if name.is_empty() {
            return Err(Error);
        }

        let name = if name[name.len() - 1] == b'.' {
            &name[..name.len() - 1]
        } else {
            name
        };

        if name.is_empty() {
            if buffer.is_empty() {
                return Err(Error);
            }

            buffer[0] = 0;
            return Self::from_const(&buffer[..1]);
        }

        Self::from_labels(buffer, name.split(|&byte| byte == b'.'))
    }

    /// Returns whether `raw_name` contains exactly one canonical, uncompressed DNS name.
    pub const fn is_canonical(raw_name: &[u8]) -> bool {
        let mut offset = 0;

        while offset < raw_name.len() {
            let len = raw_name[offset];
            if len & 0xC0 != 0 {
                return false;
            }

            offset += 1;

            if len == 0 {
                return offset == raw_name.len();
            }

            let len = len as usize;
            if len > 63 || offset + len > raw_name.len() {
                return false;
            }

            offset += len;
        }

        false
    }

    /// Validates that `raw_name` is one canonical, uncompressed wire-format DNS name and
    /// returns a [`Name`] view over it.
    pub const fn from_const(raw_name: &'a [u8]) -> Result<Self> {
        if !Self::is_canonical(raw_name) {
            return Err(Error);
        }

        Ok(Self {
            message: raw_name,
            raw_name,
        })
    }

    /// # Safety
    ///
    /// `raw_name` must contain exactly one canonical, uncompressed DNS name.
    /// It is always sound to call this with a slice borrowed from static storage produced by
    /// [`dns_name!`](crate::dns_name).
    #[allow(unsafe_code)]
    pub const unsafe fn from_const_unchecked(raw_name: &'a [u8]) -> Self {
        Self {
            message: raw_name,
            raw_name,
        }
    }

    /// Encodes a dotted string literal into canonical, uncompressed DNS wire format at compile
    /// time.
    ///
    /// Most callers should use [`dns_name!`](crate::dns_name) instead of calling this function
    /// directly.
    #[doc(hidden)]
    pub const fn encode_str_const(name: &'static str) -> ([u8; 255], usize) {
        let bytes = name.as_bytes();
        let mut encoded = [0u8; 255];

        if bytes.is_empty() {
            panic!("DNS name cannot be empty");
        }

        let mut input = 0;
        let mut output = 1;
        let mut label_len = 0usize;
        let mut label_start = 0usize;
        let len = if bytes[bytes.len() - 1] == b'.' {
            bytes.len() - 1
        } else {
            bytes.len()
        };

        if len == 0 {
            encoded[0] = 0;
            return (encoded, 1);
        }

        while input < len {
            if bytes[input] == b'.' {
                if label_len == 0 {
                    panic!("DNS name contains an empty label");
                }

                encoded[label_start] = label_len as u8;
                label_start = output;
                output += 1;
                label_len = 0;
                input += 1;
                continue;
            }

            if label_len == 63 {
                panic!("DNS label exceeds 63 bytes");
            }

            if output >= encoded.len() {
                panic!("DNS name exceeds 255 bytes");
            }

            encoded[output] = bytes[input];
            output += 1;
            label_len += 1;
            input += 1;
        }

        if label_len == 0 {
            panic!("DNS name contains an empty label");
        }

        if output >= encoded.len() {
            panic!("DNS name exceeds 255 bytes");
        }

        encoded[label_start] = label_len as u8;
        encoded[output] = 0;
        output += 1;

        (encoded, output)
    }
}

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }

        let mut first = true;
        for label in self.labels() {
            let label = label.map_err(|_| fmt::Error)?;

            if !first {
                write!(f, ".")?;
            }

            for &byte in label {
                match byte {
                    b'.' | b'\\' => {
                        write!(f, "\\{}", byte as char)?;
                    }
                    0x20..=0x7e => {
                        write!(f, "{}", byte as char)?;
                    }
                    _ => {
                        write!(f, "\\{byte:03}")?;
                    }
                }
            }

            first = false;
        }

        Ok(())
    }
}

impl PartialEq<&[u8]> for Name<'_> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.raw_name == *other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Name<'_> {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.raw_name == other.as_slice()
    }
}

pub struct NameIter<'a> {
    packet: &'a [u8],
    bytes: &'a [u8],
}

impl<'a> Iterator for NameIter<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.bytes.is_empty() {
                return Some(Err(Error));
            }

            match self.bytes[0] {
                0x00 => return None,
                x if x & 0xC0 == 0x00 => {
                    let len = (x & 0x3F) as usize;
                    if self.bytes.len() < 1 + len {
                        return Some(Err(Error));
                    }

                    let label = &self.bytes[1..1 + len];
                    self.bytes = &self.bytes[1 + len..];
                    return Some(Ok(label));
                }
                x if x & 0xC0 == 0xC0 => {
                    if self.bytes.len() < 2 {
                        return Some(Err(Error));
                    }

                    let y = self.bytes[1];
                    let ptr = ((x & 0x3F) as usize) << 8 | y as usize;
                    if self.packet.len() <= ptr {
                        return Some(Err(Error));
                    }

                    self.bytes = &self.packet[ptr..];
                    self.packet = &self.packet[..ptr];
                }
                _ => return Some(Err(Error)),
            }
        }
    }
}

/// A read/write wrapper around a DNS packet buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with DNS packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is smaller than
    /// the header length.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::HEADER_END {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[field::HEADER_END..]
    }

    pub fn transaction_id(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::ID];
        NetworkEndian::read_u16(field)
    }

    pub fn flags(&self) -> Flags {
        let field = &self.buffer.as_ref()[field::FLAGS];
        Flags::from_bits_truncate(NetworkEndian::read_u16(field))
    }

    pub fn opcode(&self) -> Opcode {
        let field = &self.buffer.as_ref()[field::FLAGS];
        let flags = NetworkEndian::read_u16(field);
        Opcode::from((flags >> 11 & 0xF) as u8)
    }

    pub fn rcode(&self) -> Rcode {
        let field = &self.buffer.as_ref()[field::FLAGS];
        let flags = NetworkEndian::read_u16(field);
        Rcode::from((flags & 0xF) as u8)
    }

    pub fn question_count(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::QDCOUNT];
        NetworkEndian::read_u16(field)
    }

    pub fn answer_record_count(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::ANCOUNT];
        NetworkEndian::read_u16(field)
    }

    pub fn authority_record_count(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::NSCOUNT];
        NetworkEndian::read_u16(field)
    }

    pub fn additional_record_count(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::ARCOUNT];
        NetworkEndian::read_u16(field)
    }

    /// Parse part of a name from `bytes`, following pointers if any.
    pub fn parse_name<'a>(&'a self, mut bytes: &'a [u8]) -> impl Iterator<Item = Result<&'a [u8]>> {
        let mut packet = self.buffer.as_ref();

        iter::from_fn(move || {
            loop {
                if bytes.is_empty() {
                    return Some(Err(Error));
                }
                match bytes[0] {
                    0x00 => return None,
                    x if x & 0xC0 == 0x00 => {
                        let len = (x & 0x3F) as usize;
                        if bytes.len() < 1 + len {
                            return Some(Err(Error));
                        }
                        let label = &bytes[1..1 + len];
                        bytes = &bytes[1 + len..];
                        return Some(Ok(label));
                    }
                    x if x & 0xC0 == 0xC0 => {
                        if bytes.len() < 2 {
                            return Some(Err(Error));
                        }
                        let y = bytes[1];
                        let ptr = ((x & 0x3F) as usize) << 8 | (y as usize);
                        if packet.len() <= ptr {
                            return Some(Err(Error));
                        }

                        // RFC1035 says: "In this scheme, an entire domain name or a list of labels at
                        //      the end of a domain name is replaced with a pointer to a ***prior*** occurrence
                        //      of the same name.
                        //
                        // Is it unclear if this means the pointer MUST point backwards in the packet or not. Either way,
                        // pointers that don't point backwards are never seen in the fields, so use this to check that
                        // there are no pointer loops.

                        // Split packet into parts before and after `ptr`.
                        // parse the part after, keep only the part before in `packet`. This ensure we never
                        // parse the same byte twice, therefore eliminating pointer loops.

                        bytes = &packet[ptr..];
                        packet = &packet[..ptr];
                    }
                    _ => return Some(Err(Error)),
                }
            }
        })
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::HEADER_END..]
    }

    pub fn set_transaction_id(&mut self, val: u16) {
        let field = &mut self.buffer.as_mut()[field::ID];
        NetworkEndian::write_u16(field, val)
    }

    pub fn set_flags(&mut self, val: Flags) {
        let field = &mut self.buffer.as_mut()[field::FLAGS];
        let mask = Flags::all().bits;
        let old = NetworkEndian::read_u16(field);
        NetworkEndian::write_u16(field, (old & !mask) | val.bits());
    }

    pub fn set_opcode(&mut self, val: Opcode) {
        let field = &mut self.buffer.as_mut()[field::FLAGS];
        let mask = 0x3800;
        let val: u8 = val.into();
        let val = (val as u16) << 11;
        let old = NetworkEndian::read_u16(field);
        NetworkEndian::write_u16(field, (old & !mask) | val);
    }

    pub fn set_question_count(&mut self, val: u16) {
        let field = &mut self.buffer.as_mut()[field::QDCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    pub fn set_answer_record_count(&mut self, val: u16) {
        let field = &mut self.buffer.as_mut()[field::ANCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    pub fn set_authority_record_count(&mut self, val: u16) {
        let field = &mut self.buffer.as_mut()[field::NSCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    pub fn set_additional_record_count(&mut self, val: u16) {
        let field = &mut self.buffer.as_mut()[field::ARCOUNT];
        NetworkEndian::write_u16(field, val)
    }
}

/// Parse part of a name from `bytes`, not following pointers.
/// Returns the unused part of `bytes`, and the pointer offset if the sequence ends with a pointer.
fn parse_name_part<'a>(
    mut bytes: &'a [u8],
    mut f: impl FnMut(&'a [u8]),
) -> Result<(&'a [u8], Option<usize>)> {
    loop {
        let x = *bytes.first().ok_or(Error)?;
        bytes = &bytes[1..];
        match x {
            0x00 => return Ok((bytes, None)),
            x if x & 0xC0 == 0x00 => {
                let len = (x & 0x3F) as usize;
                let label = bytes.get(..len).ok_or(Error)?;
                bytes = &bytes[len..];
                f(label);
            }
            x if x & 0xC0 == 0xC0 => {
                let y = *bytes.first().ok_or(Error)?;
                bytes = &bytes[1..];

                let ptr = ((x & 0x3F) as usize) << 8 | (y as usize);
                return Ok((bytes, Some(ptr)));
            }
            _ => return Err(Error),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Question<'a> {
    pub name: Name<'a>,
    pub type_: Type,
}

impl<'a> Question<'a> {
    /// Parses one DNS question from the front of `buffer`.
    ///
    /// `message` must be the full original DNS packet. `buffer` is the current rolling parse
    /// slice within that packet and is advanced by the returned remainder. The split is needed
    /// because DNS names inside `buffer` may contain compression pointers that refer back to
    /// earlier bytes in `message`.
    pub fn parse(message: &'a [u8], buffer: &'a [u8]) -> Result<(&'a [u8], Question<'a>)> {
        let (rest, _) = parse_name_part(buffer, |_| ())?;
        let name = Name::new(message, &buffer[..buffer.len() - rest.len()])?;

        if rest.len() < 4 {
            return Err(Error);
        }
        let type_ = NetworkEndian::read_u16(&rest[0..2]).into();
        let class = NetworkEndian::read_u16(&rest[2..4]) & 0x7fff;
        let rest = &rest[4..];

        if class != CLASS_IN {
            return Err(Error);
        }

        Ok((rest, Question { name, type_ }))
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        match self.name.wire_len() {
            Ok(name_len) => name_len + 4,
            Err(_) => panic!("DnsName should be validated"),
        }
    }

    /// Emit a high-level representation into a DNS packet.
    pub fn emit(&self, packet: &mut [u8]) {
        let name_len = self.name.wire_len().expect("DnsName should be validated");
        self.name
            .write_uncompressed(&mut packet[..name_len])
            .expect("packet buffer should fit DNS name");
        let rest = &mut packet[name_len..];
        NetworkEndian::write_u16(&mut rest[0..2], self.type_.into());
        NetworkEndian::write_u16(&mut rest[2..4], CLASS_IN);
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Record<'a> {
    pub name: Name<'a>,
    pub ttl: u32,
    pub data: RecordData<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SrvRecord<Target> {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Target,
}

impl<'a> SrvRecord<Name<'a>> {
    pub fn parse(message: &'a [u8], data: &'a [u8]) -> Result<SrvRecord<Name<'a>>> {
        if data.len() < 6 {
            return Err(Error);
        }

        let priority = NetworkEndian::read_u16(&data[0..2]);
        let weight = NetworkEndian::read_u16(&data[2..4]);
        let port = NetworkEndian::read_u16(&data[4..6]);
        let target = Name::parse(message, &data[6..])?;

        Ok(SrvRecord {
            priority,
            weight,
            port,
            target,
        })
    }
}

impl<'a> RecordData<'a> {
    pub fn parse(message: &'a [u8], type_: Type, data: &'a [u8]) -> Result<RecordData<'a>> {
        match type_ {
            #[cfg(feature = "proto-ipv4")]
            Type::A => Ok(RecordData::A(Ipv4Address::from_octets(
                data.try_into().map_err(|_| Error)?,
            ))),
            #[cfg(feature = "proto-ipv6")]
            Type::Aaaa => Ok(RecordData::Aaaa(Ipv6Address::from_octets(
                data.try_into().map_err(|_| Error)?,
            ))),
            Type::Cname => Ok(RecordData::Cname(Name::parse(message, data)?)),
            Type::Ptr => Ok(RecordData::Ptr(Name::parse(message, data)?)),
            Type::Srv => Ok(RecordData::Srv(SrvRecord::parse(message, data)?)),
            x => Ok(RecordData::Other(x, data)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecordData<'a> {
    #[cfg(feature = "proto-ipv4")]
    A(Ipv4Address),
    #[cfg(feature = "proto-ipv6")]
    Aaaa(Ipv6Address),
    Cname(Name<'a>),
    Ptr(Name<'a>),
    Srv(SrvRecord<Name<'a>>),
    Other(Type, &'a [u8]),
}

impl<'a> Record<'a> {
    /// Parses one DNS record from the front of `buffer`.
    ///
    /// `message` must be the full original DNS packet. `buffer` is the current rolling parse
    /// slice within that packet and is advanced by the returned remainder. The split is needed
    /// because record names and name-bearing RDATA may contain compression pointers that refer
    /// back to earlier bytes in `message`.
    pub fn parse(message: &'a [u8], buffer: &'a [u8]) -> Result<(&'a [u8], Record<'a>)> {
        let (rest, _) = parse_name_part(buffer, |_| ())?;
        let name = Name::new(message, &buffer[..buffer.len() - rest.len()])?;

        if rest.len() < 10 {
            return Err(Error);
        }
        let type_ = NetworkEndian::read_u16(&rest[0..2]).into();
        let class = NetworkEndian::read_u16(&rest[2..4]) & 0x7fff;
        let ttl = NetworkEndian::read_u32(&rest[4..8]);
        let len = NetworkEndian::read_u16(&rest[8..10]) as usize;
        let rest = &rest[10..];

        if class != CLASS_IN {
            return Err(Error);
        }

        let data = rest.get(..len).ok_or(Error)?;
        let rest = &rest[len..];

        Ok((
            rest,
            Record {
                name,
                ttl,
                data: RecordData::parse(message, type_, data)?,
            },
        ))
    }
}

/// High-level DNS packet representation.
///
/// Currently only supports query packets.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr<'a> {
    pub transaction_id: u16,
    pub opcode: Opcode,
    pub flags: Flags,
    pub question: Question<'a>,
}

impl<'a> Repr<'a> {
    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        field::HEADER_END + self.question.buffer_len()
    }

    /// Emit a high-level representation into a DNS packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_transaction_id(self.transaction_id);
        packet.set_flags(self.flags);
        packet.set_opcode(self.opcode);
        packet.set_question_count(1);
        packet.set_answer_record_count(0);
        packet.set_authority_record_count(0);
        packet.set_additional_record_count(0);
        self.question.emit(packet.payload_mut())
    }
}

#[cfg(feature = "proto-ipv4")] // tests assume ipv4
#[cfg(test)]
mod test {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn test_parse_name() {
        let bytes = &[
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f,
            0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
            0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69,
            0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ];
        let packet = Packet::new_unchecked(bytes);

        let name_vec = |bytes| {
            let mut v = Vec::new();
            Name::new(packet.buffer.as_ref(), bytes)
                .unwrap()
                .labels()
                .try_for_each(|label| label.map(|label| v.push(label)))
                .map(|_| v)
        };

        //assert_eq!(parse_name_len(bytes, 0x0c), Ok(18));
        assert_eq!(
            name_vec(&bytes[0x0c..]),
            Ok(vec![&b"www"[..], &b"facebook"[..], &b"com"[..]])
        );
        //assert_eq!(parse_name_len(bytes, 0x22), Ok(2));
        assert_eq!(
            name_vec(&bytes[0x22..]),
            Ok(vec![&b"www"[..], &b"facebook"[..], &b"com"[..]])
        );
        //assert_eq!(parse_name_len(bytes, 0x2e), Ok(17));
        assert_eq!(
            name_vec(&bytes[0x2e..]),
            Ok(vec![
                &b"star-mini"[..],
                &b"c10r"[..],
                &b"facebook"[..],
                &b"com"[..]
            ])
        );
        //assert_eq!(parse_name_len(bytes, 0x3f), Ok(2));
        assert_eq!(
            name_vec(&bytes[0x3f..]),
            Ok(vec![
                &b"star-mini"[..],
                &b"c10r"[..],
                &b"facebook"[..],
                &b"com"[..]
            ])
        );
    }

    struct Parsed<'a> {
        packet: Packet<&'a [u8]>,
        questions: Vec<Question<'a>>,
        answers: Vec<Record<'a>>,
        authorities: Vec<Record<'a>>,
        additionals: Vec<Record<'a>>,
    }

    impl<'a> Parsed<'a> {
        fn parse(bytes: &'a [u8]) -> Result<Self> {
            let packet = Packet::new_unchecked(bytes);
            let mut questions = Vec::new();
            let mut answers = Vec::new();
            let mut authorities = Vec::new();
            let mut additionals = Vec::new();

            let mut payload = &bytes[12..];

            for _ in 0..packet.question_count() {
                let (p, r) = Question::parse(bytes, payload)?;
                questions.push(r);
                payload = p;
            }
            for _ in 0..packet.answer_record_count() {
                let (p, r) = Record::parse(bytes, payload)?;
                answers.push(r);
                payload = p;
            }
            for _ in 0..packet.authority_record_count() {
                let (p, r) = Record::parse(bytes, payload)?;
                authorities.push(r);
                payload = p;
            }
            for _ in 0..packet.additional_record_count() {
                let (p, r) = Record::parse(bytes, payload)?;
                additionals.push(r);
                payload = p;
            }

            // Check that there are no bytes left
            assert_eq!(payload.len(), 0);

            Ok(Parsed {
                packet,
                questions,
                answers,
                authorities,
                additionals,
            })
        }
    }

    #[test]
    fn test_parse_request() {
        let p = Parsed::parse(&[
            0x51, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ])
        .unwrap();

        assert_eq!(p.packet.transaction_id(), 0x5184);
        assert_eq!(
            p.packet.flags(),
            Flags::RECURSION_DESIRED | Flags::AUTHENTIC_DATA
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 0);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(p.questions.len(), 1);
        assert_eq!(
            p.questions[0].name.raw(),
            &[
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        assert_eq!(p.answers.len(), 0);
        assert_eq!(p.authorities.len(), 0);
        assert_eq!(p.additionals.len(), 0);
    }

    #[test]
    fn test_parse_response() {
        let p = Parsed::parse(&[
            0x51, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xca, 0x00, 0x04, 0xac, 0xd9,
            0xa8, 0xae,
        ])
        .unwrap();

        assert_eq!(p.packet.transaction_id(), 0x5184);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 1);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 202);
        assert_eq!(
            p.answers[0].data,
            RecordData::A(Ipv4Address::new(0xac, 0xd9, 0xa8, 0xae))
        );
    }

    #[test]
    fn test_parse_response_multiple_a() {
        let p = Parsed::parse(&[
            0x4b, 0x9e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72,
            0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00,
            0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00,
            0x04, 0x0d, 0xe0, 0x77, 0x35, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x28, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x62,
        ])
        .unwrap();

        assert_eq!(p.packet.transaction_id(), 0x4b9e);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 4);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[
                0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67,
                0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 9);
        assert_eq!(
            p.answers[0].data,
            RecordData::A(Ipv4Address::new(0x0d, 0xe0, 0x77, 0x35))
        );

        assert_eq!(p.answers[1].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[1].ttl, 9);
        assert_eq!(
            p.answers[1].data,
            RecordData::A(Ipv4Address::new(0x0d, 0xe0, 0x77, 0x28))
        );

        assert_eq!(p.answers[2].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[2].ttl, 9);
        assert_eq!(
            p.answers[2].data,
            RecordData::A(Ipv4Address::new(0x0d, 0xe0, 0x77, 0x43))
        );

        assert_eq!(p.answers[3].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[3].ttl, 9);
        assert_eq!(
            p.answers[3].data,
            RecordData::A(Ipv4Address::new(0x0d, 0xe0, 0x77, 0x62))
        );
    }

    #[test]
    fn test_parse_response_cname() {
        let p = Parsed::parse(&[
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f,
            0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
            0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69,
            0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ])
        .unwrap();

        assert_eq!(p.packet.transaction_id(), 0x786c);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 2);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[
                0x03, 0x77, 0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03,
                0x63, 0x6f, 0x6d, 0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        // cname
        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 1523);
        assert_eq!(
            p.answers[0].data,
            RecordData::Cname(
                Name::new(
                    p.packet.buffer,
                    &[
                        0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x04, 0x63,
                        0x31, 0x30, 0x72, 0xc0, 0x10
                    ]
                )
                .unwrap()
            )
        );
        // a
        assert_eq!(p.answers[1].name, &[0xc0, 0x2e]);
        assert_eq!(p.answers[1].ttl, 5);
        assert_eq!(
            p.answers[1].data,
            RecordData::A(Ipv4Address::new(0x1f, 0x0d, 0x53, 0x24))
        );
    }

    #[test]
    fn test_parse_response_ptr() {
        let bytes = &[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x34,
            0x01, 0x33, 0x01, 0x32, 0x01, 0x31, 0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72,
            0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0c,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x0d, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        let p = Parsed::parse(bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x1234);
        assert_eq!(p.packet.answer_record_count(), 1);
        assert_eq!(p.questions[0].type_, Type::Ptr);
        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 60);
        assert_eq!(
            p.answers[0].data,
            RecordData::Ptr(
                Name::new(
                    p.packet.buffer,
                    &[
                        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
                        0x00
                    ]
                )
                .unwrap()
            )
        );

        let mut target_labels = Vec::new();
        match &p.answers[0].data {
            RecordData::Ptr(ptr) => ptr
                .labels()
                .try_for_each(|label| label.map(|label| target_labels.push(label)))
                .unwrap(),
            other => panic!("unexpected answer data: {other:?}"),
        }
        assert_eq!(target_labels, vec![&b"example"[..], &b"com"[..]]);
    }

    #[test]
    fn test_parse_response_srv() {
        let bytes = &[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5f,
            0x73, 0x69, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00,
            0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x05, 0x13,
            0xc4, 0x09, 0x73, 0x69, 0x70, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xc0, 0x16,
        ];

        let p = Parsed::parse(bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x1234);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 1);

        assert_eq!(p.questions[0].type_, Type::Srv);
        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 60);
        assert_eq!(
            p.answers[0].data,
            RecordData::Srv(SrvRecord {
                priority: 0,
                weight: 5,
                port: 5060,
                target: Name::new(
                    p.packet.buffer,
                    &[
                        0x09, 0x73, 0x69, 0x70, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xc0, 0x16
                    ]
                )
                .unwrap(),
            })
        );

        let mut target_labels = Vec::new();
        match &p.answers[0].data {
            RecordData::Srv(srv) => srv
                .target
                .labels()
                .try_for_each(|label| label.map(|label| target_labels.push(label)))
                .unwrap(),
            other => panic!("unexpected answer data: {other:?}"),
        }
        assert_eq!(
            target_labels,
            vec![&b"sipserver"[..], &b"example"[..], &b"com"[..]]
        );
    }

    #[test]
    fn test_parse_response_nxdomain() {
        let p = Parsed::parse(&[
            0x63, 0xc4, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x13, 0x61,
            0x68, 0x61, 0x73, 0x64, 0x67, 0x68, 0x6c, 0x61, 0x6b, 0x73, 0x6a, 0x68, 0x62, 0x61,
            0x61, 0x73, 0x6c, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x20, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x03, 0x83, 0x00, 0x3d, 0x01, 0x61, 0x0c,
            0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e,
            0x65, 0x74, 0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69,
            0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0xc0, 0x20, 0x5f, 0xce, 0x8b, 0x85,
            0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01,
            0x51, 0x80,
        ])
        .unwrap();

        assert_eq!(p.packet.transaction_id(), 0x63c4);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NXDomain);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 0);
        assert_eq!(p.packet.authority_record_count(), 1);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(p.questions[0].type_, Type::A);

        // SOA authority
        assert_eq!(p.authorities[0].name, &[0xc0, 0x20]); // com.
        assert_eq!(p.authorities[0].ttl, 899);
        assert!(matches!(
            p.authorities[0].data,
            RecordData::Other(Type::Soa, _)
        ));
    }

    #[test]
    fn test_emit() {
        let name = &[
            0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67,
            0x00,
        ];

        let repr = Repr {
            transaction_id: 0x1234,
            flags: Flags::RECURSION_DESIRED,
            opcode: Opcode::Query,
            question: Question {
                name: Name::from_const(name).unwrap(),
                type_: Type::A,
            },
        };

        let mut buf = vec![0; repr.buffer_len()];
        repr.emit(&mut Packet::new_unchecked(&mut buf));

        let want = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72,
            0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        assert_eq!(&buf, want);
    }
}
