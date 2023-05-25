//! Implementation of [RFC 6282] which specifies a compression format for IPv6 datagrams over
//! IEEE802.154-based networks.
//!
//! [RFC 6282]: https://datatracker.ietf.org/doc/html/rfc6282

use super::{Error, Result};
use crate::wire::ieee802154::Address as LlAddress;
use crate::wire::ipv6;
use crate::wire::IpProtocol;

const ADDRESS_CONTEXT_LENGTH: usize = 8;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressContext(pub [u8; ADDRESS_CONTEXT_LENGTH]);

/// The representation of an unresolved address. 6LoWPAN compression of IPv6 addresses can be with
/// and without context information. The decompression with context information is not yet
/// implemented.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UnresolvedAddress<'a> {
    WithoutContext(AddressMode<'a>),
    WithContext((usize, AddressMode<'a>)),
    Reserved,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressMode<'a> {
    /// The full address is carried in-line.
    FullInline(&'a [u8]),
    /// The first 64-bits of the address are elided. The value of those bits
    /// is the link-local prefix padded with zeros. The remaining 64 bits are
    /// carried in-line.
    InLine64bits(&'a [u8]),
    /// The first 112 bits of the address are elided. The value of the first
    /// 64 bits is the link-local prefix padded with zeros. The following 64 bits
    /// are 0000:00ff:fe00:XXXX, where XXXX are the 16 bits carried in-line.
    InLine16bits(&'a [u8]),
    /// The address is fully elided. The first 64 bits of the address are
    /// the link-local prefix padded with zeros. The remaining 64 bits are
    /// computed from the encapsulating header (e.g., 802.15.4 or IPv6 source address)
    /// as specified in Section 3.2.2.
    FullyElided,
    /// The address takes the form ffXX::00XX:XXXX:XXXX
    Multicast48bits(&'a [u8]),
    /// The address takes the form ffXX::00XX:XXXX.
    Multicast32bits(&'a [u8]),
    /// The address takes the form ff02::00XX.
    Multicast8bits(&'a [u8]),
    /// The unspecified address.
    Unspecified,
    NotSupported,
}

const LINK_LOCAL_PREFIX: [u8; 2] = [0xfe, 0x80];
const EUI64_MIDDLE_VALUE: [u8; 2] = [0xff, 0xfe];

impl<'a> UnresolvedAddress<'a> {
    pub fn resolve(
        self,
        ll_address: Option<LlAddress>,
        addr_context: &[AddressContext],
    ) -> Result<ipv6::Address> {
        let mut bytes = [0; 16];

        let copy_context = |index: usize, bytes: &mut [u8]| -> Result<()> {
            if index >= addr_context.len() {
                return Err(Error);
            }

            let context = addr_context[index];
            bytes[..ADDRESS_CONTEXT_LENGTH].copy_from_slice(&context.0);

            Ok(())
        };

        match self {
            UnresolvedAddress::WithoutContext(mode) => match mode {
                AddressMode::FullInline(addr) => Ok(ipv6::Address::from_bytes(addr)),
                AddressMode::InLine64bits(inline) => {
                    bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX[..]);
                    bytes[8..].copy_from_slice(inline);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                AddressMode::InLine16bits(inline) => {
                    bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX[..]);
                    bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE[..]);
                    bytes[14..].copy_from_slice(inline);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                AddressMode::FullyElided => {
                    bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX[..]);
                    match ll_address {
                        Some(LlAddress::Short(ll)) => {
                            bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE[..]);
                            bytes[14..].copy_from_slice(&ll);
                        }
                        Some(addr @ LlAddress::Extended(_)) => match addr.as_eui_64() {
                            Some(addr) => bytes[8..].copy_from_slice(&addr),
                            None => return Err(Error),
                        },
                        Some(LlAddress::Absent) => return Err(Error),
                        None => return Err(Error),
                    }
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                AddressMode::Multicast48bits(inline) => {
                    bytes[0] = 0xff;
                    bytes[1] = inline[0];
                    bytes[11..].copy_from_slice(&inline[1..][..5]);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                AddressMode::Multicast32bits(inline) => {
                    bytes[0] = 0xff;
                    bytes[1] = inline[0];
                    bytes[13..].copy_from_slice(&inline[1..][..3]);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                AddressMode::Multicast8bits(inline) => {
                    bytes[0] = 0xff;
                    bytes[1] = 0x02;
                    bytes[15] = inline[0];
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                _ => Err(Error),
            },
            UnresolvedAddress::WithContext(mode) => match mode {
                (_, AddressMode::Unspecified) => Ok(ipv6::Address::UNSPECIFIED),
                (index, AddressMode::InLine64bits(inline)) => {
                    copy_context(index, &mut bytes[..])?;
                    bytes[16 - inline.len()..].copy_from_slice(inline);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                (index, AddressMode::InLine16bits(inline)) => {
                    copy_context(index, &mut bytes[..])?;
                    bytes[16 - inline.len()..].copy_from_slice(inline);
                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                (index, AddressMode::FullyElided) => {
                    match ll_address {
                        Some(LlAddress::Short(ll)) => {
                            bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE[..]);
                            bytes[14..].copy_from_slice(&ll);
                        }
                        Some(addr @ LlAddress::Extended(_)) => match addr.as_eui_64() {
                            Some(addr) => bytes[8..].copy_from_slice(&addr),
                            None => return Err(Error),
                        },
                        Some(LlAddress::Absent) => return Err(Error),
                        None => return Err(Error),
                    }

                    copy_context(index, &mut bytes[..])?;

                    Ok(ipv6::Address::from_bytes(&bytes[..]))
                }
                _ => Err(Error),
            },
            UnresolvedAddress::Reserved => Err(Error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SixlowpanPacket {
    FragmentHeader,
    IphcHeader,
}

const DISPATCH_FIRST_FRAGMENT_HEADER: u8 = 0b11000;
const DISPATCH_FRAGMENT_HEADER: u8 = 0b11100;
const DISPATCH_IPHC_HEADER: u8 = 0b011;
const DISPATCH_UDP_HEADER: u8 = 0b11110;
const DISPATCH_EXT_HEADER: u8 = 0b1110;

impl SixlowpanPacket {
    /// Returns the type of the 6LoWPAN header.
    /// This can either be a fragment header or an IPHC header.
    ///
    /// # Errors
    /// Returns `[Error::Unrecognized]` when neither the Fragment Header dispatch or the IPHC
    /// dispatch is recognized.
    pub fn dispatch(buffer: impl AsRef<[u8]>) -> Result<Self> {
        let raw = buffer.as_ref();

        if raw.is_empty() {
            return Err(Error);
        }

        if raw[0] >> 3 == DISPATCH_FIRST_FRAGMENT_HEADER || raw[0] >> 3 == DISPATCH_FRAGMENT_HEADER
        {
            Ok(Self::FragmentHeader)
        } else if raw[0] >> 5 == DISPATCH_IPHC_HEADER {
            Ok(Self::IphcHeader)
        } else {
            Err(Error)
        }
    }
}

pub mod frag {
    //! Implementation of the fragment headers from [RFC 4944 § 5.3].
    //!
    //! [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

    use super::{DISPATCH_FIRST_FRAGMENT_HEADER, DISPATCH_FRAGMENT_HEADER};
    use crate::wire::{Error, Result};
    use crate::wire::{Ieee802154Address, Ieee802154Repr};
    use byteorder::{ByteOrder, NetworkEndian};

    /// Key used for identifying all the link fragments that belong to the same packet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Key {
        pub(crate) ll_src_addr: Ieee802154Address,
        pub(crate) ll_dst_addr: Ieee802154Address,
        pub(crate) datagram_size: u16,
        pub(crate) datagram_tag: u16,
    }

    /// A read/write wrapper around a 6LoWPAN Fragment header.
    /// [RFC 4944 § 5.3] specifies the format of the header.
    ///
    /// A First Fragment header has the following format:
    /// ```txt
    ///                      1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |1 1 0 0 0|    datagram_size    |         datagram_tag          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// Subsequent fragment headers have the following format:
    /// ```txt
    ///                      1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |1 1 1 0 0|    datagram_size    |         datagram_tag          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |datagram_offset|
    /// +-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    pub const FIRST_FRAGMENT_HEADER_SIZE: usize = 4;
    pub const NEXT_FRAGMENT_HEADER_SIZE: usize = 5;

    mod field {
        use crate::wire::field::*;

        pub const DISPATCH: usize = 0;
        pub const DATAGRAM_SIZE: Field = 0..2;
        pub const DATAGRAM_TAG: Field = 2..4;
        pub const DATAGRAM_OFFSET: usize = 4;

        pub const FIRST_FRAGMENT_REST: Rest = super::FIRST_FRAGMENT_HEADER_SIZE..;
        pub const NEXT_FRAGMENT_REST: Rest = super::NEXT_FRAGMENT_HEADER_SIZE..;
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        /// Input a raw octet buffer with a 6LoWPAN Fragment header structure.
        pub const fn new_unchecked(buffer: T) -> Self {
            Self { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<Self> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;

            let dispatch = packet.dispatch();

            if dispatch != DISPATCH_FIRST_FRAGMENT_HEADER && dispatch != DISPATCH_FRAGMENT_HEADER {
                return Err(Error);
            }

            Ok(packet)
        }

        /// Ensure that no accessor method will panic if called.
        /// Returns `Err(Error)` if the buffer is too short.
        pub fn check_len(&self) -> Result<()> {
            let buffer = self.buffer.as_ref();
            if buffer.is_empty() {
                return Err(Error);
            }

            match self.dispatch() {
                DISPATCH_FIRST_FRAGMENT_HEADER if buffer.len() >= FIRST_FRAGMENT_HEADER_SIZE => {
                    Ok(())
                }
                DISPATCH_FIRST_FRAGMENT_HEADER if buffer.len() < FIRST_FRAGMENT_HEADER_SIZE => {
                    Err(Error)
                }
                DISPATCH_FRAGMENT_HEADER if buffer.len() >= NEXT_FRAGMENT_HEADER_SIZE => Ok(()),
                DISPATCH_FRAGMENT_HEADER if buffer.len() < NEXT_FRAGMENT_HEADER_SIZE => Err(Error),
                _ => Err(Error),
            }
        }

        /// Consumes the frame, returning the underlying buffer.
        pub fn into_inner(self) -> T {
            self.buffer
        }

        /// Return the dispatch field.
        pub fn dispatch(&self) -> u8 {
            let raw = self.buffer.as_ref();
            raw[field::DISPATCH] >> 3
        }

        /// Return the total datagram size.
        pub fn datagram_size(&self) -> u16 {
            let raw = self.buffer.as_ref();
            NetworkEndian::read_u16(&raw[field::DATAGRAM_SIZE]) & 0b111_1111_1111
        }

        /// Return the datagram tag.
        pub fn datagram_tag(&self) -> u16 {
            let raw = self.buffer.as_ref();
            NetworkEndian::read_u16(&raw[field::DATAGRAM_TAG])
        }

        /// Return the datagram offset.
        pub fn datagram_offset(&self) -> u8 {
            match self.dispatch() {
                DISPATCH_FIRST_FRAGMENT_HEADER => 0,
                DISPATCH_FRAGMENT_HEADER => {
                    let raw = self.buffer.as_ref();
                    raw[field::DATAGRAM_OFFSET]
                }
                _ => unreachable!(),
            }
        }

        /// Returns `true` when this header is from the first fragment of a link.
        pub fn is_first_fragment(&self) -> bool {
            self.dispatch() == DISPATCH_FIRST_FRAGMENT_HEADER
        }

        /// Returns the key for identifying the packet it belongs to.
        pub fn get_key(&self, ieee802154_repr: &Ieee802154Repr) -> Key {
            Key {
                ll_src_addr: ieee802154_repr.src_addr.unwrap(),
                ll_dst_addr: ieee802154_repr.dst_addr.unwrap(),
                datagram_size: self.datagram_size(),
                datagram_tag: self.datagram_tag(),
            }
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
        /// Return the payload.
        pub fn payload(&self) -> &'a [u8] {
            match self.dispatch() {
                DISPATCH_FIRST_FRAGMENT_HEADER => {
                    let raw = self.buffer.as_ref();
                    &raw[field::FIRST_FRAGMENT_REST]
                }
                DISPATCH_FRAGMENT_HEADER => {
                    let raw = self.buffer.as_ref();
                    &raw[field::NEXT_FRAGMENT_REST]
                }
                _ => unreachable!(),
            }
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        fn set_dispatch_field(&mut self, value: u8) {
            let raw = self.buffer.as_mut();
            raw[field::DISPATCH] = (raw[field::DISPATCH] & !(0b11111 << 3)) | (value << 3);
        }

        fn set_datagram_size(&mut self, size: u16) {
            let raw = self.buffer.as_mut();
            let mut v = NetworkEndian::read_u16(&raw[field::DATAGRAM_SIZE]);
            v = (v & !0b111_1111_1111) | size;

            NetworkEndian::write_u16(&mut raw[field::DATAGRAM_SIZE], v);
        }

        fn set_datagram_tag(&mut self, tag: u16) {
            let raw = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut raw[field::DATAGRAM_TAG], tag);
        }

        fn set_datagram_offset(&mut self, offset: u8) {
            let raw = self.buffer.as_mut();
            raw[field::DATAGRAM_OFFSET] = offset;
        }
    }

    /// A high-level representation of a 6LoWPAN Fragment header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum Repr {
        FirstFragment { size: u16, tag: u16 },
        Fragment { size: u16, tag: u16, offset: u8 },
    }

    impl core::fmt::Display for Repr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Repr::FirstFragment { size, tag } => {
                    write!(f, "FirstFrag size={size} tag={tag}")
                }
                Repr::Fragment { size, tag, offset } => {
                    write!(f, "NthFrag size={size} tag={tag} offset={offset}")
                }
            }
        }
    }

    #[cfg(feature = "defmt")]
    impl defmt::Format for Repr {
        fn format(&self, fmt: defmt::Formatter) {
            match self {
                Repr::FirstFragment { size, tag } => {
                    defmt::write!(fmt, "FirstFrag size={} tag={}", size, tag);
                }
                Repr::Fragment { size, tag, offset } => {
                    defmt::write!(fmt, "NthFrag size={} tag={} offset={}", size, tag, offset);
                }
            }
        }
    }

    impl Repr {
        /// Parse a 6LoWPAN Fragment header.
        pub fn parse<T: AsRef<[u8]>>(packet: &Packet<T>) -> Result<Self> {
            let size = packet.datagram_size();
            let tag = packet.datagram_tag();

            match packet.dispatch() {
                DISPATCH_FIRST_FRAGMENT_HEADER => Ok(Self::FirstFragment { size, tag }),
                DISPATCH_FRAGMENT_HEADER => Ok(Self::Fragment {
                    size,
                    tag,
                    offset: packet.datagram_offset(),
                }),
                _ => Err(Error),
            }
        }

        /// Returns the length of the Fragment header.
        pub const fn buffer_len(&self) -> usize {
            match self {
                Self::FirstFragment { .. } => field::FIRST_FRAGMENT_REST.start,
                Self::Fragment { .. } => field::NEXT_FRAGMENT_REST.start,
            }
        }

        /// Emit a high-level representation into a 6LoWPAN Fragment header.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
            match self {
                Self::FirstFragment { size, tag } => {
                    packet.set_dispatch_field(DISPATCH_FIRST_FRAGMENT_HEADER);
                    packet.set_datagram_size(*size);
                    packet.set_datagram_tag(*tag);
                }
                Self::Fragment { size, tag, offset } => {
                    packet.set_dispatch_field(DISPATCH_FRAGMENT_HEADER);
                    packet.set_datagram_size(*size);
                    packet.set_datagram_tag(*tag);
                    packet.set_datagram_offset(*offset);
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NextHeader {
    Compressed,
    Uncompressed(IpProtocol),
}

impl core::fmt::Display for NextHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NextHeader::Compressed => write!(f, "compressed"),
            NextHeader::Uncompressed(protocol) => write!(f, "{protocol}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NextHeader {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            NextHeader::Compressed => defmt::write!(fmt, "compressed"),
            NextHeader::Uncompressed(protocol) => defmt::write!(fmt, "{}", protocol),
        }
    }
}

pub mod iphc {
    //! Implementation of IP Header Compression from [RFC 6282 § 3.1].
    //! It defines the compression of IPv6 headers.
    //!
    //! [RFC 6282 § 3.1]: https://datatracker.ietf.org/doc/html/rfc6282#section-3.1

    use super::{
        AddressContext, AddressMode, Error, NextHeader, Result, UnresolvedAddress,
        DISPATCH_IPHC_HEADER,
    };
    use crate::wire::{ieee802154::Address as LlAddress, ipv6, IpProtocol};
    use byteorder::{ByteOrder, NetworkEndian};

    mod field {
        use crate::wire::field::*;

        pub const IPHC_FIELD: Field = 0..2;
    }

    macro_rules! get_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&self) -> u8 {
                let data = self.buffer.as_ref();
                let raw = NetworkEndian::read_u16(&data[field::IPHC_FIELD]);
                ((raw >> $shift) & $mask) as u8
            }
        };
    }

    macro_rules! set_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&mut self, val: u8) {
                let data = &mut self.buffer.as_mut()[field::IPHC_FIELD];
                let mut raw = NetworkEndian::read_u16(data);

                raw = (raw & !($mask << $shift)) | ((val as u16) << $shift);
                NetworkEndian::write_u16(data, raw);
            }
        };
    }

    /// A read/write wrapper around a 6LoWPAN IPHC header.
    /// [RFC 6282 § 3.1] specifies the format of the header.
    ///
    /// The header always start with the following base format (from [RFC 6282 § 3.1.1]):
    /// ```txt
    ///    0                                       1
    ///    0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
    ///  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    ///  | 0 | 1 | 1 |  TF   |NH | HLIM  |CID|SAC|  SAM  | M |DAC|  DAM  |
    ///  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /// ```
    /// With:
    /// - TF: Traffic Class and Flow Label
    /// - NH: Next Header
    /// - HLIM: Hop Limit
    /// - CID: Context Identifier Extension
    /// - SAC: Source Address Compression
    /// - SAM: Source Address Mode
    /// - M: Multicast Compression
    /// - DAC: Destination Address Compression
    /// - DAM: Destination Address Mode
    ///
    /// Depending on the flags in the base format, the following fields are added to the header:
    /// - Traffic Class and Flow Label
    /// - Next Header
    /// - Hop Limit
    /// - IPv6 source address
    /// - IPv6 destinatino address
    ///
    /// [RFC 6282 § 3.1]: https://datatracker.ietf.org/doc/html/rfc6282#section-3.1
    /// [RFC 6282 § 3.1.1]: https://datatracker.ietf.org/doc/html/rfc6282#section-3.1.1
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        /// Input a raw octet buffer with a 6LoWPAN IPHC header structure.
        pub const fn new_unchecked(buffer: T) -> Self {
            Packet { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<Self> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;
            Ok(packet)
        }

        /// Ensure that no accessor method will panic if called.
        /// Returns `Err(Error)` if the buffer is too short.
        pub fn check_len(&self) -> Result<()> {
            let buffer = self.buffer.as_ref();
            if buffer.len() < 2 {
                return Err(Error);
            }

            let mut offset = self.ip_fields_start()
                + self.traffic_class_size()
                + self.next_header_size()
                + self.hop_limit_size();
            offset += self.src_address_size();
            offset += self.dst_address_size();

            if offset as usize > buffer.len() {
                return Err(Error);
            }

            Ok(())
        }

        /// Consumes the frame, returning the underlying buffer.
        pub fn into_inner(self) -> T {
            self.buffer
        }

        /// Return the Next Header field.
        pub fn next_header(&self) -> NextHeader {
            let nh = self.nh_field();

            if nh == 1 {
                // The next header field is compressed.
                // It is also encoded using LOWPAN_NHC.
                NextHeader::Compressed
            } else {
                // The full 8 bits for Next Header are carried in-line.
                let start = (self.ip_fields_start() + self.traffic_class_size()) as usize;

                let data = self.buffer.as_ref();
                let nh = data[start..start + 1][0];
                NextHeader::Uncompressed(IpProtocol::from(nh))
            }
        }

        /// Return the Hop Limit.
        pub fn hop_limit(&self) -> u8 {
            match self.hlim_field() {
                0b00 => {
                    let start = (self.ip_fields_start()
                        + self.traffic_class_size()
                        + self.next_header_size()) as usize;

                    let data = self.buffer.as_ref();
                    data[start..start + 1][0]
                }
                0b01 => 1,
                0b10 => 64,
                0b11 => 255,
                _ => unreachable!(),
            }
        }

        /// Return the Source Context Identifier.
        pub fn src_context_id(&self) -> Option<u8> {
            if self.cid_field() == 1 {
                let data = self.buffer.as_ref();
                Some(data[2] >> 4)
            } else {
                None
            }
        }

        /// Return the Destination Context Identifier.
        pub fn dst_context_id(&self) -> Option<u8> {
            if self.cid_field() == 1 {
                let data = self.buffer.as_ref();
                Some(data[2] & 0x0f)
            } else {
                None
            }
        }

        /// Return the ECN field (when it is inlined).
        pub fn ecn_field(&self) -> Option<u8> {
            match self.tf_field() {
                0b00 | 0b01 | 0b10 => {
                    let start = self.ip_fields_start() as usize;
                    Some(self.buffer.as_ref()[start..][0] & 0b1100_0000)
                }
                0b11 => None,
                _ => unreachable!(),
            }
        }

        /// Return the DSCP field (when it is inlined).
        pub fn dscp_field(&self) -> Option<u8> {
            match self.tf_field() {
                0b00 | 0b10 => {
                    let start = self.ip_fields_start() as usize;
                    Some(self.buffer.as_ref()[start..][0] & 0b111111)
                }
                0b01 | 0b11 => None,
                _ => unreachable!(),
            }
        }

        /// Return the flow label field (when it is inlined).
        pub fn flow_label_field(&self) -> Option<u16> {
            match self.tf_field() {
                0b00 => {
                    let start = self.ip_fields_start() as usize;
                    Some(NetworkEndian::read_u16(
                        &self.buffer.as_ref()[start..][2..4],
                    ))
                }
                0b01 => {
                    let start = self.ip_fields_start() as usize;
                    Some(NetworkEndian::read_u16(
                        &self.buffer.as_ref()[start..][1..3],
                    ))
                }
                0b10 | 0b11 => None,
                _ => unreachable!(),
            }
        }

        /// Return the Source Address.
        pub fn src_addr(&self) -> Result<UnresolvedAddress> {
            let start = (self.ip_fields_start()
                + self.traffic_class_size()
                + self.next_header_size()
                + self.hop_limit_size()) as usize;

            let data = self.buffer.as_ref();
            match (self.sac_field(), self.sam_field()) {
                (0, 0b00) => Ok(UnresolvedAddress::WithoutContext(AddressMode::FullInline(
                    &data[start..][..16],
                ))),
                (0, 0b01) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::InLine64bits(&data[start..][..8]),
                )),
                (0, 0b10) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::InLine16bits(&data[start..][..2]),
                )),
                (0, 0b11) => Ok(UnresolvedAddress::WithoutContext(AddressMode::FullyElided)),
                (1, 0b00) => Ok(UnresolvedAddress::WithContext((
                    0,
                    AddressMode::Unspecified,
                ))),
                (1, 0b01) => {
                    if let Some(id) = self.src_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::InLine64bits(&data[start..][..8]),
                        )))
                    } else {
                        Err(Error)
                    }
                }
                (1, 0b10) => {
                    if let Some(id) = self.src_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::InLine16bits(&data[start..][..2]),
                        )))
                    } else {
                        Err(Error)
                    }
                }
                (1, 0b11) => {
                    if let Some(id) = self.src_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::FullyElided,
                        )))
                    } else {
                        Err(Error)
                    }
                }
                _ => Err(Error),
            }
        }

        /// Return the Destination Address.
        pub fn dst_addr(&self) -> Result<UnresolvedAddress> {
            let start = (self.ip_fields_start()
                + self.traffic_class_size()
                + self.next_header_size()
                + self.hop_limit_size()
                + self.src_address_size()) as usize;

            let data = self.buffer.as_ref();
            match (self.m_field(), self.dac_field(), self.dam_field()) {
                (0, 0, 0b00) => Ok(UnresolvedAddress::WithoutContext(AddressMode::FullInline(
                    &data[start..][..16],
                ))),
                (0, 0, 0b01) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::InLine64bits(&data[start..][..8]),
                )),
                (0, 0, 0b10) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::InLine16bits(&data[start..][..2]),
                )),
                (0, 0, 0b11) => Ok(UnresolvedAddress::WithoutContext(AddressMode::FullyElided)),
                (0, 1, 0b00) => Ok(UnresolvedAddress::Reserved),
                (0, 1, 0b01) => {
                    if let Some(id) = self.dst_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::InLine64bits(&data[start..][..8]),
                        )))
                    } else {
                        Err(Error)
                    }
                }
                (0, 1, 0b10) => {
                    if let Some(id) = self.dst_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::InLine16bits(&data[start..][..2]),
                        )))
                    } else {
                        Err(Error)
                    }
                }
                (0, 1, 0b11) => {
                    if let Some(id) = self.dst_context_id() {
                        Ok(UnresolvedAddress::WithContext((
                            id as usize,
                            AddressMode::FullyElided,
                        )))
                    } else {
                        Err(Error)
                    }
                }
                (1, 0, 0b00) => Ok(UnresolvedAddress::WithoutContext(AddressMode::FullInline(
                    &data[start..][..16],
                ))),
                (1, 0, 0b01) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::Multicast48bits(&data[start..][..6]),
                )),
                (1, 0, 0b10) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::Multicast32bits(&data[start..][..4]),
                )),
                (1, 0, 0b11) => Ok(UnresolvedAddress::WithoutContext(
                    AddressMode::Multicast8bits(&data[start..][..1]),
                )),
                (1, 1, 0b00) => Ok(UnresolvedAddress::WithContext((
                    0,
                    AddressMode::NotSupported,
                ))),
                (1, 1, 0b01 | 0b10 | 0b11) => Ok(UnresolvedAddress::Reserved),
                _ => Err(Error),
            }
        }

        get_field!(dispatch_field, 0b111, 13);
        get_field!(tf_field, 0b11, 11);
        get_field!(nh_field, 0b1, 10);
        get_field!(hlim_field, 0b11, 8);
        get_field!(cid_field, 0b1, 7);
        get_field!(sac_field, 0b1, 6);
        get_field!(sam_field, 0b11, 4);
        get_field!(m_field, 0b1, 3);
        get_field!(dac_field, 0b1, 2);
        get_field!(dam_field, 0b11, 0);

        /// Return the start for the IP fields.
        fn ip_fields_start(&self) -> u8 {
            2 + self.cid_size()
        }

        /// Get the size in octets of the traffic class field.
        fn traffic_class_size(&self) -> u8 {
            match self.tf_field() {
                0b00 => 4,
                0b01 => 3,
                0b10 => 1,
                0b11 => 0,
                _ => unreachable!(),
            }
        }

        /// Get the size in octets of the next header field.
        fn next_header_size(&self) -> u8 {
            (self.nh_field() != 1) as u8
        }

        /// Get the size in octets of the hop limit field.
        fn hop_limit_size(&self) -> u8 {
            (self.hlim_field() == 0b00) as u8
        }

        /// Get the size in octets of the CID field.
        fn cid_size(&self) -> u8 {
            (self.cid_field() == 1) as u8
        }

        /// Get the size in octets of the source address.
        fn src_address_size(&self) -> u8 {
            match (self.sac_field(), self.sam_field()) {
                (0, 0b00) => 16, // The full address is carried in-line.
                (0, 0b01) => 8,  // The first 64 bits are elided.
                (0, 0b10) => 2,  // The first 112 bits are elided.
                (0, 0b11) => 0,  // The address is fully elided.
                (1, 0b00) => 0,  // The UNSPECIFIED address.
                (1, 0b01) => 8,  // Address derived using context information.
                (1, 0b10) => 2,  // Address derived using context information.
                (1, 0b11) => 0,  // Address derived using context information.
                _ => unreachable!(),
            }
        }

        /// Get the size in octets of the address address.
        fn dst_address_size(&self) -> u8 {
            match (self.m_field(), self.dac_field(), self.dam_field()) {
                (0, 0, 0b00) => 16, // The full address is carried in-line.
                (0, 0, 0b01) => 8,  // The first 64 bits are elided.
                (0, 0, 0b10) => 2,  // The first 112 bits are elided.
                (0, 0, 0b11) => 0,  // The address is fully elided.
                (0, 1, 0b00) => 0,  // Reserved.
                (0, 1, 0b01) => 8,  // Address derived using context information.
                (0, 1, 0b10) => 2,  // Address derived using context information.
                (0, 1, 0b11) => 0,  // Address derived using context information.
                (1, 0, 0b00) => 16, // The full address is carried in-line.
                (1, 0, 0b01) => 6,  // The address takes the form ffXX::00XX:XXXX:XXXX.
                (1, 0, 0b10) => 4,  // The address takes the form ffXX::00XX:XXXX.
                (1, 0, 0b11) => 1,  // The address takes the form ff02::00XX.
                (1, 1, 0b00) => 6,  // Match Unicast-Prefix-based IPv6.
                (1, 1, 0b01) => 0,  // Reserved.
                (1, 1, 0b10) => 0,  // Reserved.
                (1, 1, 0b11) => 0,  // Reserved.
                _ => unreachable!(),
            }
        }

        /// Return the length of the header.
        pub fn header_len(&self) -> usize {
            let mut len = self.ip_fields_start();
            len += self.traffic_class_size();
            len += self.next_header_size();
            len += self.hop_limit_size();
            len += self.src_address_size();
            len += self.dst_address_size();

            len as usize
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
        /// Return a pointer to the payload.
        pub fn payload(&self) -> &'a [u8] {
            let mut len = self.ip_fields_start();
            len += self.traffic_class_size();
            len += self.next_header_size();
            len += self.hop_limit_size();
            len += self.src_address_size();
            len += self.dst_address_size();

            let len = len as usize;

            let data = self.buffer.as_ref();
            &data[len..]
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Set the dispatch field to `0b011`.
        fn set_dispatch_field(&mut self) {
            let data = &mut self.buffer.as_mut()[field::IPHC_FIELD];
            let mut raw = NetworkEndian::read_u16(data);

            raw = (raw & !(0b111 << 13)) | (0b11 << 13);
            NetworkEndian::write_u16(data, raw);
        }

        set_field!(set_tf_field, 0b11, 11);
        set_field!(set_nh_field, 0b1, 10);
        set_field!(set_hlim_field, 0b11, 8);
        set_field!(set_cid_field, 0b1, 7);
        set_field!(set_sac_field, 0b1, 6);
        set_field!(set_sam_field, 0b11, 4);
        set_field!(set_m_field, 0b1, 3);
        set_field!(set_dac_field, 0b1, 2);
        set_field!(set_dam_field, 0b11, 0);

        fn set_field(&mut self, idx: usize, value: &[u8]) {
            let raw = self.buffer.as_mut();
            raw[idx..idx + value.len()].copy_from_slice(value);
        }

        /// Set the Next Header.
        ///
        /// **NOTE**: `idx` is the offset at which the Next Header needs to be written to.
        fn set_next_header(&mut self, nh: NextHeader, mut idx: usize) -> usize {
            match nh {
                NextHeader::Uncompressed(nh) => {
                    self.set_nh_field(0);
                    self.set_field(idx, &[nh.into()]);
                    idx += 1;
                }
                NextHeader::Compressed => self.set_nh_field(1),
            }

            idx
        }

        /// Set the Hop Limit.
        ///
        /// **NOTE**: `idx` is the offset at which the Next Header needs to be written to.
        fn set_hop_limit(&mut self, hl: u8, mut idx: usize) -> usize {
            match hl {
                255 => self.set_hlim_field(0b11),
                64 => self.set_hlim_field(0b10),
                1 => self.set_hlim_field(0b01),
                _ => {
                    self.set_hlim_field(0b00);
                    self.set_field(idx, &[hl]);
                    idx += 1;
                }
            }

            idx
        }

        /// Set the Source Address based on the IPv6 address and the Link-Local address.
        ///
        /// **NOTE**: `idx` is the offset at which the Next Header needs to be written to.
        fn set_src_address(
            &mut self,
            src_addr: ipv6::Address,
            ll_src_addr: Option<LlAddress>,
            mut idx: usize,
        ) -> usize {
            self.set_cid_field(0);
            self.set_sac_field(0);
            let src = src_addr.as_bytes();
            if src_addr == ipv6::Address::UNSPECIFIED {
                self.set_sac_field(1);
                self.set_sam_field(0b00);
            } else if src_addr.is_link_local() {
                // We have a link local address.
                // The remainder of the address can be elided when the context contains
                // a 802.15.4 short address or a 802.15.4 extended address which can be
                // converted to a eui64 address.
                let is_eui_64 = ll_src_addr
                    .map(|addr| {
                        addr.as_eui_64()
                            .map(|addr| addr[..] == src[8..])
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if src[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    let ll = [src[14], src[15]];

                    if ll_src_addr == Some(LlAddress::Short(ll)) {
                        // We have the context from the 802.15.4 frame.
                        // The context contains the short address.
                        // We can elide the source address.
                        self.set_sam_field(0b11);
                    } else {
                        // We don't have the context from the 802.15.4 frame.
                        // We cannot elide the source address, however we can elide 112 bits.
                        self.set_sam_field(0b10);

                        self.set_field(idx, &src[14..]);
                        idx += 2;
                    }
                } else if is_eui_64 {
                    // We have the context from the 802.15.4 frame.
                    // The context contains the extended address.
                    // We can elide the source address.
                    self.set_sam_field(0b11);
                } else {
                    // We cannot elide the source address, however we can elide 64 bits.
                    self.set_sam_field(0b01);

                    self.set_field(idx, &src[8..]);
                    idx += 8;
                }
            } else {
                // We cannot elide anything.
                self.set_sam_field(0b00);
                self.set_field(idx, src);
                idx += 16;
            }

            idx
        }

        /// Set the Destination Address based on the IPv6 address and the Link-Local address.
        ///
        /// **NOTE**: `idx` is the offset at which the Next Header needs to be written to.
        fn set_dst_address(
            &mut self,
            dst_addr: ipv6::Address,
            ll_dst_addr: Option<LlAddress>,
            mut idx: usize,
        ) -> usize {
            self.set_dac_field(0);
            self.set_dam_field(0);
            self.set_m_field(0);
            let dst = dst_addr.as_bytes();
            if dst_addr.is_multicast() {
                self.set_m_field(1);

                if dst[1] == 0x02 && dst[2..15] == [0; 13] {
                    self.set_dam_field(0b11);

                    self.set_field(idx, &[dst[15]]);
                    idx += 1;
                } else if dst[2..13] == [0; 11] {
                    self.set_dam_field(0b10);

                    self.set_field(idx, &[dst[1]]);
                    idx += 1;
                    self.set_field(idx, &dst[13..]);
                    idx += 3;
                } else if dst[2..11] == [0; 9] {
                    self.set_dam_field(0b01);

                    self.set_field(idx, &[dst[1]]);
                    idx += 1;
                    self.set_field(idx, &dst[11..]);
                    idx += 5;
                } else {
                    self.set_dam_field(0b11);

                    self.set_field(idx, dst);
                    idx += 16;
                }
            } else if dst_addr.is_link_local() {
                let is_eui_64 = ll_dst_addr
                    .map(|addr| {
                        addr.as_eui_64()
                            .map(|addr| addr[..] == dst[8..])
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if dst[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    let ll = [dst[14], dst[15]];

                    if ll_dst_addr == Some(LlAddress::Short(ll)) {
                        self.set_dam_field(0b11);
                    } else {
                        self.set_dam_field(0b10);

                        self.set_field(idx, &dst[14..]);
                        idx += 2;
                    }
                } else if is_eui_64 {
                    self.set_dam_field(0b11);
                } else {
                    self.set_dam_field(0b01);

                    self.set_field(idx, &dst[8..]);
                    idx += 8;
                }
            } else {
                self.set_dam_field(0b00);

                self.set_field(idx, dst);
                idx += 16;
            }

            idx
        }

        /// Return a mutable pointer to the payload.
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let mut len = self.ip_fields_start();

            len += self.traffic_class_size();
            len += self.next_header_size();
            len += self.hop_limit_size();
            len += self.src_address_size();
            len += self.dst_address_size();

            let len = len as usize;

            let data = self.buffer.as_mut();
            &mut data[len..]
        }
    }

    /// A high-level representation of a 6LoWPAN IPHC header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Repr {
        pub src_addr: ipv6::Address,
        pub ll_src_addr: Option<LlAddress>,
        pub dst_addr: ipv6::Address,
        pub ll_dst_addr: Option<LlAddress>,
        pub next_header: NextHeader,
        pub hop_limit: u8,
        // TODO(thvdveld): refactor the following fields into something else
        pub ecn: Option<u8>,
        pub dscp: Option<u8>,
        pub flow_label: Option<u16>,
    }

    impl core::fmt::Display for Repr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "IPHC src={} dst={} nxt-hdr={} hop-limit={}",
                self.src_addr, self.dst_addr, self.next_header, self.hop_limit
            )
        }
    }

    #[cfg(feature = "defmt")]
    impl defmt::Format for Repr {
        fn format(&self, fmt: defmt::Formatter) {
            defmt::write!(
                fmt,
                "IPHC src={} dst={} nxt-hdr={} hop-limit={}",
                self.src_addr,
                self.dst_addr,
                self.next_header,
                self.hop_limit
            );
        }
    }

    impl Repr {
        /// Parse a 6LoWPAN IPHC header and return a high-level representation.
        ///
        /// The `ll_src_addr` and `ll_dst_addr` are the link-local addresses used for resolving the
        /// IPv6 packets.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(
            packet: &Packet<&T>,
            ll_src_addr: Option<LlAddress>,
            ll_dst_addr: Option<LlAddress>,
            addr_context: &[AddressContext],
        ) -> Result<Self> {
            // Ensure basic accessors will work.
            packet.check_len()?;

            if packet.dispatch_field() != DISPATCH_IPHC_HEADER {
                // This is not an LOWPAN_IPHC packet.
                return Err(Error);
            }

            let src_addr = packet.src_addr()?.resolve(ll_src_addr, addr_context)?;
            let dst_addr = packet.dst_addr()?.resolve(ll_dst_addr, addr_context)?;

            Ok(Self {
                src_addr,
                ll_src_addr,
                dst_addr,
                ll_dst_addr,
                next_header: packet.next_header(),
                hop_limit: packet.hop_limit(),
                ecn: packet.ecn_field(),
                dscp: packet.dscp_field(),
                flow_label: packet.flow_label_field(),
            })
        }

        /// Return the length of a header that will be emitted from this high-level representation.
        pub fn buffer_len(&self) -> usize {
            let mut len = 0;
            len += 2; // The minimal header length

            len += match self.next_header {
                NextHeader::Compressed => 0, // The next header is compressed (we don't need to inline what the next header is)
                NextHeader::Uncompressed(_) => 1, // The next header field is inlined
            };

            // Hop Limit size
            len += match self.hop_limit {
                255 | 64 | 1 => 0, // We can inline the hop limit
                _ => 1,
            };

            // Add the length of the source address
            len += if self.src_addr == ipv6::Address::UNSPECIFIED {
                0
            } else if self.src_addr.is_link_local() {
                let src = self.src_addr.as_bytes();
                let ll = [src[14], src[15]];

                let is_eui_64 = self
                    .ll_src_addr
                    .map(|addr| {
                        addr.as_eui_64()
                            .map(|addr| addr[..] == src[8..])
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if src[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    if self.ll_src_addr == Some(LlAddress::Short(ll)) {
                        0
                    } else {
                        2
                    }
                } else if is_eui_64 {
                    0
                } else {
                    8
                }
            } else {
                16
            };

            // Add the size of the destination header
            let dst = self.dst_addr.as_bytes();
            len += if self.dst_addr.is_multicast() {
                if dst[1] == 0x02 && dst[2..15] == [0; 13] {
                    1
                } else if dst[2..13] == [0; 11] {
                    4
                } else if dst[2..11] == [0; 9] {
                    6
                } else {
                    16
                }
            } else if self.dst_addr.is_link_local() {
                let is_eui_64 = self
                    .ll_dst_addr
                    .map(|addr| {
                        addr.as_eui_64()
                            .map(|addr| addr[..] == dst[8..])
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if dst[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    let ll = [dst[14], dst[15]];

                    if self.ll_dst_addr == Some(LlAddress::Short(ll)) {
                        0
                    } else {
                        2
                    }
                } else if is_eui_64 {
                    0
                } else {
                    8
                }
            } else {
                16
            };

            len += match (self.ecn, self.dscp, self.flow_label) {
                (Some(_), Some(_), Some(_)) => 4,
                (Some(_), None, Some(_)) => 3,
                (Some(_), Some(_), None) => 1,
                (None, None, None) => 0,
                _ => unreachable!(),
            };

            len
        }

        /// Emit a high-level representation into a 6LoWPAN IPHC header.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
            let idx = 2;

            packet.set_dispatch_field();

            // FIXME(thvdveld): we don't set anything from the traffic flow.
            packet.set_tf_field(0b11);

            let idx = packet.set_next_header(self.next_header, idx);
            let idx = packet.set_hop_limit(self.hop_limit, idx);
            let idx = packet.set_src_address(self.src_addr, self.ll_src_addr, idx);
            packet.set_dst_address(self.dst_addr, self.ll_dst_addr, idx);
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn iphc_fields() {
            let bytes = [
                0x7a, 0x33, // IPHC
                0x3a, // Next header
            ];

            let packet = Packet::new_unchecked(bytes);

            assert_eq!(packet.dispatch_field(), 0b011);
            assert_eq!(packet.tf_field(), 0b11);
            assert_eq!(packet.nh_field(), 0b0);
            assert_eq!(packet.hlim_field(), 0b10);
            assert_eq!(packet.cid_field(), 0b0);
            assert_eq!(packet.sac_field(), 0b0);
            assert_eq!(packet.sam_field(), 0b11);
            assert_eq!(packet.m_field(), 0b0);
            assert_eq!(packet.dac_field(), 0b0);
            assert_eq!(packet.dam_field(), 0b11);

            assert_eq!(
                packet.next_header(),
                NextHeader::Uncompressed(IpProtocol::Icmpv6)
            );

            assert_eq!(packet.src_address_size(), 0);
            assert_eq!(packet.dst_address_size(), 0);
            assert_eq!(packet.hop_limit(), 64);

            assert_eq!(
                packet.src_addr(),
                Ok(UnresolvedAddress::WithoutContext(AddressMode::FullyElided))
            );
            assert_eq!(
                packet.dst_addr(),
                Ok(UnresolvedAddress::WithoutContext(AddressMode::FullyElided))
            );

            let bytes = [
                0x7e, 0xf7, // IPHC,
                0x00, // CID
            ];

            let packet = Packet::new_unchecked(bytes);

            assert_eq!(packet.dispatch_field(), 0b011);
            assert_eq!(packet.tf_field(), 0b11);
            assert_eq!(packet.nh_field(), 0b1);
            assert_eq!(packet.hlim_field(), 0b10);
            assert_eq!(packet.cid_field(), 0b1);
            assert_eq!(packet.sac_field(), 0b1);
            assert_eq!(packet.sam_field(), 0b11);
            assert_eq!(packet.m_field(), 0b0);
            assert_eq!(packet.dac_field(), 0b1);
            assert_eq!(packet.dam_field(), 0b11);

            assert_eq!(packet.next_header(), NextHeader::Compressed);

            assert_eq!(packet.src_address_size(), 0);
            assert_eq!(packet.dst_address_size(), 0);
            assert_eq!(packet.hop_limit(), 64);

            assert_eq!(
                packet.src_addr(),
                Ok(UnresolvedAddress::WithContext((
                    0,
                    AddressMode::FullyElided
                )))
            );
            assert_eq!(
                packet.dst_addr(),
                Ok(UnresolvedAddress::WithContext((
                    0,
                    AddressMode::FullyElided
                )))
            );
        }
    }
}

pub mod nhc {
    //! Implementation of Next Header Compression from [RFC 6282 § 4].
    //!
    //! [RFC 6282 § 4]: https://datatracker.ietf.org/doc/html/rfc6282#section-4
    use super::{Error, NextHeader, Result, DISPATCH_EXT_HEADER, DISPATCH_UDP_HEADER};
    use crate::{
        phy::ChecksumCapabilities,
        wire::{
            ip::{checksum, Address as IpAddress},
            ipv6,
            udp::Repr as UdpRepr,
            IpProtocol,
        },
    };
    use byteorder::{ByteOrder, NetworkEndian};
    use ipv6::Address;

    macro_rules! get_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&self) -> u8 {
                let data = self.buffer.as_ref();
                let raw = &data[0];
                ((raw >> $shift) & $mask) as u8
            }
        };
    }

    macro_rules! set_field {
        ($name:ident, $mask:expr, $shift:expr) => {
            fn $name(&mut self, val: u8) {
                let data = self.buffer.as_mut();
                let mut raw = data[0];
                raw = (raw & !($mask << $shift)) | (val << $shift);
                data[0] = raw;
            }
        };
    }

    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    /// A read/write wrapper around a 6LoWPAN_NHC Header.
    /// [RFC 6282 § 4.2] specifies the format of the header.
    ///
    /// The header has the following format:
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | 1 | 1 | 0 |    EID    |NH |
    /// +---+---+---+---+---+---+---+---+
    /// ```
    ///
    /// With:
    /// - EID: the extension header ID
    /// - NH: Next Header
    ///
    /// [RFC 6282 § 4.2]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.2
    pub enum NhcPacket {
        ExtHeader,
        UdpHeader,
    }

    impl NhcPacket {
        /// Returns the type of the Next Header header.
        /// This can either be an Extenstion header or an 6LoWPAN Udp header.
        ///
        /// # Errors
        /// Returns `[Error::Unrecognized]` when neither the Extension Header dispatch or the Udp
        /// dispatch is recognized.
        pub fn dispatch(buffer: impl AsRef<[u8]>) -> Result<Self> {
            let raw = buffer.as_ref();
            if raw.is_empty() {
                return Err(Error);
            }

            if raw[0] >> 4 == DISPATCH_EXT_HEADER {
                // We have a compressed IPv6 Extension Header.
                Ok(Self::ExtHeader)
            } else if raw[0] >> 3 == DISPATCH_UDP_HEADER {
                // We have a compressed UDP header.
                Ok(Self::UdpHeader)
            } else {
                Err(Error)
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum ExtHeaderId {
        HopByHopHeader,
        RoutingHeader,
        FragmentHeader,
        DestinationOptionsHeader,
        MobilityHeader,
        Header,
        Reserved,
    }

    impl From<ExtHeaderId> for IpProtocol {
        fn from(val: ExtHeaderId) -> Self {
            match val {
                ExtHeaderId::HopByHopHeader => Self::HopByHop,
                ExtHeaderId::RoutingHeader => Self::Ipv6Route,
                ExtHeaderId::FragmentHeader => Self::Ipv6Frag,
                ExtHeaderId::DestinationOptionsHeader => Self::Ipv6Opts,
                ExtHeaderId::MobilityHeader => Self::Unknown(0),
                ExtHeaderId::Header => Self::Unknown(0),
                ExtHeaderId::Reserved => Self::Unknown(0),
            }
        }
    }

    /// A read/write wrapper around a 6LoWPAN NHC Extension header.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct ExtHeaderPacket<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> ExtHeaderPacket<T> {
        /// Input a raw octet buffer with a 6LoWPAN NHC Extension Header structure.
        pub const fn new_unchecked(buffer: T) -> Self {
            ExtHeaderPacket { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<Self> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;

            if packet.eid_field() > 7 {
                return Err(Error);
            }

            Ok(packet)
        }

        /// Ensure that no accessor method will panic if called.
        /// Returns `Err(Error)` if the buffer is too short.
        pub fn check_len(&self) -> Result<()> {
            let buffer = self.buffer.as_ref();

            if buffer.is_empty() {
                return Err(Error);
            }

            let mut len = 1;
            len += self.next_header_size();

            if len <= buffer.len() {
                Ok(())
            } else {
                Err(Error)
            }
        }

        /// Consumes the frame, returning the underlying buffer.
        pub fn into_inner(self) -> T {
            self.buffer
        }

        get_field!(dispatch_field, 0b1111, 4);
        get_field!(eid_field, 0b111, 1);
        get_field!(nh_field, 0b1, 0);

        /// Return the Extension Header ID.
        pub fn extension_header_id(&self) -> ExtHeaderId {
            match self.eid_field() {
                0 => ExtHeaderId::HopByHopHeader,
                1 => ExtHeaderId::RoutingHeader,
                2 => ExtHeaderId::FragmentHeader,
                3 => ExtHeaderId::DestinationOptionsHeader,
                4 => ExtHeaderId::MobilityHeader,
                5 | 6 => ExtHeaderId::Reserved,
                7 => ExtHeaderId::Header,
                _ => unreachable!(),
            }
        }

        /// Parse the next header field.
        pub fn next_header(&self) -> NextHeader {
            if self.nh_field() == 1 {
                NextHeader::Compressed
            } else {
                // The full 8 bits for Next Header are carried in-line.
                let start = 1;

                let data = self.buffer.as_ref();
                let nh = data[start];
                NextHeader::Uncompressed(IpProtocol::from(nh))
            }
        }

        /// Return the size of the Next Header field.
        fn next_header_size(&self) -> usize {
            // If nh is set, then the Next Header is compressed using LOWPAN_NHC
            match self.nh_field() {
                0 => 1,
                1 => 0,
                _ => unreachable!(),
            }
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> ExtHeaderPacket<&'a T> {
        /// Return a pointer to the payload.
        pub fn payload(&self) -> &'a [u8] {
            let start = 2 + self.next_header_size();
            &self.buffer.as_ref()[start..]
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> ExtHeaderPacket<T> {
        /// Return a mutable pointer to the payload.
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let start = 2 + self.next_header_size();
            &mut self.buffer.as_mut()[start..]
        }

        /// Set the dispatch field to `0b1110`.
        fn set_dispatch_field(&mut self) {
            let data = self.buffer.as_mut();
            data[0] = (data[0] & !(0b1111 << 4)) | (DISPATCH_EXT_HEADER << 4);
        }

        set_field!(set_eid_field, 0b111, 1);
        set_field!(set_nh_field, 0b1, 0);

        /// Set the Extension Header ID field.
        fn set_extension_header_id(&mut self, ext_header_id: ExtHeaderId) {
            let id = match ext_header_id {
                ExtHeaderId::HopByHopHeader => 0,
                ExtHeaderId::RoutingHeader => 1,
                ExtHeaderId::FragmentHeader => 2,
                ExtHeaderId::DestinationOptionsHeader => 3,
                ExtHeaderId::MobilityHeader => 4,
                ExtHeaderId::Reserved => 5,
                ExtHeaderId::Header => 7,
            };

            self.set_eid_field(id);
        }

        /// Set the Next Header.
        fn set_next_header(&mut self, next_header: NextHeader) {
            match next_header {
                NextHeader::Compressed => self.set_nh_field(0b1),
                NextHeader::Uncompressed(nh) => {
                    self.set_nh_field(0b0);

                    let start = 1;
                    let data = self.buffer.as_mut();
                    data[start] = nh.into();
                }
            }
        }

        /// Set the length.
        fn set_length(&mut self, length: u8) {
            let start = 1 + self.next_header_size();

            let data = self.buffer.as_mut();
            data[start] = length;
        }
    }

    /// A high-level representation of an 6LoWPAN NHC Extension header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct ExtHeaderRepr {
        ext_header_id: ExtHeaderId,
        next_header: NextHeader,
        length: u8,
    }

    impl ExtHeaderRepr {
        /// Parse a 6LoWPAN NHC Extension Header packet and return a high-level representation.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &ExtHeaderPacket<&T>) -> Result<Self> {
            // Ensure basic accessors will work.
            packet.check_len()?;

            if packet.dispatch_field() != DISPATCH_EXT_HEADER {
                return Err(Error);
            }

            Ok(Self {
                ext_header_id: packet.extension_header_id(),
                next_header: packet.next_header(),
                length: packet.payload().len() as u8,
            })
        }

        /// Return the length of a header that will be emitted from this high-level representation.
        pub fn buffer_len(&self) -> usize {
            let mut len = 1; // The minimal header size

            if self.next_header != NextHeader::Compressed {
                len += 1;
            }

            len += 1; // The length

            len
        }

        /// Emit a high-level representaiton into a 6LoWPAN NHC Extension Header packet.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut ExtHeaderPacket<T>) {
            packet.set_dispatch_field();
            packet.set_extension_header_id(self.ext_header_id);
            packet.set_next_header(self.next_header);
            packet.set_length(self.length);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use crate::wire::{Ipv6RoutingHeader, Ipv6RoutingRepr};

        #[cfg(feature = "proto-rpl")]
        use crate::wire::{
            Ipv6Option, Ipv6OptionRepr, Ipv6OptionsIterator, RplHopByHopRepr, RplInstanceId,
        };

        #[cfg(feature = "proto-rpl")]
        const RPL_HOP_BY_HOP_PACKET: [u8; 9] =
            [0xe0, 0x3a, 0x06, 0x63, 0x04, 0x00, 0x1e, 0x03, 0x00];

        const ROUTING_SR_PACKET: [u8; 32] = [
            0xe3, 0x1e, 0x03, 0x03, 0x99, 0x30, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
            0x05, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
            0x02, 0x00, 0x00, 0x00,
        ];

        #[test]
        #[cfg(feature = "proto-rpl")]
        fn test_rpl_hop_by_hop_option_deconstruct() {
            let header = ExtHeaderPacket::new_checked(&RPL_HOP_BY_HOP_PACKET).unwrap();
            assert_eq!(
                header.next_header(),
                NextHeader::Uncompressed(IpProtocol::Icmpv6)
            );
            assert_eq!(header.extension_header_id(), ExtHeaderId::HopByHopHeader);

            let options = header.payload();
            let mut options = Ipv6OptionsIterator::new(options);
            let rpl_repr = options.next().unwrap();
            let rpl_repr = rpl_repr.unwrap();

            match rpl_repr {
                Ipv6OptionRepr::Rpl(rpl) => {
                    assert_eq!(
                        rpl,
                        RplHopByHopRepr {
                            down: false,
                            rank_error: false,
                            forwarding_error: false,
                            instance_id: RplInstanceId::from(0x1e),
                            sender_rank: 0x0300,
                        }
                    );
                }
                _ => unreachable!(),
            }
        }

        #[test]
        #[cfg(feature = "proto-rpl")]
        fn test_rpl_hop_by_hop_option_emit() {
            let repr = Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                down: false,
                rank_error: false,
                forwarding_error: false,
                instance_id: RplInstanceId::from(0x1e),
                sender_rank: 0x0300,
            });

            let ext_hdr = ExtHeaderRepr {
                ext_header_id: ExtHeaderId::HopByHopHeader,
                next_header: NextHeader::Uncompressed(IpProtocol::Icmpv6),
                length: repr.buffer_len() as u8,
            };

            let mut buffer = vec![0u8; ext_hdr.buffer_len() + repr.buffer_len()];
            ext_hdr.emit(&mut ExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            repr.emit(&mut Ipv6Option::new_unchecked(
                &mut buffer[ext_hdr.buffer_len()..],
            ));

            assert_eq!(&buffer[..], RPL_HOP_BY_HOP_PACKET);
        }

        #[test]
        fn test_source_routing_deconstruct() {
            let header = ExtHeaderPacket::new_checked(&ROUTING_SR_PACKET).unwrap();
            assert_eq!(header.next_header(), NextHeader::Compressed);
            assert_eq!(header.extension_header_id(), ExtHeaderId::RoutingHeader);

            let routing_hdr = Ipv6RoutingHeader::new_checked(header.payload()).unwrap();
            let repr = Ipv6RoutingRepr::parse(&routing_hdr).unwrap();
            assert_eq!(
                repr,
                Ipv6RoutingRepr::Rpl {
                    segments_left: 3,
                    cmpr_i: 9,
                    cmpr_e: 9,
                    pad: 3,
                    addresses: &[
                        0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x06, 0x00, 0x06, 0x00, 0x06,
                        0x00, 0x06, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00
                    ],
                }
            );
        }

        #[test]
        fn test_source_routing_emit() {
            let routing_hdr = Ipv6RoutingRepr::Rpl {
                segments_left: 3,
                cmpr_i: 9,
                cmpr_e: 9,
                pad: 3,
                addresses: &[
                    0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00,
                    0x06, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
                ],
            };

            let ext_hdr = ExtHeaderRepr {
                ext_header_id: ExtHeaderId::RoutingHeader,
                next_header: NextHeader::Compressed,
                length: routing_hdr.buffer_len() as u8,
            };

            let mut buffer = vec![0u8; ext_hdr.buffer_len() + routing_hdr.buffer_len()];
            ext_hdr.emit(&mut ExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            routing_hdr.emit(&mut Ipv6RoutingHeader::new_unchecked(
                &mut buffer[ext_hdr.buffer_len()..],
            ));

            assert_eq!(&buffer[..], ROUTING_SR_PACKET);
        }
    }

    /// A read/write wrapper around a 6LoWPAN_NHC UDP frame.
    /// [RFC 6282 § 4.3] specifies the format of the header.
    ///
    /// The base header has the following formath:
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | 1 | 1 | 1 | 0 | C |   P   |
    /// +---+---+---+---+---+---+---+---+
    /// With:
    /// - C: checksum, specifies if the checksum is elided.
    /// - P: ports, specifies if the ports are elided.
    /// ```
    ///
    /// [RFC 6282 § 4.3]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.3
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct UdpNhcPacket<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> UdpNhcPacket<T> {
        /// Input a raw octet buffer with a LOWPAN_NHC frame structure for UDP.
        pub const fn new_unchecked(buffer: T) -> Self {
            Self { buffer }
        }

        /// Shorthand for a combination of [new_unchecked] and [check_len].
        ///
        /// [new_unchecked]: #method.new_unchecked
        /// [check_len]: #method.check_len
        pub fn new_checked(buffer: T) -> Result<Self> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;
            Ok(packet)
        }

        /// Ensure that no accessor method will panic if called.
        /// Returns `Err(Error::Truncated)` if the buffer is too short.
        pub fn check_len(&self) -> Result<()> {
            let buffer = self.buffer.as_ref();

            if buffer.is_empty() {
                return Err(Error);
            }

            let index = 1 + self.ports_size() + self.checksum_size();
            if index > buffer.len() {
                return Err(Error);
            }

            Ok(())
        }

        /// Consumes the frame, returning the underlying buffer.
        pub fn into_inner(self) -> T {
            self.buffer
        }

        get_field!(dispatch_field, 0b11111, 3);
        get_field!(checksum_field, 0b1, 2);
        get_field!(ports_field, 0b11, 0);

        /// Returns the index of the start of the next header compressed fields.
        const fn nhc_fields_start(&self) -> usize {
            1
        }

        /// Return the source port number.
        pub fn src_port(&self) -> u16 {
            match self.ports_field() {
                0b00 | 0b01 => {
                    // The full 16 bits are carried in-line.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    NetworkEndian::read_u16(&data[start..start + 2])
                }
                0b10 => {
                    // The first 8 bits are elided.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    0xf000 + data[start] as u16
                }
                0b11 => {
                    // The first 12 bits are elided.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    0xf0b0 + (data[start] >> 4) as u16
                }
                _ => unreachable!(),
            }
        }

        /// Return the destination port number.
        pub fn dst_port(&self) -> u16 {
            match self.ports_field() {
                0b00 => {
                    // The full 16 bits are carried in-line.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    NetworkEndian::read_u16(&data[idx + 2..idx + 4])
                }
                0b01 => {
                    // The first 8 bits are elided.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    0xf000 + data[idx] as u16
                }
                0b10 => {
                    // The full 16 bits are carried in-line.
                    let data = self.buffer.as_ref();
                    let idx = self.nhc_fields_start();

                    NetworkEndian::read_u16(&data[idx + 1..idx + 1 + 2])
                }
                0b11 => {
                    // The first 12 bits are elided.
                    let data = self.buffer.as_ref();
                    let start = self.nhc_fields_start();

                    0xf0b0 + (data[start] & 0xff) as u16
                }
                _ => unreachable!(),
            }
        }

        /// Return the checksum.
        pub fn checksum(&self) -> Option<u16> {
            if self.checksum_field() == 0b0 {
                // The first 12 bits are elided.
                let data = self.buffer.as_ref();
                let start = self.nhc_fields_start() + self.ports_size();
                Some(NetworkEndian::read_u16(&data[start..start + 2]))
            } else {
                // The checksum is elided and needs to be recomputed on the 6LoWPAN termination point.
                None
            }
        }

        // Return the size of the checksum field.
        pub(crate) fn checksum_size(&self) -> usize {
            match self.checksum_field() {
                0b0 => 2,
                0b1 => 0,
                _ => unreachable!(),
            }
        }

        /// Returns the total size of both port numbers.
        pub(crate) fn ports_size(&self) -> usize {
            match self.ports_field() {
                0b00 => 4, // 16 bits + 16 bits
                0b01 => 3, // 16 bits + 8 bits
                0b10 => 3, // 8 bits + 16 bits
                0b11 => 1, // 4 bits + 4 bits
                _ => unreachable!(),
            }
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> UdpNhcPacket<&'a T> {
        /// Return a pointer to the payload.
        pub fn payload(&self) -> &'a [u8] {
            let start = 1 + self.ports_size() + self.checksum_size();
            &self.buffer.as_ref()[start..]
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> UdpNhcPacket<T> {
        /// Return a mutable pointer to the payload.
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let start = 1 + self.ports_size() + 2; // XXX(thvdveld): we assume we put the checksum inlined.
            &mut self.buffer.as_mut()[start..]
        }

        /// Set the dispatch field to `0b11110`.
        fn set_dispatch_field(&mut self) {
            let data = self.buffer.as_mut();
            data[0] = (data[0] & !(0b11111 << 3)) | (DISPATCH_UDP_HEADER << 3);
        }

        set_field!(set_checksum_field, 0b1, 2);
        set_field!(set_ports_field, 0b11, 0);

        fn set_ports(&mut self, src_port: u16, dst_port: u16) {
            let mut idx = 1;

            match (src_port, dst_port) {
                (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => {
                    // We can compress both the source and destination ports.
                    self.set_ports_field(0b11);
                    let data = self.buffer.as_mut();
                    data[idx] = (((src_port - 0xf0b0) as u8) << 4) & ((dst_port - 0xf0b0) as u8);
                }
                (0xf000..=0xf0ff, _) => {
                    // We can compress the source port, but not the destination port.
                    self.set_ports_field(0b10);
                    let data = self.buffer.as_mut();
                    data[idx] = (src_port - 0xf000) as u8;
                    idx += 1;

                    NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
                }
                (_, 0xf000..=0xf0ff) => {
                    // We can compress the destination port, but not the source port.
                    self.set_ports_field(0b01);
                    let data = self.buffer.as_mut();
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                    idx += 2;
                    data[idx] = (dst_port - 0xf000) as u8;
                }
                (_, _) => {
                    // We cannot compress any port.
                    self.set_ports_field(0b00);
                    let data = self.buffer.as_mut();
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                    idx += 2;
                    NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
                }
            };
        }

        fn set_checksum(&mut self, checksum: u16) {
            self.set_checksum_field(0b0);
            let idx = 1 + self.ports_size();
            let data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[idx..idx + 2], checksum);
        }
    }

    /// A high-level representation of a 6LoWPAN NHC UDP header.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct UdpNhcRepr(pub UdpRepr);

    impl<'a> UdpNhcRepr {
        /// Parse a 6LoWPAN NHC UDP packet and return a high-level representation.
        pub fn parse<T: AsRef<[u8]> + ?Sized>(
            packet: &UdpNhcPacket<&'a T>,
            src_addr: &ipv6::Address,
            dst_addr: &ipv6::Address,
            checksum_caps: &ChecksumCapabilities,
        ) -> Result<Self> {
            packet.check_len()?;

            if packet.dispatch_field() != DISPATCH_UDP_HEADER {
                return Err(Error);
            }

            if checksum_caps.udp.rx() {
                let payload_len = packet.payload().len();
                let chk_sum = !checksum::combine(&[
                    checksum::pseudo_header(
                        &IpAddress::Ipv6(*src_addr),
                        &IpAddress::Ipv6(*dst_addr),
                        crate::wire::ip::Protocol::Udp,
                        payload_len as u32 + 8,
                    ),
                    packet.src_port(),
                    packet.dst_port(),
                    payload_len as u16 + 8,
                    checksum::data(packet.payload()),
                ]);

                if let Some(checksum) = packet.checksum() {
                    if chk_sum != checksum {
                        return Err(Error);
                    }
                }
            }

            Ok(Self(UdpRepr {
                src_port: packet.src_port(),
                dst_port: packet.dst_port(),
            }))
        }

        /// Return the length of a packet that will be emitted from this high-level representation.
        pub fn header_len(&self) -> usize {
            let mut len = 1; // The minimal header size

            len += 2; // XXX We assume we will add the checksum at the end

            // Check if we can compress the source and destination ports
            match (self.src_port, self.dst_port) {
                (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => len + 1,
                (0xf000..=0xf0ff, _) | (_, 0xf000..=0xf0ff) => len + 3,
                (_, _) => len + 4,
            }
        }

        /// Emit a high-level representation into a LOWPAN_NHC UDP header.
        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(
            &self,
            packet: &mut UdpNhcPacket<T>,
            src_addr: &Address,
            dst_addr: &Address,
            payload_len: usize,
            emit_payload: impl FnOnce(&mut [u8]),
        ) {
            packet.set_dispatch_field();
            packet.set_ports(self.src_port, self.dst_port);
            emit_payload(packet.payload_mut());

            let chk_sum = !checksum::combine(&[
                checksum::pseudo_header(
                    &IpAddress::Ipv6(*src_addr),
                    &IpAddress::Ipv6(*dst_addr),
                    crate::wire::ip::Protocol::Udp,
                    payload_len as u32 + 8,
                ),
                self.src_port,
                self.dst_port,
                payload_len as u16 + 8,
                checksum::data(packet.payload_mut()),
            ]);

            packet.set_checksum(chk_sum);
        }
    }

    impl core::ops::Deref for UdpNhcRepr {
        type Target = UdpRepr;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl core::ops::DerefMut for UdpNhcRepr {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn ext_header_nhc_fields() {
            let bytes = [0xe3, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00];

            let packet = ExtHeaderPacket::new_checked(&bytes[..]).unwrap();
            assert_eq!(packet.next_header_size(), 0);
            assert_eq!(packet.dispatch_field(), DISPATCH_EXT_HEADER);
            assert_eq!(packet.extension_header_id(), ExtHeaderId::RoutingHeader);

            assert_eq!(packet.payload(), [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
        }

        #[test]
        fn ext_header_emit() {
            let ext_header = ExtHeaderRepr {
                ext_header_id: ExtHeaderId::RoutingHeader,
                next_header: NextHeader::Compressed,
                length: 6,
            };

            let len = ext_header.buffer_len();
            let mut buffer = [0u8; 127];
            let mut packet = ExtHeaderPacket::new_unchecked(&mut buffer[..len]);
            ext_header.emit(&mut packet);

            assert_eq!(packet.dispatch_field(), DISPATCH_EXT_HEADER);
            assert_eq!(packet.next_header(), NextHeader::Compressed);
            assert_eq!(packet.extension_header_id(), ExtHeaderId::RoutingHeader);
        }

        #[test]
        fn udp_nhc_fields() {
            let bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];

            let packet = UdpNhcPacket::new_checked(&bytes[..]).unwrap();
            assert_eq!(packet.dispatch_field(), DISPATCH_UDP_HEADER);
            assert_eq!(packet.checksum(), Some(0x28c4));
            assert_eq!(packet.src_port(), 5678);
            assert_eq!(packet.dst_port(), 8765);
        }

        #[test]
        fn udp_emit() {
            let udp = UdpNhcRepr(UdpRepr {
                src_port: 0xf0b1,
                dst_port: 0xf001,
            });

            let payload = b"Hello World!";

            let src_addr = ipv6::Address::default();
            let dst_addr = ipv6::Address::default();

            let len = udp.header_len() + payload.len();
            let mut buffer = [0u8; 127];
            let mut packet = UdpNhcPacket::new_unchecked(&mut buffer[..len]);
            udp.emit(&mut packet, &src_addr, &dst_addr, payload.len(), |buf| {
                buf.copy_from_slice(&payload[..])
            });

            assert_eq!(packet.dispatch_field(), DISPATCH_UDP_HEADER);
            assert_eq!(packet.src_port(), 0xf0b1);
            assert_eq!(packet.dst_port(), 0xf001);
            assert_eq!(packet.payload_mut(), b"Hello World!");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sixlowpan_fragment_emit() {
        let repr = frag::Repr::FirstFragment {
            size: 0xff,
            tag: 0xabcd,
        };
        let buffer = [0u8; 4];
        let mut packet = frag::Packet::new_unchecked(buffer);

        assert_eq!(repr.buffer_len(), 4);
        repr.emit(&mut packet);

        assert_eq!(packet.datagram_size(), 0xff);
        assert_eq!(packet.datagram_tag(), 0xabcd);
        assert_eq!(packet.into_inner(), [0xc0, 0xff, 0xab, 0xcd]);

        let repr = frag::Repr::Fragment {
            size: 0xff,
            tag: 0xabcd,
            offset: 0xcc,
        };
        let buffer = [0u8; 5];
        let mut packet = frag::Packet::new_unchecked(buffer);

        assert_eq!(repr.buffer_len(), 5);
        repr.emit(&mut packet);

        assert_eq!(packet.datagram_size(), 0xff);
        assert_eq!(packet.datagram_tag(), 0xabcd);
        assert_eq!(packet.into_inner(), [0xe0, 0xff, 0xab, 0xcd, 0xcc]);
    }

    #[test]
    fn sixlowpan_three_fragments() {
        use crate::wire::ieee802154::Frame as Ieee802154Frame;
        use crate::wire::ieee802154::Repr as Ieee802154Repr;
        use crate::wire::Ieee802154Address;

        let key = frag::Key {
            ll_src_addr: Ieee802154Address::Extended([50, 147, 130, 47, 40, 8, 62, 217]),
            ll_dst_addr: Ieee802154Address::Extended([26, 11, 66, 66, 66, 66, 66, 66]),
            datagram_size: 307,
            datagram_tag: 63,
        };

        let frame1: &[u8] = &[
            0x41, 0xcc, 0x92, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9,
            0x3e, 0x08, 0x28, 0x2f, 0x82, 0x93, 0x32, 0xc1, 0x33, 0x00, 0x3f, 0x6e, 0x33, 0x02,
            0x35, 0x3d, 0xf0, 0xd2, 0x5f, 0x1b, 0x39, 0xb4, 0x6b, 0x4c, 0x6f, 0x72, 0x65, 0x6d,
            0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73,
            0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65,
            0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63,
            0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e, 0x20, 0x41, 0x6c, 0x69, 0x71,
            0x75, 0x61, 0x6d, 0x20, 0x64, 0x75, 0x69, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x2c, 0x20,
            0x69, 0x61, 0x63, 0x75, 0x6c, 0x69, 0x73, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x72,
        ];

        let ieee802154_frame = Ieee802154Frame::new_checked(frame1).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame).unwrap();

        let sixlowpan_frame =
            SixlowpanPacket::dispatch(ieee802154_frame.payload().unwrap()).unwrap();

        let frag = if let SixlowpanPacket::FragmentHeader = sixlowpan_frame {
            frag::Packet::new_checked(ieee802154_frame.payload().unwrap()).unwrap()
        } else {
            unreachable!()
        };

        assert_eq!(frag.datagram_size(), 307);
        assert_eq!(frag.datagram_tag(), 0x003f);
        assert_eq!(frag.datagram_offset(), 0);

        assert_eq!(frag.get_key(&ieee802154_repr), key);

        let frame2: &[u8] = &[
            0x41, 0xcc, 0x93, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9,
            0x3e, 0x08, 0x28, 0x2f, 0x82, 0x93, 0x32, 0xe1, 0x33, 0x00, 0x3f, 0x11, 0x75, 0x74,
            0x72, 0x75, 0x6d, 0x20, 0x61, 0x74, 0x2c, 0x20, 0x74, 0x72, 0x69, 0x73, 0x74, 0x69,
            0x71, 0x75, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6e, 0x75, 0x6e, 0x63, 0x20, 0x65,
            0x72, 0x61, 0x74, 0x20, 0x63, 0x75, 0x72, 0x61, 0x65, 0x2e, 0x20, 0x4c, 0x6f, 0x72,
            0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72,
            0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e,
            0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69,
            0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74,
        ];

        let ieee802154_frame = Ieee802154Frame::new_checked(frame2).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame).unwrap();

        let sixlowpan_frame =
            SixlowpanPacket::dispatch(ieee802154_frame.payload().unwrap()).unwrap();

        let frag = if let SixlowpanPacket::FragmentHeader = sixlowpan_frame {
            frag::Packet::new_checked(ieee802154_frame.payload().unwrap()).unwrap()
        } else {
            unreachable!()
        };

        assert_eq!(frag.datagram_size(), 307);
        assert_eq!(frag.datagram_tag(), 0x003f);
        assert_eq!(frag.datagram_offset(), 136 / 8);

        assert_eq!(frag.get_key(&ieee802154_repr), key);

        let frame3: &[u8] = &[
            0x41, 0xcc, 0x94, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9,
            0x3e, 0x08, 0x28, 0x2f, 0x82, 0x93, 0x32, 0xe1, 0x33, 0x00, 0x3f, 0x1d, 0x2e, 0x20,
            0x41, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x64, 0x75, 0x69, 0x20, 0x6f, 0x64,
            0x69, 0x6f, 0x2c, 0x20, 0x69, 0x61, 0x63, 0x75, 0x6c, 0x69, 0x73, 0x20, 0x76, 0x65,
            0x6c, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x20, 0x61, 0x74, 0x2c, 0x20, 0x74,
            0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6e,
            0x75, 0x6e, 0x63, 0x20, 0x65, 0x72, 0x61, 0x74, 0x20, 0x63, 0x75, 0x72, 0x61, 0x65,
            0x2e, 0x20, 0x0a,
        ];

        let ieee802154_frame = Ieee802154Frame::new_checked(frame3).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_frame).unwrap();

        let sixlowpan_frame =
            SixlowpanPacket::dispatch(ieee802154_frame.payload().unwrap()).unwrap();

        let frag = if let SixlowpanPacket::FragmentHeader = sixlowpan_frame {
            frag::Packet::new_checked(ieee802154_frame.payload().unwrap()).unwrap()
        } else {
            unreachable!()
        };

        assert_eq!(frag.datagram_size(), 307);
        assert_eq!(frag.datagram_tag(), 0x003f);
        assert_eq!(frag.datagram_offset(), 232 / 8);

        assert_eq!(frag.get_key(&ieee802154_repr), key);
    }
}
