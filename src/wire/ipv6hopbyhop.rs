use super::{Error, Result};
use core::fmt;

use super::PacketFormat;

pub use super::IpProtocol as Protocol;
use crate::wire::ipv6option::Ipv6OptionsIterator;

/// A read/write wrapper around an IPv6 Hop-by-Hop Options Header.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
    format: PacketFormat,
}

// Format of the Hop-by-Hop Options Header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |  Hdr Ext Len  |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
// |                                                               |
// .                                                               .
// .                            Options                            .
// .                                                               .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// See https://tools.ietf.org/html/rfc8200#section-4.3 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // Minimum size of the header.
    pub const MIN_HEADER_SIZE: usize = 8;

    // 8-bit identifier of the header immediately following this header.
    pub const NXT_HDR: usize = 0;
    // 8-bit unsigned integer. Length of the OPTIONS field in 8-octet units,
    // not including the first 8 octets.
    pub const LENGTH: usize = 1;
    // Variable-length field. Option-Type-specific data.
    //
    // Length of the header is in 8-octet units, not including the first 8 octets. The first two
    // octets are the next header type and the header length.
    pub const fn OPTIONS(length_field: u8) -> Field {
        let bytes = length_field as usize * 8 + 8;
        2..bytes
    }
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Hop-by-Hop Options Header structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header {
            buffer,
            format: PacketFormat::Normal,
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Create a raw octet buffer with an IPv6 Hop-by-Hop Options Header structure.
    ///
    /// This should be used for 6LoWPAN Hop-by-Hop Options Headers.
    #[cfg(feature = "proto-sixlowpan")]
    pub const fn new_unchecked_compressed(
        buffer: T,
        next_header: super::SixlowpanExtHeaderNextheader,
    ) -> Header<T> {
        Header {
            buffer,
            format: PacketFormat::Compressed(next_header),
        }
    }

    /// Shorthand for a combination of [new_unchecked_compressed] and [check_len].
    ///
    /// [new_unchecked_compressed]: #method.new_unchecked_compressed
    /// [check_len]: #method.check_len
    #[cfg(feature = "proto-sixlowpan")]
    pub fn new_checked_compressed(
        buffer: T,
        next_header: super::SixlowpanExtHeaderNextheader,
    ) -> Result<Header<T>> {
        let header = Self::new_unchecked_compressed(buffer, next_header);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        match self.format {
            PacketFormat::Normal => {
                if len < field::MIN_HEADER_SIZE {
                    return Err(Error);
                }
            }
            #[cfg(feature = "proto-sixlowpan")]
            PacketFormat::Compressed(ext) => match ext {
                super::SixlowpanExtHeaderNextheader::Inline if len < 2 => return Err(Error),
                super::SixlowpanExtHeaderNextheader::Elided if len == 0 => return Err(Error),
                _ => (),
            },
        }

        let of = self.format.field(field::OPTIONS(
            self.format
                .ipv6_length(data[self.format.idx(field::LENGTH)]),
        ));

        if len < of.end {
            return Err(Error);
        }

        Ok(())
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Option<Protocol> {
        match self.format {
            PacketFormat::Normal => {
                let data = self.buffer.as_ref();
                Some(Protocol::from(data[field::NXT_HDR]))
            }
            #[cfg(feature = "proto-sixlowpan")]
            PacketFormat::Compressed(super::SixlowpanExtHeaderNextheader::Elided) => None,
            #[cfg(feature = "proto-sixlowpan")]
            PacketFormat::Compressed(super::SixlowpanExtHeaderNextheader::Inline) => {
                let data = self.buffer.as_ref();
                Some(Protocol::from(data[self.format.idx(field::NXT_HDR)]))
            }
        }
    }

    /// Return length of the Hop-by-Hop Options header in 8-octet units, not including the first
    /// 8 octets.
    ///
    /// **NOTE**: For 6LoWPAN, the header length field is in 1-octet units instead of 8-octet
    /// units. The length field also indicates the length of the octets that pertain to the
    /// extenion header following the Length field. See [RFC 6282 § 4.2 ] for details.
    ///
    /// [RFC 6282 § 4.2]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.2
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[self.format.idx(field::LENGTH)]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return the option data.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self
            .format
            .field(field::OPTIONS(self.format.ipv6_length(data[field::LENGTH])))]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        match self.format {
            PacketFormat::Normal => {
                let data = self.buffer.as_mut();
                data[field::NXT_HDR] = value.into();
            }
            #[cfg(feature = "proto-sixlowpan")]
            PacketFormat::Compressed(super::SixlowpanExtHeaderNextheader::Inline) => {
                let data = self.buffer.as_mut();
                data[self.format.idx(field::NXT_HDR)] = value.into();
            }
            #[cfg(feature = "proto-sixlowpan")]
            PacketFormat::Compressed(super::SixlowpanExtHeaderNextheader::Elided) => {}
        }
    }

    /// Set the option data length. Length of the Hop-by-Hop Options header in 8-octet units,
    /// not including the first 8 octets.
    ///
    /// **NOTE**: For 6LoWPAN, the header length field is in 1-octet units instead of 8-octet
    /// units. The length field also indicates the length of the octets that pertain to the
    /// extenion header following the Length field. See [RFC 6282 § 4.2 ] for details.
    ///
    /// [RFC 6282 § 4.2]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.2
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[self.format.idx(field::LENGTH)] = value;
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Header<&'a mut T> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        let len = self.format.ipv6_length(data[field::LENGTH]);
        &mut data[self.format.field(field::OPTIONS(len))]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv6 Hop-by-Hop Options ({err})")?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Hop-by-Hop Options header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr<'a> {
    /// The type of header immediately following the Hop-by-Hop Options header.
    pub next_header: Option<Protocol>,
    /// Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
    pub length: u8,
    /// The options contained in the Hop-by-Hop Options header.
    pub options: &'a [u8],
    #[cfg(feature = "proto-sixlowpan")]
    format: PacketFormat,
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Hop-by-Hop Options Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Repr {
            next_header: header.next_header(),
            length: header.header_len(),
            options: header.options(),
            #[cfg(feature = "proto-sixlowpan")]
            format: header.format,
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        #[cfg(feature = "proto-sixlowpan")]
        {
            self.format
                .field(field::OPTIONS(self.format.ipv6_length(self.length)))
                .end
        }

        #[cfg(not(feature = "proto-sixlowpan"))]
        {
            field::OPTIONS(self.length).end
        }
    }

    /// Emit a high-level representation into an IPv6 Hop-by-Hop Options Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        if matches!(header.format, PacketFormat::Normal) {
            header.set_next_header(self.next_header.unwrap());
        }

        #[cfg(feature = "proto-sixlowpan")]
        if matches!(
            header.format,
            PacketFormat::Compressed(super::SixlowpanExtHeaderNextheader::Inline)
        ) {
            header.set_next_header(self.next_header.unwrap());
        }

        header.set_header_len(self.length);
        header.options_mut().copy_from_slice(self.options);
    }

    /// Return an `Iterator` for the contained options.
    pub fn options(&self) -> Ipv6OptionsIterator {
        Ipv6OptionsIterator::new(self.options, self.buffer_len() - 2)
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv6 Hop-by-Hop Options next_hdr=")?;

        if let Some(nh) = self.next_header {
            write!(f, "{nh} ")?;
        } else {
            write!(f, "Elided ")?;
        }

        write!(f, "length={}", self.length)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Hop-by-Hop Option header with a PadN option of option data length 4.
    const REPR_PACKET_PAD4: [u8; 8] = [0x6, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0];

    // A Hop-by-Hop Option header with a PadN option of option data length 12.
    const REPR_PACKET_PAD12: [u8; 16] = [
        0x06, 0x1, 0x1, 0x0C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    // A Hop-by-Hop Option header with a RPL option.
    #[cfg(feature = "proto-sixlowpan")]
    const REPR_PACKET_RPL_OPTION: [u8; 8] = [0x3a, 0x06, 0x63, 0x04, 0x00, 0x1e, 0x03, 0x00];

    #[test]
    fn test_check_len() {
        // zero byte buffer
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..0]).check_len()
        );
        // no length field
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..1]).check_len()
        );
        // less than 8 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..7]).check_len()
        );
        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&REPR_PACKET_PAD4).check_len());
        // valid
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&REPR_PACKET_PAD12).check_len()
        );
        // length field value greater than number of bytes
        let header: [u8; 8] = [0x06, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        assert_eq!(Err(Error), Header::new_unchecked(&header).check_len());

        #[cfg(feature = "proto-sixlowpan")]
        assert_eq!(
            Ok(()),
            Header::new_unchecked_compressed(
                &REPR_PACKET_RPL_OPTION,
                crate::wire::SixlowpanExtHeaderNextheader::Inline
            )
            .check_len(),
        );
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4);
        assert_eq!(header.next_header(), Some(Protocol::Tcp));
        assert_eq!(header.header_len(), 0);
        assert_eq!(header.options(), &REPR_PACKET_PAD4[2..]);

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        assert_eq!(header.next_header(), Some(Protocol::Tcp));
        assert_eq!(header.header_len(), 1);
        assert_eq!(header.options(), &REPR_PACKET_PAD12[2..]);

        #[cfg(feature = "proto-sixlowpan")]
        {
            let header = Header::new_unchecked_compressed(
                &REPR_PACKET_RPL_OPTION,
                crate::wire::SixlowpanExtHeaderNextheader::Inline,
            );
            assert_eq!(header.next_header(), Some(Protocol::Icmpv6));
            assert_eq!(header.header_len(), 6);
            assert_eq!(header.options(), &REPR_PACKET_RPL_OPTION[2..]);
        }
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD4[..]);
        bytes.push(0);

        assert_eq!(
            Header::new_unchecked(&bytes).options().len(),
            REPR_PACKET_PAD4[2..].len()
        );
        assert_eq!(
            Header::new_unchecked(&mut bytes).options_mut().len(),
            REPR_PACKET_PAD4[2..].len()
        );

        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD12[..]);
        bytes.push(0);

        assert_eq!(
            Header::new_unchecked(&bytes).options().len(),
            REPR_PACKET_PAD12[2..].len()
        );
        assert_eq!(
            Header::new_unchecked(&mut bytes).options_mut().len(),
            REPR_PACKET_PAD12[2..].len()
        );
    }

    #[test]
    fn test_header_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(REPR_PACKET_PAD4);
        let len = bytes.len() as u8;
        Header::new_unchecked(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error);

        let mut bytes = vec![];
        bytes.extend(REPR_PACKET_PAD12);
        let len = bytes.len() as u8;
        Header::new_unchecked(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                next_header: Some(Protocol::Tcp),
                length: 0,
                options: &REPR_PACKET_PAD4[2..],
                #[cfg(feature = "proto-sixlowpan")]
                format: PacketFormat::Normal,
            }
        );

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                next_header: Some(Protocol::Tcp),
                length: 1,
                options: &REPR_PACKET_PAD12[2..],
                #[cfg(feature = "proto-sixlowpan")]
                format: PacketFormat::Normal,
            }
        );

        #[cfg(feature = "proto-sixlowpan")]
        {
            let header = Header::new_unchecked_compressed(
                &REPR_PACKET_RPL_OPTION,
                crate::wire::SixlowpanExtHeaderNextheader::Inline,
            );
            let repr = Repr::parse(&header).unwrap();
            assert_eq!(
                repr,
                Repr {
                    next_header: Some(Protocol::Icmpv6),
                    length: 6,
                    options: &REPR_PACKET_RPL_OPTION[2..],
                    format: PacketFormat::Compressed(
                        crate::wire::SixlowpanExtHeaderNextheader::Inline
                    ),
                }
            );
        }
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            next_header: Some(Protocol::Tcp),
            length: 0,
            options: &REPR_PACKET_PAD4[2..],
            #[cfg(feature = "proto-sixlowpan")]
            format: PacketFormat::Normal,
        };
        let mut bytes = [0u8; 8];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD4[..]);

        let repr = Repr {
            next_header: Some(Protocol::Tcp),
            length: 1,
            options: &REPR_PACKET_PAD12[2..],
            #[cfg(feature = "proto-sixlowpan")]
            format: PacketFormat::Normal,
        };
        let mut bytes = [0u8; 16];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD12[..]);

        #[cfg(feature = "proto-sixlowpan")]
        {
            let repr = Repr {
                next_header: Some(Protocol::Icmpv6),
                length: 6,
                options: &REPR_PACKET_RPL_OPTION[2..],
                format: PacketFormat::Compressed(crate::wire::SixlowpanExtHeaderNextheader::Inline),
            };
            let mut bytes = [0u8; 8];

            let mut header = Header::new_unchecked_compressed(
                &mut bytes,
                crate::wire::SixlowpanExtHeaderNextheader::Inline,
            );
            repr.emit(&mut header);
            assert_eq!(header.into_inner(), &REPR_PACKET_RPL_OPTION[..]);
        }
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), REPR_PACKET_PAD4.len());

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), REPR_PACKET_PAD12.len());

        #[cfg(feature = "proto-sixlowpan")]
        {
            let header = Header::new_unchecked_compressed(
                &REPR_PACKET_RPL_OPTION,
                crate::wire::SixlowpanExtHeaderNextheader::Inline,
            );
            let repr = Repr::parse(&header).unwrap();
            assert_eq!(repr.buffer_len(), REPR_PACKET_RPL_OPTION.len());
        }
    }
}
