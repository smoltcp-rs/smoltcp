use core::fmt;
use crate::{Error, Result};

use byteorder::{ByteOrder, NetworkEndian};

pub use super::IpProtocol as Protocol;

/// A read/write wrapper around an IPv6 Fragment Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T
}

// Format of the Fragment Header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Identification                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc8200#section-4.5 for details.
mod field {
    use crate::wire::field::*;

    // 8-bit identifier of the header immediately following this header.
    pub const NXT_HDR:          usize = 0;
    // 8-bit reserved field.
    pub const RESERVED:         usize = 1;
    // 16-bit field containing the fragment offset, reserved and more fragments values.
    pub const FR_OF_M:          Field = 2..4;
    // 32-bit field identifying the fragmented packet
    pub const IDENT:            Field = 4..8;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Fragment Header structure.
    pub fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
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

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::IDENT.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::NXT_HDR])
    }

    /// Return the fragment offset field.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FR_OF_M]) >> 3
    }

    /// Return more fragment flag field.
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[3] & 0x1) == 1
    }

    /// Return the fragment identification value field.
    #[inline]
    pub fn ident(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::IDENT])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// Set reserved fields.
    ///
    /// Set 8-bit reserved field after the next header field.
    /// Set 2-bit reserved field between fragment offset and more fragments.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();

        data[field::RESERVED] = 0;

        // Retain the higher order 5 bits and lower order 1 bit
        data[3] &= 0xf9;
    }

    /// Set the fragment offset field.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        // Retain the lower order 3 bits
        let raw = ((value & 0x1fff) << 3) | ((data[3] & 0x7) as u16);
        NetworkEndian::write_u16(&mut data[field::FR_OF_M], raw);
    }

    /// Set the more fragments flag field.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        // Retain the high order 7 bits
        let raw = (data[3] & 0xfe) | (value as u8 & 0x1);
        data[3] = raw;
    }

    /// Set the fragmentation identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::IDENT], value);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv6 Fragment ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Fragment header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The type of header immediately following the Fragment header.
    pub next_header: Protocol,
    /// The offset of the data following this header, relative to the start of the Fragmentable
    /// Part of the original packet.
    pub frag_offset: u16,
    /// Whethere are not there are more fragments following this header
    pub more_frags: bool,
    /// The identification for every packet that is fragmented.
    pub ident: u32,

}

impl Repr {
    /// Parse an IPv6 Fragment Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr> where T: AsRef<[u8]> + ?Sized {
        Ok(Repr {
            next_header: header.next_header(),
            frag_offset: header.frag_offset(),
            more_frags: header.more_frags(),
            ident: header.ident()
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        field::IDENT.end
    }

    /// Emit a high-level representation into an IPv6 Fragment Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.set_next_header(self.next_header);
        header.clear_reserved();
        header.set_frag_offset(self.frag_offset);
        header.set_more_frags(self.more_frags);
        header.set_ident(self.ident);
    }
}

impl<'a> fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv6 Fragment next_hdr={} offset={} more={} ident={}",
               self.next_header, self.frag_offset, self.more_frags, self.ident)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Fragment Header with more fragments remaining
    static BYTES_HEADER_MORE_FRAG: [u8; 8] = [0x6, 0x0, 0x0,  0x1,
                                              0x0, 0x0, 0x30, 0x39];

    // A Fragment Header with no more fragments remaining
    static BYTES_HEADER_LAST_FRAG: [u8; 8] = [0x6, 0x0, 0xa, 0x0,
                                              0x0, 0x1, 0x9, 0x32];

    #[test]
    fn test_check_len() {
        // less than 8 bytes
        assert_eq!(Err(Error::Truncated),
                   Header::new_unchecked(&BYTES_HEADER_MORE_FRAG[..7]).check_len());
        // valid
        assert_eq!(Ok(()),
                   Header::new_unchecked(&BYTES_HEADER_MORE_FRAG).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        assert_eq!(header.next_header(), Protocol::Tcp);
        assert_eq!(header.frag_offset(), 0);
        assert_eq!(header.more_frags(), true);
        assert_eq!(header.ident(), 12345);

        let header = Header::new_unchecked(&BYTES_HEADER_LAST_FRAG);
        assert_eq!(header.next_header(), Protocol::Tcp);
        assert_eq!(header.frag_offset(), 320);
        assert_eq!(header.more_frags(), false);
        assert_eq!(header.ident(), 67890);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr,
            Repr{ next_header: Protocol::Tcp, frag_offset: 0, more_frags: true, ident: 12345 });

        let header = Header::new_unchecked(&BYTES_HEADER_LAST_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr,
            Repr{ next_header: Protocol::Tcp, frag_offset: 320, more_frags: false, ident: 67890 });
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr{ next_header: Protocol::Tcp, frag_offset: 0, more_frags: true, ident: 12345 };
        let mut bytes = [0u8; 8];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER_MORE_FRAG[0..8]);

        let repr = Repr{ next_header: Protocol::Tcp, frag_offset: 320, more_frags: false, ident: 67890 };
        let mut bytes = [0u8; 8];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER_LAST_FRAG[0..8]);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER_MORE_FRAG.len());
    }
}
