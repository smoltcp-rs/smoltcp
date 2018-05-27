use core::fmt;
use {Error, Result};

use super::ipv6option::Ipv6OptionsIterator;
pub use super::IpProtocol as Protocol;

/// A read/write wrapper around an IPv6 Hop-by-Hop Options Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T
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

    use wire::field::*;

    // Minimum size of the header.
    pub const MIN_HEADER_SIZE:  usize = 8;

    // 8-bit identifier of the header immediately following this header.
    pub const NXT_HDR:          usize = 0;
    // 8-bit unsigned integer. Length of the OPTIONS field in 8-octet units,
    // not including the first 8 octets.
    pub const LENGTH:           usize = 1;
    // Variable-length field. Option-Type-specific data.
    //
    // Length of the header is in 8-octet units, not including the first 8 octets. The first two
    // octets are the next header type and the header length.
    pub fn OPTIONS(length_field: u8) -> Field {
        let bytes = length_field * 8 + 8;
        2..bytes as usize
    }
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Hop-by-Hop Options Header structure.
    pub fn new(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::MIN_HEADER_SIZE {
            return Err(Error::Truncated);
        }

        let of = field::OPTIONS(data[field::LENGTH]);

        if len < of.end {
            return Err(Error::Truncated);
        }

        Ok(())
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

    /// Return length of the Hop-by-Hop Options header in 8-octet units, not including the first
    /// 8 octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return the option data.
    #[inline]
    pub fn options(&self) -> &'a[u8] {
        let data = self.buffer.as_ref();
        &data[field::OPTIONS(data[field::LENGTH])]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// Set the option data length. Length of the Hop-by-Hop Options header in 8-octet units,
    /// not including the first 8 octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Header<&'a mut T> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        let len = data[field::LENGTH];
        &mut data[field::OPTIONS(len)]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv6 Hop-by-Hop Options ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Hop-by-Hop Options header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    /// The type of header immediately following the Hop-by-Hop Options header.
    pub next_header: Protocol,
    /// Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
    pub length:      u8,
    /// The options contained in the Hop-by-Hop Options header.
    pub options:     &'a [u8]
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Hop-by-Hop Options Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&'a T>) -> Result<Repr<'a>> where T: AsRef<[u8]> + ?Sized {
        Ok(Repr {
            next_header: header.next_header(),
            length: header.header_len(),
            options: header.options()
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub fn buffer_len(&self) -> usize {
        field::OPTIONS(self.length).end
    }

    /// Emit a high-level representation into an IPv6 Hop-by-Hop Options Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.set_next_header(self.next_header);
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
        write!(f, "IPv6 Hop-by-Hop Options next_hdr={} length={} ", self.next_header, self.length)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Hop-by-Hop Option header with a PadN option of option data length 4.
    static REPR_PACKET_PAD4: [u8; 8] = [0x6, 0x0, 0x1, 0x4,
                                        0x0, 0x0, 0x0, 0x0];

    // A Hop-by-Hop Option header with a PadN option of option data length 12.
    static REPR_PACKET_PAD12: [u8; 16] = [0x06, 0x1, 0x1, 0x12,
                                          0x0,  0x0, 0x0, 0x0,
                                          0x0,  0x0, 0x0, 0x0,
                                          0x0,  0x0, 0x0, 0x0];

    #[test]
    fn test_check_len() {
        // zero byte buffer
        assert_eq!(Err(Error::Truncated), Header::new(&REPR_PACKET_PAD4[..0]).check_len());
        // no length field
        assert_eq!(Err(Error::Truncated), Header::new(&REPR_PACKET_PAD4[..1]).check_len());
        // less than 8 bytes
        assert_eq!(Err(Error::Truncated), Header::new(&REPR_PACKET_PAD4[..7]).check_len());
        // valid
        assert_eq!(Ok(()), Header::new(&REPR_PACKET_PAD4).check_len());
        // valid
        assert_eq!(Ok(()), Header::new(&REPR_PACKET_PAD12).check_len());
        // length field value greater than number of bytes
        let header: [u8; 8] = [0x06, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        assert_eq!(Err(Error::Truncated), Header::new(&header).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new(&REPR_PACKET_PAD4);
        assert_eq!(header.next_header(), Protocol::Tcp);
        assert_eq!(header.header_len(), 0);
        assert_eq!(header.options(), &REPR_PACKET_PAD4[2..]);

        let header = Header::new(&REPR_PACKET_PAD12);
        assert_eq!(header.next_header(), Protocol::Tcp);
        assert_eq!(header.header_len(), 1);
        assert_eq!(header.options(), &REPR_PACKET_PAD12[2..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD4[..]);
        bytes.push(0);

        assert_eq!(Header::new(&bytes).options().len(), REPR_PACKET_PAD4[2..].len());
        assert_eq!(Header::new(&mut bytes).options_mut().len(), REPR_PACKET_PAD4[2..].len());

        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD12[..]);
        bytes.push(0);

        assert_eq!(Header::new(&bytes).options().len(), REPR_PACKET_PAD12[2..].len());
        assert_eq!(Header::new(&mut bytes).options_mut().len(), REPR_PACKET_PAD12[2..].len());
    }

    #[test]
    fn test_header_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD4);
        let len = bytes.len() as u8;
        Header::new(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error::Truncated);

        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD12);
        let len = bytes.len() as u8;
        Header::new(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr, Repr{ next_header: Protocol::Tcp, length: 0, options: &REPR_PACKET_PAD4[2..] });

        let header = Header::new(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr, Repr{ next_header: Protocol::Tcp, length: 1, options: &REPR_PACKET_PAD12[2..] });
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr{ next_header: Protocol::Tcp, length: 0, options: &REPR_PACKET_PAD4[2..] };
        let mut bytes = [0u8; 8];
        let mut header = Header::new(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD4[..]);

        let repr = Repr{ next_header: Protocol::Tcp, length: 1, options: &REPR_PACKET_PAD12[2..] };
        let mut bytes = [0u8; 16];
        let mut header = Header::new(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD12[..]);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), REPR_PACKET_PAD4.len());

        let header = Header::new(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), REPR_PACKET_PAD12.len());
    }
}
