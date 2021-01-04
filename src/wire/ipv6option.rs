use core::fmt;
use crate::{Error, Result};

enum_with_unknown! {
    /// IPv6 Extension Header Option Type
    pub doc enum Type(u8) {
        /// 1 byte of padding
        Pad1 =  0,
        /// Multiple bytes of padding
        PadN =  1
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Type::Pad1        => write!(f, "Pad1"),
            Type::PadN        => write!(f, "PadN"),
            Type::Unknown(id) => write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Action required when parsing the given IPv6 Extension
    /// Header Option Type fails
    pub doc enum FailureType(u8) {
        /// Skip this option and continue processing the packet
        Skip               = 0b00000000,
        /// Discard the containing packet
        Discard            = 0b01000000,
        /// Discard the containing packet and notify the sender
        DiscardSendAll     = 0b10000000,
        /// Discard the containing packet and only notify the sender
        /// if the sender is a unicast address
        DiscardSendUnicast = 0b11000000,
    }
}

impl fmt::Display for FailureType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FailureType::Skip               => write!(f, "skip"),
            FailureType::Discard            => write!(f, "discard"),
            FailureType::DiscardSendAll     => write!(f, "discard and send error"),
            FailureType::DiscardSendUnicast => write!(f, "discard and send error if unicast"),
            FailureType::Unknown(id)        => write!(f, "Unknown({})", id),
        }
    }
}

impl From<Type> for FailureType {
    fn from(other: Type) -> FailureType {
        let raw: u8 = other.into();
        Self::from(raw & 0b11000000u8)
    }
}

/// A read/write wrapper around an IPv6 Extension Header Option.
#[derive(Debug, PartialEq)]
pub struct Ipv6Option<T: AsRef<[u8]>> {
    buffer: T
}

// Format of Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
// |  Option Type  |  Opt Data Len |  Option Data
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
//
//
// See https://tools.ietf.org/html/rfc8200#section-4.2 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE:     usize = 0;
    // 8-bit unsigned integer. Length of the DATA field of this option, in octets.
    pub const LENGTH:   usize = 1;
    // Variable-length field. Option-Type-specific data.
    pub fn DATA(length: u8) -> Field {
        2..length as usize + 2
    }
}

impl<T: AsRef<[u8]>> Ipv6Option<T> {
    /// Create a raw octet buffer with an IPv6 Extension Header Option structure.
    pub fn new_unchecked(buffer: T) -> Ipv6Option<T> {
        Ipv6Option { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Ipv6Option<T>> {
        let opt = Self::new_unchecked(buffer);
        opt.check_len()?;
        Ok(opt)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_data_len].
    ///
    /// [set_data_len]: #method.set_data_len
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::LENGTH {
            return Err(Error::Truncated);
        }

        if self.option_type() == Type::Pad1 {
            return Ok(());
        }

        if len == field::LENGTH {
            return Err(Error::Truncated);
        }

        let df = field::DATA(data[field::LENGTH]);

        if len < df.end {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    /// Consume the ipv6 option, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the option type.
    #[inline]
    pub fn option_type(&self) -> Type {
        let data = self.buffer.as_ref();
        Type::from(data[field::TYPE])
    }

    /// Return the length of the data.
    ///
    /// # Panics
    /// This function panics if this is an 1-byte padding option.
    #[inline]
    pub fn data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Ipv6Option<&'a T> {
    /// Return the option data.
    ///
    /// # Panics
    /// This function panics if this is an 1-byte padding option.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let len = self.data_len();
        let data = self.buffer.as_ref();
        &data[field::DATA(len)]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv6Option<T> {
    /// Set the option type.
    #[inline]
    pub fn set_option_type(&mut self, value: Type) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into();
    }

    /// Set the option data length.
    ///
    /// # Panics
    /// This function panics if this is an 1-byte padding option.
    #[inline]
    pub fn set_data_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Ipv6Option<&'a mut T> {
    /// Return a mutable pointer to the option data.
    ///
    /// # Panics
    /// This function panics if this is an 1-byte padding option.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        let data = self.buffer.as_mut();
        &mut data[field::DATA(len)]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Ipv6Option<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => {
                write!(f, "IPv6 Extension Option ({})", err)?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Extension Header Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    Pad1,
    PadN(u8),
    Unknown {
        type_:  Type,
        length: u8,
        data:   &'a [u8]
    },

    #[doc(hidden)]
    __Nonexhaustive
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Extension Header Option and return a high-level representation.
    pub fn parse<T>(opt: &Ipv6Option<&'a T>) -> Result<Repr<'a>> where T: AsRef<[u8]> + ?Sized {
        match opt.option_type() {
            Type::Pad1 =>
                Ok(Repr::Pad1),
            Type::PadN =>
                Ok(Repr::PadN(opt.data_len())),
            unknown_type @ Type::Unknown(_) => {
                Ok(Repr::Unknown {
                    type_:  unknown_type,
                    length: opt.data_len(),
                    data:   opt.data(),
                })
            }
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match *self {
            Repr::Pad1 => 1,
            Repr::PadN(length) =>
               field::DATA(length).end,
            Repr::Unknown{ length, .. } =>
               field::DATA(length).end,

            Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Emit a high-level representation into an IPv6 Extension Header Option.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, opt: &mut Ipv6Option<&'a mut T>) {
        match *self {
            Repr::Pad1 =>
                opt.set_option_type(Type::Pad1),
            Repr::PadN(len) => {
                opt.set_option_type(Type::PadN);
                opt.set_data_len(len);
                // Ensure all padding bytes are set to zero.
                for x in opt.data_mut().iter_mut() {
                    *x = 0
                }
            }
            Repr::Unknown{ type_, length, data } => {
                opt.set_option_type(type_);
                opt.set_data_len(length);
                opt.data_mut().copy_from_slice(&data[..length as usize]);
            }

            Repr::__Nonexhaustive => unreachable!()
        }
    }
}

/// A iterator for IPv6 options.
#[derive(Debug)]
pub struct Ipv6OptionsIterator<'a> {
    pos: usize,
    length: usize,
    data: &'a [u8],
    hit_error: bool
}

impl<'a> Ipv6OptionsIterator<'a> {
    /// Create a new `Ipv6OptionsIterator`, used to iterate over the
    /// options contained in a IPv6 Extension Header (e.g. the Hop-by-Hop
    /// header).
    ///
    /// # Panics
    /// This function panics if the `length` provided is larger than the
    /// length of the `data` buffer.
    pub fn new(data: &'a [u8], length: usize) -> Ipv6OptionsIterator<'a> {
        assert!(length <= data.len());
        Ipv6OptionsIterator {
            pos: 0,
            hit_error: false,
            length, data
        }
    }
}

impl<'a> Iterator for Ipv6OptionsIterator<'a> {
    type Item = Result<Repr<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.length && !self.hit_error {
            // If we still have data to parse and we have not previously
            // hit an error, attempt to parse the next option.
            match Ipv6Option::new_checked(&self.data[self.pos..]) {
                Ok(hdr) => {
                    match Repr::parse(&hdr) {
                        Ok(repr) => {
                            self.pos += repr.buffer_len();
                            Some(Ok(repr))
                        }
                        Err(e) => {
                            self.hit_error = true;
                            Some(Err(e))
                        }
                    }
                }
                Err(e) => {
                    self.hit_error = true;
                    Some(Err(e))
                }
            }
        } else {
            // If we failed to parse a previous option or hit the end of the
            // buffer, we do not continue to iterate.
            None
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IPv6 Option ")?;
        match *self {
            Repr::Pad1 =>
               write!(f, "{} ", Type::Pad1),
            Repr::PadN(len) =>
               write!(f, "{} length={} ", Type::PadN, len),
            Repr::Unknown{ type_, length, .. } =>
               write!(f, "{} length={} ", type_, length),

            Repr::__Nonexhaustive => unreachable!()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static IPV6OPTION_BYTES_PAD1:    [u8; 1] = [0x0];
    static IPV6OPTION_BYTES_PADN:    [u8; 3] = [0x1, 0x1, 0x0];
    static IPV6OPTION_BYTES_UNKNOWN: [u8; 5] = [0xff, 0x3, 0x0, 0x0, 0x0];

    #[test]
    fn test_check_len() {
        let bytes = [0u8];
        // zero byte buffer
        assert_eq!(Err(Error::Truncated),
                   Ipv6Option::new_unchecked(&bytes[..0]).check_len());
        // pad1
        assert_eq!(Ok(()),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PAD1).check_len());

        // padn with truncated data
        assert_eq!(Err(Error::Truncated),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PADN[..2]).check_len());
        // padn
        assert_eq!(Ok(()),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PADN).check_len());

        // unknown option type with truncated data
        assert_eq!(Err(Error::Truncated),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_UNKNOWN[..4]).check_len());
        assert_eq!(Err(Error::Truncated),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_UNKNOWN[..1]).check_len());
        // unknown type
        assert_eq!(Ok(()),
                   Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_UNKNOWN).check_len());
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_data_len() {
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PAD1);
        opt.data_len();
    }

    #[test]
    fn test_option_deconstruct() {
        // one octet of padding
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PAD1);
        assert_eq!(opt.option_type(), Type::Pad1);

        // two octets of padding
        let bytes:  [u8; 2] = [0x1, 0x0];
        let opt = Ipv6Option::new_unchecked(&bytes);
        assert_eq!(opt.option_type(), Type::PadN);
        assert_eq!(opt.data_len(), 0);

        // three octets of padding
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PADN);
        assert_eq!(opt.option_type(), Type::PadN);
        assert_eq!(opt.data_len(), 1);
        assert_eq!(opt.data(), &[0]);

        // extra bytes in buffer
        let bytes:  [u8; 10] = [0x1, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff];
        let opt = Ipv6Option::new_unchecked(&bytes);
        assert_eq!(opt.option_type(), Type::PadN);
        assert_eq!(opt.data_len(), 7);
        assert_eq!(opt.data(), &[0, 0, 0, 0, 0, 0, 0]);

        // unrecognized option
        let bytes:  [u8; 1] = [0xff];
        let opt = Ipv6Option::new_unchecked(&bytes);
        assert_eq!(opt.option_type(), Type::Unknown(255));

        // unrecognized option without length and data
        assert_eq!(Ipv6Option::new_checked(&bytes), Err(Error::Truncated));
    }

    #[test]
    fn test_option_parse() {
        // one octet of padding
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PAD1);
        let pad1 = Repr::parse(&opt).unwrap();
        assert_eq!(pad1, Repr::Pad1);
        assert_eq!(pad1.buffer_len(), 1);

        // two or more octets of padding
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_PADN);
        let padn = Repr::parse(&opt).unwrap();
        assert_eq!(padn, Repr::PadN(1));
        assert_eq!(padn.buffer_len(), 3);

        // unrecognized option type
        let data = [0u8; 3];
        let opt = Ipv6Option::new_unchecked(&IPV6OPTION_BYTES_UNKNOWN);
        let unknown = Repr::parse(&opt).unwrap();
        assert_eq!(unknown, Repr::Unknown { type_: Type::Unknown(255), length: 3, data: &data });
    }

    #[test]
    fn test_option_emit() {
        let repr = Repr::Pad1;
        let mut bytes = [255u8; 1]; // don't assume bytes are initialized to zero
        let mut opt = Ipv6Option::new_unchecked(&mut bytes);
        repr.emit(&mut opt);
        assert_eq!(opt.into_inner(), &IPV6OPTION_BYTES_PAD1);

        let repr = Repr::PadN(1);
        let mut bytes = [255u8; 3]; // don't assume bytes are initialized to zero
        let mut opt = Ipv6Option::new_unchecked(&mut bytes);
        repr.emit(&mut opt);
        assert_eq!(opt.into_inner(), &IPV6OPTION_BYTES_PADN);

        let data = [0u8; 3];
        let repr = Repr::Unknown { type_: Type::Unknown(255), length: 3, data: &data };
        let mut bytes = [254u8; 5]; // don't assume bytes are initialized to zero
        let mut opt = Ipv6Option::new_unchecked(&mut bytes);
        repr.emit(&mut opt);
        assert_eq!(opt.into_inner(), &IPV6OPTION_BYTES_UNKNOWN);
    }

    #[test]
    fn test_failure_type() {
        let mut failure_type: FailureType = Type::Pad1.into();
        assert_eq!(failure_type, FailureType::Skip);
        failure_type = Type::PadN.into();
        assert_eq!(failure_type, FailureType::Skip);
        failure_type = Type::Unknown(0b01000001).into();
        assert_eq!(failure_type, FailureType::Discard);
        failure_type = Type::Unknown(0b10100000).into();
        assert_eq!(failure_type, FailureType::DiscardSendAll);
        failure_type = Type::Unknown(0b11000100).into();
        assert_eq!(failure_type, FailureType::DiscardSendUnicast);
    }

    #[test]
    fn test_options_iter() {
        let options = [0x00, 0x01, 0x01, 0x00,
                       0x01, 0x02, 0x00, 0x00,
                       0x01, 0x00, 0x00, 0x11,
                       0x00, 0x01, 0x08, 0x00];

        let mut iterator = Ipv6OptionsIterator::new(&options, 0);
        assert_eq!(iterator.next(), None);

        iterator = Ipv6OptionsIterator::new(&options, 16);
        for (i, opt) in iterator.enumerate() {
            match (i, opt) {
                (0, Ok(Repr::Pad1)) => continue,
                (1, Ok(Repr::PadN(1))) => continue,
                (2, Ok(Repr::PadN(2))) => continue,
                (3, Ok(Repr::PadN(0))) => continue,
                (4, Ok(Repr::Pad1)) => continue,
                (5, Ok(Repr::Unknown { type_: Type::Unknown(0x11), length: 0, .. })) =>
                    continue,
                (6, Err(Error::Truncated)) => continue,
                (i, res) => panic!("Unexpected option `{:?}` at index {}", res, i),
            }
        }
    }

    #[test]
    #[should_panic(expected = "length <= data.len()")]
    fn test_options_iter_truncated() {
        let options = [0x01, 0x02, 0x00, 0x00];
        let _ = Ipv6OptionsIterator::new(&options, 5);
    }
}
