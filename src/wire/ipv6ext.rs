use {Error, Result};

enum_with_unknown! {
    /// IPv6 Extension Header Option type
    pub doc enum OptionType(u8) {
        /// Pad1 option
        Pad1 =  0,
        /// PadN option
        PadN =  1
    }
}

/// A read/write wrapper around a variable number of IPv6 Extension Header Options
#[derive(Debug, PartialEq)]
pub struct Packet<T: AsRef<[u8]>> {
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
    use wire::field::*;

    // 8-bit identifier of the type of option
    pub const TYPE:     usize = 0;
    // 8-bit unsigned integer. Length of the DATA field of this option, in octets
    pub const LENGTH:   usize = 1;
	// Variable-length field. Option-Type-specific data.
    pub const DATA:     Rest  = 2..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with an IPv6 Extension Header Option packet structure.
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_option_data_length].
    ///
    /// [set_option_data_length]: #method.set_option_data_length
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::LENGTH {
            return Err(Error::Truncated);
        }

        if self.option_type() == OptionType::Pad1 {
            return Ok(());
        }

        if len < field::DATA.start {
            return Err(Error::Truncated);
        }

        if data[field::DATA.start..].len() < (self.option_data_length() as usize) {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the option type.
    #[inline]
    pub fn option_type(&self) -> OptionType {
        let data = self.buffer.as_ref();
        OptionType::from(data[field::TYPE])
    }

    /// Return the length of the data.
    ///
    /// # Panics
    /// The function panics if the type does not support this field
    #[inline]
    pub fn option_data_length(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return the option data.
    ///
    /// # Panics
    /// The function panics if the type does not support this field
    #[inline]
    pub fn data(&self) -> &'a[u8] {
        let len = (self.option_data_length() as usize) + field::DATA.start;
        let data = self.buffer.as_ref();
        &data[field::DATA.start..len]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the option type.
    #[inline]
    pub fn set_option_type(&mut self, value: OptionType) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into();
    }

    /// Set the option data length.
    #[inline]
    pub fn set_option_data_length(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = (self.option_data_length() as usize) + field::DATA.start;
        let data = self.buffer.as_mut();
        &mut data[field::DATA.start..len]
    }
}

/// A high-level representation of an IPv6 Extension Header Option
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    Pad1,
    PadN {
        length: u8,
        data:   &'a [u8]
    },

    #[doc(hidden)]
    __Nonexhaustive
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Extension Header Option packet and return a high-level representation.
    pub fn parse<T>(packet: &'a Packet<&'a T>) -> Result<Repr<'a>> where T: AsRef<[u8]> + ?Sized {
        match packet.option_type() {
            OptionType::Pad1 => {
                Ok(Repr::Pad1)
            }
            OptionType::PadN => {
                Ok(Repr::PadN {
                    length: packet.option_data_length(),
                    data: packet.data(),
                })
            }
            _ => Err(Error::Unrecognized),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::Pad1 => {
                1
            }
            &Repr::PadN{length, ..} => {
                (length as usize) + field::DATA.start
            }

            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Emit a high-level representation into an IPv6 Extension Header Option packet.
           //<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&'a mut T>) {
        match self {
            &Repr::Pad1 => {
                packet.set_option_type(From::from(OptionType::Pad1));
            }
            &Repr::PadN{length, data} => {
                packet.set_option_type(From::from(OptionType::PadN));
                packet.set_option_data_length(length);
                let len = length as usize;
                packet.data_mut().copy_from_slice(&data[..len]);
            }

            &Repr::__Nonexhaustive => unreachable!()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_len() {
        let bytes = [0u8];
        // zero byte buffer
        assert_eq!(Err(Error::Truncated), Packet::new(&bytes[..0]).check_len());
        // pad1
        assert_eq!(Ok(()), Packet::new(&bytes).check_len());

        let bytes: [u8; 3] = [0x1, 0x1, 0x0];
        // padn with truncated data
        assert_eq!(Err(Error::Truncated), Packet::new(&bytes[..2]).check_len());
        // padn
        assert_eq!(Ok(()), Packet::new(&bytes).check_len());

        let bytes: [u8; 5] = [0xff, 0x3, 0x0, 0x0, 0x0];
        // unknown option type with truncated data
        assert_eq!(Err(Error::Truncated), Packet::new(&bytes[..4]).check_len());
        assert_eq!(Err(Error::Truncated), Packet::new(&bytes[..1]).check_len());
        // unknown type
        assert_eq!(Ok(()), Packet::new(&bytes).check_len());
    }

    #[test]
    #[should_panic]
    fn test_option_data_length() {
        let bytes:  [u8; 1] = [0x0];
        let packet = Packet::new(&bytes);
        packet.option_data_length();
    }

    #[test]
    fn test_option_deconstruct() {
        // one octet of padding
        let bytes:  [u8; 1] = [0x0];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::Pad1);

        // two octets of padding
        let bytes:  [u8; 2] = [0x1, 0x0];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 0);

        // three octets of padding
        let bytes:  [u8; 3] = [0x1, 0x1, 0x0];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 1);
        assert_eq!(packet.data(), &[0]);

        // extra bytes in buffer
        let bytes:  [u8; 10] = [0x1, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 7);
        assert_eq!(packet.data(), &[0, 0, 0, 0, 0, 0, 0]);

        // unrecognized option actions
        let bytes:  [u8; 1] = [0xff];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::Unknown(255));
        assert_eq!(Packet::new_checked(&bytes), Err(Error::Truncated));
    }

    #[test]
    fn test_option_parse() {
        // one octet of padding
        let bytes:  [u8; 1] = [0x0];
        let packet = Packet::new(&bytes);
        let pad1 = Repr::parse(&packet).unwrap();
        assert_eq!(pad1, Repr::Pad1);
        assert_eq!(pad1.buffer_len(), 1);

        // two or more octets of padding
        let bytes:  [u8; 3] = [0x1, 0x1, 0x0];
        let packet = Packet::new(&bytes);
        let padn = Repr::parse(&packet).unwrap();
        assert_eq!(padn, Repr::PadN { length: 1, data: &bytes[2..3] });
        assert_eq!(padn.buffer_len(), 3);

        // unrecognized option type
        let bytes:  [u8; 3] = [0xff, 0x1, 0x0];
        let packet = Packet::new(&bytes);
        assert_eq!(Repr::parse(&packet), Err(Error::Unrecognized));
    }

    #[test]
    fn test_option_emit() {
        let repr = Repr::Pad1;
        let mut bytes = [0u8; 1];
        let mut packet = Packet::new(&mut bytes);
        repr.emit(&mut packet);
        assert_eq!(packet.into_inner(), &[0x0]);

        let data = [0u8; 1];
        let repr = Repr::PadN { length: 1, data: &data };
        let mut bytes = [0u8; 3];
        let mut packet = Packet::new(&mut bytes);
        repr.emit(&mut packet);
        assert_eq!(packet.into_inner(), &[0x1, 0x1, 0x0]);
    }
}
