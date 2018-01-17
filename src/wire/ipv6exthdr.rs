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
    pub const TYPE:     usize = 0;
    pub const LENGTH:   usize = 1;
    pub const DATA:     Rest  = 2..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn option_type(&self) -> OptionType {
        let data = self.buffer.as_ref();
        OptionType::from(data[field::TYPE])
    }

    #[inline]
    pub fn option_data_length(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        let len = (self.option_data_length() as usize) + field::DATA.start;
        &data[field::DATA.start..len]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    #[inline]
    pub fn set_option_type(&mut self, value: OptionType) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into();
    }

    #[inline]
    pub fn set_option_data(&mut self, value: &[u8], len: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = len;

        let len = len as usize;

        // TODO find idiomatic way of doing this
        //data[field::DATA.start..len] = value[..len];
        for i in field::DATA.start..len {
            data[i] = value[(i-2)];
        }
    }
}

/// A high-level representation of an IPv6 Extension Header Option
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    Pad1 {
        ident:  OptionType,
    },
    PadN {
        ident:  OptionType,
        length: u8, // TODO -  should this value represent the total lenght or the data length?
        data:   &'a [u8]
    },

    #[doc(hidden)]
    __Nonexhaustive
}

impl<'a> Repr<'a> {
    pub fn parse<T>(packet: &'a Packet<&'a T>) -> Result<Repr<'a>> where T: AsRef<[u8]> + ?Sized {
        match packet.option_type() {
            OptionType::Pad1 => {
                Ok(Repr::Pad1 {
                    ident: packet.option_type(),
                })
            }
            OptionType::PadN => {
                Ok(Repr::PadN {
                    ident: packet.option_type(),
                    length: packet.option_data_length(),
                    data: packet.option_data(),
                })
            }
            _ => Err(Error::Unrecognized),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // This function is not strictly necessary, but it can make client code more readable.
        match self {
            &Repr::Pad1{..} => {
                1
            }
            &Repr::PadN{length, ..} => {
                (length as usize) + 2
            }
            _ => 0
        }
    }

    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        match self {
            &Repr::Pad1{ident} => {
                packet.set_option_type(ident);
            }
            &Repr::PadN{ident, length, data} => {
                packet.set_option_type(ident);
                packet.set_option_data(data, length);
            }

            &Repr::__Nonexhaustive => unreachable!()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        assert_eq!(packet.option_data(), &[0]);

        // extra bytes in buffer
        let bytes:  [u8; 10] = [0x1, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 7);
        assert_eq!(packet.option_data(), &[0, 0, 0, 0, 0, 0, 0]);

        // unrecognized option actions
        let bytes:  [u8; 1] = [0xff];
        let packet = Packet::new(&bytes);
        assert_eq!(packet.option_type(), OptionType::Unknown(255));
    }

    #[test]
    fn test_option_parse() {
        // one octet of padding
        let bytes:  [u8; 1] = [0x0];
        let packet = Packet::new(&bytes);
        let pad1 = Repr::parse(&packet).unwrap();
        assert_eq!(pad1, Repr::Pad1 { ident: OptionType::Pad1 });
        assert_eq!(pad1.buffer_len(), 1);

        // two or more octets of padding
        let bytes:  [u8; 3] = [0x1, 0x1, 0x0];
        let packet = Packet::new(&bytes);
        let padn = Repr::parse(&packet).unwrap();
        assert_eq!(padn, Repr::PadN { ident: OptionType::PadN, length: 1, data: &bytes[2..3] });
        assert_eq!(padn.buffer_len(), 3);

        // unrecognized option type
        let bytes:  [u8; 3] = [0xff, 0x1, 0x0];
        let packet = Packet::new(&bytes);
        assert_eq!(Repr::parse(&packet), Err(Error::Unrecognized));
    }

    #[test]
    fn test_option_emit() {
        let repr = Repr::Pad1 { ident: OptionType::Pad1 };
        let mut bytes = [0u8; 1];
        let mut packet = Packet::new(&mut bytes);
        repr.emit(&mut packet);
        assert_eq!(packet.into_inner(), &[0x0]);

        let data = [0u8; 1];
        let repr = Repr::PadN { ident: OptionType::PadN, length: 1, data: &data };
        let mut bytes = [0u8; 3];
        let mut packet = Packet::new(&mut bytes);
        repr.emit(&mut packet);
        assert_eq!(packet.into_inner(), &[0x1, 0x1, 0x0]);
    }
}
