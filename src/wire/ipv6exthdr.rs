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

/// A high-level representation of an IPv6 Extension Header Option
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    Pad1 {
        ident:  u8,
    },
    PadN {
        ident:  u8,
        length: u8,
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
                    ident: From::from(packet.option_type()),
                })
            }
            OptionType::PadN => {
                Ok(Repr::PadN {
                    ident: From::from(packet.option_type()),
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

    //pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
    //    match self {
    //        Pad1 => {
    //            packet.set_option_type
    //        }
    //        PadN => {
    //        }
    //    }
    //    packet.set_version(6);
    //    packet.set_traffic_class(1);
    //    packet.set_flow_label(0);
    //    packet.set_payload_len(self.payload_len as u16);
    //    packet.set_hop_limit(self.hop_limit);
    //    packet.set_next_header(self.next_header);
    //    packet.set_src_addr(self.src_addr);
    //    packet.set_dst_addr(self.dst_addr);
    //}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_option_deconstruct() {
        // one octet of padding
        let data:  [u8; 1] = [0x0];
        let packet = Packet::new(&data);
        assert_eq!(packet.option_type(), OptionType::Pad1);

        // two octets of padding
        let data:  [u8; 2] = [0x1, 0x0];
        let packet = Packet::new(&data);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 0);

        // three octets of padding
        let data:  [u8; 3] = [0x1, 0x1, 0x0];
        let packet = Packet::new(&data);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 1);
        assert_eq!(packet.option_data(), &[0]);

        // extra data in buffer
        let data:  [u8; 10] = [0x1, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff];
        let packet = Packet::new(&data);
        assert_eq!(packet.option_type(), OptionType::PadN);
        assert_eq!(packet.option_data_length(), 7);
        assert_eq!(packet.option_data(), &[0, 0, 0, 0, 0, 0, 0]);

        // unrecognized option actions
        let data:  [u8; 1] = [0xff];
        let packet = Packet::new(&data);
        assert_eq!(packet.option_type(), OptionType::Unknown(255));
    }

    #[test]
    fn test_option_parse() {
        // one octet of padding
        let data:  [u8; 1] = [0x0];
        let packet = Packet::new(&data);
        let pad1 = Repr::parse(&packet).unwrap();
        assert_eq!(pad1, Repr::Pad1 { ident: 0 });
        assert_eq!(pad1.buffer_len(), 1);

        // two or more octets of padding
        let data:  [u8; 3] = [0x1, 0x1, 0x0];
        let packet = Packet::new(&data);
        let padn = Repr::parse(&packet).unwrap();
        assert_eq!(padn, Repr::PadN { ident: 1, length: 1, data: &data[2..3] });
        assert_eq!(pad1.buffer_len(), 3);

        // unrecognized option type
        let data:  [u8; 3] = [0xff, 0x1, 0x0];
        let packet = Packet::new(&data);
        assert_eq!(Repr::parse(&packet), Err(Error::Unrecognized));
    }
}
