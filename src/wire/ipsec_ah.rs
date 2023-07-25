use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, IpProtocol, Result};

/// A read/write wrapper around an IPSec Authentication Header packet buffer.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::Field;

    pub const NEXT_HEADER: usize = 0;
    pub const PAYLOAD_LEN: usize = 1;
    pub const RESERVED: Field = 2..4;
    pub const SPI: Field = 4..8;
    pub const SEQUENCE_NUMBER: Field = 8..16;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IPsec Authentication Header packet structure.
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
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the buffer is shorter than payload length
    ///
    /// The result of this check is invalidated by calling [set_payload_len].
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::SEQUENCE_NUMBER.end {
            Err(Error)
        } else if len < self.header_len() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return length of Authentication Header in octets
    pub fn header_len(&self) -> usize {
        (self.payload_len() as usize + 2) * 4
    }

    /// Return next header protocol type
    /// The value is taken from the list of IP protocol numbers.
    pub fn next_header(&self) -> IpProtocol {
        let data = self.buffer.as_ref();
        IpProtocol::from(data[field::NEXT_HEADER])
    }

    /// Return the length of this Authentication Header in 4-octet units, minus 2
    pub fn payload_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::PAYLOAD_LEN]
    }

    /// Return the security parameters index
    pub fn security_parameters_index(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::SPI];
        NetworkEndian::read_u32(field)
    }

    /// Return sequence number
    pub fn sequence_number(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::SEQUENCE_NUMBER];
        NetworkEndian::read_u32(field)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the integrity check value
    #[inline]
    pub fn integrity_check_value(&self) -> &'a [u8] {
        let range = field::SEQUENCE_NUMBER.end as usize..self.header_len();
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    fn set_next_header(&mut self, value: IpProtocol) {
        let data = self.buffer.as_mut();
        data[field::NEXT_HEADER] = value.into()
    }

    fn set_payload_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::PAYLOAD_LEN] = value
    }

    fn set_security_parameters_index(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::SPI], value)
    }

    fn set_sequence_number(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::SEQUENCE_NUMBER], value)
    }
}
