use core::{cmp, fmt};
use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::ip::checksum;

/// A read/write wrapper around an User Datagram Protocol packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    use wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH:   Field = 4..6;
    pub const CHECKSUM: Field = 6..8;
    pub const PAYLOAD:  Rest  = 8..;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Wrap a buffer with an UDP packet. Returns an error if the buffer
    /// is too small to contain one.
    pub fn new(buffer: T) -> Result<Packet<T>, Error> {
        let len = buffer.as_ref().len();
        if len < field::CHECKSUM.end {
            Err(Error::Truncated)
        } else {
            let packet = Packet { buffer: buffer };
            if len < packet.len() as usize {
                Err(Error::Truncated)
            } else {
                Ok(packet)
            }
        }
    }

    /// Consumes the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the source port field.
    #[inline(always)]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline(always)]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT])
    }

    /// Return the length field.
    #[inline(always)]
    pub fn len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the checksum field.
    #[inline(always)]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Validate the packet checksum.
    pub fn verify_checksum(&self) -> bool {
        let data = self.buffer.as_ref();
        checksum(&data[..self.len() as usize]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline(always)]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the source port field.
    #[inline(always)]
    pub fn set_src_port(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SRC_PORT], value)
    }

    /// Set the destination port field.
    #[inline(always)]
    pub fn set_dst_port(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value)
    }

    /// Set the length field.
    #[inline(always)]
    pub fn set_len(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the checksum field.
    #[inline(always)]
    pub fn set_checksum(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum(&data[..self.len() as usize])
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the type-specific data.
    #[inline(always)]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let mut data = self.buffer.as_mut();
        &mut data[field::PAYLOAD]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 12] =
        [0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x95, 0xbe,
         0xaa, 0x00, 0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x95be);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert_eq!(packet.verify_checksum(), true);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0; 12];
        let mut packet = Packet::new(&mut bytes).unwrap();
        packet.set_src_port(48896);
        packet.set_dst_port(53);
        packet.set_len(12);
        packet.set_checksum(0xffff);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }
}
