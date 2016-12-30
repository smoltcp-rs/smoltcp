use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::{IpProtocol, IpAddress};
use super::ip::checksum;

/// A read/write wrapper around an User Datagram Protocol packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    #![allow(non_snake_case)]

    use wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH:   Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub fn PAYLOAD(length: u16) -> Field {
        CHECKSUM.end..(length as usize)
    }
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
    #[inline]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::DST_PORT])
    }

    /// Return the length field.
    #[inline]
    pub fn len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp,
                                    self.len() as u32),
            checksum::data(&data[..self.len() as usize])
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let length = self.len();
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD(length)]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the source port field.
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SRC_PORT], value)
    }

    /// Set the destination port field.
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value)
    }

    /// Set the length field.
    #[inline]
    pub fn set_len(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp,
                                        self.len() as u32),
                checksum::data(&data[..self.len() as usize])
            ])
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let length = self.len();
        let mut data = self.buffer.as_mut();
        &mut data[field::PAYLOAD(length)]
    }
}

/// A high-level representation of an User Datagram Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload:  &'a [u8]
}

impl<'a> Repr<'a> {
    /// Parse an User Datagram Protocol packet and return a high-level representation.
    pub fn parse<T: ?Sized>(packet: &Packet<&'a T>,
                            src_addr: &IpAddress,
                            dst_addr: &IpAddress) -> Result<Repr<'a>, Error>
            where T: AsRef<[u8]> {
        // Destination port cannot be omitted (but source port can be).
        if packet.dst_port() == 0 { return Err(Error::Malformed) }
        // Valid checksum is expected...
        if !packet.verify_checksum(src_addr, dst_addr) {
            match (src_addr, dst_addr) {
                (&IpAddress::Ipv4(_), &IpAddress::Ipv4(_))
                        if packet.checksum() != 0 => {
                    // ... except on UDP-over-IPv4, where it can be omitted.
                    return Err(Error::Checksum)
                },
                _ => {
                    return Err(Error::Checksum)
                }
            }
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            payload:  packet.payload()
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::CHECKSUM.end + self.payload.len()
    }

    /// Emit a high-level representation into an User Datagram Protocol packet.
    pub fn emit<T: ?Sized>(&self, packet: &mut Packet<&mut T>,
                           src_addr: &IpAddress,
                           dst_addr: &IpAddress)
            where T: AsRef<[u8]> + AsMut<[u8]> {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_len((field::CHECKSUM.end + self.payload.len()) as u16);
        packet.payload_mut().copy_from_slice(self.payload);
        packet.fill_checksum(src_addr, dst_addr)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cannot use Repr::parse because we don't have the IP addresses.
        write!(f, "UDP src={} dst={} len={}",
               self.src_port(), self.dst_port(), self.payload().len())
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UDP src={} dst={} len={}",
               self.src_port, self.dst_port, self.payload.len())
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        match Packet::new(buffer) {
            Err(err)   => write!(f, "{}({})\n", indent, err),
            Ok(packet) => write!(f, "{}{}\n", indent, packet)
        }
    }
}

#[cfg(test)]
mod test {
    use wire::Ipv4Address;
    use super::*;

    const SRC_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 1]);
    const DST_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 2]);

    static PACKET_BYTES: [u8; 12] =
        [0xbf, 0x00, 0x00, 0x35,
         0x00, 0x0c, 0x12, 0x4d,
         0xaa, 0x00, 0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert_eq!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()), true);
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
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr<'static> {
        Repr {
            src_port: 48896,
            dst_port: 53,
            payload:  &PAYLOAD_BYTES
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        let repr = Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0; repr.buffer_len()];
        let mut packet = Packet::new(&mut bytes).unwrap();
        repr.emit(&mut packet, &SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }
}
