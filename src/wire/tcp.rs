use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::{InternetProtocolType, InternetAddress};
use super::ip::checksum;

/// A read/write wrapper around an Transmission Control Protocol packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    #![allow(non_snake_case)]

    use wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM:  Field = 4..8;
    pub const ACK_NUM:  Field = 8..12;
    pub const FLAGS:    Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT:   Field = 18..20;

    pub const FLG_FIN: u16 = 0x001;
    pub const FLG_SYN: u16 = 0x002;
    pub const FLG_RST: u16 = 0x004;
    pub const FLG_PSH: u16 = 0x008;
    pub const FLG_ACK: u16 = 0x010;
    pub const FLG_URG: u16 = 0x020;
    pub const FLG_ECE: u16 = 0x040;
    pub const FLG_CWR: u16 = 0x080;
    pub const FLG_NS:  u16 = 0x100;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Wrap a buffer with a TCP packet. Returns an error if the buffer
    /// is too small to contain one.
    pub fn new(buffer: T) -> Result<Packet<T>, Error> {
        let len = buffer.as_ref().len();
        if len < field::URGENT.end {
            Err(Error::Truncated)
        } else {
            Ok(Packet { buffer: buffer })
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

    /// Return the sequence number field.
    #[inline(always)]
    pub fn seq_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::SEQ_NUM])
    }

    /// Return the acknowledgement number field.
    #[inline(always)]
    pub fn ack_number(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::ACK_NUM])
    }

    /// Return the FIN flag.
    #[inline(always)]
    pub fn fin(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_FIN != 0
    }

    /// Return the SYN flag.
    #[inline(always)]
    pub fn syn(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_SYN != 0
    }

    /// Return the RST flag.
    #[inline(always)]
    pub fn rst(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_RST != 0
    }

    /// Return the PSH flag.
    #[inline(always)]
    pub fn psh(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_PSH != 0
    }

    /// Return the ACK flag.
    #[inline(always)]
    pub fn ack(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ACK != 0
    }

    /// Return the URG flag.
    #[inline(always)]
    pub fn urg(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_URG != 0
    }

    /// Return the ECE flag.
    #[inline(always)]
    pub fn ece(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ECE != 0
    }

    /// Return the CWR flag.
    #[inline(always)]
    pub fn cwr(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_CWR != 0
    }

    /// Return the NS flag.
    #[inline(always)]
    pub fn ns(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_NS != 0
    }

    /// Return the header length, in octets.
    #[inline(always)]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        ((raw >> 12) * 4) as u8
    }

    /// Return the window size field.
    #[inline(always)]
    pub fn window_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::WIN_SIZE])
    }

    /// Return the checksum field.
    #[inline(always)]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the urgent pointer field.
    #[inline(always)]
    pub fn urgent_at(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::URGENT])
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn verify_checksum(&self, src_addr: &InternetAddress, dst_addr: &InternetAddress) -> bool {
        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, InternetProtocolType::Tcp,
                                    data.len() as u32),
            checksum::data(data)
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline(always)]
    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[header_len..]
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

    /// Set the sequence number field.
    #[inline(always)]
    pub fn set_seq_number(&mut self, value: u32) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::SEQ_NUM], value)
    }

    /// Set the acknowledgement number field.
    #[inline(always)]
    pub fn set_ack_number(&mut self, value: u32) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::ACK_NUM], value)
    }

    /// Clear the entire flags field.
    #[inline(always)]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = raw & !0x0fff;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the FIN flag.
    #[inline(always)]
    pub fn set_fin(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_FIN } else { raw & !field::FLG_FIN };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the SYN flag.
    #[inline(always)]
    pub fn set_syn(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_SYN } else { raw & !field::FLG_SYN };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the RST flag.
    #[inline(always)]
    pub fn set_rst(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_RST } else { raw & !field::FLG_RST };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the PSH flag.
    #[inline(always)]
    pub fn set_psh(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_PSH } else { raw & !field::FLG_PSH };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ACK flag.
    #[inline(always)]
    pub fn set_ack(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_ACK } else { raw & !field::FLG_ACK };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the URG flag.
    #[inline(always)]
    pub fn set_urg(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_URG } else { raw & !field::FLG_URG };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ECE flag.
    #[inline(always)]
    pub fn set_ece(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_ECE } else { raw & !field::FLG_ECE };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the CWR flag.
    #[inline(always)]
    pub fn set_cwr(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_CWR } else { raw & !field::FLG_CWR };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the NS flag.
    #[inline(always)]
    pub fn set_ns(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_NS } else { raw & !field::FLG_NS };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the header length, in octets.
    #[inline(always)]
    pub fn set_header_len(&mut self, value: u8) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = (raw & !0xf000) | ((value as u16) / 4) << 12;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Return the window size field.
    #[inline(always)]
    pub fn set_window_len(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::WIN_SIZE], value)
    }

    /// Set the checksum field.
    #[inline(always)]
    pub fn set_checksum(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the urgent pointer field.
    #[inline(always)]
    pub fn set_urgent_at(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::URGENT], value)
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &InternetAddress, dst_addr: &InternetAddress) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, InternetProtocolType::Tcp,
                                        data.len() as u32),
                checksum::data(data)
            ])
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the payload data.
    #[inline(always)]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let mut data = self.buffer.as_mut();
        &mut data[header_len..]
    }
}

/// A high-level representation of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    src_port:   u16,
    dst_port:   u16,
    seq_number: u32,
    ack_number: Option<u32>,
    window_len: u16,
    control:    Control,
    payload:    &'a [u8]
}

/// The control flags of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Syn,
    Fin,
    Rst
}

impl<'a> Repr<'a> {
    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    pub fn parse<T: ?Sized>(packet: &Packet<&'a T>,
                            src_addr: &InternetAddress,
                            dst_addr: &InternetAddress) -> Result<Repr<'a>, Error>
            where T: AsRef<[u8]> {
        // Source and destination ports must be present.
        if packet.src_port() == 0 { return Err(Error::Malformed) }
        if packet.dst_port() == 0 { return Err(Error::Malformed) }
        // Valid checksum is expected...
        if !packet.verify_checksum(src_addr, dst_addr) { return Err(Error::Checksum) }

        let control =
            match (packet.syn(), packet.fin(), packet.rst()) {
                (false, false, false) => Control::None,
                (true,  false, false) => Control::Syn,
                (false, true,  false) => Control::Fin,
                (false, false, true ) => Control::Rst,
                _ => return Err(Error::Malformed)
            };
        let ack_number =
            match packet.ack() {
                true  => Some(packet.ack_number()),
                false => None
            };
        // The PSH flag is ignored.
        // The URG flag and the urgent field is ignored. This behavior is standards-compliant,
        // however, most deployed systems (e.g. Linux) are *not* standards-compliant, and would
        // cut the byte at the urgent pointer from the stream.

        Ok(Repr {
            src_port:   packet.src_port(),
            dst_port:   packet.dst_port(),
            seq_number: packet.seq_number(),
            ack_number: ack_number,
            window_len: packet.window_len(),
            control:    control,
            payload:    packet.payload()
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::URGENT.end + self.payload.len()
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    pub fn emit<T: ?Sized>(&self, packet: &mut Packet<&mut T>,
                           src_addr: &InternetAddress,
                           dst_addr: &InternetAddress)
            where T: AsRef<[u8]> + AsMut<[u8]> {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(0));
        packet.set_window_len(self.window_len);
        packet.set_header_len(20);
        packet.clear_flags();
        match self.control {
            Control::None => (),
            Control::Syn  => packet.set_syn(true),
            Control::Fin  => packet.set_fin(true),
            Control::Rst  => packet.set_rst(true)
        }
        packet.payload_mut().copy_from_slice(self.payload);
        packet.fill_checksum(src_addr, dst_addr)
    }
}

#[cfg(test)]
mod test {
    use wire::Ipv4Address;
    use super::*;

    const SRC_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 1]);
    const DST_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 2]);

    static PACKET_BYTES: [u8; 24] =
        [0xbf, 0x00, 0x00, 0x50,
         0x01, 0x23, 0x45, 0x67,
         0x89, 0xab, 0xcd, 0xef,
         0x50, 0x35, 0x01, 0x23,
         0x20, 0xbe, 0x02, 0x01,
         0xaa, 0x00, 0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), 0x01234567);
        assert_eq!(packet.ack_number(), 0x89abcdef);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.fin(), true);
        assert_eq!(packet.syn(), false);
        assert_eq!(packet.rst(), true);
        assert_eq!(packet.psh(), false);
        assert_eq!(packet.ack(), true);
        assert_eq!(packet.urg(), true);
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.urgent_at(), 0x0201);
        assert_eq!(packet.checksum(), 0x20be);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert_eq!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()), true);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0; 24];
        let mut packet = Packet::new(&mut bytes).unwrap();
        packet.set_src_port(48896);
        packet.set_dst_port(80);
        packet.set_seq_number(0x01234567);
        packet.set_ack_number(0x89abcdef);
        packet.set_header_len(20);
        packet.set_fin(true);
        packet.set_syn(false);
        packet.set_rst(true);
        packet.set_psh(false);
        packet.set_ack(true);
        packet.set_urg(true);
        packet.set_window_len(0x0123);
        packet.set_urgent_at(0x0201);
        packet.set_checksum(0xEEEE);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }

    static SYN_PACKET_BYTES: [u8; 24] =
        [0xbf, 0x00, 0x00, 0x50,
         0x01, 0x23, 0x45, 0x67,
         0x00, 0x00, 0x00, 0x00,
         0x50, 0x02, 0x01, 0x23,
         0x7a, 0x8d, 0x00, 0x00,
         0xaa, 0x00, 0x00, 0xff];

    fn packet_repr() -> Repr<'static> {
        Repr {
            src_port:   48896,
            dst_port:   80,
            seq_number: 0x01234567,
            ack_number: None,
            window_len: 0x0123,
            control:    Control::Syn,
            payload:    &PAYLOAD_BYTES
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new(&SYN_PACKET_BYTES[..]).unwrap();
        let repr = Repr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0; repr.buffer_len()];
        let mut packet = Packet::new(&mut bytes).unwrap();
        repr.emit(&mut packet, &SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&packet.into_inner()[..], &SYN_PACKET_BYTES[..]);
    }
}
