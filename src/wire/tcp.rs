use core::{i32, ops, cmp, fmt};
use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::{IpProtocol, IpAddress};
use super::ip::checksum;

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo 2<sup>32</sup>.
/// Sequence numbers do not have a discontiguity when compared pairwise across a signed overflow.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SeqNumber(pub i32);

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u32)
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl ops::AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl ops::Sub for SeqNumber {
    type Output = usize;

    fn sub(self, rhs: SeqNumber) -> usize {
        (self.0 - rhs.0) as usize
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        (self.0 - other.0).partial_cmp(&0)
    }
}

/// A read/write wrapper around a Transmission Control Protocol packet buffer.
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

    pub const OPT_END: u8 = 0x00;
    pub const OPT_NOP: u8 = 0x01;
    pub const OPT_MSS: u8 = 0x02;
    pub const OPT_WS:  u8 = 0x03;
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

    /// Return the sequence number field.
    #[inline]
    pub fn seq_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::SEQ_NUM]))
    }

    /// Return the acknowledgement number field.
    #[inline]
    pub fn ack_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(NetworkEndian::read_i32(&data[field::ACK_NUM]))
    }

    /// Return the FIN flag.
    #[inline]
    pub fn fin(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_FIN != 0
    }

    /// Return the SYN flag.
    #[inline]
    pub fn syn(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_SYN != 0
    }

    /// Return the RST flag.
    #[inline]
    pub fn rst(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_RST != 0
    }

    /// Return the PSH flag.
    #[inline]
    pub fn psh(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_PSH != 0
    }

    /// Return the ACK flag.
    #[inline]
    pub fn ack(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ACK != 0
    }

    /// Return the URG flag.
    #[inline]
    pub fn urg(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_URG != 0
    }

    /// Return the ECE flag.
    #[inline]
    pub fn ece(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_ECE != 0
    }

    /// Return the CWR flag.
    #[inline]
    pub fn cwr(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_CWR != 0
    }

    /// Return the NS flag.
    #[inline]
    pub fn ns(&self) -> bool {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        raw & field::FLG_NS != 0
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        ((raw >> 12) * 4) as u8
    }

    /// Return the window size field.
    #[inline]
    pub fn window_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::WIN_SIZE])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the urgent pointer field.
    #[inline]
    pub fn urgent_at(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::URGENT])
    }

    /// Return the length of the segment, in terms of sequence space.
    #[inline]
    pub fn segment_len(&self) -> usize {
        let data = self.buffer.as_ref();
        let mut length = data.len() - self.header_len() as usize;
        if self.syn() { length += 1 }
        if self.fin() { length += 1 }
        length
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp,
                                    data.len() as u32),
            checksum::data(data)
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[field::URGENT.end..header_len]
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        &data[header_len..]
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

    /// Set the sequence number field.
    #[inline]
    pub fn set_seq_number(&mut self, value: SeqNumber) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::SEQ_NUM], value.0)
    }

    /// Set the acknowledgement number field.
    #[inline]
    pub fn set_ack_number(&mut self, value: SeqNumber) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_i32(&mut data[field::ACK_NUM], value.0)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = raw & !0x0fff;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the FIN flag.
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_FIN } else { raw & !field::FLG_FIN };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the SYN flag.
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_SYN } else { raw & !field::FLG_SYN };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the RST flag.
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_RST } else { raw & !field::FLG_RST };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the PSH flag.
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_PSH } else { raw & !field::FLG_PSH };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ACK flag.
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_ACK } else { raw & !field::FLG_ACK };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the URG flag.
    #[inline]
    pub fn set_urg(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_URG } else { raw & !field::FLG_URG };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the ECE flag.
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_ECE } else { raw & !field::FLG_ECE };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the CWR flag.
    #[inline]
    pub fn set_cwr(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_CWR } else { raw & !field::FLG_CWR };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the NS flag.
    #[inline]
    pub fn set_ns(&mut self, value: bool) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = if value { raw | field::FLG_NS } else { raw & !field::FLG_NS };
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let mut data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLAGS]);
        let raw = (raw & !0xf000) | ((value as u16) / 4) << 12;
        NetworkEndian::write_u16(&mut data[field::FLAGS], raw)
    }

    /// Return the window size field.
    #[inline]
    pub fn set_window_len(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::WIN_SIZE], value)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the urgent pointer field.
    #[inline]
    pub fn set_urgent_at(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::URGENT], value)
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
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp,
                                        data.len() as u32),
                checksum::data(data)
            ])
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[field::URGENT.end..header_len]
    }

    /// Return a mutable pointer to the payload data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let mut data = self.buffer.as_mut();
        &mut data[header_len..]
    }
}

/// A representation of a single TCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption<'a> {
    EndOfList,
    NoOperation,
    MaxSegmentSize(u16),
    WindowScale(u8),
    Unknown { kind: u8, data: &'a [u8] }
}

impl<'a> TcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>), Error> {
        let (length, option);
        match *buffer.get(0).ok_or(Error::Truncated)? {
            field::OPT_END => {
                length = 1;
                option = TcpOption::EndOfList;
            }
            field::OPT_NOP => {
                length = 1;
                option = TcpOption::NoOperation;
            }
            kind => {
                length = *buffer.get(1).ok_or(Error::Truncated)? as usize;
                if buffer.len() < length { return Err(Error::Truncated) }
                let data = &buffer[2..length];
                match (kind, length) {
                    (field::OPT_END, _) |
                    (field::OPT_NOP, _) =>
                        unreachable!(),
                    (field::OPT_MSS, 4) =>
                        option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data)),
                    (field::OPT_MSS, _) =>
                        return Err(Error::Malformed),
                    (field::OPT_WS, 3) =>
                        option = TcpOption::WindowScale(data[0]),
                    (field::OPT_WS, _) =>
                        return Err(Error::Malformed),
                    (_, _) =>
                        option = TcpOption::Unknown { kind: kind, data: data }
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &TcpOption::EndOfList => 1,
            &TcpOption::NoOperation => 1,
            &TcpOption::MaxSegmentSize(_) => 4,
            &TcpOption::WindowScale(_) => 3,
            &TcpOption::Unknown { data, .. } => 2 + data.len()
        }
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match self {
            &TcpOption::EndOfList => {
                length    = 1;
                buffer[0] = field::OPT_END;
            }
            &TcpOption::NoOperation => {
                length    = 1;
                buffer[0] = field::OPT_NOP;
            }
            _ => {
                length    = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &TcpOption::EndOfList |
                    &TcpOption::NoOperation =>
                        unreachable!(),
                    &TcpOption::MaxSegmentSize(value) => {
                        buffer[0] = field::OPT_MSS;
                        NetworkEndian::write_u16(&mut buffer[2..], value)
                    }
                    &TcpOption::WindowScale(value) => {
                        buffer[0] = field::OPT_WS;
                        buffer[2] = value;
                    }
                    &TcpOption::Unknown { kind, data: provided } => {
                        buffer[0] = kind;
                        buffer[2..].copy_from_slice(provided)
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// The control flags of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Syn,
    Fin,
    Rst
}

/// A high-level representation of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    pub src_port:     u16,
    pub dst_port:     u16,
    pub control:      Control,
    pub seq_number:   SeqNumber,
    pub ack_number:   Option<SeqNumber>,
    pub window_len:   u16,
    pub max_seg_size: Option<u16>,
    pub payload:      &'a [u8]
}

impl<'a> Repr<'a> {
    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    pub fn parse<T: ?Sized>(packet: &Packet<&'a T>,
                            src_addr: &IpAddress,
                            dst_addr: &IpAddress) -> Result<Repr<'a>, Error>
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

        let mut max_seg_size = None;
        let mut options = packet.options();
        while options.len() > 0 {
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) =>
                    max_seg_size = Some(value),
                _ => ()
            }
            options = next_options;
        }

        Ok(Repr {
            src_port:     packet.src_port(),
            dst_port:     packet.dst_port(),
            control:      control,
            seq_number:   packet.seq_number(),
            ack_number:   ack_number,
            window_len:   packet.window_len(),
            max_seg_size: max_seg_size,
            payload:      packet.payload()
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub fn header_len(&self) -> usize {
        let mut length = field::URGENT.end;
        if self.max_seg_size.is_some() {
            length += 4
        }
        length
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        self.header_len() + self.payload.len()
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    pub fn emit<T: ?Sized>(&self, packet: &mut Packet<&mut T>,
                           src_addr: &IpAddress,
                           dst_addr: &IpAddress)
            where T: AsRef<[u8]> + AsMut<[u8]> {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(SeqNumber(0)));
        packet.set_window_len(self.window_len);
        packet.set_header_len(self.header_len() as u8);
        packet.clear_flags();
        match self.control {
            Control::None => (),
            Control::Syn  => packet.set_syn(true),
            Control::Fin  => packet.set_fin(true),
            Control::Rst  => packet.set_rst(true)
        }
        packet.set_ack(self.ack_number.is_some());
        {
            let mut options = packet.options_mut();
            if let Some(value) = self.max_seg_size {
                let tmp = options; options = TcpOption::MaxSegmentSize(value).emit(tmp);
            }
            if options.len() > 0 {
                TcpOption::EndOfList.emit(options);
            }
        }
        packet.payload_mut().copy_from_slice(self.payload);
        packet.fill_checksum(src_addr, dst_addr)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cannot use Repr::parse because we don't have the IP addresses.
        try!(write!(f, "TCP src={} dst={}",
                    self.src_port(), self.dst_port()));
        if self.syn() { try!(write!(f, " syn")) }
        if self.fin() { try!(write!(f, " fin")) }
        if self.rst() { try!(write!(f, " rst")) }
        if self.psh() { try!(write!(f, " psh")) }
        if self.ece() { try!(write!(f, " ece")) }
        if self.cwr() { try!(write!(f, " cwr")) }
        if self.ns()  { try!(write!(f, " ns" )) }
        try!(write!(f, " seq={}", self.seq_number()));
        if self.ack() {
            try!(write!(f, " ack={}", self.ack_number()));
        }
        try!(write!(f, " win={}", self.window_len()));
        if self.urg() {
            try!(write!(f, " urg={}", self.urgent_at()))
        }
        try!(write!(f, " len={}", self.payload().len()));
        let mut options = self.options();
        while options.len() > 0 {
            let (next_options, option) =
                match TcpOption::parse(options) {
                    Ok(res) => res,
                    Err(err) => return write!(f, " ({})", err)
                };
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) =>
                    try!(write!(f, " mss={}", value)),
                TcpOption::WindowScale(value) =>
                    try!(write!(f, " ws={}", value)),
                TcpOption::Unknown { kind, .. } =>
                    try!(write!(f, " opt({})", kind)),
            }
            options = next_options;
        }
        Ok(())
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "TCP src={} dst={}",
                    self.src_port, self.dst_port));
        match self.control {
            Control::Syn => try!(write!(f, " syn")),
            Control::Fin => try!(write!(f, " fin")),
            Control::Rst => try!(write!(f, " rst")),
            Control::None => ()
        }
        try!(write!(f, " seq={}", self.seq_number));
        if let Some(ack_number) = self.ack_number {
            try!(write!(f, " ack={}", ack_number));
        }
        try!(write!(f, " win={}", self.window_len));
        try!(write!(f, " len={}", self.payload.len()));
        if let Some(max_seg_size) = self.max_seg_size {
            try!(write!(f, " mss={}", max_seg_size));
        }
        Ok(())
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

    static PACKET_BYTES: [u8; 28] =
        [0xbf, 0x00, 0x00, 0x50,
         0x01, 0x23, 0x45, 0x67,
         0x89, 0xab, 0xcd, 0xef,
         0x60, 0x35, 0x01, 0x23,
         0x01, 0xb6, 0x02, 0x01,
         0x03, 0x03, 0x0c, 0x01,
         0xaa, 0x00, 0x00, 0xff];

    static OPTION_BYTES: [u8; 4] =
        [0x03, 0x03, 0x0c, 0x01];

    static PAYLOAD_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new(&PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), SeqNumber(0x01234567));
        assert_eq!(packet.ack_number(), SeqNumber(0x89abcdefu32 as i32));
        assert_eq!(packet.header_len(), 24);
        assert_eq!(packet.fin(), true);
        assert_eq!(packet.syn(), false);
        assert_eq!(packet.rst(), true);
        assert_eq!(packet.psh(), false);
        assert_eq!(packet.ack(), true);
        assert_eq!(packet.urg(), true);
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.urgent_at(), 0x0201);
        assert_eq!(packet.checksum(), 0x01b6);
        assert_eq!(packet.options(), &OPTION_BYTES[..]);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert_eq!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()), true);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0; PACKET_BYTES.len()];
        let mut packet = Packet::new(&mut bytes).unwrap();
        packet.set_src_port(48896);
        packet.set_dst_port(80);
        packet.set_seq_number(SeqNumber(0x01234567));
        packet.set_ack_number(SeqNumber(0x89abcdefu32 as i32));
        packet.set_header_len(24);
        packet.set_fin(true);
        packet.set_syn(false);
        packet.set_rst(true);
        packet.set_psh(false);
        packet.set_ack(true);
        packet.set_urg(true);
        packet.set_window_len(0x0123);
        packet.set_urgent_at(0x0201);
        packet.set_checksum(0xEEEE);
        packet.options_mut().copy_from_slice(&OPTION_BYTES[..]);
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
            src_port:     48896,
            dst_port:     80,
            seq_number:   SeqNumber(0x01234567),
            ack_number:   None,
            window_len:   0x0123,
            control:      Control::Syn,
            max_seg_size: None,
            payload:      &PAYLOAD_BYTES
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

    macro_rules! assert_option_parses {
        ($opt:expr, $data:expr) => ({
            assert_eq!(TcpOption::parse($data), Ok((&[][..], $opt)));
            let buffer = &mut [0; 20][..$opt.buffer_len()];
            assert_eq!($opt.emit(buffer), &mut []);
            assert_eq!(&*buffer, $data);
        })
    }

    #[test]
    fn test_tcp_options() {
        assert_option_parses!(TcpOption::EndOfList,
                              &[0x00]);
        assert_option_parses!(TcpOption::NoOperation,
                              &[0x01]);
        assert_option_parses!(TcpOption::MaxSegmentSize(1500),
                              &[0x02, 0x04, 0x05, 0xdc]);
        assert_option_parses!(TcpOption::WindowScale(12),
                              &[0x03, 0x03, 0x0c]);
        assert_option_parses!(TcpOption::Unknown { kind: 12, data: &[1, 2, 3][..] },
                              &[0x0c, 0x05, 0x01, 0x02, 0x03])
    }

    #[test]
    fn test_malformed_tcp_options() {
        assert_eq!(TcpOption::parse(&[]),
                   Err(Error::Truncated));
        assert_eq!(TcpOption::parse(&[0xc]),
                   Err(Error::Truncated));
        assert_eq!(TcpOption::parse(&[0xc, 0x05, 0x01, 0x02]),
                   Err(Error::Truncated));
        assert_eq!(TcpOption::parse(&[0x2, 0x02]),
                   Err(Error::Malformed));
        assert_eq!(TcpOption::parse(&[0x3, 0x02]),
                   Err(Error::Malformed));
    }
}
