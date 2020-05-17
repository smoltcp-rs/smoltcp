// See https://tools.ietf.org/html/rfc4330 for the SNTPv4 specification.

use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};

enum_with_unknown! {
    /// The SNTP leap indicator field.
    pub enum LeapIndicator(u8) {
        NoWarning = 0,
        LastMinute61Sec = 1,
        LastMinute59Sec = 2,
        AlarmCondition = 3,
    }
}

enum_with_unknown! {
    /// The SNTP protocol mode.
    ///
    /// Only unicast mode is supported at the time.
    pub enum ProtocolMode(u8) {
        Reserved = 0,
        SymmetricActive = 1,
        SymmetricPassive = 2,
        Client = 3,
        Server = 4,
        Broadcast = 5,
        NtpControlMessage = 6,
        Private = 7,
    }
}

/// The SNTP stratum.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Stratum {
    KissOfDeath,
    Primary,
    Secondary(u8),
    Reserved(u8),
}

impl From<u8> for Stratum {
    fn from(s: u8) -> Self {
        match s {
            0 => Stratum::KissOfDeath,
            1 => Stratum::Primary,
            2..=15 => Stratum::Secondary(s),
            _ => Stratum::Reserved(s),
        }
    }
}

impl Into<u8> for Stratum {
    fn into(self) -> u8 {
        match self {
            Stratum::KissOfDeath => 0,
            Stratum::Primary => 1,
            Stratum::Secondary(s) | Stratum::Reserved(s) => s,
        }
    }
}

/// An SNTP timestamp, represented as integer and fractional part.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct Timestamp {
    pub(crate) sec: u32,
    pub(crate) frac: u32,
}

impl Timestamp {
    fn parse(buffer: &[u8]) -> Result<Timestamp> {
        let sec = NetworkEndian::read_u32(buffer.get(0..4).ok_or(Error::Truncated)?);
        let frac = NetworkEndian::read_u32(buffer.get(4..8).ok_or(Error::Truncated)?);
        Ok(Timestamp { sec, frac })
    }

    fn emit(&self, buffer: &mut [u8]) {
        NetworkEndian::write_u32(&mut buffer[0..4], self.sec);
        NetworkEndian::write_u32(&mut buffer[4..8], self.frac);
    }
}

/// A read/write wrapper around a Simple Network Time Protocol v4 packet buffer.
#[derive(Debug, PartialEq)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

pub(crate) mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use wire::field::*;

    pub const LI_VN_MODE: usize = 0;
    pub const STRATUM: usize = 1;
    pub const POLL: usize = 2;
    pub const PRECISION: usize = 3;
    pub const ROOT_DELAY: Field = 4..8;
    pub const ROOT_DISPERSION: Field = 8..12;
    pub const REFERENCE_IDENTIFIER: Field = 12..16;
    pub const REFERENCE_TIMESTAMP: Field = 16..24;
    pub const ORIGINATE_TIMESTAMP: Field = 24..32;
    pub const RECEIVE_TIMESTAMP: Field = 32..40;
    pub const TRANSMIT_TIMESTAMP: Field = 40..48;
    pub const KEY_IDENTIFIER: Field = 48..52;
    pub const MESSAGE_DIGEST: Field = 52..68;

    // Offsets and masks for LI_VN_MODE bitfield
    pub const LI_MASK: u8 = 0xc0;
    pub const LI_SHIFT: u8 = 6;
    pub const VN_MASK: u8 = 0x38;
    pub const VN_SHIFT: u8 = 3;
    pub const MODE_MASK: u8 = 0x07;
    pub const MODE_SHIFT: u8 = 0x00;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with SNTP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
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
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::TRANSMIT_TIMESTAMP.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns the leap indicator of this packet.
    pub fn leap_indicator(&self) -> LeapIndicator {
        let data = self.buffer.as_ref();
        LeapIndicator::from((data[field::LI_VN_MODE] & field::LI_MASK) >> field::LI_SHIFT)
    }

    /// Returns the version of this packet.
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::LI_VN_MODE] & field::VN_MASK) >> field::VN_SHIFT
    }

    /// Returns the protocol mode of this packet.
    pub fn protocol_mode(&self) -> ProtocolMode {
        let data = self.buffer.as_ref();
        ProtocolMode::from((data[field::LI_VN_MODE] & field::MODE_MASK) >> field::MODE_SHIFT)
    }

    /// Returns the stratum of this packet.
    pub fn stratum(&self) -> Stratum {
        self.buffer.as_ref()[field::STRATUM].into()
    }

    /// Returns the poll interval of this packet.
    pub fn poll_interval(&self) -> u8 {
        self.buffer.as_ref()[field::POLL]
    }

    /// Returns the precision of this packet.
    pub fn precision(&self) -> i8 {
        self.buffer.as_ref()[field::PRECISION] as i8
    }

    /// Returns the root delay of this packet.
    pub fn root_delay(&self) -> i32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_i32(&data[field::ROOT_DELAY])
    }

    /// Returns the root dispersion of this packet.
    pub fn root_dispersion(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::ROOT_DISPERSION])
    }

    /// Returns the reference identifier of this packet.
    pub fn ref_identifier(&self) -> [u8; 4] {
        let d = &self.buffer.as_ref()[field::REFERENCE_IDENTIFIER];
        [d[0], d[1], d[2], d[3]]
    }

    /// Returns the reference timestamp of this packet.
    pub fn ref_timestamp(&self) -> Result<Timestamp> {
        let data = self.buffer.as_ref();
        Timestamp::parse(&data[field::REFERENCE_TIMESTAMP])
    }

    /// Returns the originate timestamp of this packet.
    pub fn orig_timestamp(&self) -> Result<Timestamp> {
        let data = self.buffer.as_ref();
        Timestamp::parse(&data[field::ORIGINATE_TIMESTAMP])
    }

    /// Returns the receive timestamp of this packet.
    pub fn recv_timestamp(&self) -> Result<Timestamp> {
        let data = self.buffer.as_ref();
        Timestamp::parse(&data[field::RECEIVE_TIMESTAMP])
    }

    /// Returns the transmit timestamp of this packet.
    pub fn xmit_timestamp(&self) -> Result<Timestamp> {
        let data = self.buffer.as_ref();
        Timestamp::parse(&data[field::TRANSMIT_TIMESTAMP])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the leap indicator for this packet.
    pub fn set_leap_indicator(&mut self, li: LeapIndicator) {
        let data = self.buffer.as_mut();
        let li: u8 = li.into();
        data[field::LI_VN_MODE] &= !field::LI_MASK;
        data[field::LI_VN_MODE] |= li << field::LI_SHIFT;
    }

    /// Sets the version number for this packet.
    pub fn set_version(&mut self, vn: u8) {
        let data = self.buffer.as_mut();
        data[field::LI_VN_MODE] &= !field::VN_MASK;
        data[field::LI_VN_MODE] |= vn << field::VN_SHIFT;
    }

    /// Sets the protocol mode for this packet.
    pub fn set_protocol_mode(&mut self, mode: ProtocolMode) {
        let data = self.buffer.as_mut();
        let mode: u8 = mode.into();
        data[field::LI_VN_MODE] &= !field::MODE_MASK;
        data[field::LI_VN_MODE] |= mode << field::MODE_SHIFT;
    }

    /// Sets the stratum for this packet.
    pub fn set_stratum(&mut self, stratum: Stratum) {
        self.buffer.as_mut()[field::STRATUM] = stratum.into();
    }

    /// Sets the poll interval for this packet.
    pub fn set_poll_interval(&mut self, poll: u8) {
        self.buffer.as_mut()[field::POLL] = poll;
    }

    /// Sets the precision for this packet.
    pub fn set_precision(&mut self, precision: i8) {
        self.buffer.as_mut()[field::PRECISION] = precision as u8;
    }

    /// Sets the root delay for this packet.
    pub fn set_root_delay(&mut self, delay: i32) {
        let data = &mut self.buffer.as_mut()[field::ROOT_DELAY];
        NetworkEndian::write_i32(data, delay);
    }

    /// Sets the root dispersion for this packet.
    pub fn set_root_dispersion(&mut self, disp: u32) {
        let data = &mut self.buffer.as_mut()[field::ROOT_DISPERSION];
        NetworkEndian::write_u32(data, disp);
    }

    /// Sets the reference identifier for this packet.
    pub fn set_ref_identifier(&mut self, id: [u8; 4]) {
        self.buffer.as_mut()[field::REFERENCE_IDENTIFIER].copy_from_slice(&id[..]);
    }

    /// Sets the reference timestamp for this packet.
    pub fn set_ref_timestamp(&mut self, ts: Timestamp) {
        let field = &mut self.buffer.as_mut()[field::REFERENCE_TIMESTAMP];
        ts.emit(field);
    }

    /// Sets the originate timestamp for this packet.
    pub fn set_orig_timestamp(&mut self, ts: Timestamp) {
        let field = &mut self.buffer.as_mut()[field::ORIGINATE_TIMESTAMP];
        ts.emit(field);
    }

    /// Sets the receive timestamp for this packet.
    pub fn set_recv_timestamp(&mut self, ts: Timestamp) {
        let field = &mut self.buffer.as_mut()[field::RECEIVE_TIMESTAMP];
        ts.emit(field);
    }
    /// Sets the transmit timestamp for this packet.
    pub fn set_xmit_timestamp(&mut self, ts: Timestamp) {
        let field = &mut self.buffer.as_mut()[field::TRANSMIT_TIMESTAMP];
        ts.emit(field);
    }
}

/// A high-level representation of a Simple Network Time Protocol v4 packet.
///
/// SNTPv4 messages have the following layout
/// (see [RFC 4330](https://tools.ietf.org/html/rfc4330) for details):
///
/// ```no_rust
///                      1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |LI | VN  |Mode |    Stratum    |     Poll      |   Precision    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Root  Delay                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Root  Dispersion                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Reference Identifier                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                                |
/// |                    Reference Timestamp (64)                    |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                                |
/// |                    Originate Timestamp (64)                    |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                                |
/// |                     Receive Timestamp (64)                     |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                                |
/// |                     Transmit Timestamp (64)                    |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Key Identifier (optional) (32)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                                |
/// |                                                                |
/// |                 Message Digest (optional) (128)                |
/// |                                                                |
/// |                                                                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Note that most of these fields are ignored right now, as only unicast mode
/// is supported, without any advanced features (delays, response checks, etc.).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Repr {
    /// Leap indicator for leap second insertion/deletion.
    pub leap_indicator: LeapIndicator,
    /// Version number.
    pub version: u8,
    /// Protocol mode. Only unicast mode is supported.
    pub protocol_mode: ProtocolMode,
    /// Stratum of the server in an SNTP response.
    pub stratum: Stratum,
    /// Maximum interval between successive messages.
    pub poll_interval: u8,
    /// Precision of the system clock in seconds.
    pub precision: i8,
    /// Total roundtrip delay to the primary reference source.
    /// Signed fixed-point in 16.16 format.
    pub root_delay: i32,
    /// Maximum error due to clock frequency tolerances.
    /// Unsigned fixed-point in 16.16 format.
    pub root_dispersion: u32,
    /// Bitstring identifying the particular reference source.
    pub ref_identifier: [u8; 4],
    /// The time at which the system clock was last set or corrected.
    pub ref_timestamp: Timestamp,
    /// The time at which the request departed the client for the server.
    pub orig_timestamp: Timestamp,
    /// The time at which the request arrived at the server
    /// or the reply arrived at the client.
    pub recv_timestamp: Timestamp,
    /// The time at which the request departed the client
    /// or the reply departed the server.
    pub xmit_timestamp: Timestamp,
}

impl Repr {
    /// Return the length of a packet that will be emitted
    /// from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        field::KEY_IDENTIFIER.start
    }

    /// Parse an SNTP packet and return a high-level representation.
    pub fn parse<T>(packet: &Packet<&T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Repr {
            leap_indicator: packet.leap_indicator(),
            version: packet.version(),
            protocol_mode: packet.protocol_mode(),
            stratum: packet.stratum(),
            poll_interval: packet.poll_interval(),
            precision: packet.precision(),
            root_delay: packet.root_delay(),
            root_dispersion: packet.root_dispersion(),
            ref_identifier: packet.ref_identifier(),
            ref_timestamp: packet.ref_timestamp()?,
            orig_timestamp: packet.orig_timestamp()?,
            recv_timestamp: packet.recv_timestamp()?,
            xmit_timestamp: packet.xmit_timestamp()?,
        })
    }

    /// Emit a high-level representation into an SNTP packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>) -> Result<()>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_leap_indicator(self.leap_indicator);
        packet.set_version(self.version);
        packet.set_protocol_mode(self.protocol_mode);
        packet.set_stratum(self.stratum);
        packet.set_poll_interval(self.poll_interval);
        packet.set_precision(self.precision);
        packet.set_root_delay(self.root_delay);
        packet.set_root_dispersion(self.root_dispersion);
        packet.set_ref_identifier(self.ref_identifier);
        packet.set_ref_timestamp(self.ref_timestamp);
        packet.set_orig_timestamp(self.orig_timestamp);
        packet.set_recv_timestamp(self.recv_timestamp);
        packet.set_xmit_timestamp(self.xmit_timestamp);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 48] = [
        0x24, 0x02, 0x00, 0xe6, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x6f, 0x50, 0x42, 0xe0,
        0x02, 0xe2, 0x6c, 0x32, 0xf1, 0x0e, 0xd5, 0xfe, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xe2, 0x6c, 0x35, 0x11, 0x6a, 0x8c, 0xe6, 0x47, 0xe2, 0x6c, 0x35, 0x11, 0x6a,
        0x8d, 0xf8, 0x8f,
    ];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.protocol_mode(), ProtocolMode::Server);
        assert_eq!(packet.stratum(), Stratum::Secondary(2));
        assert_eq!(packet.poll_interval(), 0);
        assert_eq!(packet.precision(), -26);
        assert_eq!(packet.root_delay(), 0x120);
        assert_eq!(packet.root_dispersion(), 0x6f);
        assert_eq!(packet.ref_identifier(), [80, 66, 224, 2]);
        assert_eq!(
            packet.ref_timestamp(),
            Ok(Timestamp {
                sec: 0xe26c32f1,
                frac: 0x0ed5fea9,
            })
        );
        assert_eq!(
            packet.orig_timestamp(),
            Ok(Timestamp {
                sec: 0x00000000,
                frac: 0x00000000
            })
        );
        assert_eq!(
            packet.recv_timestamp(),
            Ok(Timestamp {
                sec: 0xe26c3511,
                frac: 0x6a8ce647,
            })
        );
        assert_eq!(
            packet.xmit_timestamp(),
            Ok(Timestamp {
                sec: 0xe26c3511,
                frac: 0x6a8df88f
            })
        )
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 48];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_leap_indicator(LeapIndicator::NoWarning);
        packet.set_version(4);
        packet.set_protocol_mode(ProtocolMode::Server);
        packet.set_stratum(Stratum::Secondary(2));
        packet.set_poll_interval(0);
        packet.set_precision(-26);
        packet.set_root_delay(0x120);
        packet.set_root_dispersion(0x6f);
        packet.set_ref_identifier([80, 66, 224, 2]);
        packet.set_ref_timestamp(Timestamp {
            sec: 0xe26c32f1,
            frac: 0x0ed5fea9,
        });
        packet.set_orig_timestamp(Timestamp {
            sec: 0x00000000,
            frac: 0x00000000,
        });
        packet.set_recv_timestamp(Timestamp {
            sec: 0xe26c3511,
            frac: 0x6a8ce647,
        });
        packet.set_xmit_timestamp(Timestamp {
            sec: 0xe26c3511,
            frac: 0x6a8df88f,
        });
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr {
        Repr {
            leap_indicator: LeapIndicator::NoWarning,
            version: 4,
            protocol_mode: ProtocolMode::Server,
            stratum: Stratum::Secondary(2),
            poll_interval: 0,
            precision: -26,
            root_delay: 0x120,
            root_dispersion: 0x6f,
            ref_identifier: [80, 66, 224, 2],
            ref_timestamp: Timestamp {
                sec: 0xe26c32f1,
                frac: 0x0ed5fea9,
            },
            orig_timestamp: Timestamp {
                sec: 0x00000000,
                frac: 0x00000000,
            },
            recv_timestamp: Timestamp {
                sec: 0xe26c3511,
                frac: 0x6a8ce647,
            },
            xmit_timestamp: Timestamp {
                sec: 0xe26c3511,
                frac: 0x6a8df88f,
            },
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0xa5; 48];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet_repr().emit(&mut packet).unwrap();
        assert_eq!(&packet.into_inner()[..], &PACKET_BYTES[..]);
    }
}
