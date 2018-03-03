/// Internet Group Management Protocol v2
/// defined in [RFC_2236]
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |      Type     | Max Resp Time |           Checksum            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                         Group Address                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///

use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use phy::ChecksumCapabilities;
use super::ip::checksum;

use wire::Ipv4Address;

enum_with_unknown! {
    /// Internet Group Management Protocol v2 message type.
    pub doc enum Message(u8) {
    /// Membership Query
    MembershipQuery = 0x11,
    /// Version 2 Membership Report
    MembershipReportV2 = 0x16,
    /// Leave Group
    LeaveGroup = 0x17,
    /// Version 1 Membership Report
    MembershipReportV1 = 0x12
    }
}

/// A read/write wrapper around an Internet Group Management Protocol v2 packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use wire::field::*;

    pub const TYPE: usize = 0;
    pub const MAX_RESP_TIME: usize = 1;
    pub const CHECKSUM: Field = 2..4;
    pub const GROUP_ADDRESS: Field = 4..8;
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Message::MembershipQuery => write!(f, "membership query"),
            &Message::MembershipReportV2 => write!(f, "version 2 membership report "),
            &Message::LeaveGroup => write!(f, "leave group"),
            &Message::MembershipReportV1 => write!(f, "version 1 membership report"),
            &Message::Unknown(id) => write!(f, "Unknown message {}", id),
        }
    }
}


impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IGMPv2 packet structure.
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
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::CHECKSUM.end {
            Err(Error::Truncated)
        } else {
            if len < field::GROUP_ADDRESS.end as usize {
                Err(Error::Truncated)
            } else {
                Ok(())
            }
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        Message::from(data[field::TYPE])
    }

    /// Return the Max reponse time
    #[inline]
    pub fn max_resp_time(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::MAX_RESP_TIME]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the source address field.
    #[inline]
    pub fn group_addr(&self) -> Ipv4Address {
        let data = self.buffer.as_ref();
        Ipv4Address::from_bytes(&data[field::GROUP_ADDRESS])
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the Max Resp Time field.
    #[inline]
    pub fn set_max_resp_time(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::MAX_RESP_TIME] = value
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the group address field
    #[inline]
    pub fn set_group_address(&mut self, addr: Ipv4Address) {
        let data = self.buffer.as_mut();
        let addr_bytes = addr.as_bytes();
        // TODO: check for host endiannes?
        let addr_u32: u32 = (addr_bytes[3] as u32) | (addr_bytes[2] as u32) << 8 |
                            (addr_bytes[1] as u32) << 16 |
                            (addr_bytes[0] as u32) << 24;
        NetworkEndian::write_u32(&mut data[field::GROUP_ADDRESS], addr_u32)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }
}


/// A high-level representation of an Internet Group Management Protocol v2 header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr {
    MembershipQuery {
        max_resp_time: u8,
        group_addr: Ipv4Address,
    },
    MembershipReport {
        group_addr: Ipv4Address,
        version: ReportVersion,
    },
    LeaveGroup { group_addr: Ipv4Address },
}

/// Type of IGMPv2 membership report version
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReportVersion {
    Version1,
    Version2,
}

impl Repr {
    /// Parse an Internet Group Management Protocol v2 packet and return
    /// a high-level representation.
    pub fn parse<T>(packet: &Packet<&T>, checksum_caps: &ChecksumCapabilities) -> Result<Repr>
        where T: AsRef<[u8]> + ?Sized
    {
        // Valid checksum is expected.
        if checksum_caps.icmpv4.rx() && !packet.verify_checksum() {
            return Err(Error::Checksum);
        }

        // Check if the address is multicast
        let addr = packet.group_addr();
        if !addr.is_multicast() {
            return Err(Error::Malformed);
        }

        // construct a packet based on the Type field
        match packet.msg_type() {
            Message::MembershipQuery => {
                // TODO: act accordingly ?
                Ok(Repr::MembershipQuery {
                       max_resp_time: packet.max_resp_time(),
                       group_addr: addr,
                   })
            }
            Message::MembershipReportV2 => {
                Ok(Repr::MembershipReport {
                       group_addr: packet.group_addr(),
                       version: ReportVersion::Version2,
                   })
            }
            Message::LeaveGroup => Ok(Repr::LeaveGroup { group_addr: packet.group_addr() }),
            Message::MembershipReportV1 => {
                // for backwards compatibility with IGMPv1
                Ok(Repr::MembershipReport {
                       group_addr: packet.group_addr(),
                       version: ReportVersion::Version1,
                   })
            }
            _ => Err(Error::Unrecognized),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        // always 8 bytes
        field::GROUP_ADDRESS.end
    }

    /// Emit a high-level representation into an Internet Group Management Protocol v2 packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
        where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized
    {
        match self {
            &Repr::MembershipQuery {
                max_resp_time,
                group_addr,
            } => {
                packet.set_msg_type(Message::MembershipQuery);
                packet.set_max_resp_time(max_resp_time);
                packet.set_group_address(group_addr);
            }
            &Repr::MembershipReport {
                group_addr,
                version,
            } => {
                match version {
                    ReportVersion::Version1 => packet.set_msg_type(Message::MembershipReportV1),
                    ReportVersion::Version2 => packet.set_msg_type(Message::MembershipReportV2),
                };
                packet.set_max_resp_time(0);
                packet.set_group_address(group_addr);
            }
            &Repr::LeaveGroup { group_addr } => {
                packet.set_msg_type(Message::LeaveGroup);
                packet.set_group_address(group_addr);
            }
        }
        packet.fill_checksum()
    }
}



impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self, &ChecksumCapabilities::default()) {
            Ok(repr) => write!(f, "{}", repr),
            Err(err) => write!(f, "IGMPv2 ({})", err),
        }
    }
}

impl<'a> fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Repr::MembershipQuery {
                max_resp_time,
                group_addr,
            } => {
                write!(f,
                       "IGMPv2 membership query max_resp_time={} group_addr={}",
                       max_resp_time,
                       group_addr)
            }
            &Repr::MembershipReport {
                group_addr,
                version,
            } => {
                write!(f,
                       "IGMPv2 Membership report group_addr={} version={:?}",
                       group_addr,
                       version)
            }
            &Repr::LeaveGroup { group_addr } => {
                write!(f, "IGMPv2 Leave Group group_addr={})", group_addr)
            }
        }
    }
}

use super::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &AsRef<[u8]>,
                    f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent)
                    -> fmt::Result {
        match Packet::new_checked(buffer) {
            Err(err) => write!(f, "{}({})\n", indent, err),
            Ok(packet) => write!(f, "{}{}\n", indent, packet),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;


    static LEAVE_PACKET_BYTES: [u8; 8] = [0x17, 0x00, 0x02, 0x69, 0xe0, 0x00, 0x06, 0x96];
    static REPORT_PACKET_BYTES: [u8; 8] = [0x16, 0x00, 0x08, 0xda, 0xe1, 0x00, 0x00, 0x25];

    #[test]
    fn test_leave_group_deconstruct() {
        let packet = Packet::new(&LEAVE_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::LeaveGroup);
        assert_eq!(packet.max_resp_time(), 0);
        assert_eq!(packet.checksum(), 0x269);
        assert_eq!(packet.group_addr(),
                   Ipv4Address::from_bytes(&[224, 0, 6, 150]));
        assert_eq!(packet.verify_checksum(), true);
    }

    #[test]
    fn test_report_deconstruct() {
        let packet = Packet::new(&REPORT_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::MembershipReportV2);
        assert_eq!(packet.max_resp_time(), 0);
        assert_eq!(packet.checksum(), 0x08da);
        assert_eq!(packet.group_addr(),
                   Ipv4Address::from_bytes(&[225, 0, 0, 37]));
        assert_eq!(packet.verify_checksum(), true);
    }

    #[test]
    fn test_leave_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new(&mut bytes);
        packet.set_msg_type(Message::LeaveGroup);
        packet.set_max_resp_time(0);
        packet.set_group_address(Ipv4Address::from_bytes(&[224, 0, 6, 150]));
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &LEAVE_PACKET_BYTES[..]);
    }

    #[test]
    fn test_report_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new(&mut bytes);
        packet.set_msg_type(Message::MembershipReportV2);
        packet.set_max_resp_time(0);
        packet.set_group_address(Ipv4Address::from_bytes(&[225, 0, 0, 37]));
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &REPORT_PACKET_BYTES[..]);
    }


}
