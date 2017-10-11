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

use core::{cmp, fmt};
use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use phy::ChecksumCapabilities;
use super::ip::checksum;
use super::{Ipv4Packet, Ipv4Repr};

use wire::Ipv4Address;

enum_with_unknown! {
    /// Internet protocol control message type.
    pub doc enum Igmpv2MessageType(u8) {
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

impl fmt::Display for Igmpv2MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Igmpv2MessageType::MembershipQuery => write!(f, "membership query"),
            &Igmpv2MessageType::MembershipReportV2 => write!(f, "version 2 membership report "),
            &Igmpv2MessageType::LeaveGroup => write!(f, "leave group"),
            &Igmpv2MessageType::MembershipReportV1 => write!(f, "version 1 membership report"),
        }
    }
}


impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ICMPv4 packet structure.
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
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::CHECKSUM.end {
            Err(Error::Truncated)
        } else {
            if len < self.header_len() as usize {
                Err(Error::Truncated)
            } else {
                Ok(())
            }
        }
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        field::GROUP_ADDRESS.end
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Igmpv2MessageType {
        let data = self.buffer.as_ref();
        Igmpv2MessageType::from(data[field::TYPE])
    }

    /// Return the Max reponse time
    #[inline]
    pub fn get_max_resp_time(&self) -> u8 {
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


impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }
}


impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Igmpv2MessageType) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the Max Resp Time field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
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
        let addr_u32: u32 = (addr_bytes[0] as u32) | (addr_bytes[1] as u32) << 8 |
                            (addr_bytes[2] as u32) << 16 |
                            (addr_bytes[3] as u32) << 24;
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

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}


/// A high-level representation of an Internet Group Management Protocol v2 header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    MembershipQuery { max_resp_time: u8, data: &'a [u8] },
    MembershipReport { max_resp_time: u8, data: &'a [u8] },
    LeaveGroup { max_resp_time: u8, data: &'a [u8] },
}

impl<'a> Repr<'a> {
    /// Parse an Internet Group Management Protocol v2 packet and return
    /// a high-level representation.
    pub fn parse<T>(packet: &Packet<&'a T>,
                    checksum_caps: &ChecksumCapabilities)
                    -> Result<Repr<'a>>
        where T: AsRef<[u8]> + ?Sized
    {
        // Valid checksum is expected.
        if checksum_caps.icmpv4.rx() && !packet.verify_checksum() {
            return Err(Error::Checksum);
        }

        // construct a packet based on the Type field
        match (packet.msg_type(), packet.get_max_resp_time()) {
            (Igmpv2MessageType::MembershipQuery, time) => {
                // There are two sub-types of Membership Query messages:
                // - General Query, used to learn which groups have members on an
                //   attached network.
                // - Group-Specific Query, used to learn if a particular group
                //   has any members on an attached network.
                // TODO: timer for setting the response time
                // 
            }
            (Igmpv2MessageType::MembershipReportV2, time) => {
                // TODO
            }
            (Igmpv2MessageType::LeaveGroup, time) => {
                // TODO
            }
            (Igmpv2MessageType::MembershipReportV1, _) => {
                // for backwards compatibility with IGMPv1
                // TODO
            }
        }
    }
}
