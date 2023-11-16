//! Implementation of the RPL packet formats. See [RFC 6550 § 6].
//!
//! [RFC 6550 § 6]: https://datatracker.ietf.org/doc/html/rfc6550#section-6

use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};
use crate::wire::icmpv6::Packet;
use crate::wire::ipv6::Address;

pub mod hbh;
pub mod instance_id;
pub mod options;
pub mod sequence_counter;

pub use instance_id::InstanceId;
pub use sequence_counter::SequenceCounter;

mod field {
    use crate::wire::field::*;

    pub const RPL_INSTANCE_ID: usize = 4;

    // DODAG information solicitation fields (DIS)
    pub const DIS_FLAGS: usize = 4;
    pub const DIS_RESERVED: usize = 5;

    // DODAG information object fields (DIO)
    pub const DIO_VERSION_NUMBER: usize = 5;
    pub const DIO_RANK: Field = 6..8;
    pub const DIO_GROUNDED: usize = 8;
    pub const DIO_MOP: usize = 8;
    pub const DIO_PRF: usize = 8;
    pub const DIO_DTSN: usize = 9;
    //pub const DIO_FLAGS: usize = 10;
    //pub const DIO_RESERVED: usize = 11;
    pub const DIO_DODAG_ID: Field = 12..12 + 16;

    // Destination advertisement object (DAO)
    pub const DAO_K: usize = 5;
    pub const DAO_D: usize = 5;
    //pub const DAO_FLAGS: usize = 5;
    //pub const DAO_RESERVED: usize = 6;
    pub const DAO_SEQUENCE: usize = 7;
    pub const DAO_DODAG_ID: Field = 8..8 + 16;

    // Destination advertisement object ack (DAO-ACK)
    pub const DAO_ACK_D: usize = 5;
    //pub const DAO_ACK_RESERVED: usize = 5;
    pub const DAO_ACK_SEQUENCE: usize = 6;
    pub const DAO_ACK_STATUS: usize = 7;
    pub const DAO_ACK_DODAG_ID: Field = 8..8 + 16;
}

enum_with_unknown! {
    /// RPL Control Message subtypes.
    pub enum RplControlMessage(u8) {
        DodagInformationSolicitation = 0x00,
        DodagInformationObject = 0x01,
        DestinationAdvertisementObject = 0x02,
        DestinationAdvertisementObjectAck = 0x03,
        SecureDodagInformationSolicitation = 0x80,
        SecureDodagInformationObject = 0x81,
        SecureDestinationAdvertisementObject = 0x82,
        SecureDestinationAdvertisementObjectAck = 0x83,
        ConsistencyCheck = 0x8a,
    }
}

impl core::fmt::Display for RplControlMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RplControlMessage::DodagInformationSolicitation => {
                write!(f, "DODAG information solicitation (DIS)")
            }
            RplControlMessage::DodagInformationObject => {
                write!(f, "DODAG information object (DIO)")
            }
            RplControlMessage::DestinationAdvertisementObject => {
                write!(f, "destination advertisement object (DAO)")
            }
            RplControlMessage::DestinationAdvertisementObjectAck => write!(
                f,
                "destination advertisement object acknowledgement (DAO-ACK)"
            ),
            RplControlMessage::SecureDodagInformationSolicitation => {
                write!(f, "secure DODAG information solicitation (DIS)")
            }
            RplControlMessage::SecureDodagInformationObject => {
                write!(f, "secure DODAG information object (DIO)")
            }
            RplControlMessage::SecureDestinationAdvertisementObject => {
                write!(f, "secure destination advertisement object (DAO)")
            }
            RplControlMessage::SecureDestinationAdvertisementObjectAck => write!(
                f,
                "secure destination advertisement object acknowledgement (DAO-ACK)"
            ),
            RplControlMessage::ConsistencyCheck => write!(f, "consistency check (CC)"),
            RplControlMessage::Unknown(id) => write!(f, "{}", id),
        }
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the RPL instance ID.
    #[inline]
    pub fn rpl_instance_id(&self) -> InstanceId {
        get!(self.buffer, into: InstanceId, field: field::RPL_INSTANCE_ID)
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return a pointer to the options.
    pub fn options(&self) -> Result<&'p [u8]> {
        let len = self.buffer.as_ref().len();
        match RplControlMessage::from(self.msg_code()) {
            RplControlMessage::DodagInformationSolicitation if len < field::DIS_RESERVED + 1 => {
                return Err(Error)
            }
            RplControlMessage::DodagInformationObject if len < field::DIO_DODAG_ID.end => {
                return Err(Error)
            }
            RplControlMessage::DestinationAdvertisementObject
                if self.dao_dodag_id_present() && len < field::DAO_DODAG_ID.end =>
            {
                return Err(Error)
            }
            RplControlMessage::DestinationAdvertisementObject if len < field::DAO_SEQUENCE + 1 => {
                return Err(Error)
            }
            RplControlMessage::DestinationAdvertisementObjectAck
                if self.dao_ack_dodag_id_present() && len < field::DAO_ACK_DODAG_ID.end =>
            {
                return Err(Error)
            }
            RplControlMessage::DestinationAdvertisementObjectAck
                if len < field::DAO_ACK_STATUS + 1 =>
            {
                return Err(Error)
            }
            RplControlMessage::SecureDodagInformationSolicitation
            | RplControlMessage::SecureDodagInformationObject
            | RplControlMessage::SecureDestinationAdvertisementObject
            | RplControlMessage::SecureDestinationAdvertisementObjectAck
            | RplControlMessage::ConsistencyCheck => return Err(Error),
            RplControlMessage::Unknown(_) => return Err(Error),
            _ => {}
        }

        let buffer = &self.buffer.as_ref();
        Ok(match RplControlMessage::from(self.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => &buffer[field::DIS_RESERVED + 1..],
            RplControlMessage::DodagInformationObject => &buffer[field::DIO_DODAG_ID.end..],
            RplControlMessage::DestinationAdvertisementObject if self.dao_dodag_id_present() => {
                &buffer[field::DAO_DODAG_ID.end..]
            }
            RplControlMessage::DestinationAdvertisementObject => &buffer[field::DAO_SEQUENCE + 1..],
            RplControlMessage::DestinationAdvertisementObjectAck
                if self.dao_ack_dodag_id_present() =>
            {
                &buffer[field::DAO_ACK_DODAG_ID.end..]
            }
            RplControlMessage::DestinationAdvertisementObjectAck => {
                &buffer[field::DAO_ACK_STATUS + 1..]
            }
            RplControlMessage::SecureDodagInformationSolicitation
            | RplControlMessage::SecureDodagInformationObject
            | RplControlMessage::SecureDestinationAdvertisementObject
            | RplControlMessage::SecureDestinationAdvertisementObjectAck
            | RplControlMessage::ConsistencyCheck => unreachable!(),
            RplControlMessage::Unknown(_) => unreachable!(),
        })
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the RPL Instance ID field.
    #[inline]
    pub fn set_rpl_instance_id(&mut self, value: u8) {
        set!(self.buffer, value, field: field::RPL_INSTANCE_ID)
    }
}

impl<'p, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'p mut T> {
    /// Return a pointer to the options.
    pub fn options_mut(&mut self) -> &mut [u8] {
        match RplControlMessage::from(self.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => {
                &mut self.buffer.as_mut()[field::DIS_RESERVED + 1..]
            }
            RplControlMessage::DodagInformationObject => {
                &mut self.buffer.as_mut()[field::DIO_DODAG_ID.end..]
            }
            RplControlMessage::DestinationAdvertisementObject => {
                if self.dao_dodag_id_present() {
                    &mut self.buffer.as_mut()[field::DAO_DODAG_ID.end..]
                } else {
                    &mut self.buffer.as_mut()[field::DAO_SEQUENCE + 1..]
                }
            }
            RplControlMessage::DestinationAdvertisementObjectAck => {
                if self.dao_ack_dodag_id_present() {
                    &mut self.buffer.as_mut()[field::DAO_ACK_DODAG_ID.end..]
                } else {
                    &mut self.buffer.as_mut()[field::DAO_ACK_STATUS + 1..]
                }
            }
            RplControlMessage::SecureDodagInformationSolicitation
            | RplControlMessage::SecureDodagInformationObject
            | RplControlMessage::SecureDestinationAdvertisementObject
            | RplControlMessage::SecureDestinationAdvertisementObjectAck
            | RplControlMessage::ConsistencyCheck => todo!("Secure messages not supported"),
            RplControlMessage::Unknown(_) => todo!(),
        }
    }
}

/// Getters for the DODAG information solicitation (DIS) message.
///
/// ```txt
///  0                   1                   2
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Flags     |   Reserved    |   Option(s)...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the DIS flags field.
    #[inline]
    pub fn dis_flags(&self) -> u8 {
        get!(self.buffer, field: field::DIS_FLAGS)
    }

    /// Return the DIS reserved field.
    #[inline]
    pub fn dis_reserved(&self) -> u8 {
        get!(self.buffer, field: field::DIS_RESERVED)
    }
}

/// Setters for the DODAG information solicitation (DIS) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the DIS flags field.
    pub fn clear_dis_flags(&mut self) {
        self.buffer.as_mut()[field::DIS_FLAGS] = 0;
    }

    /// Clear the DIS rserved field.
    pub fn clear_dis_reserved(&mut self) {
        self.buffer.as_mut()[field::DIS_RESERVED] = 0;
    }
}

enum_with_unknown! {
    pub enum ModeOfOperation(u8) {
        NoDownwardRoutesMaintained = 0x00,
        NonStoringMode = 0x01,
        StoringModeWithoutMulticast = 0x02,
        StoringModeWithMulticast = 0x03,
    }
}

impl Default for ModeOfOperation {
    fn default() -> Self {
        Self::StoringModeWithoutMulticast
    }
}

/// Getters for the DODAG information object (DIO) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |Version Number |             Rank              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |G|0| MOP | Prf |     DTSN      |     Flags     |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID                            +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Version Number field.
    #[inline]
    pub fn dio_version_number(&self) -> u8 {
        get!(self.buffer, field: field::DIO_VERSION_NUMBER)
    }

    /// Return the Rank field.
    #[inline]
    pub fn dio_rank(&self) -> u16 {
        get!(self.buffer, u16, field: field::DIO_RANK)
    }

    /// Return the value of the Grounded flag.
    #[inline]
    pub fn dio_grounded(&self) -> bool {
        get!(self.buffer, bool, field: field::DIO_GROUNDED, shift: 7, mask: 0b01)
    }

    /// Return the mode of operation field.
    #[inline]
    pub fn dio_mode_of_operation(&self) -> ModeOfOperation {
        get!(self.buffer, into: ModeOfOperation, field: field::DIO_MOP, shift: 3, mask: 0b111)
    }

    /// Return the DODAG preference field.
    #[inline]
    pub fn dio_dodag_preference(&self) -> u8 {
        get!(self.buffer, field: field::DIO_PRF, mask: 0b111)
    }

    /// Return the destination advertisement trigger sequence number.
    #[inline]
    pub fn dio_dest_adv_trigger_seq_number(&self) -> u8 {
        get!(self.buffer, field: field::DIO_DTSN)
    }

    /// Return the DODAG id, which is an IPv6 address.
    #[inline]
    pub fn dio_dodag_id(&self) -> Address {
        get!(
            self.buffer,
            into: Address,
            fun: from_bytes,
            field: field::DIO_DODAG_ID
        )
    }
}

/// Setters for the DODAG information object (DIO) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Version Number field.
    #[inline]
    pub fn set_dio_version_number(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_VERSION_NUMBER)
    }

    /// Set the Rank field.
    #[inline]
    pub fn set_dio_rank(&mut self, value: u16) {
        set!(self.buffer, value, u16, field: field::DIO_RANK)
    }

    /// Set the value of the Grounded flag.
    #[inline]
    pub fn set_dio_grounded(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DIO_GROUNDED, shift: 7, mask: 0b01)
    }

    ///  Set the mode of operation field.
    #[inline]
    pub fn set_dio_mode_of_operation(&mut self, mode: ModeOfOperation) {
        let raw = (self.buffer.as_ref()[field::DIO_MOP] & !(0b111 << 3)) | (u8::from(mode) << 3);
        self.buffer.as_mut()[field::DIO_MOP] = raw;
    }

    /// Set the DODAG preference field.
    #[inline]
    pub fn set_dio_dodag_preference(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_PRF, mask: 0b111)
    }

    /// Set the destination advertisement trigger sequence number.
    #[inline]
    pub fn set_dio_dest_adv_trigger_seq_number(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_DTSN)
    }

    /// Set the DODAG id, which is an IPv6 address.
    #[inline]
    pub fn set_dio_dodag_id(&mut self, address: Address) {
        set!(self.buffer, address: address, field: field::DIO_DODAG_ID)
    }
}

/// Getters for the Destination Advertisement Object (DAO) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |K|D|   Flags   |   Reserved    | DAOSequence   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID*                           +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Returns the Expect DAO-ACK flag.
    #[inline]
    pub fn dao_ack_request(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_K, shift: 7, mask: 0b1)
    }

    /// Returns the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn dao_dodag_id_present(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_D, shift: 6, mask: 0b1)
    }

    /// Returns the DODAG sequence flag.
    #[inline]
    pub fn dao_dodag_sequence(&self) -> u8 {
        get!(self.buffer, field: field::DAO_SEQUENCE)
    }

    /// Returns the DODAG ID, an IPv6 address, when it is present.
    #[inline]
    pub fn dao_dodag_id(&self) -> Option<Address> {
        if self.dao_dodag_id_present() {
            Some(Address::from_bytes(
                &self.buffer.as_ref()[field::DAO_DODAG_ID],
            ))
        } else {
            None
        }
    }
}

/// Setters for the Destination Advertisement Object (DAO) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Expect DAO-ACK flag.
    #[inline]
    pub fn set_dao_ack_request(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_K, shift: 7, mask: 0b1,)
    }

    /// Set the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn set_dao_dodag_id_present(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_D, shift: 6, mask: 0b1)
    }

    /// Set the DODAG sequence flag.
    #[inline]
    pub fn set_dao_dodag_sequence(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_SEQUENCE)
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dao_dodag_id(&mut self, address: Option<Address>) {
        match address {
            Some(address) => {
                self.buffer.as_mut()[field::DAO_DODAG_ID].copy_from_slice(address.as_bytes());
                self.set_dao_dodag_id_present(true);
            }
            None => {
                self.set_dao_dodag_id_present(false);
            }
        }
    }
}

/// Getters for the Destination Advertisement Object acknowledgement (DAO-ACK) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |D|  Reserved   |  DAOSequence  |    Status     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID*                           +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Returns the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn dao_ack_dodag_id_present(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_ACK_D, shift: 7, mask: 0b1)
    }

    /// Return the DODAG sequence number.
    #[inline]
    pub fn dao_ack_sequence(&self) -> u8 {
        get!(self.buffer, field: field::DAO_ACK_SEQUENCE)
    }

    /// Return the DOA status field.
    #[inline]
    pub fn dao_ack_status(&self) -> u8 {
        get!(self.buffer, field: field::DAO_ACK_STATUS)
    }

    /// Returns the DODAG ID, an IPv6 address, when it is present.
    #[inline]
    pub fn dao_ack_dodag_id(&self) -> Option<Address> {
        if self.dao_ack_dodag_id_present() {
            Some(Address::from_bytes(
                &self.buffer.as_ref()[field::DAO_ACK_DODAG_ID],
            ))
        } else {
            None
        }
    }
}

/// Setters for the Destination Advertisement Object acknowledgement (DAO-ACK) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn set_dao_ack_dodag_id_present(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_ACK_D, shift: 7, mask: 0b1)
    }

    /// Set the DODAG sequence number.
    #[inline]
    pub fn set_dao_ack_sequence(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_ACK_SEQUENCE)
    }

    /// Set the DOA status field.
    #[inline]
    pub fn set_dao_ack_status(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_ACK_STATUS)
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dao_ack_dodag_id(&mut self, address: Option<Address>) {
        match address {
            Some(address) => {
                self.buffer.as_mut()[field::DAO_ACK_DODAG_ID].copy_from_slice(address.as_bytes());
                self.set_dao_ack_dodag_id_present(true);
            }
            None => {
                self.set_dao_ack_dodag_id_present(false);
            }
        }
    }
}

type RplOptions<'p> = heapless::Vec<options::Repr<'p>, { crate::config::RPL_MAX_OPTIONS }>;

/// A high-level representation of a RPL control packet.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'p> {
    DodagInformationSolicitation(DodagInformationSolicitation<'p>),
    DodagInformationObject(DodagInformationObject<'p>),
    DestinationAdvertisementObject(DestinationAdvertisementObject<'p>),
    DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck),
}

/// A high-level representation of a RPL DODAG Information Solicitation (DIS).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DodagInformationSolicitation<'p> {
    pub options: RplOptions<'p>,
}

/// A high-level representation of a RPL DODAG Information Object (DIO).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DodagInformationObject<'p> {
    pub rpl_instance_id: InstanceId,
    pub version_number: SequenceCounter,
    pub rank: u16,
    pub grounded: bool,
    pub mode_of_operation: ModeOfOperation,
    pub dodag_preference: u8,
    pub dtsn: SequenceCounter,
    pub dodag_id: Address,
    pub options: RplOptions<'p>,
}

/// A high-level representation of a RPL Destination Advertisement Object (DAO).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DestinationAdvertisementObject<'p> {
    pub rpl_instance_id: InstanceId,
    pub expect_ack: bool,
    pub sequence: SequenceCounter,
    pub dodag_id: Option<Address>,
    pub options: RplOptions<'p>,
}

/// A high-level representation of a RPL Destination Advertisement Object Acknowledgement
/// (DAO-ACK).
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DestinationAdvertisementObjectAck {
    pub rpl_instance_id: InstanceId,
    pub sequence: SequenceCounter,
    pub status: u8,
    pub dodag_id: Option<Address>,
}

impl core::fmt::Display for Repr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Repr::DodagInformationSolicitation { .. } => {
                write!(f, "DIS")?;
            }
            Repr::DodagInformationObject(DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                ..
            }) => {
                write!(
                    f,
                    "{rpl_instance_id:?} V={version_number} R={rank} G={grounded} \
                    MOP={mode_of_operation:?} Pref={dodag_preference} \
                    DTSN={dtsn} DODAGID={dodag_id}"
                )?;
            }
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                ..
            }) => {
                write!(
                    f,
                    "DAO IID={rpl_instance_id:?} Ack={expect_ack} Seq={sequence} \
                    DODAGID={dodag_id:?}"
                )?;
            }
            Repr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                ..
            }) => {
                write!(
                    f,
                    "DAO-ACK IID={rpl_instance_id:?} Seq={sequence} Status={status} \
                    DODAGID={dodag_id:?}"
                )?;
            }
        };

        Ok(())
    }
}

impl<'p> Repr<'p> {
    pub fn set_options(&mut self, options: RplOptions<'p>) {
        let opts = match self {
            Repr::DodagInformationSolicitation(DodagInformationSolicitation { options }) => options,
            Repr::DodagInformationObject(DodagInformationObject { options, .. }) => options,
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                options,
                ..
            }) => options,
            Repr::DestinationAdvertisementObjectAck { .. } => unreachable!(),
        };

        *opts = options;
    }

    /// Parse a RPL packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'p T>) -> Result<Self> {
        packet.check_len()?;

        let mut options = heapless::Vec::new();

        let iter = options::OptionsIterator::new(packet.options()?);
        for opt in iter {
            let opt = opt?;
            options.push(opt).unwrap();
        }

        match RplControlMessage::from(packet.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => Ok(
                Repr::DodagInformationSolicitation(DodagInformationSolicitation { options }),
            ),
            RplControlMessage::DodagInformationObject => {
                Ok(Repr::DodagInformationObject(DodagInformationObject {
                    rpl_instance_id: packet.rpl_instance_id(),
                    version_number: packet.dio_version_number().into(),
                    rank: packet.dio_rank(),
                    grounded: packet.dio_grounded(),
                    mode_of_operation: packet.dio_mode_of_operation(),
                    dodag_preference: packet.dio_dodag_preference(),
                    dtsn: packet.dio_dest_adv_trigger_seq_number().into(),
                    dodag_id: packet.dio_dodag_id(),
                    options,
                }))
            }
            RplControlMessage::DestinationAdvertisementObject => Ok(
                Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                    rpl_instance_id: packet.rpl_instance_id(),
                    expect_ack: packet.dao_ack_request(),
                    sequence: packet.dao_dodag_sequence().into(),
                    dodag_id: packet.dao_dodag_id(),
                    options,
                }),
            ),
            RplControlMessage::DestinationAdvertisementObjectAck => Ok(
                Repr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                    rpl_instance_id: packet.rpl_instance_id(),
                    sequence: packet.dao_ack_sequence().into(),
                    status: packet.dao_ack_status(),
                    dodag_id: packet.dao_ack_dodag_id(),
                }),
            ),
            RplControlMessage::SecureDodagInformationSolicitation
            | RplControlMessage::SecureDodagInformationObject
            | RplControlMessage::SecureDestinationAdvertisementObject
            | RplControlMessage::SecureDestinationAdvertisementObjectAck
            | RplControlMessage::ConsistencyCheck => Err(Error),
            RplControlMessage::Unknown(_) => Err(Error),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    /// The length also contains the lengths of the emitted options.
    pub fn buffer_len(&self) -> usize {
        let mut len = 4 + match self {
            Repr::DodagInformationSolicitation { .. } => 2,
            Repr::DodagInformationObject { .. } => 24,
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                dodag_id,
                ..
            }) => {
                if dodag_id.is_some() {
                    20
                } else {
                    4
                }
            }
            Repr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                dodag_id,
                ..
            }) => {
                if dodag_id.is_some() {
                    20
                } else {
                    4
                }
            }
        };

        let opts = match self {
            Repr::DodagInformationSolicitation(DodagInformationSolicitation { options }) => {
                &options[..]
            }
            Repr::DodagInformationObject(DodagInformationObject { options, .. }) => &options[..],
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                options,
                ..
            }) => &options[..],
            Repr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                ..
            }) => &[],
        };

        len += opts.iter().map(|o| o.buffer_len()).sum::<usize>();

        len
    }

    /// Emit a high-level representation into an RPL packet. This also emits the options the
    /// high-level representation contains.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&mut T>) {
        packet.set_msg_type(crate::wire::icmpv6::Message::RplControl);

        match self {
            Repr::DodagInformationSolicitation { .. } => {
                packet.set_msg_code(RplControlMessage::DodagInformationSolicitation.into());
                packet.clear_dis_flags();
                packet.clear_dis_reserved();
            }
            Repr::DodagInformationObject(DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                ..
            }) => {
                packet.set_msg_code(RplControlMessage::DodagInformationObject.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dio_version_number(version_number.value());
                packet.set_dio_rank(*rank);
                packet.set_dio_grounded(*grounded);
                packet.set_dio_mode_of_operation(*mode_of_operation);
                packet.set_dio_dodag_preference(*dodag_preference);
                packet.set_dio_dest_adv_trigger_seq_number(dtsn.value());
                packet.set_dio_dodag_id(*dodag_id);
            }
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                ..
            }) => {
                packet.set_msg_code(RplControlMessage::DestinationAdvertisementObject.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dao_ack_request(*expect_ack);
                packet.set_dao_dodag_sequence(sequence.value());
                packet.set_dao_dodag_id(*dodag_id);
            }
            Repr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                ..
            }) => {
                packet.set_msg_code(RplControlMessage::DestinationAdvertisementObjectAck.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dao_ack_sequence(sequence.value());
                packet.set_dao_ack_status(*status);
                packet.set_dao_ack_dodag_id(*dodag_id);
            }
        }

        let options = match self {
            Repr::DodagInformationSolicitation(DodagInformationSolicitation { options }) => {
                &options[..]
            }
            Repr::DodagInformationObject(DodagInformationObject { options, .. }) => &options[..],
            Repr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                options,
                ..
            }) => &options[..],
            Repr::DestinationAdvertisementObjectAck { .. } => &[],
        };

        let mut buffer = packet.options_mut();
        for opt in options {
            let len = opt.buffer_len();
            opt.emit(&mut options::Packet::new_unchecked(&mut buffer[..len]));
            buffer = &mut buffer[len..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::options::{
        DodagConfiguration, Packet as OptionPacket, PrefixInformation, Repr as OptionRepr,
    };
    use super::Repr as RplRepr;
    use super::*;
    use crate::phy::ChecksumCapabilities;
    use crate::wire::rpl::options::TransitInformation;
    use crate::wire::{icmpv6::*, *};

    #[test]
    fn dis_packet() {
        let data = [0x7a, 0x3b, 0x3a, 0x1a, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00];

        let ll_src_address =
            Ieee802154Address::Extended([0x9e, 0xd3, 0xa2, 0x9c, 0x57, 0x1a, 0x4f, 0xe4]);
        let ll_dst_address = Ieee802154Address::Short([0xff, 0xff]);

        let packet = SixlowpanIphcPacket::new_checked(&data).unwrap();
        let repr =
            SixlowpanIphcRepr::parse(&packet, Some(ll_src_address), Some(ll_dst_address), &[])
                .unwrap();

        let icmp_repr = match repr.next_header {
            SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                let icmp_packet = Icmpv6Packet::new_checked(packet.payload()).unwrap();
                match Icmpv6Repr::parse(
                    &repr.src_addr,
                    &repr.dst_addr,
                    &icmp_packet,
                    &ChecksumCapabilities::ignored(),
                ) {
                    Ok(icmp @ Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation { .. })) => {
                        icmp
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        };

        // We also try to emit the packet:
        let mut buffer = vec![0u8; repr.buffer_len() + icmp_repr.buffer_len()];
        repr.emit(&mut SixlowpanIphcPacket::new_unchecked(
            &mut buffer[..repr.buffer_len()],
        ));
        icmp_repr.emit(
            &repr.src_addr.into(),
            &repr.dst_addr.into(),
            &mut Icmpv6Packet::new_unchecked(
                &mut buffer[repr.buffer_len()..][..icmp_repr.buffer_len()],
            ),
            &ChecksumCapabilities::ignored(),
        );

        assert_eq!(&data[..], &buffer[..]);
    }

    /// Parsing of DIO packets.
    #[test]
    fn dio_packet() {
        let data = [
            0x9b, 0x01, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x80, 0x08, 0xf0, 0x00, 0x00, 0xfd, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x04, 0x0e, 0x00, 0x08, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x01, 0x00, 0x1e,
            0x00, 0x3c, 0x08, 0x1e, 0x40, 0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let addr = Address::from_bytes(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01,
        ]);

        let dest_prefix = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let packet = Packet::new_checked(&data[..]).unwrap();
        assert_eq!(packet.msg_type(), Message::RplControl);
        assert_eq!(
            RplControlMessage::from(packet.msg_code()),
            RplControlMessage::DodagInformationObject
        );

        let mut dio_repr = RplRepr::parse(&packet).unwrap();
        match dio_repr {
            RplRepr::DodagInformationObject(DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                ..
            }) => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert_eq!(version_number, 240.into());
                assert_eq!(rank, 128);
                assert!(!grounded);
                assert_eq!(mode_of_operation, ModeOfOperation::NonStoringMode);
                assert_eq!(dodag_preference, 0);
                assert_eq!(dtsn, 240.into());
                assert_eq!(dodag_id, addr);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(packet.options().unwrap());
        let dodag_conf_option = OptionRepr::parse(&option).unwrap();
        match dodag_conf_option {
            OptionRepr::DodagConfiguration(DodagConfiguration {
                authentication_enabled,
                path_control_size,
                dio_interval_doublings,
                dio_interval_min,
                dio_redundancy_constant,
                max_rank_increase,
                minimum_hop_rank_increase,
                objective_code_point,
                default_lifetime,
                lifetime_unit,
            }) => {
                assert!(!authentication_enabled);
                assert_eq!(path_control_size, 0);
                assert_eq!(dio_interval_doublings, 8);
                assert_eq!(dio_interval_min, 12);
                assert_eq!(dio_redundancy_constant, 0);
                assert_eq!(max_rank_increase, 1024);
                assert_eq!(minimum_hop_rank_increase, 128);
                assert_eq!(objective_code_point, 1);
                assert_eq!(default_lifetime, 30);
                assert_eq!(lifetime_unit, 60);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(option.next_option().unwrap());
        let prefix_info_option = OptionRepr::parse(&option).unwrap();
        match prefix_info_option {
            OptionRepr::PrefixInformation(PrefixInformation {
                prefix_length,
                on_link,
                autonomous_address_configuration,
                valid_lifetime,
                preferred_lifetime,
                destination_prefix,
                ..
            }) => {
                assert_eq!(prefix_length, 64);
                assert!(!on_link);
                assert!(autonomous_address_configuration);
                assert_eq!(valid_lifetime, u32::MAX);
                assert_eq!(preferred_lifetime, u32::MAX);
                assert_eq!(destination_prefix, &dest_prefix[..]);
            }
            _ => unreachable!(),
        }

        let mut options = heapless::Vec::new();
        options.push(dodag_conf_option).unwrap();
        options.push(prefix_info_option).unwrap();
        dio_repr.set_options(options);

        let mut buffer = vec![0u8; dio_repr.buffer_len()];
        dio_repr.emit(&mut Packet::new_unchecked(&mut buffer[..]));

        assert_eq!(&data[..], &buffer[..]);
    }

    /// Parsing of DAO packets.
    #[test]
    fn dao_packet() {
        let data = [
            0x9b, 0x02, 0x00, 0x00, 0x00, 0x80, 0x00, 0xf1, 0x05, 0x12, 0x00, 0x80, 0xfd, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
            0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        ];

        let target_prefix = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02,
            0x00, 0x02,
        ];

        let parent_addr = Address::from_bytes(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01,
        ]);

        let packet = Packet::new_checked(&data[..]).unwrap();
        let mut dao_repr = RplRepr::parse(&packet).unwrap();
        match dao_repr {
            RplRepr::DestinationAdvertisementObject(DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                ..
            }) => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert!(expect_ack);
                assert_eq!(sequence, 241.into());
                assert_eq!(dodag_id, None);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(packet.options().unwrap());

        let rpl_target_option = OptionRepr::parse(&option).unwrap();
        match rpl_target_option {
            OptionRepr::RplTarget(RplTarget {
                prefix_length,
                prefix,
            }) => {
                assert_eq!(prefix_length, 128);
                assert_eq!(prefix.as_bytes(), &target_prefix[..]);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(option.next_option().unwrap());
        let transit_info_option = OptionRepr::parse(&option).unwrap();
        match transit_info_option {
            OptionRepr::TransitInformation(TransitInformation {
                external,
                path_control,
                path_sequence,
                path_lifetime,
                parent_address,
            }) => {
                assert!(!external);
                assert_eq!(path_control, 0);
                assert_eq!(path_sequence, 0);
                assert_eq!(path_lifetime, 30);
                assert_eq!(parent_address, Some(parent_addr));
            }
            _ => unreachable!(),
        }

        let mut options = heapless::Vec::new();
        options.push(rpl_target_option).unwrap();
        options.push(transit_info_option).unwrap();
        dao_repr.set_options(options);

        let mut buffer = vec![0u8; dao_repr.buffer_len()];
        dao_repr.emit(&mut Packet::new_unchecked(&mut buffer[..]));

        assert_eq!(&data[..], &buffer[..]);
    }

    /// Parsing of DAO-ACK packets.
    #[test]
    fn dao_ack_packet() {
        let data = [0x9b, 0x03, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x00];

        let packet = Packet::new_checked(&data[..]).unwrap();
        let dao_ack_repr = RplRepr::parse(&packet).unwrap();
        match dao_ack_repr {
            RplRepr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                ..
            }) => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert_eq!(sequence, 241.into());
                assert_eq!(status, 0);
                assert_eq!(dodag_id, None);
            }
            _ => unreachable!(),
        }

        let mut buffer = vec![0u8; dao_ack_repr.buffer_len()];
        dao_ack_repr.emit(&mut Packet::new_unchecked(&mut buffer[..]));

        assert_eq!(&data[..], &buffer[..]);

        let data = [
            0x9b, 0x03, 0x0, 0x0, 0x1e, 0x80, 0xf0, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let packet = Packet::new_checked(&data[..]).unwrap();
        let dao_ack_repr = RplRepr::parse(&packet).unwrap();
        match dao_ack_repr {
            RplRepr::DestinationAdvertisementObjectAck(DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                ..
            }) => {
                assert_eq!(rpl_instance_id, InstanceId::from(30));
                assert_eq!(sequence, 240.into());
                assert_eq!(status, 0x0);
                assert_eq!(
                    dodag_id,
                    Some(Ipv6Address([
                        254, 128, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1
                    ]))
                );
            }
            _ => unreachable!(),
        }

        let mut buffer = vec![0u8; dao_ack_repr.buffer_len()];
        dao_ack_repr.emit(&mut Packet::new_unchecked(&mut buffer[..]));

        assert_eq!(&data[..], &buffer[..]);
    }
}
