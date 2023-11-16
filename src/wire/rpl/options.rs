use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, InstanceId, Result, SequenceCounter};
use crate::wire::ipv6::Address;

/// A read/write wrapper around a RPL Control Message Option.
#[derive(Debug, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

enum_with_unknown! {
    pub enum OptionType(u8) {
        Pad1 = 0x00,
        PadN = 0x01,
        DagMetricContainer = 0x02,
        RouteInformation = 0x03,
        DodagConfiguration = 0x04,
        RplTarget = 0x05,
        TransitInformation = 0x06,
        SolicitedInformation = 0x07,
        PrefixInformation = 0x08,
        RplTargetDescriptor = 0x09,
    }
}

impl From<&Repr<'_>> for OptionType {
    fn from(repr: &Repr) -> Self {
        match repr {
            Repr::Pad1 => Self::Pad1,
            Repr::PadN(_) => Self::PadN,
            Repr::DagMetricContainer => Self::DagMetricContainer,
            Repr::RouteInformation { .. } => Self::RouteInformation,
            Repr::DodagConfiguration { .. } => Self::DodagConfiguration,
            Repr::RplTarget { .. } => Self::RplTarget,
            Repr::TransitInformation { .. } => Self::TransitInformation,
            Repr::SolicitedInformation { .. } => Self::SolicitedInformation,
            Repr::PrefixInformation { .. } => Self::PrefixInformation,
            Repr::RplTargetDescriptor { .. } => Self::RplTargetDescriptor,
        }
    }
}

mod field {
    use crate::wire::field::*;

    // Generic fields.
    pub const TYPE: usize = 0;
    pub const LENGTH: usize = 1;

    pub const PADN: Rest = 2..;

    // Route Information fields.
    pub const ROUTE_INFO_PREFIX_LENGTH: usize = 2;
    pub const ROUTE_INFO_RESERVED: usize = 3;
    pub const ROUTE_INFO_PREFERENCE: usize = 3;
    pub const ROUTE_INFO_LIFETIME: Field = 4..9;

    // DODAG Configuration fields.
    pub const DODAG_CONF_FLAGS: usize = 2;
    pub const DODAG_CONF_AUTHENTICATION_ENABLED: usize = 2;
    pub const DODAG_CONF_PATH_CONTROL_SIZE: usize = 2;
    pub const DODAG_CONF_DIO_INTERVAL_DOUBLINGS: usize = 3;
    pub const DODAG_CONF_DIO_INTERVAL_MINIMUM: usize = 4;
    pub const DODAG_CONF_DIO_REDUNDANCY_CONSTANT: usize = 5;
    pub const DODAG_CONF_DIO_MAX_RANK_INCREASE: Field = 6..8;
    pub const DODAG_CONF_MIN_HOP_RANK_INCREASE: Field = 8..10;
    pub const DODAG_CONF_OBJECTIVE_CODE_POINT: Field = 10..12;
    pub const DODAG_CONF_DEFAULT_LIFETIME: usize = 13;
    pub const DODAG_CONF_LIFETIME_UNIT: Field = 14..16;

    // RPL Target fields.
    pub const RPL_TARGET_FLAGS: usize = 2;
    pub const RPL_TARGET_PREFIX_LENGTH: usize = 3;

    // Transit Information fields.
    pub const TRANSIT_INFO_FLAGS: usize = 2;
    pub const TRANSIT_INFO_EXTERNAL: usize = 2;
    pub const TRANSIT_INFO_PATH_CONTROL: usize = 3;
    pub const TRANSIT_INFO_PATH_SEQUENCE: usize = 4;
    pub const TRANSIT_INFO_PATH_LIFETIME: usize = 5;
    pub const TRANSIT_INFO_PARENT_ADDRESS: Field = 6..6 + 16;

    // Solicited Information fields.
    pub const SOLICITED_INFO_RPL_INSTANCE_ID: usize = 2;
    pub const SOLICITED_INFO_FLAGS: usize = 3;
    pub const SOLICITED_INFO_VERSION_PREDICATE: usize = 3;
    pub const SOLICITED_INFO_INSTANCE_ID_PREDICATE: usize = 3;
    pub const SOLICITED_INFO_DODAG_ID_PREDICATE: usize = 3;
    pub const SOLICITED_INFO_DODAG_ID: Field = 4..20;
    pub const SOLICITED_INFO_VERSION_NUMBER: usize = 20;

    // Prefix Information fields.
    pub const PREFIX_INFO_PREFIX_LENGTH: usize = 2;
    pub const PREFIX_INFO_RESERVED1: usize = 3;
    pub const PREFIX_INFO_ON_LINK: usize = 3;
    pub const PREFIX_INFO_AUTONOMOUS_CONF: usize = 3;
    pub const PREFIX_INFO_ROUTER_ADDRESS_FLAG: usize = 3;
    pub const PREFIX_INFO_VALID_LIFETIME: Field = 4..8;
    pub const PREFIX_INFO_PREFERRED_LIFETIME: Field = 8..12;
    pub const PREFIX_INFO_RESERVED2: Field = 12..16;
    pub const PREFIX_INFO_PREFIX: Field = 16..16 + 16;

    // RPL Target Descriptor fields.
    pub const TARGET_DESCRIPTOR: Field = 2..6;
}

/// Getters for the RPL Control Message Options.
impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with RPL Control Message Option structure.
    #[inline]
    pub fn new_unchecked(buffer: T) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_checked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().is_empty() {
            return Err(Error);
        }

        Ok(())
    }

    /// Return the type field.
    #[inline]
    pub fn option_type(&self) -> OptionType {
        OptionType::from(self.buffer.as_ref()[field::TYPE])
    }

    /// Return the length field.
    #[inline]
    pub fn option_length(&self) -> u8 {
        get!(self.buffer, field: field::LENGTH)
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return a pointer to the next option.
    #[inline]
    pub fn next_option(&self) -> Option<&'p [u8]> {
        if !self.buffer.as_ref().is_empty() {
            match self.option_type() {
                OptionType::Pad1 => Some(&self.buffer.as_ref()[1..]),
                OptionType::Unknown(_) => unreachable!(),
                _ => {
                    let len = self.option_length();
                    Some(&self.buffer.as_ref()[2 + len as usize..])
                }
            }
        } else {
            None
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Option Type field.
    #[inline]
    pub fn set_option_type(&mut self, option_type: OptionType) {
        self.buffer.as_mut()[field::TYPE] = option_type.into();
    }

    /// Set the Option Length field.
    #[inline]
    pub fn set_option_length(&mut self, length: u8) {
        self.buffer.as_mut()[field::LENGTH] = length;
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    #[inline]
    pub fn clear_padn(&mut self, size: u8) {
        for b in &mut self.buffer.as_mut()[field::PADN][..size as usize] {
            *b = 0;
        }
    }
}

/// Getters for the Route Information Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x03 | Option Length | Prefix Length |Resvd|Prf|Resvd|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Route Lifetime                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                   Prefix (Variable Length)                    .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Prefix Length field.
    #[inline]
    pub fn prefix_length(&self) -> u8 {
        get!(self.buffer, field: field::ROUTE_INFO_PREFIX_LENGTH)
    }

    /// Return the Route Preference field.
    #[inline]
    pub fn route_preference(&self) -> u8 {
        (self.buffer.as_ref()[field::ROUTE_INFO_PREFERENCE] & 0b0001_1000) >> 3
    }

    /// Return the Route Lifetime field.
    #[inline]
    pub fn route_lifetime(&self) -> u32 {
        get!(self.buffer, u32, field: field::ROUTE_INFO_LIFETIME)
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return the Prefix field.
    #[inline]
    pub fn prefix(&self) -> &'p [u8] {
        let option_len = self.option_length();
        &self.buffer.as_ref()[field::ROUTE_INFO_LIFETIME.end..]
            [..option_len as usize - field::ROUTE_INFO_LIFETIME.end]
    }
}

/// Setters for the Route Information Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Prefix Length field.
    #[inline]
    pub fn set_route_info_prefix_length(&mut self, value: u8) {
        set!(self.buffer, value, field: field::ROUTE_INFO_PREFIX_LENGTH)
    }

    /// Set the Route Preference field.
    #[inline]
    pub fn set_route_info_route_preference(&mut self, _value: u8) {
        todo!();
    }

    /// Set the Route Lifetime field.
    #[inline]
    pub fn set_route_info_route_lifetime(&mut self, value: u32) {
        set!(self.buffer, value, u32, field: field::ROUTE_INFO_LIFETIME)
    }

    /// Set the prefix field.
    #[inline]
    pub fn set_route_info_prefix(&mut self, _prefix: &[u8]) {
        todo!();
    }

    /// Clear the reserved field.
    #[inline]
    pub fn clear_route_info_reserved(&mut self) {
        self.buffer.as_mut()[field::ROUTE_INFO_RESERVED] = 0;
    }
}

/// Getters for the DODAG Configuration Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x04 |Opt Length = 14| Flags |A| PCS | DIOIntDoubl.  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  DIOIntMin.   |   DIORedun.   |        MaxRankIncrease        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      MinHopRankIncrease       |              OCP              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Reserved    | Def. Lifetime |      Lifetime Unit            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Authentication Enabled field.
    #[inline]
    pub fn authentication_enabled(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::DODAG_CONF_AUTHENTICATION_ENABLED,
            shift: 3,
            mask: 0b1
        )
    }

    /// Return the Path Control Size field.
    #[inline]
    pub fn path_control_size(&self) -> u8 {
        get!(self.buffer, field: field::DODAG_CONF_PATH_CONTROL_SIZE, mask: 0b111)
    }

    /// Return the DIO Interval Doublings field.
    #[inline]
    pub fn dio_interval_doublings(&self) -> u8 {
        get!(self.buffer, field: field::DODAG_CONF_DIO_INTERVAL_DOUBLINGS)
    }

    /// Return the DIO Interval Minimum field.
    #[inline]
    pub fn dio_interval_minimum(&self) -> u8 {
        get!(self.buffer, field: field::DODAG_CONF_DIO_INTERVAL_MINIMUM)
    }

    /// Return the DIO Redundancy Constant field.
    #[inline]
    pub fn dio_redundancy_constant(&self) -> u8 {
        get!(
            self.buffer,
            field: field::DODAG_CONF_DIO_REDUNDANCY_CONSTANT
        )
    }

    /// Return the Max Rank Increase field.
    #[inline]
    pub fn max_rank_increase(&self) -> u16 {
        get!(
            self.buffer,
            u16,
            field: field::DODAG_CONF_DIO_MAX_RANK_INCREASE
        )
    }

    /// Return the Minimum Hop Rank Increase field.
    #[inline]
    pub fn minimum_hop_rank_increase(&self) -> u16 {
        get!(
            self.buffer,
            u16,
            field: field::DODAG_CONF_MIN_HOP_RANK_INCREASE
        )
    }

    /// Return the Objective Code Point field.
    #[inline]
    pub fn objective_code_point(&self) -> u16 {
        get!(
            self.buffer,
            u16,
            field: field::DODAG_CONF_OBJECTIVE_CODE_POINT
        )
    }

    /// Return the Default Lifetime field.
    #[inline]
    pub fn default_lifetime(&self) -> u8 {
        get!(self.buffer, field: field::DODAG_CONF_DEFAULT_LIFETIME)
    }

    /// Return the Lifetime Unit field.
    #[inline]
    pub fn lifetime_unit(&self) -> u16 {
        get!(self.buffer, u16, field: field::DODAG_CONF_LIFETIME_UNIT)
    }
}

/// Getters for the DODAG Configuration Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the Flags field.
    #[inline]
    pub fn clear_dodag_conf_flags(&mut self) {
        self.buffer.as_mut()[field::DODAG_CONF_FLAGS] = 0;
    }

    /// Set the Authentication Enabled field.
    #[inline]
    pub fn set_dodag_conf_authentication_enabled(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::DODAG_CONF_AUTHENTICATION_ENABLED,
            shift: 3,
            mask: 0b1
        )
    }

    /// Set the Path Control Size field.
    #[inline]
    pub fn set_dodag_conf_path_control_size(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::DODAG_CONF_PATH_CONTROL_SIZE,
            mask: 0b111
        )
    }

    /// Set the DIO Interval Doublings field.
    #[inline]
    pub fn set_dodag_conf_dio_interval_doublings(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::DODAG_CONF_DIO_INTERVAL_DOUBLINGS
        )
    }

    /// Set the DIO Interval Minimum field.
    #[inline]
    pub fn set_dodag_conf_dio_interval_minimum(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::DODAG_CONF_DIO_INTERVAL_MINIMUM
        )
    }

    /// Set the DIO Redundancy Constant field.
    #[inline]
    pub fn set_dodag_conf_dio_redundancy_constant(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::DODAG_CONF_DIO_REDUNDANCY_CONSTANT
        )
    }

    /// Set the Max Rank Increase field.
    #[inline]
    pub fn set_dodag_conf_max_rank_increase(&mut self, value: u16) {
        set!(
            self.buffer,
            value,
            u16,
            field: field::DODAG_CONF_DIO_MAX_RANK_INCREASE
        )
    }

    /// Set the Minimum Hop Rank Increase field.
    #[inline]
    pub fn set_dodag_conf_minimum_hop_rank_increase(&mut self, value: u16) {
        set!(
            self.buffer,
            value,
            u16,
            field: field::DODAG_CONF_MIN_HOP_RANK_INCREASE
        )
    }

    /// Set the Objective Code Point field.
    #[inline]
    pub fn set_dodag_conf_objective_code_point(&mut self, value: u16) {
        set!(
            self.buffer,
            value,
            u16,
            field: field::DODAG_CONF_OBJECTIVE_CODE_POINT
        )
    }

    /// Set the Default Lifetime field.
    #[inline]
    pub fn set_dodag_conf_default_lifetime(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::DODAG_CONF_DEFAULT_LIFETIME
        )
    }

    /// Set the Lifetime Unit field.
    #[inline]
    pub fn set_dodag_conf_lifetime_unit(&mut self, value: u16) {
        set!(
            self.buffer,
            value,
            u16,
            field: field::DODAG_CONF_LIFETIME_UNIT
        )
    }
}

/// Getters for the RPL Target Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x05 | Option Length |     Flags     | Prefix Length |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                Target Prefix (Variable Length)                |
/// .                                                               .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Target Prefix Length field.
    pub fn target_prefix_length(&self) -> u8 {
        get!(self.buffer, field: field::RPL_TARGET_PREFIX_LENGTH)
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return the Target Prefix field.
    #[inline]
    pub fn target_prefix(&self) -> &'p [u8] {
        let option_len = self.option_length();
        &self.buffer.as_ref()[field::RPL_TARGET_PREFIX_LENGTH + 1..]
            [..option_len as usize - field::RPL_TARGET_PREFIX_LENGTH + 1]
    }
}

/// Setters for the RPL Target Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the Flags field.
    #[inline]
    pub fn clear_rpl_target_flags(&mut self) {
        self.buffer.as_mut()[field::RPL_TARGET_FLAGS] = 0;
    }

    /// Set the Target Prefix Length field.
    #[inline]
    pub fn set_rpl_target_prefix_length(&mut self, value: u8) {
        set!(self.buffer, value, field: field::RPL_TARGET_PREFIX_LENGTH)
    }

    /// Set the Target Prefix field.
    #[inline]
    pub fn set_rpl_target_prefix(&mut self, prefix: &[u8]) {
        self.buffer.as_mut()[field::RPL_TARGET_PREFIX_LENGTH + 1..][..prefix.len()]
            .copy_from_slice(prefix);
    }
}

/// Getters for the Transit Information Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x06 | Option Length |E|    Flags    | Path Control  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Path Sequence | Path Lifetime |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                        Parent Address*                        +
/// |                                                               |
/// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the External flag.
    #[inline]
    pub fn is_external(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::TRANSIT_INFO_EXTERNAL,
            shift: 7,
            mask: 0b1,
        )
    }

    /// Return the Path Control field.
    #[inline]
    pub fn path_control(&self) -> u8 {
        get!(self.buffer, field: field::TRANSIT_INFO_PATH_CONTROL)
    }

    /// Return the Path Sequence field.
    #[inline]
    pub fn path_sequence(&self) -> u8 {
        get!(self.buffer, field: field::TRANSIT_INFO_PATH_SEQUENCE)
    }

    /// Return the Path Lifetime field.
    #[inline]
    pub fn path_lifetime(&self) -> u8 {
        get!(self.buffer, field: field::TRANSIT_INFO_PATH_LIFETIME)
    }

    /// Return the Parent Address field.
    #[inline]
    pub fn parent_address(&self) -> Option<Address> {
        if self.option_length() > 5 {
            Some(Address::from_bytes(
                &self.buffer.as_ref()[field::TRANSIT_INFO_PARENT_ADDRESS],
            ))
        } else {
            None
        }
    }
}

/// Setters for the Transit Information Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the Flags field.
    #[inline]
    pub fn clear_transit_info_flags(&mut self) {
        self.buffer.as_mut()[field::TRANSIT_INFO_FLAGS] = 0;
    }

    /// Set the External flag.
    #[inline]
    pub fn set_transit_info_is_external(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::TRANSIT_INFO_EXTERNAL,
            shift: 7,
            mask: 0b1
        )
    }

    /// Set the Path Control field.
    #[inline]
    pub fn set_transit_info_path_control(&mut self, value: u8) {
        set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_CONTROL)
    }

    /// Set the Path Sequence field.
    #[inline]
    pub fn set_transit_info_path_sequence(&mut self, value: u8) {
        set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_SEQUENCE)
    }

    /// Set the Path Lifetime field.
    #[inline]
    pub fn set_transit_info_path_lifetime(&mut self, value: u8) {
        set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_LIFETIME)
    }

    /// Set the Parent Address field.
    #[inline]
    pub fn set_transit_info_parent_address(&mut self, address: Address) {
        self.buffer.as_mut()[field::TRANSIT_INFO_PARENT_ADDRESS]
            .copy_from_slice(address.as_bytes());
    }
}

/// Getters for the Solicited Information Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x07 |Opt Length = 19| RPLInstanceID |V|I|D|  Flags  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID                            +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version Number |
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the RPL Instance ID field.
    #[inline]
    pub fn rpl_instance_id(&self) -> u8 {
        get!(self.buffer, field: field::SOLICITED_INFO_RPL_INSTANCE_ID)
    }

    /// Return the Version Predicate flag.
    #[inline]
    pub fn version_predicate(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::SOLICITED_INFO_VERSION_PREDICATE,
            shift: 7,
            mask: 0b1,
        )
    }

    /// Return the Instance ID Predicate flag.
    #[inline]
    pub fn instance_id_predicate(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::SOLICITED_INFO_INSTANCE_ID_PREDICATE,
            shift: 6,
            mask: 0b1,
        )
    }

    /// Return the DODAG Predicate ID flag.
    #[inline]
    pub fn dodag_id_predicate(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::SOLICITED_INFO_DODAG_ID_PREDICATE,
            shift: 5,
            mask: 0b1,
        )
    }

    /// Return the DODAG ID field.
    #[inline]
    pub fn dodag_id(&self) -> Address {
        get!(
            self.buffer,
            into: Address,
            fun: from_bytes,
            field: field::SOLICITED_INFO_DODAG_ID
        )
    }

    /// Return the Version Number field.
    #[inline]
    pub fn version_number(&self) -> u8 {
        get!(self.buffer, field: field::SOLICITED_INFO_VERSION_NUMBER)
    }
}

/// Setters for the Solicited Information Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the Flags field.
    #[inline]
    pub fn clear_solicited_info_flags(&mut self) {
        self.buffer.as_mut()[field::SOLICITED_INFO_FLAGS] = 0;
    }

    /// Set the RPL Instance ID field.
    #[inline]
    pub fn set_solicited_info_rpl_instance_id(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::SOLICITED_INFO_RPL_INSTANCE_ID
        )
    }

    /// Set the Version Predicate flag.
    #[inline]
    pub fn set_solicited_info_version_predicate(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::SOLICITED_INFO_VERSION_PREDICATE,
            shift: 7,
            mask: 0b1
        )
    }

    /// Set the Instance ID Predicate flag.
    #[inline]
    pub fn set_solicited_info_instance_id_predicate(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::SOLICITED_INFO_INSTANCE_ID_PREDICATE,
            shift: 6,
            mask: 0b1
        )
    }

    /// Set the DODAG Predicate ID flag.
    #[inline]
    pub fn set_solicited_info_dodag_id_predicate(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::SOLICITED_INFO_DODAG_ID_PREDICATE,
            shift: 5,
            mask: 0b1
        )
    }

    /// Set the DODAG ID field.
    #[inline]
    pub fn set_solicited_info_dodag_id(&mut self, address: Address) {
        set!(
            self.buffer,
            address: address,
            field: field::SOLICITED_INFO_DODAG_ID
        )
    }

    /// Set the Version Number field.
    #[inline]
    pub fn set_solicited_info_version_number(&mut self, value: u8) {
        set!(
            self.buffer,
            value,
            field: field::SOLICITED_INFO_VERSION_NUMBER
        )
    }
}

/// Getters for the Prefix Information Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x08 |Opt Length = 30| Prefix Length |L|A|R|Reserved1|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Valid Lifetime                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Preferred Lifetime                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved2                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            Prefix                             +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Prefix Length field.
    #[inline]
    pub fn prefix_info_prefix_length(&self) -> u8 {
        get!(self.buffer, field: field::PREFIX_INFO_PREFIX_LENGTH)
    }

    /// Return the On-Link flag.
    #[inline]
    pub fn on_link(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::PREFIX_INFO_ON_LINK,
            shift: 7,
            mask: 0b1,
        )
    }

    /// Return the Autonomous Address-Configuration flag.
    #[inline]
    pub fn autonomous_address_configuration(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::PREFIX_INFO_AUTONOMOUS_CONF,
            shift: 6,
            mask: 0b1,
        )
    }

    /// Return the Router Address flag.
    #[inline]
    pub fn router_address(&self) -> bool {
        get!(
            self.buffer,
            bool,
            field: field::PREFIX_INFO_ROUTER_ADDRESS_FLAG,
            shift: 5,
            mask: 0b1,
        )
    }

    /// Return the Valid Lifetime field.
    #[inline]
    pub fn valid_lifetime(&self) -> u32 {
        get!(self.buffer, u32, field: field::PREFIX_INFO_VALID_LIFETIME)
    }

    /// Return the Preferred Lifetime field.
    #[inline]
    pub fn preferred_lifetime(&self) -> u32 {
        get!(
            self.buffer,
            u32,
            field: field::PREFIX_INFO_PREFERRED_LIFETIME
        )
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return the Prefix field.
    #[inline]
    pub fn destination_prefix(&self) -> &'p [u8] {
        &self.buffer.as_ref()[field::PREFIX_INFO_PREFIX]
    }
}

/// Setters for the Prefix Information Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the reserved fields.
    #[inline]
    pub fn clear_prefix_info_reserved(&mut self) {
        self.buffer.as_mut()[field::PREFIX_INFO_RESERVED1] = 0;
        self.buffer.as_mut()[field::PREFIX_INFO_RESERVED2].copy_from_slice(&[0; 4]);
    }

    /// Set the Prefix Length field.
    #[inline]
    pub fn set_prefix_info_prefix_length(&mut self, value: u8) {
        set!(self.buffer, value, field: field::PREFIX_INFO_PREFIX_LENGTH)
    }

    /// Set the On-Link flag.
    #[inline]
    pub fn set_prefix_info_on_link(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::PREFIX_INFO_ON_LINK, shift: 7, mask: 0b1)
    }

    /// Set the Autonomous Address-Configuration flag.
    #[inline]
    pub fn set_prefix_info_autonomous_address_configuration(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::PREFIX_INFO_AUTONOMOUS_CONF,
            shift: 6,
            mask: 0b1
        )
    }

    /// Set the Router Address flag.
    #[inline]
    pub fn set_prefix_info_router_address(&mut self, value: bool) {
        set!(
            self.buffer,
            value,
            bool,
            field: field::PREFIX_INFO_ROUTER_ADDRESS_FLAG,
            shift: 5,
            mask: 0b1
        )
    }

    /// Set the Valid Lifetime field.
    #[inline]
    pub fn set_prefix_info_valid_lifetime(&mut self, value: u32) {
        set!(
            self.buffer,
            value,
            u32,
            field: field::PREFIX_INFO_VALID_LIFETIME
        )
    }

    /// Set the Preferred Lifetime field.
    #[inline]
    pub fn set_prefix_info_preferred_lifetime(&mut self, value: u32) {
        set!(
            self.buffer,
            value,
            u32,
            field: field::PREFIX_INFO_PREFERRED_LIFETIME
        )
    }

    /// Set the Prefix field.
    #[inline]
    pub fn set_prefix_info_destination_prefix(&mut self, prefix: &[u8]) {
        self.buffer.as_mut()[field::PREFIX_INFO_PREFIX].copy_from_slice(prefix);
    }
}

/// Getters for the RPL Target Descriptor Option Message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x09 |Opt Length = 4 |           Descriptor
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        Descriptor (cont.)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Descriptor field.
    #[inline]
    pub fn descriptor(&self) -> u32 {
        get!(self.buffer, u32, field: field::TARGET_DESCRIPTOR)
    }
}

/// Setters for the RPL Target Descriptor Option Message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Descriptor field.
    #[inline]
    pub fn set_rpl_target_descriptor_descriptor(&mut self, value: u32) {
        set!(self.buffer, value, u32, field: field::TARGET_DESCRIPTOR)
    }
}

/// A high-level representation of a RPL Option.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'p> {
    Pad1,
    PadN(u8),
    DagMetricContainer,
    RouteInformation(RouteInformation<'p>),
    DodagConfiguration(DodagConfiguration),
    RplTarget(RplTarget),
    TransitInformation(TransitInformation),
    SolicitedInformation(SolicitedInformation),
    PrefixInformation(PrefixInformation<'p>),
    RplTargetDescriptor(u32),
}

/// A high-level representation of a RPL Route Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteInformation<'p> {
    pub prefix_length: u8,
    pub preference: u8,
    pub lifetime: u32,
    pub prefix: &'p [u8],
}

/// A high-level representation of a RPL DODAG Configuration Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DodagConfiguration {
    pub authentication_enabled: bool,
    pub path_control_size: u8,
    pub dio_interval_doublings: u8,
    pub dio_interval_min: u8,
    pub dio_redundancy_constant: u8,
    pub max_rank_increase: u16,
    pub minimum_hop_rank_increase: u16,
    pub objective_code_point: u16,
    pub default_lifetime: u8,
    pub lifetime_unit: u16,
}

/// A high-level representation of a RPL Target Option.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RplTarget {
    pub prefix_length: u8,
    pub prefix: heapless::Vec<u8, 16>,
}

/// A high-level representation of a RPL Transit Information Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TransitInformation {
    pub external: bool,
    pub path_control: u8,
    pub path_sequence: u8,
    pub path_lifetime: u8,
    pub parent_address: Option<Address>,
}

/// A high-level representation of a RPL Solicited Information Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SolicitedInformation {
    pub rpl_instance_id: InstanceId,
    pub version_predicate: bool,
    pub instance_id_predicate: bool,
    pub dodag_id_predicate: bool,
    pub dodag_id: Address,
    pub version_number: SequenceCounter,
}

/// A high-level representation of a RPL Prefix Information Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrefixInformation<'p> {
    pub prefix_length: u8,
    pub on_link: bool,
    pub autonomous_address_configuration: bool,
    pub router_address: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub destination_prefix: &'p [u8],
}

impl core::fmt::Display for Repr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Repr::Pad1 => write!(f, "Pad1"),
            Repr::PadN(n) => write!(f, "PadN({n})"),
            Repr::DagMetricContainer => todo!(),
            Repr::RouteInformation(RouteInformation {
                prefix_length,
                preference,
                lifetime,
                prefix,
            }) => {
                write!(
                    f,
                    "ROUTE INFO PrefixLength={prefix_length} Preference={preference} \
                    Lifetime={lifetime} Prefix={prefix:0x?}"
                )
            }
            Repr::DodagConfiguration(DodagConfiguration {
                dio_interval_doublings,
                dio_interval_min,
                dio_redundancy_constant,
                max_rank_increase,
                minimum_hop_rank_increase,
                objective_code_point,
                default_lifetime,
                lifetime_unit,
                ..
            }) => {
                write!(
                    f,
                    "DODAG CONF IntD={dio_interval_doublings} IntMin={dio_interval_min} \
                    RedCst={dio_redundancy_constant} MaxRankIncr={max_rank_increase} \
                    MinHopRankIncr={minimum_hop_rank_increase} OCP={objective_code_point} \
                    DefaultLifetime={default_lifetime} LifeUnit={lifetime_unit}"
                )
            }
            Repr::RplTarget(RplTarget {
                prefix_length,
                prefix,
            }) => {
                write!(
                    f,
                    "RPL Target PrefixLength={prefix_length} Prefix={prefix:0x?}"
                )
            }
            Repr::TransitInformation(TransitInformation {
                external,
                path_control,
                path_sequence,
                path_lifetime,
                parent_address,
            }) => {
                write!(
                    f,
                    "Transit Info External={external} PathCtrl={path_control} \
                    PathSqnc={path_sequence} PathLifetime={path_lifetime} \
                    Parent={parent_address:0x?}"
                )
            }
            Repr::SolicitedInformation(SolicitedInformation {
                rpl_instance_id,
                version_predicate,
                instance_id_predicate,
                dodag_id_predicate,
                dodag_id,
                version_number,
            }) => {
                write!(
                    f,
                    "Solicited Info I={instance_id_predicate} IID={rpl_instance_id:0x?} \
                    D={dodag_id_predicate} DODAGID={dodag_id} V={version_predicate} \
                    Version={version_number}"
                )
            }
            Repr::PrefixInformation(PrefixInformation {
                prefix_length,
                on_link,
                autonomous_address_configuration,
                router_address,
                valid_lifetime,
                preferred_lifetime,
                destination_prefix,
            }) => {
                write!(
                    f,
                    "Prefix Info PrefixLength={prefix_length} L={on_link} \
                    A={autonomous_address_configuration} R={router_address} \
                    Valid={valid_lifetime} Prefered={preferred_lifetime} \
                    Prefix={destination_prefix:0x?}"
                )
            }
            Repr::RplTargetDescriptor(_) => write!(f, "Target Descriptor"),
        }
    }
}

impl<'p> Repr<'p> {
    /// Parse a RPL Option and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'p T>) -> Result<Self> {
        match packet.option_type() {
            OptionType::Pad1 => Ok(Repr::Pad1),
            OptionType::PadN => Ok(Repr::PadN(packet.option_length())),
            OptionType::DagMetricContainer => todo!(),
            OptionType::RouteInformation => Ok(Repr::RouteInformation(RouteInformation {
                prefix_length: packet.prefix_length(),
                preference: packet.route_preference(),
                lifetime: packet.route_lifetime(),
                prefix: packet.prefix(),
            })),
            OptionType::DodagConfiguration => Ok(Repr::DodagConfiguration(DodagConfiguration {
                authentication_enabled: packet.authentication_enabled(),
                path_control_size: packet.path_control_size(),
                dio_interval_doublings: packet.dio_interval_doublings(),
                dio_interval_min: packet.dio_interval_minimum(),
                dio_redundancy_constant: packet.dio_redundancy_constant(),
                max_rank_increase: packet.max_rank_increase(),
                minimum_hop_rank_increase: packet.minimum_hop_rank_increase(),
                objective_code_point: packet.objective_code_point(),
                default_lifetime: packet.default_lifetime(),
                lifetime_unit: packet.lifetime_unit(),
            })),
            OptionType::RplTarget => Ok(Repr::RplTarget(RplTarget {
                prefix_length: packet.target_prefix_length(),
                prefix: heapless::Vec::from_slice(packet.target_prefix()).map_err(|_| Error)?,
            })),
            OptionType::TransitInformation => Ok(Repr::TransitInformation(TransitInformation {
                external: packet.is_external(),
                path_control: packet.path_control(),
                path_sequence: packet.path_sequence(),
                path_lifetime: packet.path_lifetime(),
                parent_address: packet.parent_address(),
            })),
            OptionType::SolicitedInformation => {
                Ok(Repr::SolicitedInformation(SolicitedInformation {
                    rpl_instance_id: InstanceId::from(packet.rpl_instance_id()),
                    version_predicate: packet.version_predicate(),
                    instance_id_predicate: packet.instance_id_predicate(),
                    dodag_id_predicate: packet.dodag_id_predicate(),
                    dodag_id: packet.dodag_id(),
                    version_number: packet.version_number().into(),
                }))
            }
            OptionType::PrefixInformation => Ok(Repr::PrefixInformation(PrefixInformation {
                prefix_length: packet.prefix_info_prefix_length(),
                on_link: packet.on_link(),
                autonomous_address_configuration: packet.autonomous_address_configuration(),
                router_address: packet.router_address(),
                valid_lifetime: packet.valid_lifetime(),
                preferred_lifetime: packet.preferred_lifetime(),
                destination_prefix: packet.destination_prefix(),
            })),
            OptionType::RplTargetDescriptor => Ok(Repr::RplTargetDescriptor(packet.descriptor())),
            OptionType::Unknown(_) => Err(Error),
        }
    }

    /// Return the length of an option that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            Repr::Pad1 => 1,
            Repr::PadN(size) => 2 + *size as usize,
            Repr::DagMetricContainer => todo!(),
            Repr::RouteInformation(RouteInformation { prefix, .. }) => 2 + 6 + prefix.len(),
            Repr::DodagConfiguration { .. } => 2 + 14,
            Repr::RplTarget(RplTarget { prefix, .. }) => 2 + 2 + prefix.len(),
            Repr::TransitInformation(TransitInformation { parent_address, .. }) => {
                2 + 4 + if parent_address.is_some() { 16 } else { 0 }
            }
            Repr::SolicitedInformation { .. } => 2 + 2 + 16 + 1,
            Repr::PrefixInformation { .. } => 32,
            Repr::RplTargetDescriptor { .. } => 2 + 4,
        }
    }

    /// Emit a high-level representation into an RPL Option packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&'p mut T>) {
        let mut option_length = self.buffer_len() as u8;

        packet.set_option_type(self.into());

        if !matches!(self, Repr::Pad1) {
            option_length -= 2;
            packet.set_option_length(option_length);
        }

        match self {
            Repr::Pad1 => {}
            Repr::PadN(size) => {
                packet.clear_padn(*size);
            }
            Repr::DagMetricContainer => {
                unimplemented!();
            }
            Repr::RouteInformation(RouteInformation {
                prefix_length,
                preference,
                lifetime,
                prefix,
            }) => {
                packet.clear_route_info_reserved();
                packet.set_route_info_prefix_length(*prefix_length);
                packet.set_route_info_route_preference(*preference);
                packet.set_route_info_route_lifetime(*lifetime);
                packet.set_route_info_prefix(prefix);
            }
            Repr::DodagConfiguration(DodagConfiguration {
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
                packet.clear_dodag_conf_flags();
                packet.set_dodag_conf_authentication_enabled(*authentication_enabled);
                packet.set_dodag_conf_path_control_size(*path_control_size);
                packet.set_dodag_conf_dio_interval_doublings(*dio_interval_doublings);
                packet.set_dodag_conf_dio_interval_minimum(*dio_interval_min);
                packet.set_dodag_conf_dio_redundancy_constant(*dio_redundancy_constant);
                packet.set_dodag_conf_max_rank_increase(*max_rank_increase);
                packet.set_dodag_conf_minimum_hop_rank_increase(*minimum_hop_rank_increase);
                packet.set_dodag_conf_objective_code_point(*objective_code_point);
                packet.set_dodag_conf_default_lifetime(*default_lifetime);
                packet.set_dodag_conf_lifetime_unit(*lifetime_unit);
            }
            Repr::RplTarget(RplTarget {
                prefix_length,
                prefix,
            }) => {
                packet.clear_rpl_target_flags();
                packet.set_rpl_target_prefix_length(*prefix_length);
                packet.set_rpl_target_prefix(&prefix);
            }
            Repr::TransitInformation(TransitInformation {
                external,
                path_control,
                path_sequence,
                path_lifetime,
                parent_address,
            }) => {
                packet.clear_transit_info_flags();
                packet.set_transit_info_is_external(*external);
                packet.set_transit_info_path_control(*path_control);
                packet.set_transit_info_path_sequence(*path_sequence);
                packet.set_transit_info_path_lifetime(*path_lifetime);

                if let Some(address) = parent_address {
                    packet.set_transit_info_parent_address(*address);
                }
            }
            Repr::SolicitedInformation(SolicitedInformation {
                rpl_instance_id,
                version_predicate,
                instance_id_predicate,
                dodag_id_predicate,
                dodag_id,
                version_number,
            }) => {
                packet.clear_solicited_info_flags();
                packet.set_solicited_info_rpl_instance_id((*rpl_instance_id).into());
                packet.set_solicited_info_version_predicate(*version_predicate);
                packet.set_solicited_info_instance_id_predicate(*instance_id_predicate);
                packet.set_solicited_info_dodag_id_predicate(*dodag_id_predicate);
                packet.set_solicited_info_version_number(version_number.value());
                packet.set_solicited_info_dodag_id(*dodag_id);
            }
            Repr::PrefixInformation(PrefixInformation {
                prefix_length,
                on_link,
                autonomous_address_configuration,
                router_address,
                valid_lifetime,
                preferred_lifetime,
                destination_prefix,
            }) => {
                packet.clear_prefix_info_reserved();
                packet.set_prefix_info_prefix_length(*prefix_length);
                packet.set_prefix_info_on_link(*on_link);
                packet.set_prefix_info_autonomous_address_configuration(
                    *autonomous_address_configuration,
                );
                packet.set_prefix_info_router_address(*router_address);
                packet.set_prefix_info_valid_lifetime(*valid_lifetime);
                packet.set_prefix_info_preferred_lifetime(*preferred_lifetime);
                packet.set_prefix_info_destination_prefix(destination_prefix);
            }
            Repr::RplTargetDescriptor(descriptor) => {
                packet.set_rpl_target_descriptor_descriptor(*descriptor);
            }
        }
    }
}

/// An Iterator for RPL options.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OptionsIterator<'a> {
    pos: usize,
    length: usize,
    data: &'a [u8],
    hit_error: bool,
}

impl<'a> OptionsIterator<'a> {
    /// Create a new `OptionsIterator`, used to iterate over the
    /// options contained in a RPL header.
    pub fn new(data: &'a [u8]) -> Self {
        let length = data.len();
        Self {
            pos: 0,
            hit_error: false,
            length,
            data,
        }
    }
}

impl<'a> Iterator for OptionsIterator<'a> {
    type Item = Result<Repr<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.length && !self.hit_error {
            // If we still have data to parse and we have not previously
            // hit an error, attempt to parse the next option.
            match Packet::new_checked(&self.data[self.pos..]) {
                Ok(hdr) => match Repr::parse(&hdr) {
                    Ok(repr) => {
                        self.pos += repr.buffer_len();
                        Some(Ok(repr))
                    }
                    Err(e) => {
                        self.hit_error = true;
                        Some(Err(e))
                    }
                },
                Err(e) => {
                    self.hit_error = true;
                    Some(Err(e))
                }
            }
        } else {
            // If we failed to parse a previous option or hit the end of the
            // buffer, we do not continue to iterate.
            None
        }
    }
}
