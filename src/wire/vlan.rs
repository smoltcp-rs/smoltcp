use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::ethernet::EtherType;
use super::{Error, Result};

enum_with_unknown! {
    /// Priority code point.
    pub enum Pcp(u8) {
        Bk = 1, // lowest
        Be = 0, // default
        Ee = 2,
        Ca = 3,
        Vi = 4,
        Vo = 5,
        Ic = 6,
        NC = 7, // highest
    }
}

/// A struct holding VLAN configuration parameters
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VlanConfig {
    pub inner_vlan_id: u16,
    pub outer_vlan_id: Option<u16>,
}

impl VlanConfig {
    pub fn get_additional_header_length(&self) -> usize {
        if self.outer_vlan_id.is_some() {
            2 * HEADER_LEN
        } else {
            HEADER_LEN
        }
    }

    pub(crate) fn emit_to_payload(&self, payload: &mut [u8], ethertype: EtherType) {
        let mut inner_header = if let Some(outer_vlan_id) = self.outer_vlan_id {
            let mut outer_header = Packet::new_unchecked(&mut payload[..]);
            let outer_header_repr = Repr {
                vlan_identifier: outer_vlan_id,
                drop_eligible_indicator: false,
                priority_code_point: Pcp::Be,
                ethertype: EtherType::VlanInner,
            };
            outer_header_repr.emit(&mut outer_header);
            Packet::new_unchecked(&mut payload[HEADER_LEN..])
        } else {
            Packet::new_unchecked(payload)
        };

        let inner_header_repr = Repr {
            vlan_identifier: self.inner_vlan_id,
            drop_eligible_indicator: false,
            priority_code_point: Pcp::Be,
            ethertype,
        };
        inner_header_repr.emit(&mut inner_header);
    }

    pub(crate) fn get_outer_ethertype(&self) -> EtherType {
        if self.outer_vlan_id.is_some() {
            EtherType::VlanOuter
        } else {
            EtherType::VlanInner
        }
    }
}

/// A read/write wrapper around a VLAN header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

//  VLAN according to IEEE 802.1Q adds 4 bytes after the source MAC address and EtherType of an
//  Ethernet frame as follows:
//
//  ```txt
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         TPID (0x8100)         | PCP |D|        VLAN ID        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  ```
//
//  The first two bytes are the Tag Protocol Identifier (TPID) and the last two are the
//  Tag Control Information (TCI).
//
//  IEEE 802.1ad adds the concept of double tagging which allows an outer header with a
//  TPID of 0x88A8 in front of the IEEE 802.1Q header.
//
//  For simplicity it is practical to treat the TPID as EtherType of the standard Ethernet
//  header. One can then handle VLAN as a normal Ethernet protocol with the TCI as first field
//  followed by the EtherType of the next protocol:
//
//  ```txt
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | PCP |D|        VLAN ID        |           EtherType           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  ```
//
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const TCI: Field = 0..2;
    pub const ETHERTYPE: Field = 2..4;
    pub const PAYLOAD: Rest = 4..;
}

/// The VLAN header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with VLAN header structure.
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
    /// Returns `Err(Error)` if the buffer is shorter than four bytes.
    ///
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the length of a VLAN header.
    pub const fn header_len() -> usize {
        HEADER_LEN
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the TCI field.
    #[inline]
    pub fn tag_control_information(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::TCI])
    }

    /// Return the VID field.
    #[inline]
    pub fn vlan_identifier(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::TCI]) & 0xfff
    }

    /// Return the DEI flag.
    #[inline]
    pub fn drop_eligible_indicator(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::TCI]) & 0x1000 != 0
    }

    /// Return the PCP field.
    #[inline]
    pub fn priority_code_point(&self) -> Pcp {
        let data = self.buffer.as_ref();
        let raw = data[field::TCI.start] & (0xe0_u8 >> 5);
        Pcp::from(raw)
    }

    /// Return the EtherType field
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ETHERTYPE]);
        EtherType::from(raw)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the TCI field.
    #[inline]
    pub fn set_tag_control_information(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::TCI], value);
    }

    /// Set the VID field.
    #[inline]
    pub fn set_vlan_identifier(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let tci = NetworkEndian::read_u16(&data[field::TCI]);
        let raw = (tci & 0xf000) | (value & !0xf000);
        NetworkEndian::write_u16(&mut data[field::TCI], raw)
    }

    /// Set the DEI flag.
    #[inline]
    pub fn set_drop_eligible_indicator(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = data[field::TCI.start];
        data[field::TCI.start] = if value { raw | 0x10 } else { raw & !0x10 };
    }

    /// Set the PCP field.
    #[inline]
    pub fn set_priority_code_point(&mut self, value: Pcp) {
        let data = self.buffer.as_mut();
        let raw = data[field::TCI.start];
        data[field::TCI.start] = (raw & 0x1f) | (u8::from(value) << 5);
    }

    /// Set the EtherType field.
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ETHERTYPE], value.into())
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of a VLAN header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    vlan_identifier: u16,
    drop_eligible_indicator: bool,
    priority_code_point: Pcp,
    ethertype: EtherType,
}

impl Repr {
    /// Parse a VLAN header and return a high-level representation,
    /// or return `Err(Error)` if the packet is not recognized.
    pub fn parse<T: AsRef<[u8]>>(packet: &Packet<T>) -> Result<Repr> {
        packet.check_len()?;

        Ok(Repr {
            vlan_identifier: packet.vlan_identifier(),
            drop_eligible_indicator: packet.drop_eligible_indicator(),
            priority_code_point: packet.priority_code_point(),
            ethertype: packet.ethertype(),
        })
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an VLAN header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        assert!(packet.buffer.as_ref().len() >= self.buffer_len());
        packet.set_vlan_identifier(self.vlan_identifier);
        packet.set_drop_eligible_indicator(self.drop_eligible_indicator);
        packet.set_priority_code_point(self.priority_code_point);
        packet.set_ethertype(self.ethertype);
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            _ => {
                write!(f, "VLAN (unrecognized)")?;
                write!(
                    f,
                    " vid={:?} dei={:?} pcp={:?} ethetype={:?}",
                    self.vlan_identifier(),
                    self.drop_eligible_indicator(),
                    self.priority_code_point(),
                    self.ethertype(),
                )?;
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "VLAN vid={} ethertype={}",
            self.vlan_identifier, self.ethertype,
        )
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Packet::new_checked(buffer) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 4] = [0x00, 0x64, 0x08, 0x06];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.priority_code_point(), Pcp::Be);
        assert!(!packet.drop_eligible_indicator());
        assert_eq!(packet.vlan_identifier(), 100);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 4];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_priority_code_point(Pcp::Be);
        packet.set_drop_eligible_indicator(false);
        packet.set_vlan_identifier(100);
        packet.set_ethertype(EtherType::Arp);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr {
        Repr {
            vlan_identifier: 100,
            drop_eligible_indicator: false,
            priority_code_point: Pcp::Be,
            ethertype: EtherType::Arp,
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
        let mut bytes = vec![0xa5; 4];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet_repr().emit(&mut packet);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..HEADER_LEN]);
    }
}
