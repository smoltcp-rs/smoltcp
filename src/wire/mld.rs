// Packet implementation for the Multicast Listener Discovery
// protocol. See [RFC 3810] and [RFC 2710].
//
// [RFC 3810]: https://tools.ietf.org/html/rfc3810
// [RFC 2710]: https://tools.ietf.org/html/rfc2710

use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use super::icmpv6::{field, Packet};
use super::Ipv6Address;

enum_with_unknown! {
    /// MLDv2 Multicast Listener Report Record Type. See [RFC 3810 § 5.2.12] for
    /// more details.
    ///
    /// [RFC 3810 § 5.2.12]: https://tools.ietf.org/html/rfc3010#section-5.2.12
    pub doc enum RecordType(u8) {
        /// Interface has a filter mode of INCLUDE for the specified multicast address.
        ModeIsInclude   = 0x01,
        /// Interface has a filter mode of EXCLUDE for the specified multicast address.
        ModeIsExclude   = 0x02,
        /// Interface has changed to a filter mode of INCLUDE for the specified
        /// multicast address.
        ChangeToInclude = 0x03,
        /// Interface has changed to a filter mode of EXCLUDE for the specified
        /// multicast address.
        ChangeToExclude = 0x04,
        /// Interface wishes to listen to the sources in the specified list.
        AllowNewSources = 0x05,
        /// Interface no longer wishes to listen to the sources in the specified list.
        BlockOldSources = 0x06
    }
}

/// Getters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the maximum response code field.
    #[inline]
    pub fn max_resp_code(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::MAX_RESP_CODE])
    }

    /// Return the address being queried.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::QUERY_MCAST_ADDR])
    }

    /// Return the Suppress Router-Side Processing flag.
    #[inline]
    pub fn s_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[field::SQRV] & 0x08) != 0
    }

    /// Return the Querier's Robustness Variable.
    #[inline]
    pub fn qrv(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::SQRV] & 0x7
    }

    /// Return the Querier's Query Interval Code.
    #[inline]
    pub fn qqic(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::QQIC]
    }

    /// Return number of sources.
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::QUERY_NUM_SRCS])
    }
}

/// Getters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the number of Multicast Address Records.
    #[inline]
    pub fn nr_mcast_addr_rcrds(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::NR_MCAST_RCRDS])
    }
}

/// Setters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the maximum response code field.
    #[inline]
    pub fn set_max_resp_code(&mut self, code: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::MAX_RESP_CODE], code);
    }

    /// Set the address being queried.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::QUERY_MCAST_ADDR].copy_from_slice(addr.as_bytes());
    }

    /// Set the Suppress Router-Side Processing flag.
    #[inline]
    pub fn set_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        let current = data[field::SQRV];
        data[field::SQRV] = 0x8 | (current & 0x7);
    }

    /// Clear the Suppress Router-Side Processing flag.
    #[inline]
    pub fn clear_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        data[field::SQRV] = data[field::SQRV] & 0x7;
    }

    /// Set the Querier's Robustness Variable.
    #[inline]
    pub fn set_qrv(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::SQRV] = (data[field::SQRV] & 0x8) | value & 0x7;
    }

    /// Set the Querier's Query Interval Code.
    #[inline]
    pub fn set_qqic(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::QQIC] = value;
    }

    /// Set number of sources.
    #[inline]
    pub fn set_num_srcs(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::QUERY_NUM_SRCS], value);
    }
}

/// Setters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the number of Multicast Address Records.
    #[inline]
    pub fn set_nr_mcast_addr_rcrds(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::NR_MCAST_RCRDS], value)
    }
}

/// A read/write wrapper around an MLDv2 Listener Report Message Address Record.
#[derive(Debug, PartialEq, Clone)]
pub struct AddressRecord<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Imbue a raw octet buffer with a Address Record structure.
    pub fn new(buffer: T) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::RECORD_MCAST_ADDR.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

/// Getters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[inline]
    pub fn record_type(&self) -> RecordType {
        let data = self.buffer.as_ref();
        RecordType::from(data[field::RECORD_TYPE])
    }

    /// Return the length of the auxilary data.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::AUX_DATA_LEN]
    }

    /// Return the number of sources field.
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::RECORD_NUM_SRCS])
    }

    /// Return the multicast address field.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::RECORD_MCAST_ADDR])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AddressRecord<&'a T> {
    /// Return a pointer to the address records.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::RECORD_MCAST_ADDR.end..]
    }
}

/// Setters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsMut<[u8]> + AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[inline]
    pub fn set_record_type(&mut self, rty: RecordType) {
        let data = self.buffer.as_mut();
        data[field::RECORD_TYPE] = rty.into();
    }

    /// Return the length of the auxilary data.
    #[inline]
    pub fn set_aux_data_len(&mut self, len: u8) {
        let data = self.buffer.as_mut();
        data[field::AUX_DATA_LEN] = len;
    }

    /// Return the number of sources field.
    #[inline]
    pub fn set_num_srcs(&mut self, num_srcs: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::RECORD_NUM_SRCS], num_srcs);
    }

    /// Return the multicast address field.
    ///
    /// # Panics
    /// This function panics if the given address is not a multicast address.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        assert!(addr.is_multicast());
        let data = self.buffer.as_mut();
        data[field::RECORD_MCAST_ADDR].copy_from_slice(addr.as_bytes());
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressRecord<T> {
    /// Return a pointer to the address records.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::RECORD_MCAST_ADDR.end..]
    }
}

#[cfg(test)]
mod test {
    use wire::icmpv6::Message;
    use super::*;

    static QUERY_PACKET_BYTES: [u8; 44] =
        [0x82, 0x00, 0x73, 0x74,
         0x04, 0x00, 0x00, 0x00,
         0xff, 0x02, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01,
         0x0a, 0x12, 0x00, 0x01,
         0xff, 0x02, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x02];

    static REPORT_PACKET_BYTES: [u8; 44] =
        [0x8f, 0x00, 0x73, 0x85,
         0x00, 0x00, 0x00, 0x01,
         0x01, 0x00, 0x00, 0x01,
         0xff, 0x02, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x01,
         0xff, 0x02, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x02];

    #[test]
    fn test_query_deconstruct() {
        let packet = Packet::new(&QUERY_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::MldQuery);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x7374);
        assert_eq!(packet.max_resp_code(), 0x0400);
        assert_eq!(packet.mcast_addr(), Ipv6Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.s_flag(), true);
        assert_eq!(packet.qrv(), 0x02);
        assert_eq!(packet.qqic(), 0x12);
        assert_eq!(packet.num_srcs(), 0x01);
        assert_eq!(Ipv6Address::from_bytes(packet.payload()),
                   Ipv6Address::LINK_LOCAL_ALL_ROUTERS);
    }

    #[test]
    fn test_query_construct() {
        let mut bytes = vec![0xff; 44];
        let mut packet = Packet::new(&mut bytes[..]);
        packet.set_msg_type(Message::MldQuery);
        packet.set_msg_code(0);
        packet.set_max_resp_code(0x0400);
        packet.set_mcast_addr(Ipv6Address::LINK_LOCAL_ALL_NODES);
        packet.set_s_flag();
        packet.set_qrv(0x02);
        packet.set_qqic(0x12);
        packet.set_num_srcs(0x01);
        packet.payload_mut().copy_from_slice(Ipv6Address::LINK_LOCAL_ALL_ROUTERS.as_bytes());
        packet.clear_reserved();
        packet.fill_checksum(&Ipv6Address::LINK_LOCAL_ALL_NODES.into(),
                             &Ipv6Address::LINK_LOCAL_ALL_ROUTERS.into());
        assert_eq!(&packet.into_inner()[..], &QUERY_PACKET_BYTES[..]);
    }

    #[test]
    fn test_record_deconstruct() {
        let packet = Packet::new(&REPORT_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::MldReport);
        assert_eq!(packet.msg_code(), 0);
        //assert_eq!(packet.checksum(), 0x7374);
        assert_eq!(packet.nr_mcast_addr_rcrds(), 0x01);
        let addr_rcrd = AddressRecord::new(packet.payload());
        assert_eq!(addr_rcrd.record_type(), RecordType::ModeIsInclude);
        assert_eq!(addr_rcrd.aux_data_len(), 0x00);
        assert_eq!(addr_rcrd.num_srcs(), 0x01);
        assert_eq!(addr_rcrd.mcast_addr(), Ipv6Address::LINK_LOCAL_ALL_NODES);
        assert_eq!(Ipv6Address::from_bytes(addr_rcrd.payload()),
                   Ipv6Address::LINK_LOCAL_ALL_ROUTERS);
    }

    #[test]
    fn test_record_construct() {
        let mut bytes = vec![0xff; 44];
        let mut packet = Packet::new(&mut bytes[..]);
        packet.set_msg_type(Message::MldReport);
        packet.set_msg_code(0);
        packet.clear_reserved();
        packet.set_nr_mcast_addr_rcrds(1);
        {
            let mut addr_rcrd = AddressRecord::new(packet.payload_mut());
            addr_rcrd.set_record_type(RecordType::ModeIsInclude);
            addr_rcrd.set_aux_data_len(0);
            addr_rcrd.set_num_srcs(1);
            addr_rcrd.set_mcast_addr(Ipv6Address::LINK_LOCAL_ALL_NODES);
            addr_rcrd.payload_mut()
                .copy_from_slice(Ipv6Address::LINK_LOCAL_ALL_ROUTERS.as_bytes());
        }
        packet.fill_checksum(&Ipv6Address::LINK_LOCAL_ALL_NODES.into(),
                             &Ipv6Address::LINK_LOCAL_ALL_ROUTERS.into());
        assert_eq!(&packet.into_inner()[..], &REPORT_PACKET_BYTES[..]);
    }
}
