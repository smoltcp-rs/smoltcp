use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use super::icmpv6::{field, Message, NeighborFlags, Packet, RouterFlags};
use time::Duration;
use super::Ipv6Address;

/// Getters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the current hop limit field.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CUR_HOP_LIMIT]
    }

    /// Return the Router Advertisement flags.
    #[inline]
    pub fn router_flags(&self) -> RouterFlags {
        let data = self.buffer.as_ref();
        RouterFlags::from_bits_truncate(data[field::ROUTER_FLAGS])
    }

    /// Return the router lifetime field.
    #[inline]
    pub fn router_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_secs(NetworkEndian::read_u16(&data[field::ROUTER_LT]) as u64)
    }

    /// Return the reachable time field.
    #[inline]
    pub fn reachable_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::REACHABLE_TM]) as u64)
    }

    /// Return the retransmit time field.
    #[inline]
    pub fn retrans_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        Duration::from_millis(NetworkEndian::read_u32(&data[field::RETRANS_TM]) as u64)
    }
}

/// Getters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the target address field.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::TARGET_ADDR])
    }
}


/// Getters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Neighbor Solicitation flags.
    #[inline]
    pub fn neighbor_flags(&self) -> NeighborFlags {
        let data = self.buffer.as_ref();
        NeighborFlags::from_bits_truncate(data[field::NEIGH_FLAGS])
    }
}

/// Getters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the destination address field.
    #[inline]
    pub fn dest_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::DEST_ADDR])
    }
}

/// Setters for the Router Solicitation message header.
/// See [RFC 4861 § 4.1].
///
/// [RFC 4861 § 4.1]: https://tools.ietf.org/html/rfc4861#section-4.1
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the reserved field.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::UNUSED], 0);
    }
}

/// Setters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the current hop limit field.
    #[inline]
    pub fn set_current_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CUR_HOP_LIMIT] = value;
    }

    /// Set the Router Advertisement flags.
    #[inline]
    pub fn set_router_flags(&mut self, flags: RouterFlags) {
        self.buffer.as_mut()[field::ROUTER_FLAGS] = flags.bits();
    }

    /// Set the router lifetime field.
    #[inline]
    pub fn set_router_lifetime(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ROUTER_LT], value.secs() as u16);
    }

    /// Set the reachable time field.
    #[inline]
    pub fn set_reachable_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::REACHABLE_TM], value.total_millis() as u32);
    }

    /// Set the retransmit time field.
    #[inline]
    pub fn set_retrans_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::RETRANS_TM], value.total_millis() as u32);
    }
}

/// Setters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the target address field.
    #[inline]
    pub fn set_target_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::TARGET_ADDR].copy_from_slice(value.as_bytes());
    }
}

/// Setters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Neighbor Solicitation flags.
    #[inline]
    pub fn set_neighbor_flags(&mut self, flags: NeighborFlags) {
        self.buffer.as_mut()[field::NEIGH_FLAGS] = flags.bits();
    }
}

/// Setters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the destination address field.
    #[inline]
    pub fn set_dest_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::DEST_ADDR].copy_from_slice(value.as_bytes());
    }
}

/// A high-level representation of an Neighbor Discovery packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    RouterSolicit {
        options:   &'a [u8]
    },
    RouterAdvert {
        hop_limit: u8,
        flags: RouterFlags,
        router_lifetime: Duration,
        reachable_time: Duration,
        retrans_time: Duration,
        options:   &'a [u8]
    },
    NeighborSolicit {
        target_addr: Ipv6Address,
        options:   &'a [u8]
    },
    NeighborAdvert {
        flags: NeighborFlags,
        target_addr: Ipv6Address,
        options:   &'a [u8]
    },
    Redirect {
        target_addr: Ipv6Address,
        dest_addr: Ipv6Address,
        options:   &'a [u8]
    }
}

impl<'a> Repr<'a> {
    /// Parse an NDISC packet and return a high-level representation of the
    /// packet.
    pub fn parse<T>(packet: &Packet<&'a T>)
                   -> Result<Repr<'a>>
                where T: AsRef<[u8]> + ?Sized {
        match packet.msg_type() {
            Message::RouterSolicit => {
                Ok(Repr::RouterSolicit {
                    options: packet.payload()
                })
            },
            Message::RouterAdvert => {
                Ok(Repr::RouterAdvert {
                    hop_limit: packet.current_hop_limit(),
                    flags: packet.router_flags(),
                    router_lifetime: packet.router_lifetime(),
                    reachable_time: packet.reachable_time(),
                    retrans_time: packet.retrans_time(),
                    options: packet.payload()
                })
            },
            Message::NeighborSolicit => {
                Ok(Repr::NeighborSolicit {
                    target_addr: packet.target_addr(),
                    options: packet.payload()
                })
            },
            Message::NeighborAdvert => {
                Ok(Repr::NeighborAdvert {
                    flags: packet.neighbor_flags(),
                    target_addr: packet.target_addr(),
                    options: packet.payload()
                })
            },
            Message::Redirect => {
                Ok(Repr::Redirect {
                    target_addr: packet.target_addr(),
                    dest_addr: packet.dest_addr(),
                    options: packet.payload()
                })
            },
            _ => Err(Error::Unrecognized)
        }
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::RouterSolicit { options, .. } => {
                field::UNUSED.end + options.len()
            },
            &Repr::RouterAdvert { options, .. } => {
                field::RETRANS_TM.end + options.len()
            },
            &Repr::NeighborSolicit { options, .. } | &Repr::NeighborAdvert { options, .. } => {
                field::TARGET_ADDR.end + options.len()
            },
            &Repr::Redirect { options, .. } => {
                field::DEST_ADDR.end + options.len()
            }
        }
    }

    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        match self {
            &Repr::RouterSolicit { options } => {
                packet.set_msg_type(Message::RouterSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.payload_mut().copy_from_slice(&options[..]);
            },

            &Repr::RouterAdvert { hop_limit, flags, router_lifetime, reachable_time, retrans_time, options } => {
                packet.set_msg_type(Message::RouterAdvert);
                packet.set_msg_code(0);
                packet.set_current_hop_limit(hop_limit);
                packet.set_router_flags(flags);
                packet.set_router_lifetime(router_lifetime);
                packet.set_reachable_time(reachable_time);
                packet.set_retrans_time(retrans_time);
                packet.payload_mut().copy_from_slice(&options[..]);
            },

            &Repr::NeighborSolicit { target_addr, options } => {
                packet.set_msg_type(Message::NeighborSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.payload_mut().copy_from_slice(&options[..]);
            },

            &Repr::NeighborAdvert { flags, target_addr, options } => {
                packet.set_msg_type(Message::NeighborAdvert);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_neighbor_flags(flags);
                packet.set_target_addr(target_addr);
                packet.payload_mut().copy_from_slice(&options[..]);
            },

            &Repr::Redirect { target_addr, dest_addr, options } => {
                packet.set_msg_type(Message::Redirect);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.set_dest_addr(dest_addr);
                packet.payload_mut().copy_from_slice(&options[..]);
            },
        }
    }
}

#[cfg(test)]
mod test {
    use phy::ChecksumCapabilities;
    use super::*;
    use wire::Icmpv6Repr;

    static ROUTER_ADVERT_BYTES: [u8; 24] =
        [0x86, 0x00, 0xa7, 0x35,
         0x40, 0x80, 0x03, 0x84,
         0x00, 0x00, 0x03, 0x84,
         0x00, 0x00, 0x03, 0x84,
         0x01, 0x01, 0x52, 0x54,
         0x00, 0x12, 0x34, 0x56];
    static SOURCE_LINK_LAYER_OPT: [u8; 8] =
        [0x01, 0x01, 0x52, 0x54,
         0x00, 0x12, 0x34, 0x56];

    fn create_repr<'a>() -> Icmpv6Repr<'a> {
        Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::from_millis(900),
            retrans_time: Duration::from_millis(900),
            options: &SOURCE_LINK_LAYER_OPT[..]
        })
    }

    #[test]
    fn test_router_advert_deconstruct() {
        let packet = Packet::new(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::RouterAdvert);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.current_hop_limit(), 64);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        assert_eq!(packet.router_lifetime(), Duration::from_secs(900));
        assert_eq!(packet.reachable_time(), Duration::from_millis(900));
        assert_eq!(packet.retrans_time(), Duration::from_millis(900));
        assert_eq!(packet.payload(), &SOURCE_LINK_LAYER_OPT[..]);
    }

    #[test]
    fn test_router_advert_construct() {
        let mut bytes = vec![0x0; 24];
        let mut packet = Packet::new(&mut bytes);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        packet.payload_mut().copy_from_slice(&SOURCE_LINK_LAYER_OPT[..]);
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    fn test_router_advert_repr_parse() {
        let packet = Packet::new(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(Icmpv6Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap(),
                   create_repr());
    }

    #[test]
    fn test_router_advert_repr_emit() {
        let mut bytes = vec![0x2a; 24];
        let mut packet = Packet::new(&mut bytes[..]);
        create_repr().emit(&mut packet, &ChecksumCapabilities::default());
        assert_eq!(&packet.into_inner()[..], &ROUTER_ADVERT_BYTES[..]);
    }
}
