use core::fmt;

use Error;
use super::{Ipv4Address, Ipv4Packet, Ipv4Repr};

enum_with_unknown! {
    /// Internetworking protocol.
    pub enum Protocol(u8) {
        Icmp = 0x01,
        Tcp  = 0x06,
        Udp  = 0x11
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Protocol::Icmp => write!(f, "ICMP"),
            &Protocol::Tcp  => write!(f, "TCP"),
            &Protocol::Udp  => write!(f, "UDP"),
            &Protocol::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// An internetworking address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An unspecified address.
    /// May be used as a placeholder for storage where the address is not assigned yet.
    Unspecified,
    /// An IPv4 address.
    Ipv4(Ipv4Address)
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    pub fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            &Address::Unspecified => false,
            &Address::Ipv4(addr)  => addr.is_unicast()
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            &Address::Unspecified => true,
            &Address::Ipv4(addr)  => addr.is_unspecified()
        }
    }
}

impl Default for Address {
    fn default() -> Address {
        Address::Unspecified
    }
}

impl From<Ipv4Address> for Address {
    fn from(addr: Ipv4Address) -> Self {
        Address::Ipv4(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Address::Unspecified => write!(f, "*"),
            &Address::Ipv4(addr)  => write!(f, "{}", addr)
        }
    }
}

/// An internet endpoint address.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16
}

impl Endpoint {
    // pub const UNSPECIFIED: Endpoint = Endpoint { addr: Address::Unspecified, port: 0 };

    /// Create an endpoint address from given address and port.
    pub fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr: addr, port: port }
    }

    /// Query whether the endpoint has an unspecified address.
    pub fn is_unspecified(&self) -> bool {
        self.addr.is_unspecified()
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl From<u16> for Endpoint {
    fn from(port: u16) -> Endpoint {
        Endpoint { addr: Address::Unspecified, port: port }
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint { addr: addr.into(), port: port }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains a concrete
/// high-level representation for some IP protocol version, or an unspecified representation,
/// which permits the `IpAddress::Unspecified` addresses.
#[derive(Debug, Clone)]
pub enum IpRepr {
    Unspecified {
        src_addr:    Address,
        dst_addr:    Address,
        protocol:    Protocol,
        payload_len: usize
    },
    Ipv4(Ipv4Repr),
    #[doc(hidden)]
    __Nonexhaustive
}

impl IpRepr {
    /// Return the source address.
    pub fn src_addr(&self) -> Address {
        match self {
            &IpRepr::Unspecified { src_addr, .. } => src_addr,
            &IpRepr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the destination address.
    pub fn dst_addr(&self) -> Address {
        match self {
            &IpRepr::Unspecified { dst_addr, .. } => dst_addr,
            &IpRepr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the protocol.
    pub fn protocol(&self) -> Protocol {
        match self {
            &IpRepr::Unspecified { protocol, .. } => protocol,
            &IpRepr::Ipv4(repr) => repr.protocol,
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the payload length.
    pub fn payload_len(&self) -> usize {
        match self {
            &IpRepr::Unspecified { payload_len, .. } => payload_len,
            &IpRepr::Ipv4(repr) => repr.payload_len,
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Convert an unspecified representation into a concrete one, or return
    /// `Err(Error::Unaddressable)` if not possible.
    ///
    /// # Panics
    /// This function panics if source and destination addresses belong to different families,
    /// or the destination address is unspecified, since this indicates a logic error.
    pub fn lower(&self, fallback_src_addrs: &[Address]) -> Result<IpRepr, Error> {
        match self {
            &IpRepr::Unspecified {
                src_addr: Address::Ipv4(src_addr),
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len
            } => {
                Ok(IpRepr::Ipv4(Ipv4Repr {
                    src_addr:    src_addr,
                    dst_addr:    dst_addr,
                    protocol:    protocol,
                    payload_len: payload_len
                }))
            }

            &IpRepr::Unspecified {
                src_addr: Address::Unspecified,
                dst_addr: Address::Ipv4(dst_addr),
                protocol, payload_len
            } => {
                let mut src_addr = None;
                for addr in fallback_src_addrs {
                    match addr {
                        &Address::Ipv4(addr) => {
                            src_addr = Some(addr);
                            break
                        }
                        _ => ()
                    }
                }
                Ok(IpRepr::Ipv4(Ipv4Repr {
                    src_addr:    try!(src_addr.ok_or(Error::Unaddressable)),
                    dst_addr:    dst_addr,
                    protocol:    protocol,
                    payload_len: payload_len
                }))
            }

            &IpRepr::Unspecified { dst_addr: Address::Unspecified, .. } =>
                panic!("unspecified destination IP address"),
            // &IpRepr::Unspecified { .. } =>
            //     panic!("source and destination IP address families do not match"),

            repr @ &IpRepr::Ipv4(_) => Ok(repr.clone()),
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &IpRepr::Unspecified { .. } => panic!("unspecified IP representation"),
            &IpRepr::Ipv4(repr) => repr.buffer_len(),
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }

    /// Emit this high-level representation into a buffer.
    ///
    /// # Panics
    /// This function panics if invoked on an unspecified representation.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match self {
            &IpRepr::Unspecified { .. } => panic!("unspecified IP representation"),
            &IpRepr::Ipv4(repr) => {
                let mut packet = Ipv4Packet::new(buffer).expect("undersized buffer");
                repr.emit(&mut packet)
            }
            &IpRepr::__Nonexhaustive => unreachable!()
        }
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(data: &[u8]) -> u16 {
        let mut accum: u32 = 0;
        let mut i = 0;
        while i < data.len() {
            let word;
            if i + 2 <= data.len() {
                word = NetworkEndian::read_u16(&data[i..i + 2]) as u32
            } else {
                word = (data[i] as u32) << 8
            }
            accum += word;
            i += 2;
        }
        propagate_carries(accum)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    /// Compute an IP pseudo header checksum.
    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address,
                         protocol: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            (&Address::Ipv4(src_addr), &Address::Ipv4(dst_addr)) => {
                let mut proto_len = [0u8; 4];
                proto_len[1] = protocol.into();
                NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

                combine(&[
                    data(src_addr.as_bytes()),
                    data(dst_addr.as_bytes()),
                    data(&proto_len[..])
                ])
            },

            _ => panic!("Unexpected pseudo header ")
        }
    }
}
