use core::fmt;
use byteorder::{ByteOrder, NetworkEndian};

enum_with_unknown! {
    /// Internet protocol type.
    pub enum ProtocolType(u8) {
        Icmp = 0x01,
        Tcp  = 0x06,
        Udp  = 0x11
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ProtocolType::Icmp => write!(f, "ICMP"),
            &ProtocolType::Tcp  => write!(f, "TCP"),
            &ProtocolType::Udp  => write!(f, "UDP"),
            &ProtocolType::Unknown(id) => write!(f, "0x{:02x}", id)
        }
    }
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
pub fn checksum(data: &[u8]) -> u16 {
    let mut accum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        let word = NetworkEndian::read_u16(&data[i..i + 2]) as u32;
        accum += word;
    }
    (((accum >> 16) as u16) + (accum as u16))
}
