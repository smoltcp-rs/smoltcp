use core::fmt;

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
