use core::fmt;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum LinkLayer {
    /// macOS loopback or utun, Linux tun without `IFF_NO_PI` flag
    Null,
    /// Ethernet Frame
    Eth,
    /// Raw IP Packet (IPv4 Packet / IPv6 Packet)
    Ip,
}

impl fmt::Display for LinkLayer {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LinkLayer::Null => write!(f, "tun"),
            LinkLayer::Eth => write!(f, "loopback/ethernet"),
            LinkLayer::Ip => write!(f, "ipv4/ipv6"),
        }
    }

    #[cfg(target_os = "macos")]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LinkLayer::Null => write!(f, "loopback/utun"),
            LinkLayer::Eth => write!(f, "ethernet"),
            LinkLayer::Ip => write!(f, "ipv4/ipv6"),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LinkLayer::Null => write!(f, "null"),
            LinkLayer::Eth => write!(f, "ethernet"),
            LinkLayer::Ip => write!(f, "ipv4/ipv6"),
        }
    }
}