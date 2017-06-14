use libc;

#[cfg(any(feature = "raw_socket"))]
pub const SIOCGIFMTU:   libc::c_ulong = 0x8921;
#[cfg(any(feature = "raw_socket"))]
pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
#[cfg(any(feature = "raw_socket"))]
pub const ETH_P_ALL:    libc::c_short = 0x0003;

#[cfg(feature = "tap_interface")]
pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;
#[cfg(feature = "tap_interface")]
pub const IFF_TAP:      libc::c_int   = 0x0002;
#[cfg(feature = "tap_interface")]
pub const IFF_NO_PI:    libc::c_int   = 0x1000;

