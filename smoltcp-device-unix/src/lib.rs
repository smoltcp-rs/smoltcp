#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

#[macro_use]
mod macros;
mod sys;

pub mod raw_socket;
pub mod tuntap_interface;

pub use sys::wait;

pub use self::raw_socket::RawSocket;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::tuntap_interface::TunTapInterface;
