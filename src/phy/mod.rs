//! Access to networking hardware.
//!
//! The `phy` module provides a way to capture and inject packets.
//! It requires the standard library, and currently only works on Linux.

#[cfg(all(unix, feature = "std"))]
mod raw_socket;

#[cfg(all(unix, feature = "std"))]
pub use self::raw_socket::RawSocket;
