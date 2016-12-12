#![feature(associated_consts, const_fn, step_by)]
#![no_std]

extern crate byteorder;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(feature = "std")]
extern crate libc;

use core::fmt;

pub mod phy;
pub mod wire;
pub mod iface;

/// The error type for the networking stack.
#[derive(Debug)]
pub enum Error {
    /// A packet could not be parsed or emitted because a field was out of bounds
    /// for the underlying buffer.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. a packet with an unknown EtherType.
    Unrecognized,
    /// An incoming packet was recognized but contained invalid data.
    /// E.g. a packet with IPv4 EtherType but containing a value other than 4
    /// in the version field.
    Malformed,
    /// An incoming packet had an incorrect checksum and was dropped.
    Checksum,
    /// An incoming packet has been fragmented and was dropped.
    Fragmented,

    #[doc(hidden)]
    __Nonexhaustive
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Truncated    => write!(f, "truncated packet"),
            &Error::Unrecognized => write!(f, "unrecognized packet"),
            &Error::Malformed    => write!(f, "malformed packet"),
            &Error::Checksum     => write!(f, "checksum error"),
            &Error::Fragmented   => write!(f, "fragmented packet"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
