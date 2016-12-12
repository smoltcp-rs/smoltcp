#![feature(associated_consts, const_fn)]
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
    /// A packet could not be recognized and was dropped.
    Unrecognized,

    #[doc(hidden)]
    __Nonexhaustive
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Truncated    => write!(f, "truncated packet"),
            &Error::Unrecognized => write!(f, "unrecognized packet"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
