#![feature(associated_consts, const_fn)]
#![cfg_attr(feature = "use_alloc", feature(alloc))]
#![no_std]

extern crate byteorder;

#[cfg(any(test, feature = "use_std"))]
#[macro_use]
extern crate std;
#[cfg(feature = "use_std")]
extern crate libc;
#[cfg(feature = "use_alloc")]
extern crate alloc;
#[cfg(feature = "use_log")]
#[macro_use(trace, log)]
extern crate log;

macro_rules! net_trace {
    ($($arg:expr),*) => {
        #[cfg(feature = "use_log")]
        trace!($($arg),*);
        #[cfg(not(feature = "use_log"))]
        $( let _ = $arg );*; // suppress unused variable warnings
    }
}

use core::fmt;

mod managed;

pub mod phy;
pub mod wire;
pub mod iface;
pub mod socket;

pub use managed::Managed;

/// The error type for the networking stack.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// An incoming packet could not be parsed, or an outgoing packet could not be emitted
    /// because a field was out of bounds for the underlying buffer.
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
    /// An outgoing packet could not be sent because a protocol address could not be mapped
    /// to hardware address. E.g. an IPv4 packet did not have an Ethernet address
    /// corresponding to its IPv4 destination address.
    Unaddressable,
    /// A buffer for incoming packets is empty, or a buffer for outgoing packets is full.
    Exhausted,
    /// An incoming packet does not match the socket endpoint.
    Rejected,

    #[doc(hidden)]
    __Nonexhaustive
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Truncated     => write!(f, "truncated packet"),
            &Error::Unrecognized  => write!(f, "unrecognized packet"),
            &Error::Malformed     => write!(f, "malformed packet"),
            &Error::Checksum      => write!(f, "checksum error"),
            &Error::Fragmented    => write!(f, "fragmented packet"),
            &Error::Unaddressable => write!(f, "unaddressable destination"),
            &Error::Exhausted     => write!(f, "buffer space exhausted"),
            &Error::Rejected      => write!(f, "rejected by socket"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
