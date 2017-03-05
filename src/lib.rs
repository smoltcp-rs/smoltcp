#![cfg_attr(feature = "alloc", feature(alloc))]
#![no_std]

//! The _smoltcp_ library is built in a layered structure, with the layers corresponding
//! to the levels of API abstraction. Only the highest layers would be used by a typical
//! application; however, the goal of _smoltcp_ is not just to provide a simple interface
//! for writing applications but also to be a toolbox of networking primitives, so
//! every layer is fully exposed and documented.
//!
//! When discussing networking stacks and layering, often the [OSI model][osi] is invoked.
//! _smoltcp_ makes no effort to conform to the OSI model as it is not applicable to TCP/IP.
//! [osi]: https://en.wikipedia.org/wiki/OSI_model
//!
//! # The socket layer
//! The socket layer APIs are provided in the module [socket](socket/index.html); currently,
//! TCP and UDP sockets are provided. The socket API provides the usual primitives, but
//! necessarily differs in many from the [Berkeley socket API][berk], as the latter was not
//! designed to be used without heap allocation.
//! [berk]: https://en.wikipedia.org/wiki/Berkeley_sockets
//!
//! The socket layer provides the buffering, packet construction and validation, and (for
//! stateful sockets) the state machines, but it is interface-agnostic. An application must
//! use sockets together with a network interface.
//!
//! # The interface layer
//! The interface layer APIs are provided in the module [iface](iface/index.html); currently,
//! Ethernet interface is provided.
//!
//! The interface layer handles the control messages, physical addressing and neighbor discovery.
//! It routes packets to and from sockets.
//!
//! # The physical layer
//! The physical layer APIs are provided in the module [phy](phy/index.html); currently,
//! raw socket and TAP interface are provided. In addition, two _middleware_ interfaces
//! are provided: the _tracer device_, which prints a human-readable representation of packets,
//! and the _fault injector device_, which randomly introduces errors into the transmitted
//! and received packet sequences.
//!
//! The physical layer handles interaction with a platform-specific network device.
//!
//! # The wire layers
//! Unlike the higher layers, the wire layer APIs will not be used by a typical application.
//! They however are the bedrock of _smoltcp_, and everything else is built on top of them.
//!
//! The wire layer APIs are designed by the principle "make illegal states irrepresentable".
//! If a wire layer object can be constructed, then it can also be parsed from or emitted to
//! a lower level.
//!
//! The wire layer APIs also provide _tcpdump_-like pretty printing.
//!
//! ## The representation layer
//! The representation layer APIs are provided in the module [wire](wire/index.html); currently,
//! Ethernet, ARP, generic IP, IPv4, ICMPv4, TCP and UDP packet representations are provided.
//!
//! The representation layer exists to reduce the state space of raw packets. Raw packets
//! may be nonsensical in a multitude of ways: invalid checksums, impossible combinations of flags,
//! pointers to fields out of bounds, meaningless options... Representations shed all that,
//! as well as any features not supported by _smoltcp_.
//!
//! ## The packet layer
//! The packet layer APIs are also provided in the module [wire](wire/index.html); currently,
//! Ethernet, ARP, IPv4, ICMPv4, TCP and UDP packet representations are provided.
//!
//! The packet layer exists to provide a more structured way to work with packets than
//! treating them as sequences of octets. It makes no judgement as to content of the packets,
//! except where necessary to provide safe access to fields, and strives to implement every
//! feature ever defined, to ensure that, when the representation layer is unable to make sense
//! of a packet, it is still logged correctly and in full.

extern crate byteorder;
extern crate managed;
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(feature = "std")]
extern crate libc;
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(test, feature = "log"))]
#[macro_use(trace, log)]
extern crate log;

macro_rules! net_trace {
    ($($arg:expr),*) => {
        #[cfg(feature = "log")]
        trace!($($arg),*);
        #[cfg(not(feature = "log"))]
        $( let _ = $arg );*; // suppress unused variable warnings
    }
}

use core::fmt;

pub mod phy;
pub mod wire;
pub mod iface;
pub mod socket;

mod parsing;

/// The error type for the networking stack.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// An incoming packet could not be parsed, or an outgoing packet could not be emitted
    /// because a field was out of bounds for the underlying buffer.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. a packet with an unknown EtherType.
    Unrecognized,
    /// An incoming packet was recognized but contained invalid control information.
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
    /// An incoming packet was recognized by a stateful socket and contained invalid control
    /// information that caused the socket to drop it.
    Dropped,

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
            &Error::Dropped       => write!(f, "dropped by socket"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
