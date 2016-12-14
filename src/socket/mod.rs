//! Communication between endpoints.
//!
//! The `socket` module deals with *network endpoints* and *buffering*.
//! It provides interfaces for accessing buffers of data, and protocol state machines
//! for filling and emptying these buffers.
//!
//! The programming interface implemented here differs greatly from the common Berkeley socket
//! interface. Specifically, in the Berkeley interface the buffering is implicit:
//! the operating system decides on the good size for a buffer and manages it.
//! The interface implemented by this module uses explicit buffering: you decide on the good
//! size for a buffer, allocate it, and let the networking stack use it.
//!
//! Every socket implementation allows selecting transmit and receive buffers separately;
//! this means that, for example, a socket that never receives data does not have to allocate
//! any storage to receive buffers.

use core::fmt;

mod udp;

pub use self::udp::Buffer as UdpBuffer;
pub use self::udp::NullBuffer as UdpNullBuffer;
pub use self::udp::UnitaryBuffer as UdpUnitaryBuffer;
pub use self::udp::Socket as UdpSocket;
