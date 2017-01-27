//! Low-level packet access and construction.
//!
//! The `wire` module deals with the packet *representation*. It provides two levels
//! of functionality.
//!
//!  * First, it provides functions to extract fields from sequences of octets,
//!    and to insert fields into sequences of octets. This happens through the `Frame`
//!    and `Packet` families of structures, e.g. [EthernetPacket](struct.EthernetPacket.html).
//!  * Second, in cases where the space of valid field values is much smaller than the space
//!    of possible field values, it provides a compact, high-level representation
//!    of packet data that can be parsed from and emitted into a sequence of octets.
//!    This happens through the `Repr` family of enums, e.g. [ArpRepr](enum.ArpRepr.html).
// https://github.com/rust-lang/rust/issues/38739
//! </ul>
//!
//! The functions in the `wire` module are designed for robustness and use together with
//! `-Cpanic=abort`. The accessor and parsing functions never panic. The setter and emission
//! functions only panic if the underlying buffer is too small.
//!
//! The `Frame` and `Packet` families of data structures in the `wire` module do not perform
//! validation of received data except as needed to access the contents without panicking;
//! the `Repr` family does.
//!
//! # Examples
//!
//! To emit an IP packet header into an octet buffer, and then parse it back:
//!
/*!
```rust
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    protocol:    IpProtocol::Tcp,
    payload_len: 10
};
let mut buffer = vec![0; repr.buffer_len() + 10];
{ // emission
    let mut packet = Ipv4Packet::new(&mut buffer).unwrap();
    repr.emit(&mut packet);
}
{ // parsing
    let packet = Ipv4Packet::new(&buffer).unwrap();
    let parsed = Ipv4Repr::parse(&packet).unwrap();
    assert_eq!(repr, parsed);
}
```
*/

macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $( $variant:ident = $value:expr ),+
        }
    ) => {
        enum_with_unknown! {
            $( #[$enum_attr] )*
            pub doc enum $name($ty) {
                $( #[doc(shown)] $variant = $value ),+
            }
        }
    };
    (
        $( #[$enum_attr:meta] )*
        pub doc enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )+
              $variant:ident = $value:expr
            ),+
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest  = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

mod ethernet;
mod arp;
mod ip;
mod ipv4;
mod icmpv4;
mod udp;
mod tcp;

pub use self::pretty_print::PrettyPrinter;

pub use self::ethernet::EtherType as EthernetProtocol;
pub use self::ethernet::Address as EthernetAddress;
pub use self::ethernet::Frame as EthernetFrame;

pub use self::arp::Hardware as ArpHardware;
pub use self::arp::Operation as ArpOperation;
pub use self::arp::Packet as ArpPacket;
pub use self::arp::Repr as ArpRepr;

pub use self::ip::Protocol as IpProtocol;
pub use self::ip::Address as IpAddress;
pub use self::ip::Endpoint as IpEndpoint;
pub use self::ip::IpRepr as IpRepr;

pub use self::ipv4::Address as Ipv4Address;
pub use self::ipv4::Packet as Ipv4Packet;
pub use self::ipv4::Repr as Ipv4Repr;

pub use self::icmpv4::Message as Icmpv4Message;
pub use self::icmpv4::DstUnreachable as Icmpv4DstUnreachable;
pub use self::icmpv4::Redirect as Icmpv4Redirect;
pub use self::icmpv4::TimeExceeded as Icmpv4TimeExceeded;
pub use self::icmpv4::ParamProblem as Icmpv4ParamProblem;
pub use self::icmpv4::Packet as Icmpv4Packet;
pub use self::icmpv4::Repr as Icmpv4Repr;

pub use self::udp::Packet as UdpPacket;
pub use self::udp::Repr as UdpRepr;

pub use self::tcp::SeqNumber as TcpSeqNumber;
pub use self::tcp::Packet as TcpPacket;
pub use self::tcp::TcpOption;
pub use self::tcp::Repr as TcpRepr;
pub use self::tcp::Control as TcpControl;
