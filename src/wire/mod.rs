//! Low-level packet access and construction.
//!
//! The `wire` module deals with the packet *representation*. It provides two levels
//! of functionality.
//!
//!  * First, it provides functions to extract fields from sequences of octets,
//!    and to insert fields into sequences of octets. This happens `Packet` family of
//!    structures, e.g. [EthernetFrame] or [Ipv4Packet].
//!  * Second, in cases where the space of valid field values is much smaller than the space
//!    of possible field values, it provides a compact, high-level representation
//!    of packet data that can be parsed from and emitted into a sequence of octets.
//!    This happens through the `Repr` family of structs and enums, e.g. [ArpRepr] or [Ipv4Repr].
// https://github.com/rust-lang/rust/issues/38739
//! </ul>
//!
//! [EthernetFrame]: struct.EthernetFrame.html
//! [Ipv4Packet]: struct.Ipv4Packet.html
//! [ArpRepr]: enum.ArpRepr.html
//! [Ipv4Repr]: struct.Ipv4Repr.html
//!
//! The functions in the `wire` module are designed for use together with `-Cpanic=abort`.
//!
//! The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
//! returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
//! provided by `Packet::check_len()` may no longer hold after changing certain fields,
//! which are listed in the documentation for the specific packet.
//!
//! The `Packet::new_checked` method is a shorthand for a combination of `Packet::new` and
//! `Packet::check_len`.
//! When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
//! so long as the buffer is not modified, no accessor will fail.
//! When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
//! the length check is likely to succeed on a zeroed buffer, but fail on a buffer
//! filled with data from a previous packet, such as when reusing buffers, resulting
//! in nondeterministic panics with some network devices but not others.
//! The buffer length for emission is not calculated by the `Packet` layer.
//!
//! In the `Repr` family of data structures, the `Repr::parse()` method never panics
//! as long as `Packet::new_checked()` (or `Packet::check_len()`) has succeeded, and
//! the `Repr::emit()` method never panics as long as the underlying buffer is exactly
//! `Repr::buffer_len()` octets long.
//!
//! # Examples
//!
//! To emit an IP packet header into an octet buffer, and then parse it back:
//!
/*!
```rust
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    protocol:    IpProtocol::Tcp,
    payload_len: 10,
    ttl:         64
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let mut packet = Ipv4Packet::new(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
}
{ // parsing
    let packet = Ipv4Packet::new_checked(&buffer)
                            .expect("truncated packet");
    let parsed = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())
                          .expect("malformed packet");
    assert_eq!(repr, parsed);
}
```
*/

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

pub use self::ip::Version as IpVersion;
pub use self::ip::Protocol as IpProtocol;
pub use self::ip::Address as IpAddress;
pub use self::ip::Endpoint as IpEndpoint;
pub use self::ip::Repr as IpRepr;
pub use self::ip::Cidr as IpCidr;

pub use self::ipv4::Address as Ipv4Address;
pub use self::ipv4::Packet as Ipv4Packet;
pub use self::ipv4::Repr as Ipv4Repr;
pub use self::ipv4::Cidr as Ipv4Cidr;

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
