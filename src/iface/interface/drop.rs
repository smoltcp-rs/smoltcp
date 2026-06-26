//! Inbound packet drop / non-delivery notification.
//!
//! This module provides a mechanism for the user to observe what the interface
//! does with inbound packets that are *not* delivered to a socket: packets that
//! are silently discarded, and packets the stack rejects by replying with a TCP
//! RST or an ICMP "unreachable" message. This is useful for diagnostics, logging
//! or metrics, and in particular for VPN-style use cases where you want to know
//! which inbound flows are falling through unhandled. See
//! [`Interface::set_packet_drop_callback`].

use super::*;

/// The reason an inbound packet was not delivered to a socket.
///
/// This describes *why* and roughly *where* in the receive path the packet was
/// dropped or rejected. New variants may be added in the future, so this enum is
/// marked `#[non_exhaustive]`; matches on it must include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketDropReason {
    /// A packet (or one of its headers) could not be parsed: it was truncated,
    /// had an invalid checksum, used an unsupported feature, etc.
    ///
    /// This is reported for every malformed-packet drop in the receive path,
    /// regardless of protocol layer. No parsed representation is available, but
    /// the raw bytes that failed to parse can be inspected via
    /// [`PacketDropInfo::frame`].
    Malformed,

    /// An Ethernet frame was not addressed to this interface (its destination
    /// was neither our hardware address, nor broadcast, nor a multicast group).
    #[cfg(feature = "medium-ethernet")]
    NotForUs,

    /// The frame carried a protocol the interface does not handle at the link
    /// layer, e.g. an unknown EtherType, or a non-IP packet on an IP-only medium.
    UnknownProtocol,

    /// An IEEE 802.15.4 frame was not a data frame (e.g. an ACK or MAC command
    /// frame), and so is not processed by the stack.
    #[cfg(feature = "medium-ieee802154")]
    NotADataFrame,

    /// An IEEE 802.15.4 frame's destination PAN id did not match the configured
    /// PAN id (and was not the broadcast PAN id).
    #[cfg(feature = "medium-ieee802154")]
    WrongPanId,

    /// The source address of an IP packet was not a unicast address (and not the
    /// unspecified address, where that is permitted). Such packets are never
    /// valid and are always discarded.
    NonUnicastSource,

    /// An IP packet was not destined for this interface: its destination address
    /// is not assigned to us, is not a multicast group we have joined, and is not
    /// a broadcast address. The destination is itself a non-unicast address, so
    /// the packet cannot be routed either.
    NotForUsNonUnicast,

    /// An IP packet was destined for an address that is not ours, but no route to
    /// it could be found (the interface is not acting as a router for it).
    NoRoute,

    /// An IP packet was destined for an address that is not ours, and although a
    /// route exists, the interface has no address assigned that would let it
    /// originate a reply.
    NoSourceAddress,

    /// A well-formed IP packet for us carried a transport/next-header protocol
    /// that no socket is listening for, and that the interface does not handle
    /// itself.
    ///
    /// The interface normally replies with an ICMP "protocol unreachable"
    /// message; see [`PacketDropInfo::disposition`].
    UnknownTransportProtocol,

    /// A TCP segment for us did not match any open socket.
    ///
    /// Unless suppressed (e.g. the segment was itself a RST), the interface
    /// replies with a TCP RST; see [`PacketDropInfo::disposition`].
    #[cfg(feature = "socket-tcp")]
    TcpNoSocket,

    /// A TCP segment used the unspecified address as its source or destination,
    /// which RFC 1122 § 3.2.1.3 forbids.
    #[cfg(feature = "socket-tcp")]
    TcpUnspecifiedEndpoint,

    /// A UDP datagram for us did not match any open socket.
    ///
    /// The interface normally replies with an ICMP "port unreachable" message;
    /// see [`PacketDropInfo::disposition`].
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    UdpNoSocket,

    /// An ICMP message for us was not an echo request we answer, was not claimed
    /// by an ICMP socket, and required no other action, so it was ignored.
    IcmpUnhandled,

    /// An ARP packet was not targeted at one of our protocol addresses.
    #[cfg(feature = "medium-ethernet")]
    ArpNotForUs,

    /// An ARP packet was otherwise invalid: an unknown operation, a non-unicast
    /// source address, or a source that is not on a connected network.
    #[cfg(feature = "medium-ethernet")]
    ArpInvalid,

    /// A fragmented IP or 6LoWPAN packet could not be reassembled, either because
    /// no reassembly buffer was available or because the fragments were
    /// inconsistent.
    ///
    /// Note: a fragment that is merely *incomplete* (more fragments are still
    /// expected) is not reported, since that is normal and not a drop.
    #[cfg(feature = "_proto-fragmentation")]
    FragmentReassembly,

    /// 6LoWPAN header decompression failed, or fragmentation support is required
    /// but not enabled.
    #[cfg(feature = "proto-sixlowpan")]
    Sixlowpan,
}

/// What the interface did with an inbound packet it would not deliver to a
/// socket.
///
/// Not every "drop" is a silent discard: for several well-formed-but-unhandled
/// cases the stack rejects the packet by sending a reply. This lets a callback
/// distinguish those.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketDropDisposition {
    /// The packet was silently discarded; no reply was generated.
    Dropped,

    /// The packet was rejected and the interface generated a TCP RST in reply.
    #[cfg(feature = "socket-tcp")]
    RepliedTcpReset,

    /// The packet was rejected and the interface generated an ICMP "unreachable"
    /// (destination/port/protocol unreachable) message in reply.
    RepliedIcmpUnreachable,
}

/// Information passed to a [packet drop callback](PacketDropCallback) describing
/// a single inbound packet that was not delivered to a socket.
///
/// Parsed details are provided opportunistically. [`ip_repr`] is populated
/// wherever the IP header had already been parsed when the decision was made;
/// [`src_port`]/[`dst_port`] are populated for TCP/UDP cases where the transport
/// header was parsed; and [`frame`] (raw bytes) is populated where the bytes are
/// available for free. A callback must therefore treat all of these as
/// best-effort context — see [`five_tuple`](Self::five_tuple) for the common
/// case.
///
/// [`ip_repr`]: PacketDropInfo::ip_repr
/// [`src_port`]: PacketDropInfo::src_port
/// [`dst_port`]: PacketDropInfo::dst_port
/// [`frame`]: PacketDropInfo::frame
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PacketDropInfo<'a> {
    /// Why the packet was not delivered.
    pub reason: PacketDropReason,

    /// What the interface did with the packet (dropped, or rejected with a
    /// reply).
    pub disposition: PacketDropDisposition,

    /// The parsed IP header, if the packet had been parsed to the IP layer
    /// before the decision was made. `None` for malformed or pre-IP (e.g.
    /// link-layer) drops.
    pub ip_repr: Option<IpRepr>,

    /// The source transport port, if a TCP/UDP header had been parsed.
    pub src_port: Option<u16>,

    /// The destination transport port, if a TCP/UDP header had been parsed.
    pub dst_port: Option<u16>,

    /// The raw bytes of the offending packet or frame, if available at the drop
    /// point. The slice begins at whichever header was being processed when the
    /// decision was made (for example, the Ethernet frame for a link-layer drop,
    /// or the IP packet for an IP-layer drop). `None` when the bytes are not
    /// readily available.
    pub frame: Option<&'a [u8]>,
}

impl<'a> PacketDropInfo<'a> {
    pub(crate) const fn new(reason: PacketDropReason) -> Self {
        Self {
            reason,
            disposition: PacketDropDisposition::Dropped,
            ip_repr: None,
            src_port: None,
            dst_port: None,
            frame: None,
        }
    }

    pub(crate) const fn with_disposition(mut self, disposition: PacketDropDisposition) -> Self {
        self.disposition = disposition;
        self
    }

    pub(crate) const fn with_ip_repr(mut self, ip_repr: IpRepr) -> Self {
        self.ip_repr = Some(ip_repr);
        self
    }

    #[allow(dead_code)] // not used by every feature combination
    pub(crate) const fn with_ports(mut self, src_port: u16, dst_port: u16) -> Self {
        self.src_port = Some(src_port);
        self.dst_port = Some(dst_port);
        self
    }

    pub(crate) const fn with_frame(mut self, frame: &'a [u8]) -> Self {
        self.frame = Some(frame);
        self
    }

    pub(crate) const fn with_optional_frame(mut self, frame: Option<&'a [u8]>) -> Self {
        self.frame = frame;
        self
    }

    /// The IP protocol (next header) of the offending packet, if its IP header
    /// was parsed.
    pub fn protocol(&self) -> Option<IpProtocol> {
        self.ip_repr.as_ref().map(|repr| repr.next_header())
    }

    /// The source endpoint (address + port) of the offending packet, when both
    /// the IP header and a transport port were available.
    ///
    /// Returns `None` if the IP header was not parsed. The port is `0` when the
    /// IP header was parsed but no transport port was available (e.g. a non
    /// TCP/UDP protocol).
    pub fn source(&self) -> Option<IpEndpoint> {
        self.ip_repr.as_ref().map(|repr| IpEndpoint {
            addr: repr.src_addr(),
            port: self.src_port.unwrap_or(0),
        })
    }

    /// The destination endpoint (address + port) of the offending packet, when
    /// the IP header was available.
    ///
    /// Returns `None` if the IP header was not parsed. The port is `0` when the
    /// IP header was parsed but no transport port was available.
    pub fn destination(&self) -> Option<IpEndpoint> {
        self.ip_repr.as_ref().map(|repr| IpEndpoint {
            addr: repr.dst_addr(),
            port: self.dst_port.unwrap_or(0),
        })
    }

    /// The full 5-tuple (source endpoint, destination endpoint, protocol) of the
    /// offending packet, when its IP header was parsed.
    ///
    /// This is the convenient way to identify *which flow* was not handled — for
    /// example to decide whether to open a proxied connection for it. Returns
    /// `None` for malformed or pre-IP drops, where no IP header is available.
    /// Ports are `0` when the packet was not TCP/UDP.
    pub fn five_tuple(&self) -> Option<FiveTuple> {
        let repr = self.ip_repr.as_ref()?;
        Some(FiveTuple {
            src: IpEndpoint {
                addr: repr.src_addr(),
                port: self.src_port.unwrap_or(0),
            },
            dst: IpEndpoint {
                addr: repr.dst_addr(),
                port: self.dst_port.unwrap_or(0),
            },
            protocol: repr.next_header(),
        })
    }
}

/// The transport 5-tuple identifying an inbound flow, as reported by
/// [`PacketDropInfo::five_tuple`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FiveTuple {
    /// Source address and port. The port is `0` for non-TCP/UDP protocols.
    pub src: IpEndpoint,
    /// Destination address and port. The port is `0` for non-TCP/UDP protocols.
    pub dst: IpEndpoint,
    /// The IP protocol (next header).
    pub protocol: IpProtocol,
}

/// Callback invoked whenever the interface does not deliver an inbound packet to
/// a socket.
///
/// Set with [`Interface::set_packet_drop_callback`]. The callback receives a
/// [`PacketDropInfo`] describing the [reason](PacketDropReason), the
/// [disposition](PacketDropDisposition) (silently dropped, or rejected with a
/// reply), and — where they were parsed for free — the offending packet's IP
/// header, transport ports and/or raw bytes.
///
/// The second argument is the opaque `usize` cookie that was supplied alongside
/// the callback to [`Interface::set_packet_drop_callback`]. The interface never
/// interprets it: use it as an index into your own table, a tag, or (with your
/// own `unsafe`) a pointer back to your application state. This is how the
/// callback reaches your state, since — being a plain `fn` pointer rather than a
/// boxed closure, so that it works in `no_std` builds without an allocator — it
/// cannot capture anything itself.
pub type PacketDropCallback = fn(PacketDropInfo, usize);

impl InterfaceInner {
    /// Notify the configured packet drop callback, if any, that an inbound
    /// packet was not delivered to a socket.
    ///
    /// This is a no-op when no callback has been installed, so it is cheap to
    /// call from every drop site.
    pub(crate) fn report_packet_drop(&self, info: PacketDropInfo) {
        if let Some((callback, cookie)) = self.packet_drop_callback {
            callback(info, cookie);
        }
    }
}
