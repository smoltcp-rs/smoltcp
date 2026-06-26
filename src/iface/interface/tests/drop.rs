//! Tests for the inbound packet drop / non-delivery callback.

use super::*;

use core::cell::RefCell;

use crate::tests::setup;

/// An owned, `'static` copy of the parts of a [`PacketDropInfo`] we want to
/// assert on (the real struct borrows the frame, so it can't be stored), plus
/// the opaque cookie that was passed to the callback.
#[derive(Debug, Clone, PartialEq)]
struct RecordedDrop {
    reason: PacketDropReason,
    disposition: PacketDropDisposition,
    five_tuple: Option<FiveTuple>,
    had_frame: bool,
    cookie: usize,
}

thread_local! {
    static RECORDED: RefCell<Vec<RecordedDrop>> = const { RefCell::new(Vec::new()) };
}

/// The cookie we hand to the interface; the callback must receive it verbatim.
const TEST_COOKIE: usize = 0xdead_beef;

fn record_drop(info: PacketDropInfo, cookie: usize) {
    RECORDED.with(|r| {
        r.borrow_mut().push(RecordedDrop {
            reason: info.reason,
            disposition: info.disposition,
            five_tuple: info.five_tuple(),
            had_frame: info.frame.is_some(),
            cookie,
        })
    });
}

fn take_recorded() -> Vec<RecordedDrop> {
    RECORDED.with(|r| core::mem::take(&mut *r.borrow_mut()))
}

fn clear_recorded() {
    RECORDED.with(|r| r.borrow_mut().clear());
}

/// A TCP segment for us that matches no socket is dropped with a TCP RST reply,
/// and the callback reports the flow's 5-tuple.
#[cfg(feature = "socket-tcp")]
#[test]
fn test_drop_tcp_no_socket() {
    use crate::wire::{TcpControl, TcpRepr, TcpSeqNumber};

    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    let tcp_repr = TcpRepr {
        src_port: 49500,
        dst_port: 80,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1500,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    });

    let mut bytes = vec![0xa5u8; tcp_repr.buffer_len()];
    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(&mut bytes),
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        &ChecksumCapabilities::default(),
    );

    // Not handled by a socket -> a RST reply is generated.
    let reply = iface
        .inner
        .process_tcp(&mut sockets, false, ip_repr, &bytes);
    assert!(reply.is_some());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    let drop = &recorded[0];
    assert_eq!(drop.reason, PacketDropReason::TcpNoSocket);
    assert_eq!(drop.disposition, PacketDropDisposition::RepliedTcpReset);
    // The opaque cookie is passed back to the callback verbatim.
    assert_eq!(drop.cookie, TEST_COOKIE);
    let ft = drop.five_tuple.expect("five-tuple should be present");
    assert_eq!(ft.protocol, IpProtocol::Tcp);
    assert_eq!(ft.src.addr, IpAddress::v4(192, 168, 1, 2));
    assert_eq!(ft.src.port, 49500);
    assert_eq!(ft.dst.addr, IpAddress::v4(192, 168, 1, 1));
    assert_eq!(ft.dst.port, 80);
}

/// A UDP datagram for us that matches no socket is dropped with an ICMP port
/// unreachable reply, and the callback reports the flow's 5-tuple.
#[cfg(feature = "socket-udp")]
#[test]
fn test_drop_udp_no_socket() {
    use crate::wire::UdpRepr;

    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    let udp_repr = UdpRepr {
        src_port: 12345,
        dst_port: 54321,
    };
    static PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + PAYLOAD.len(),
        hop_limit: 64,
    });

    let mut bytes = vec![0u8; udp_repr.header_len() + PAYLOAD.len()];
    udp_repr.emit(
        &mut UdpPacket::new_unchecked(&mut bytes),
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        PAYLOAD.len(),
        |buf| buf.copy_from_slice(&PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    let reply =
        iface
            .inner
            .process_udp(&mut sockets, PacketMeta::default(), false, ip_repr, &bytes);
    assert!(reply.is_some());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    let drop = &recorded[0];
    assert_eq!(drop.reason, PacketDropReason::UdpNoSocket);
    assert_eq!(
        drop.disposition,
        PacketDropDisposition::RepliedIcmpUnreachable
    );
    let ft = drop.five_tuple.expect("five-tuple should be present");
    assert_eq!(ft.protocol, IpProtocol::Udp);
    assert_eq!(ft.src.port, 12345);
    assert_eq!(ft.dst.port, 54321);
}

/// A well-formed IP packet for us carrying a protocol with no socket / handler
/// is dropped with an ICMP unreachable reply.
#[test]
fn test_drop_unknown_protocol() {
    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 64,
    });
    let mut bytes = vec![0u8; repr.buffer_len()];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    let reply = iface.inner.process_ipv4(
        &mut sockets,
        PacketMeta::default(),
        HardwareAddress::default(),
        &frame,
        &mut iface.fragments,
    );
    assert!(reply.is_some());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].reason, PacketDropReason::UnknownTransportProtocol);
    assert_eq!(
        recorded[0].disposition,
        PacketDropDisposition::RepliedIcmpUnreachable
    );
    let ft = recorded[0].five_tuple.expect("five-tuple present");
    assert_eq!(ft.protocol, IpProtocol::Unknown(0x0c));
    // No transport header was parsed, so ports default to 0.
    assert_eq!(ft.src.port, 0);
    assert_eq!(ft.dst.port, 0);
}

/// An IP packet whose destination is neither ours nor routable is silently
/// dropped, and the callback reports it with no reply.
#[test]
fn test_drop_not_for_us_no_route() {
    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    // Destination is a unicast address that is not ours and has no route.
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(10, 9, 8, 7),
        next_header: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    });
    let mut bytes = vec![0u8; repr.buffer_len()];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    let reply = iface.inner.process_ipv4(
        &mut sockets,
        PacketMeta::default(),
        HardwareAddress::default(),
        &frame,
        &mut iface.fragments,
    );
    // Silently dropped, no reply.
    assert!(reply.is_none());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].reason, PacketDropReason::NoRoute);
    assert_eq!(recorded[0].disposition, PacketDropDisposition::Dropped);
    assert_eq!(
        recorded[0].five_tuple.map(|ft| ft.dst.addr),
        Some(IpAddress::v4(10, 9, 8, 7))
    );
}

/// A malformed IP packet is reported as a `Malformed` drop with the raw frame
/// bytes attached and no parsed 5-tuple.
#[test]
fn test_drop_malformed() {
    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    // An IPv4 header claiming a total length far larger than the buffer fails
    // `Ipv4Repr::parse`.
    let mut bytes = vec![0u8; 20];
    bytes[0] = 0x45; // version 4, IHL 5
    bytes[3] = 0xff; // total length = 255, but buffer is only 20 bytes
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    let reply = iface.inner.process_ipv4(
        &mut sockets,
        PacketMeta::default(),
        HardwareAddress::default(),
        &frame,
        &mut iface.fragments,
    );
    assert!(reply.is_none());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].reason, PacketDropReason::Malformed);
    assert_eq!(recorded[0].disposition, PacketDropDisposition::Dropped);
    assert!(recorded[0].five_tuple.is_none());
}

/// No callback is invoked for a packet that is delivered to a socket, and
/// removing the callback stops notifications.
#[cfg(feature = "socket-udp")]
#[test]
fn test_no_drop_when_delivered_and_callback_removable() {
    use crate::socket::udp;
    use crate::wire::UdpRepr;

    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    // Bind a UDP socket on the destination port.
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(54321).unwrap();
    let handle = sockets.add(socket);

    let udp_repr = UdpRepr {
        src_port: 12345,
        dst_port: 54321,
    };
    static PAYLOAD: [u8; 4] = [1, 2, 3, 4];
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + PAYLOAD.len(),
        hop_limit: 64,
    });
    let mut bytes = vec![0u8; udp_repr.header_len() + PAYLOAD.len()];
    udp_repr.emit(
        &mut UdpPacket::new_unchecked(&mut bytes),
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        PAYLOAD.len(),
        |buf| buf.copy_from_slice(&PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_udp(
        &mut sockets,
        PacketMeta::default(),
        false,
        ip_repr,
        &bytes,
    );

    // The datagram was delivered to the socket: no drop reported.
    assert!(take_recorded().is_empty());
    let _ = handle;

    // Removing the callback stops further notifications.
    iface.set_packet_drop_callback(None);
    assert!(iface.packet_drop_callback().is_none());
}

/// An ICMP message that no socket handled and that the stack does not answer
/// (here, an unsolicited echo *reply*) is reported as `IcmpUnhandled`, dropped
/// with no reply.
#[test]
fn test_drop_icmp_unhandled() {
    use crate::wire::{Icmpv4Packet, Icmpv4Repr};

    clear_recorded();
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    iface.set_packet_drop_callback(Some((record_drop, TEST_COOKIE)));

    // Build an ICMP echo *reply* (which we never solicited) addressed to us.
    static ECHO_DATA: [u8; 4] = [b'p', b'i', b'n', b'g'];
    let echo_reply = Icmpv4Repr::EchoReply {
        ident: 0x1234,
        seq_no: 1,
        data: &ECHO_DATA,
    };
    let mut icmp_bytes = vec![0u8; echo_reply.buffer_len()];
    echo_reply.emit(
        &mut Icmpv4Packet::new_unchecked(&mut icmp_bytes),
        &ChecksumCapabilities::default(),
    );

    let ipv4_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Icmp,
        payload_len: echo_reply.buffer_len(),
        hop_limit: 64,
    };

    let reply = iface
        .inner
        .process_icmpv4(&mut sockets, ipv4_repr, &icmp_bytes);
    // Echo replies are ignored: no reply generated.
    assert!(reply.is_none());

    let recorded = take_recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].reason, PacketDropReason::IcmpUnhandled);
    assert_eq!(recorded[0].disposition, PacketDropDisposition::Dropped);
    assert_eq!(recorded[0].cookie, TEST_COOKIE);
    assert_eq!(
        recorded[0].five_tuple.map(|ft| ft.protocol),
        Some(IpProtocol::Icmp)
    );
}

/// The opaque cookie is stored and returned by the getter, and can be used as an
/// index to route drops into per-context buckets (the canonical "user data" use
/// case).
#[test]
fn test_cookie_as_index() {
    // Per-context drop counters; the cookie selects which one to bump.
    thread_local! {
        static COUNTERS: RefCell<[usize; 4]> = const { RefCell::new([0; 4]) };
    }

    fn count_by_cookie(_info: PacketDropInfo, cookie: usize) {
        COUNTERS.with(|c| c.borrow_mut()[cookie] += 1);
    }

    let (mut iface, mut sockets, _device) = setup(Medium::Ip);

    // Install the callback with cookie = 2 (an index into COUNTERS).
    iface.set_packet_drop_callback(Some((count_by_cookie, 2)));
    assert_eq!(
        iface.packet_drop_callback().map(|(_, cookie)| cookie),
        Some(2)
    );

    // Drive a packet that gets dropped (destination not for us, no route).
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(10, 9, 8, 7),
        next_header: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    });
    let mut bytes = vec![0u8; repr.buffer_len()];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);
    iface.inner.process_ipv4(
        &mut sockets,
        PacketMeta::default(),
        HardwareAddress::default(),
        &frame,
        &mut iface.fragments,
    );

    // Only bucket 2 (our cookie) was incremented.
    COUNTERS.with(|c| {
        let c = c.borrow();
        assert_eq!(c[2], 1);
        assert_eq!(c[0], 0);
        assert_eq!(c[1], 0);
        assert_eq!(c[3], 0);
    });
}
