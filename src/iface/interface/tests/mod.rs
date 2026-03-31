#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[allow(unused)]
use std::vec::Vec;

use crate::tests::setup;

use rstest::*;

use super::*;

use crate::iface::Interface;
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "alloc")]
use crate::phy::Loopback;
use crate::time::Instant;

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

#[allow(unused)]
fn recv_all(device: &mut crate::tests::TestingDevice, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some(pkt) = device.tx_queue.pop_front() {
        pkts.push(pkt)
    }
    pkts
}

#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn emit_ipv6_tcp_packet(repr: &TcpRepr, src: Ipv6Address, dst: Ipv6Address) -> Vec<u8> {
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Tcp,
        payload_len: repr.buffer_len(),
        hop_limit: 64,
    });
    let mut ip_bytes = vec![0u8; ip_repr.buffer_len()];
    ip_repr.emit(&mut ip_bytes, &ChecksumCapabilities::default());
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut ip_bytes[ip_repr.header_len()..]),
        &src.into(),
        &dst.into(),
        &ChecksumCapabilities::default(),
    );
    ip_bytes
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MockTxToken;

impl TxToken for MockTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut junk = [0; 1536];
        f(&mut junk[..len])
    }
}

#[test]
#[should_panic(expected = "The hardware address does not match the medium of the interface.")]
#[cfg(all(feature = "medium-ip", feature = "medium-ethernet", feature = "alloc"))]
fn test_new_panic() {
    let mut device = Loopback::new(Medium::Ethernet);
    let config = Config::new(HardwareAddress::Ip);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn test_handle_udp_broadcast(#[case] medium: Medium) {
    use crate::socket::udp;
    use crate::wire::IpEndpoint;

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _device) = setup(medium);

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);

    let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

    let mut udp_bytes = vec![0u8; 13];
    let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

    let socket_handle = sockets.add(udp_socket);

    #[cfg(feature = "proto-ipv6")]
    let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    #[cfg(feature = "proto-ipv6")]
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: src_ip,
        dst_addr: IPV6_LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: src_ip,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    let dst_addr = ip_repr.dst_addr();

    // Bind the socket to port 68
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert_eq!(socket.bind(68), Ok(()));
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    udp_repr.emit(
        &mut packet,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Packet should be handled by bound UDP socket
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr,
            packet.into_inner(),
        ),
        None
    );

    // Make sure the payload to the UDP packet processed by process_udp is
    // appended to the bound sockets rx_buffer
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            &UDP_PAYLOAD[..],
            udp::UdpMetadata {
                local_address: Some(dst_addr),
                ..IpEndpoint::new(src_ip.into(), 67).into()
            }
        ))
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
pub fn tcp_not_accepted() {
    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(-10001),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];

    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        Some(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Tcp(TcpRepr {
                src_port: 4243,
                dst_port: 4242,
                control: TcpControl::Rst,
                seq_number: TcpSeqNumber(0),
                ack_number: Some(TcpSeqNumber(-10000)),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            })
        ))
    );
    // Unspecified destination address.
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::UNSPECIFIED.into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::UNSPECIFIED,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        None,
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_listen_socket_syn_queue_accept() {
    use crate::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
    use crate::socket::tcp_listener;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);

    // Create a TcpListenSocket with room for 2 pending connections.
    let mut syn_buf = [None; 4];
    let mut accept_buf = [None, None];
    let mut listen = tcp_listener::Socket::new(&mut syn_buf, &mut accept_buf);
    listen.listen(4243).unwrap();
    let listen_handle = sockets.add(listen);

    let syn = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let client = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let server = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    // Step 1: Send SYN → expect SYN-ACK (half-open created in SYN queue).
    device
        .rx_queue
        .push_back(emit_ipv6_tcp_packet(&syn, client, server));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Listen socket should NOT have any pending connection yet.
    assert!(
        !sockets
            .get::<tcp_listener::Socket>(listen_handle)
            .can_accept()
    );

    // A SYN|ACK should have been sent.
    let synack_ip = device
        .tx_queue
        .pop_front()
        .expect("expected SYN|ACK packet");
    let synack_ip = Ipv6Packet::new_unchecked(&synack_ip);
    let synack_tcp = TcpPacket::new_unchecked(synack_ip.payload());
    assert!(synack_tcp.syn());
    assert!(synack_tcp.ack());

    // Step 2: Complete the handshake with ACK.
    let ack = TcpRepr {
        src_port: syn.src_port,
        dst_port: syn.dst_port,
        control: TcpControl::None,
        seq_number: synack_tcp.ack_number(),
        ack_number: Some(synack_tcp.seq_number() + 1),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    device
        .rx_queue
        .push_back(emit_ipv6_tcp_packet(&ack, client, server));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Now the listen socket should have a pending connection.
    assert!(
        sockets
            .get::<tcp_listener::Socket>(listen_handle)
            .can_accept()
    );

    // Step 3: Accept and create a full TcpSocket.
    let pending = sockets
        .get_mut::<tcp_listener::Socket>(listen_handle)
        .accept()
        .expect("expected pending connection");
    assert_eq!(pending.remote.port, 4242);
    assert_eq!(pending.local.port, 4243);

    let mut tcp = TcpSocket::new(
        SocketBuffer::new(vec![0; 1024]),
        SocketBuffer::new(vec![0; 1024]),
    );
    tcp.accept(pending).unwrap();
    assert_eq!(tcp.state(), TcpState::Established);
    sockets.add(tcp);
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_listen_socket_retransmits_synack() {
    use crate::socket::tcp_listener;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);

    let mut syn_buf = [None; 1];
    let mut accept_buf = [None; 1];
    let mut listen = tcp_listener::Socket::new(&mut syn_buf, &mut accept_buf);
    listen.listen(4243).unwrap();
    sockets.add(listen);

    let client = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let server = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let syn = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    device
        .rx_queue
        .push_back(emit_ipv6_tcp_packet(&syn, client, server));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let first = device.tx_queue.pop_front().expect("expected first SYN-ACK");

    iface.poll(Instant::from_millis(1000), &mut device, &mut sockets);
    let second = device
        .tx_queue
        .pop_front()
        .expect("expected retransmitted SYN-ACK");

    let first = Ipv6Packet::new_unchecked(&first);
    let second = Ipv6Packet::new_unchecked(&second);
    let first_tcp = TcpPacket::new_unchecked(first.payload());
    let second_tcp = TcpPacket::new_unchecked(second.payload());
    assert_eq!(first_tcp.seq_number(), second_tcp.seq_number());
    assert_eq!(first_tcp.ack_number(), second_tcp.ack_number());
    assert!(second_tcp.syn());
    assert!(second_tcp.ack());
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_listen_socket_drops_syn_when_syn_queue_full() {
    use crate::socket::tcp_listener;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);

    let mut syn_buf = [None; 1];
    let mut accept_buf = [None; 1];
    let mut listen = tcp_listener::Socket::new(&mut syn_buf, &mut accept_buf);
    listen.listen(4243).unwrap();
    sockets.add(listen);

    let server = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let syn1 = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let syn2 = TcpRepr {
        src_port: 4343,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(200),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    device.rx_queue.push_back(emit_ipv6_tcp_packet(
        &syn1,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
        server,
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    device.tx_queue.clear();

    device.rx_queue.push_back(emit_ipv6_tcp_packet(
        &syn2,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3),
        server,
    ));
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);

    assert!(
        device.tx_queue.is_empty(),
        "queue-full SYN should be dropped, not RSTed"
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
fn tcp_listen_socket_recycles_expired_half_open() {
    use crate::socket::tcp_listener;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);

    let mut syn_buf = [None; 1];
    let mut accept_buf = [None; 1];
    let mut listen = tcp_listener::Socket::new(&mut syn_buf, &mut accept_buf);
    listen.listen(4243).unwrap();
    sockets.add(listen);

    let server = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let syn1 = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let syn2 = TcpRepr {
        src_port: 4343,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(200),
        ack_number: None,
        window_len: 256,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: true,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    device.rx_queue.push_back(emit_ipv6_tcp_packet(
        &syn1,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
        server,
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    device.tx_queue.clear();

    device.rx_queue.push_back(emit_ipv6_tcp_packet(
        &syn2,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3),
        server,
    ));
    iface.poll(Instant::from_millis(75_001), &mut device, &mut sockets);

    let synack = device
        .tx_queue
        .pop_front()
        .expect("expired half-open should free a slot for a new SYN");
    let synack = Ipv6Packet::new_unchecked(&synack);
    let synack_tcp = TcpPacket::new_unchecked(synack.payload());
    assert_eq!(synack_tcp.dst_port(), 4343);
    assert!(synack_tcp.syn());
    assert!(synack_tcp.ack());
}
