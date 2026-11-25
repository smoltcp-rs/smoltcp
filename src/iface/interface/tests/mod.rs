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
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv4"))]
pub fn tcp_listen_drops_unspecified_src() {
    use crate::socket::tcp;

    let (mut iface, mut sockets, _) = setup(Medium::Ip);

    let tcp_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(tcp_socket);
    sockets.get_mut::<tcp::Socket>(handle).listen(1234).unwrap();

    let tcp = TcpRepr {
        src_port: 65000,
        dst_port: 1234,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv4Address::UNSPECIFIED.into(),
        &Ipv4Address::new(127, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    let reply = iface.inner.process_tcp(
        &mut sockets,
        false,
        IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }),
        &tcp_bytes,
    );

    assert_eq!(reply, None);
    assert!(sockets.get_mut::<tcp::Socket>(handle).is_listening());
}

#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv4"))]
mod tcp_connection_precedence {
    use super::*;

    use crate::iface::{SocketHandle, SocketSet};
    use crate::socket::tcp;
    use crate::wire::IpEndpoint;

    const SERVER_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const CLIENT_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const SERVER_PORT: u16 = 80;
    const CLIENT_PORT: u16 = 50_000;
    const CLIENT_ISN: TcpSeqNumber = TcpSeqNumber(1_000);

    struct TestContext {
        iface: Interface,
        sockets: SocketSet<'static>,
        connection: SocketHandle,
        listener: SocketHandle,
        server_isn: TcpSeqNumber,
    }

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        )
    }

    fn process_segment(
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        src_port: u16,
        seq_number: TcpSeqNumber,
        ack_number: Option<TcpSeqNumber>,
        control: TcpControl,
        payload: &[u8],
    ) -> Option<(TcpControl, TcpSeqNumber, Option<TcpSeqNumber>)> {
        let tcp = TcpRepr {
            src_port,
            dst_port: SERVER_PORT,
            control,
            seq_number,
            ack_number,
            window_len: 1024,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: CLIENT_ADDR,
            dst_addr: SERVER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut tcp_bytes = vec![0; tcp.buffer_len()];
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut tcp_bytes),
            &CLIENT_ADDR.into(),
            &SERVER_ADDR.into(),
            &ChecksumCapabilities::default(),
        );

        iface
            .inner
            .process_tcp(sockets, false, IpRepr::Ipv4(ip), &tcp_bytes)
            .map(|packet| match packet.payload() {
                IpPayload::Tcp(tcp) => (tcp.control, tcp.seq_number, tcp.ack_number),
                _ => unreachable!(),
            })
    }

    fn dispatch_segment(
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        handle: SocketHandle,
    ) -> Option<(TcpControl, TcpSeqNumber, Option<TcpSeqNumber>)> {
        let mut response = None;
        sockets
            .get_mut::<tcp::Socket>(handle)
            .dispatch(&mut iface.inner, |_, _, (_, tcp)| {
                response = Some((tcp.control, tcp.seq_number, tcp.ack_number));
                Ok::<_, ()>(())
            })
            .unwrap();
        response
    }

    fn setup_connection(established: bool) -> TestContext {
        let (mut iface, mut sockets, _) = setup(Medium::Ip);

        // Keep slot 0 occupied while the connection is created in slot 1.
        let placeholder = sockets.add(socket());
        let connection = sockets.add(socket());
        sockets
            .get_mut::<tcp::Socket>(connection)
            .listen(SERVER_PORT)
            .unwrap();

        assert_eq!(
            process_segment(
                &mut iface,
                &mut sockets,
                CLIENT_PORT,
                CLIENT_ISN,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        let syn_ack = dispatch_segment(&mut iface, &mut sockets, connection).unwrap();
        assert_eq!(syn_ack.0, TcpControl::Syn);
        assert_eq!(syn_ack.2, Some(CLIENT_ISN + 1));

        if established {
            assert_eq!(
                process_segment(
                    &mut iface,
                    &mut sockets,
                    CLIENT_PORT,
                    CLIENT_ISN + 1,
                    Some(syn_ack.1 + 1),
                    TcpControl::None,
                    &[],
                ),
                None
            );
        }

        // Reuse slot 0 for a listener on the same local port.
        sockets.remove(placeholder);
        let listener = sockets.add(socket());
        sockets
            .get_mut::<tcp::Socket>(listener)
            .listen(SERVER_PORT)
            .unwrap();

        TestContext {
            iface,
            sockets,
            connection,
            listener,
            server_isn: syn_ack.1,
        }
    }

    fn enter_time_wait(cx: &mut TestContext, client_seq: TcpSeqNumber) -> TcpSeqNumber {
        cx.sockets.get_mut::<tcp::Socket>(cx.connection).close();
        let fin = dispatch_segment(&mut cx.iface, &mut cx.sockets, cx.connection).unwrap();
        assert_eq!(fin.0, TcpControl::Fin);

        let successor_isn = fin.1 + 1 + 65_535 + 2;
        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                client_seq,
                Some(fin.1 + 1),
                TcpControl::Fin,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::TimeWait
        );
        successor_isn
    }

    #[test]
    fn repeated_syn_prefers_syn_received_connection() {
        let mut cx = setup_connection(false);

        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::SynReceived
        );
        assert_eq!(
            cx.sockets
                .get::<tcp::Socket>(cx.connection)
                .remote_endpoint(),
            Some(IpEndpoint::new(CLIENT_ADDR.into(), CLIENT_PORT))
        );
        assert!(cx.sockets.get::<tcp::Socket>(cx.listener).is_listening());
    }

    #[test]
    fn repeated_syn_prefers_established_connection() {
        let mut cx = setup_connection(true);

        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::Established
        );
        assert!(cx.sockets.get::<tcp::Socket>(cx.listener).is_listening());
    }

    #[test]
    fn listener_accepts_syn_for_new_connection() {
        const NEW_CLIENT_PORT: u16 = CLIENT_PORT + 1;
        const NEW_CLIENT_ISN: TcpSeqNumber = TcpSeqNumber(2_000);

        let mut cx = setup_connection(true);
        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                NEW_CLIENT_PORT,
                NEW_CLIENT_ISN,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        let syn_ack = dispatch_segment(&mut cx.iface, &mut cx.sockets, cx.listener).unwrap();

        assert_eq!(syn_ack.0, TcpControl::Syn);
        assert_eq!(syn_ack.2, Some(NEW_CLIENT_ISN + 1));
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.listener).state(),
            tcp::State::SynReceived
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.listener).remote_endpoint(),
            Some(IpEndpoint::new(CLIENT_ADDR.into(), NEW_CLIENT_PORT))
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::Established
        );
    }

    #[test]
    fn syn_reopens_time_wait_connection_through_listener() {
        let mut cx = setup_connection(true);
        let successor_isn = enter_time_wait(&mut cx, CLIENT_ISN + 1);
        let new_client_isn = CLIENT_ISN + 100_000;

        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                new_client_isn,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        let syn_ack = dispatch_segment(&mut cx.iface, &mut cx.sockets, cx.listener).unwrap();

        assert_eq!(syn_ack.0, TcpControl::Syn);
        assert_eq!(syn_ack.1, successor_isn);
        assert_eq!(syn_ack.2, Some(new_client_isn + 1));
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.listener).state(),
            tcp::State::SynReceived
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.listener).remote_endpoint(),
            Some(IpEndpoint::new(CLIENT_ADDR.into(), CLIENT_PORT))
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::Closed
        );
    }

    #[test]
    fn old_duplicate_syn_does_not_reopen_time_wait() {
        let mut cx = setup_connection(true);
        enter_time_wait(&mut cx, CLIENT_ISN + 1);

        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::TimeWait
        );
        assert!(cx.sockets.get::<tcp::Socket>(cx.listener).is_listening());
    }

    #[test]
    fn syn_without_listener_keeps_time_wait() {
        let mut cx = setup_connection(true);
        enter_time_wait(&mut cx, CLIENT_ISN + 1);
        cx.sockets.remove(cx.listener);

        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN + 100_000,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::TimeWait
        );
    }

    #[test]
    fn time_wait_with_unread_data_is_not_reopened() {
        const PAYLOAD: &[u8] = b"unread";

        let mut cx = setup_connection(true);
        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN + 1,
                Some(cx.server_isn + 1),
                TcpControl::Psh,
                PAYLOAD,
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).recv_queue(),
            PAYLOAD.len()
        );

        enter_time_wait(&mut cx, CLIENT_ISN + 1 + PAYLOAD.len());
        assert_eq!(
            process_segment(
                &mut cx.iface,
                &mut cx.sockets,
                CLIENT_PORT,
                CLIENT_ISN + 100_000,
                None,
                TcpControl::Syn,
                &[],
            ),
            None
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).state(),
            tcp::State::TimeWait
        );
        assert_eq!(
            cx.sockets.get::<tcp::Socket>(cx.connection).recv_queue(),
            PAYLOAD.len()
        );
        assert!(cx.sockets.get::<tcp::Socket>(cx.listener).is_listening());
    }
}
