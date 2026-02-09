use super::*;

#[cfg(feature = "socket-raw-ethernet")]
use crate::socket::raw_ethernet;

#[cfg(feature = "socket-raw-ethernet")]
fn make_frame(ethertype: EthernetProtocol) -> [u8; 18] {
    let mut bytes = [0u8; 18];
    let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
    EthernetRepr {
        src_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        dst_addr: EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
        ethertype,
    }
    .emit(&mut frame);
    frame
        .payload_mut()
        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    bytes
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "socket-raw-ethernet"))]
fn test_raw_ethernet_socket_captures_unknown_ethertype() {
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);

    let rx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let tx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let handle = sockets.add(raw_ethernet::Socket::new(None, rx_buffer, tx_buffer));

    let frame = make_frame(EthernetProtocol::Unknown(0x88b5));

    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            &frame,
            &mut iface.fragments,
        ),
        None
    );

    let socket = sockets.get_mut::<raw_ethernet::Socket>(handle);
    assert!(socket.can_recv());
    assert_eq!(socket.recv(), Ok(&frame[..]));
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "socket-raw-ethernet"))]
fn test_raw_ethernet_socket_ethertype_filter() {
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);

    let rx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let tx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let handle = sockets.add(raw_ethernet::Socket::new(
        Some(EthernetProtocol::Unknown(0x88b5)),
        rx_buffer,
        tx_buffer,
    ));

    let accepted = make_frame(EthernetProtocol::Unknown(0x88b5));
    let rejected = make_frame(EthernetProtocol::Unknown(0x88b6));

    let _ = iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        &accepted,
        &mut iface.fragments,
    );
    let _ = iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        &rejected,
        &mut iface.fragments,
    );

    let socket = sockets.get_mut::<raw_ethernet::Socket>(handle);
    assert!(socket.can_recv());
    assert_eq!(socket.recv(), Ok(&accepted[..]));
    assert!(!socket.can_recv());
}

#[test]
#[cfg(all(feature = "medium-ethernet", feature = "socket-raw-ethernet"))]
fn test_raw_ethernet_socket_egress_transmits_verbatim_frame() {
    use crate::time::Instant;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);

    let rx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let tx_buffer =
        raw_ethernet::PacketBuffer::new(vec![raw_ethernet::PacketMetadata::EMPTY], vec![0; 64]);
    let handle = sockets.add(raw_ethernet::Socket::new(None, rx_buffer, tx_buffer));

    let frame = make_frame(EthernetProtocol::Unknown(0x88b5));
    {
        let socket = sockets.get_mut::<raw_ethernet::Socket>(handle);
        assert_eq!(socket.send_slice(&frame), Ok(()));
    }

    assert_eq!(
        iface.poll(Instant::from_millis(0), &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );

    let transmitted: Vec<Vec<u8>> = device.tx_queue.drain(..).collect();
    assert!(transmitted.iter().any(|pkt| pkt.as_slice() == frame));
}
