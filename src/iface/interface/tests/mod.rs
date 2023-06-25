#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "proto-igmp")]
use std::vec::Vec;

use rstest::*;

use super::*;

use crate::iface::Interface;
use crate::phy::{ChecksumCapabilities, Loopback};
use crate::time::Instant;

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

fn setup<'a>(medium: Medium) -> (Interface, SocketSet<'a>, Loopback) {
    let mut device = Loopback::new(medium);

    let config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => HardwareAddress::Ethernet(Default::default()),
        #[cfg(feature = "medium-ip")]
        Medium::Ip => HardwareAddress::Ip,
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => HardwareAddress::Ieee802154(Default::default()),
    });

    let mut iface = Interface::new(config, &mut device, Instant::ZERO);

    #[cfg(feature = "proto-ipv4")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
    }

    #[cfg(feature = "proto-ipv6")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
        });
    }

    (iface, SocketSet::new(vec![]), device)
}

#[cfg(feature = "proto-igmp")]
fn recv_all(device: &mut Loopback, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some((rx, _tx)) = device.receive(timestamp) {
        rx.consume(|pkt| {
            pkts.push(pkt.to_vec());
        });
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
#[cfg(all(feature = "medium-ip", feature = "medium-ethernet"))]
fn test_new_panic() {
    let mut device = Loopback::new(Medium::Ethernet);
    let config = Config::new(HardwareAddress::Ip);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[rstest]
#[cfg(feature = "default")]
fn test_handle_udp_broadcast(
    #[values(Medium::Ip, Medium::Ethernet, Medium::Ieee802154)] medium: Medium,
) {
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
        dst_addr: Ipv6Address::LINK_LOCAL_ALL_NODES,
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
            ip_repr,
            udp_repr,
            false,
            &UDP_PAYLOAD,
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
        Ok((&UDP_PAYLOAD[..], IpEndpoint::new(src_ip.into(), 67).into()))
    );
}
