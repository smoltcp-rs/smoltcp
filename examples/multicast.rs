mod utils;

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use log::debug;

use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, IpVersion, IpProtocol, IpAddress, IpCidr, Ipv4Address,
                    Ipv4Packet, IgmpPacket, IgmpRepr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::{SocketSet,
                      RawSocket, RawSocketBuffer, RawPacketMetadata,
                      UdpSocket, UdpSocketBuffer, UdpPacketMetadata};
use smoltcp::time::Instant;

const MDNS_PORT: u16 = 5353;
const MDNS_GROUP: [u8; 4] = [224, 0, 0, 251];

fn main() {
    utils::setup_logging("warn");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches,
                                                 device,
                                                 /*loopback=*/
                                                 false);
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let local_addr = Ipv4Address::new(192, 168, 69, 2);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addr = IpCidr::new(IpAddress::from(local_addr), 24);
    let mut ipv4_multicast_storage = [None; 1];
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs([ip_addr])
            .ipv4_multicast_groups(&mut ipv4_multicast_storage[..])
            .finalize();

    let now = Instant::now();
    // Join a multicast group to receive mDNS traffic
    iface.join_multicast_group(Ipv4Address::from_bytes(&MDNS_GROUP), now).unwrap();

    let mut sockets = SocketSet::new(vec![]);

    // Must fit at least one IGMP packet
    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; 2], vec![0; 512]);
    // Will not send IGMP
    let raw_tx_buffer = RawSocketBuffer::new(vec![], vec![]);
    let raw_socket = RawSocket::new(
        IpVersion::Ipv4, IpProtocol::Igmp,
        raw_rx_buffer, raw_tx_buffer
    );
    let raw_handle = sockets.add(raw_socket);

    // Must fit mDNS payload of at least one packet
    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
    // Will not send mDNS
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 0]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_handle = sockets.add(udp_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}",e);
            }
        }

        {
            let mut socket = sockets.get::<RawSocket>(raw_handle);

            if socket.can_recv() {
                // For display purposes only - normally we wouldn't process incoming IGMP packets
                // in the application layer
                socket.recv()
                    .and_then(|payload| Ipv4Packet::new_checked(payload))
                    .and_then(|ipv4_packet| IgmpPacket::new_checked(ipv4_packet.payload()))
                    .and_then(|igmp_packet| IgmpRepr::parse(&igmp_packet))
                    .map(|igmp_repr| println!("IGMP packet: {:?}", igmp_repr))
                    .unwrap_or_else(|e| println!("Recv IGMP error: {:?}", e));
            }
        }
        {
            let mut socket = sockets.get::<UdpSocket>(udp_handle);
            if !socket.is_open() {
                socket.bind(MDNS_PORT).unwrap()
            }

            if socket.can_recv() {
                socket.recv()
                    .map(|(data, sender)| println!("mDNS traffic: {} UDP bytes from {}", data.len(), sender))
                    .unwrap_or_else(|e| println!("Recv UDP error: {:?}", e));
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
