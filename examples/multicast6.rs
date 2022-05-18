mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;

use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::wait as phy_wait;
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv6Address};

// Note: If testing with a tap interface in linux, you may need to specify the
// interface index when addressing. E.g.,
//
// ```
// nc -u ff02::1234%tap0 8123
// ```
//
// will send packets to the multicast group we join below on tap0.

const PORT: u16 = 8123;
const GROUP: [u16; 8] = [0xff02, 0, 0, 0, 0, 0, 0, 0x1234];
const LOCAL_ADDR: [u16; 8] = [0xfe80, 0, 0, 0, 0, 0, 0, 0x101];

fn main() {
    utils::setup_logging("warn");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let local_addr = Ipv6Address::from_parts(&LOCAL_ADDR);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addr = IpCidr::new(IpAddress::from(local_addr), 64);
    let mut ipv6_multicast_storage = [None; 1];
    let mut iface = InterfaceBuilder::new(device, vec![])
        .hardware_addr(ethernet_addr.into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs([ip_addr])
        .ipv6_multicast_groups(&mut ipv6_multicast_storage[..])
        .finalize();

    let now = Instant::now();
    // Join a multicast group
    iface
        .join_multicast_group(Ipv6Address::from_parts(&GROUP), now)
        .unwrap();

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 0]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_handle = iface.add_socket(udp_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        let socket = iface.get_socket::<UdpSocket>(udp_handle);
        if !socket.is_open() {
            socket.bind(PORT).unwrap()
        }

        if socket.can_recv() {
            socket
                .recv()
                .map(|(data, sender)| println!("traffic: {} UDP bytes from {}", data.len(), sender))
                .unwrap_or_else(|e| println!("Recv UDP error: {:?}", e));
        }

        phy_wait(fd, iface.poll_delay(timestamp)).expect("wait error");
    }
}
