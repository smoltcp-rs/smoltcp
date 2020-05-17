#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use smoltcp::apps::sntp::Client;
use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache, Routes};
use smoltcp::phy::wait as phy_wait;
use smoltcp::socket::{SocketSet, UdpPacketMetadata, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("SERVER");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let server = IpAddress::from_str(&matches.free[0]).expect("invalid address format");

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let sntp_rx_buffer = UdpSocketBuffer::new([UdpPacketMetadata::EMPTY; 1], vec![0; 900]);
    let sntp_tx_buffer = UdpSocketBuffer::new([UdpPacketMetadata::EMPTY; 1], vec![0; 600]);
    let mut sockets = SocketSet::new(vec![]);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);

    let mut routes_storage = [None; 2];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();

    let mut iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();

    let mut sntp = Client::new(
        &mut sockets,
        sntp_rx_buffer,
        sntp_tx_buffer,
        server,
        Instant::now(),
    );

    loop {
        let timestamp = Instant::now();

        iface
            .poll(&mut sockets, timestamp)
            .map(|_| ())
            .unwrap_or_else(|e| error!("poll error: {}", e));

        let network_time = sntp.poll(&mut sockets, timestamp).unwrap_or_else(|e| {
            error!("sntp: {}", e);
            None
        });

        if let Some(t) = network_time {
            info!("sntp time: {:?}", t);
        }

        let mut timeout = sntp.next_poll(timestamp);

        iface
            .poll_delay(&sockets, timestamp)
            .map(|sockets_timeout| timeout = sockets_timeout);

        phy_wait(fd, Some(timeout)).unwrap_or_else(|e| error!("wait: {}", e));
    }
}
