#[macro_use]
extern crate log;
extern crate byteorder;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use smoltcp::iface::{InterfaceBuilder, NeighborCache, Routes};
use smoltcp::phy::Device;
use smoltcp::phy::{wait as phy_wait, Medium};
use smoltcp::socket::DnsSocket;
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address,
};
use smoltcp::Error;
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;

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

    let servers = &[
        Ipv4Address::new(8, 8, 4, 4).into(),
        Ipv4Address::new(8, 8, 8, 8).into(),
    ];
    let dns_socket = DnsSocket::new(servers, vec![]);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let src_ipv6 = IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
        IpCidr::new(src_ipv6, 64),
        IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
    ];
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let default_v6_gw = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100);
    let mut routes_storage = [None; 2];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    routes.add_default_ipv6_route(default_v6_gw).unwrap();

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(device, vec![])
        .ip_addrs(ip_addrs)
        .routes(routes);
    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(HardwareAddress::Ethernet(ethernet_addr))
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize();

    let dns_handle = iface.add_socket(dns_socket);

    //let name = b"\x08facebook\x03com\x00";
    //let name = b"\x03www\x08facebook\x03com\x00";
    //let name = b"\x06reddit\x03com\x00";
    let name = b"\x09rust-lang\x03org\x00";

    let (socket, cx) = iface.get_socket_and_context::<DnsSocket>(dns_handle);
    let query = socket.start_query(cx, name).unwrap();

    loop {
        let timestamp = Instant::now();
        debug!("timestamp {:?}", timestamp);

        match iface.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        match iface
            .get_socket::<DnsSocket>(dns_handle)
            .get_query_result(query)
        {
            Ok(addrs) => {
                println!("Query done: {:?}", addrs);
                break;
            }
            Err(Error::Exhausted) => {} // not done yet
            Err(e) => panic!("query failed: {:?}", e),
        }

        phy_wait(fd, iface.poll_delay(timestamp)).expect("wait error");
    }
}
