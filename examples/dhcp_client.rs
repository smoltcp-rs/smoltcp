mod utils;

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, Ipv4Address, IpCidr, Ipv4Cidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, Routes};
use smoltcp::socket::{SocketSet, RawSocketBuffer, RawPacketMetadata};
use smoltcp::time::Instant;
use smoltcp::dhcp::Dhcpv4Client;

fn main() {
    #[cfg(feature = "log")]
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)];
    let mut routes_storage = [None; 1];
    let routes = Routes::new(&mut routes_storage[..]);
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .routes(routes)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let dhcp_rx_buffer = RawSocketBuffer::new(
        [RawPacketMetadata::EMPTY; 1],
        vec![0; 900]
    );
    let dhcp_tx_buffer = RawSocketBuffer::new(
        [RawPacketMetadata::EMPTY; 1],
        vec![0; 600]
    );
    let mut dhcp = Dhcpv4Client::new(&mut sockets, dhcp_rx_buffer, dhcp_tx_buffer, Instant::now());
    let mut prev_cidr = Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0);
    loop {
        let timestamp = Instant::now();
        iface.poll(&mut sockets, timestamp)
            .map(|_| ())
            .unwrap_or_else(|e| println!("Poll: {:?}", e));
        let config = dhcp.poll(&mut iface, &mut sockets, timestamp)
            .unwrap_or_else(|e| {
                println!("DHCP: {:?}", e);
                None
            });
        config.map(|config| {
            println!("DHCP config: {:?}", config);
            match config.address {
                Some(cidr) => if cidr != prev_cidr {
                    iface.update_ip_addrs(|addrs| {
                        addrs.iter_mut().nth(0)
                            .map(|addr| {
                                *addr = IpCidr::Ipv4(cidr);
                            });
                    });
                    prev_cidr = cidr;
                    println!("Assigned a new IPv4 address: {}", cidr);
                }
                _ => {}
            }

            config.router.map(|router| iface.routes_mut()
                              .add_default_ipv4_route(router.into())
                              .unwrap()
            );
            iface.routes_mut()
                .update(|routes_map| {
                    routes_map.get(&IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0))
                        .map(|default_route| {
                            println!("Default gateway: {}", default_route.via_router);
                        });
                });

            if config.dns_servers.iter().any(|s| s.is_some()) {
                println!("DNS servers:");
                for dns_server in config.dns_servers.iter().filter_map(|s| *s) {
                    println!("- {}", dns_server);
                }
            }
        });

        let mut timeout = dhcp.next_poll(timestamp);
        iface.poll_delay(&sockets, timestamp)
            .map(|sockets_timeout| timeout = sockets_timeout);
        phy_wait(fd, Some(timeout))
            .unwrap_or_else(|e| println!("Wait: {:?}", e));
    }
}
