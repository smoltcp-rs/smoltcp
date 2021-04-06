#![allow(clippy::option_map_unit_fn)]
mod utils;

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use log::*;

use smoltcp::phy::{Device, Medium, wait as phy_wait};
use smoltcp::wire::{EthernetAddress, Ipv4Address, IpCidr, Ipv4Cidr};
use smoltcp::iface::{NeighborCache, InterfaceBuilder, Interface, Routes};
use smoltcp::socket::{SocketSet, Dhcpv4Socket, Dhcpv4Event};
use smoltcp::time::Instant;

fn main() {
    #[cfg(feature = "log")]
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)];
    let mut routes_storage = [None; 1];
    let routes = Routes::new(&mut routes_storage[..]);

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs)
            .routes(routes);
    if medium == Medium::Ethernet {
        builder = builder
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize();

    let mut sockets = SocketSet::new(vec![]);
    let dhcp_handle = sockets.add(Dhcpv4Socket::new());

    loop {
        let timestamp = Instant::now();
        if let Err(e) = iface.poll(&mut sockets, timestamp) {
            debug!("poll error: {}", e);
        }

        match sockets.get::<Dhcpv4Socket>(dhcp_handle).poll() {
            Dhcpv4Event::NoChange => {}
            Dhcpv4Event::Configured(config) => {
                debug!("DHCP config acquired!");

                debug!("IP address:      {}", config.address);
                set_ipv4_addr(&mut iface, config.address);

                if let Some(router) = config.router {
                    debug!("Default gateway: {}", router);
                    iface.routes_mut().add_default_ipv4_route(router).unwrap();
                } else {
                    debug!("Default gateway: None");
                    iface.routes_mut().remove_default_ipv4_route();
                }

                for (i, s) in config.dns_servers.iter().enumerate() {
                    if let Some(s) = s {
                        debug!("DNS server {}:    {}", i, s);
                    }
                }
            }
            Dhcpv4Event::Deconfigured => {
                debug!("DHCP lost config!");
                set_ipv4_addr(&mut iface, Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                iface.routes_mut().remove_default_ipv4_route();
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}

fn set_ipv4_addr<DeviceT>(iface: &mut Interface<'_, DeviceT>, cidr: Ipv4Cidr)
    where DeviceT: for<'d> Device<'d>
{
    iface.update_ip_addrs(|addrs| {
        let dest = addrs.iter_mut().next().unwrap();
        *dest = IpCidr::Ipv4(cidr);
    });
}

