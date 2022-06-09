mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::str::{self, FromStr};

#[cfg(any(
    feature = "proto-sixlowpan-fragmentation",
    feature = "proto-ipv4-fragmentation"
))]
use smoltcp::iface::FragmentsCache;

use smoltcp::iface::{InterfaceBuilder, NeighborCache, Routes, SocketSet};
use smoltcp::phy::{wait as phy_wait, Device, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("ADDRESS");
    free.push("PORT");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);

    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let address = IpAddress::from_str(&matches.free[0]).expect("invalid address format");
    let port = u16::from_str(&matches.free[1]).expect("invalid port format");

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1500]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1500]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 2), 24)];
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new().ip_addrs(ip_addrs).routes(routes);

    #[cfg(feature = "proto-ipv4-fragmentation")]
    {
        let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
        builder = builder.ipv4_fragments_cache(ipv4_frag_cache);
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    let mut out_packet_buffer = [0u8; 1280];
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    {
        let sixlowpan_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
        builder = builder
            .sixlowpan_fragments_cache(sixlowpan_frag_cache)
            .sixlowpan_out_packet_cache(&mut out_packet_buffer[..]);
    }

    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(ethernet_addr.into())
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize(&mut device);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
    socket
        .connect(iface.context(), (address, port), 49500)
        .unwrap();

    let mut tcp_active = false;
    loop {
        let timestamp = Instant::now();
        match iface.poll(timestamp, &mut device, &mut sockets) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if socket.is_active() && !tcp_active {
            debug!("connected");
        } else if !socket.is_active() && tcp_active {
            debug!("disconnected");
            break;
        }
        tcp_active = socket.is_active();

        if socket.may_recv() {
            let data = socket
                .recv(|data| {
                    let mut data = data.to_owned();
                    if !data.is_empty() {
                        debug!(
                            "recv data: {:?}",
                            str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                        );
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (data.len(), data)
                })
                .unwrap();
            if socket.can_send() && !data.is_empty() {
                debug!(
                    "send data: {:?}",
                    str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                );
                socket.send_slice(&data[..]).unwrap();
            }
        } else if socket.may_send() {
            debug!("close");
            socket.close();
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
