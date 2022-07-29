//! 6lowpan exmaple
//!
//! This example is designed to run using the Linux ieee802154/6lowpan support,
//! using mac802154_hwsim.
//!
//! mac802154_hwsim allows you to create multiple "virtual" radios and specify
//! which is in range with which. This is very useful for testing without
//! needing real hardware. By default it creates two interfaces `wpan0` and
//! `wpan1` that are in range with each other. You can customize this with
//! the `wpan-hwsim` tool.
//!
//! We'll configure Linux to speak 6lowpan on `wpan0`, and leave `wpan1`
//! unconfigured so smoltcp can use it with a raw socket.
//!
//! # Setup
//!
//!     modprobe mac802154_hwsim
//!
//!     ip link set wpan0 down
//!     ip link set wpan1 down
//!     iwpan dev wpan0 set pan_id 0xbeef
//!     iwpan dev wpan1 set pan_id 0xbeef
//!     ip link add link wpan0 name lowpan0 type lowpan
//!     ip link set wpan0 up
//!     ip link set wpan1 up
//!     ip link set lowpan0 up
//!
//! # Running
//!
//! Run it with `sudo ./target/debug/examples/sixlowpan`.
//!
//! You can set wireshark to sniff on interface `wpan0` to see the packets.
//!
//! Ping it with `ping fe80::180b:4242:4242:4242%lowpan0`.
//!
//! Speak UDP with `nc -uv fe80::180b:4242:4242:4242%lowpan0 6969`.
//!
//! # Teardown
//!
//!     rmmod mac802154_hwsim
//!

mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::str;

use smoltcp::iface::{FragmentsCache, InterfaceBuilder, NeighborCache, SocketSet};
use smoltcp::phy::{wait as phy_wait, Medium, RawSocket};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{Ieee802154Pan, IpAddress, IpCidr};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);

    let device = RawSocket::new("wpan1", Medium::Ieee802154).unwrap();

    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 1280]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 1280]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 4096]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ieee802154_addr = smoltcp::wire::Ieee802154Address::Extended([
        0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ]);
    let ip_addrs = [IpCidr::new(
        IpAddress::v6(0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242),
        64,
    )];

    let mut builder = InterfaceBuilder::new()
        .ip_addrs(ip_addrs)
        .pan_id(Ieee802154Pan(0xbeef));
    builder = builder
        .hardware_addr(ieee802154_addr.into())
        .neighbor_cache(neighbor_cache);

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

    let mut iface = builder.finalize(&mut device);

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);
    let tcp_handle = sockets.add(tcp_socket);

    let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
    socket.listen(50000).unwrap();

    let mut tcp_active = false;

    loop {
        let timestamp = Instant::now();

        let mut poll = true;
        while poll {
            match iface.poll(timestamp, &mut device, &mut sockets) {
                Ok(r) => poll = r,
                Err(e) => {
                    debug!("poll error: {}", e);
                    break;
                }
            }
        }

        // udp:6969: respond "hello"
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(6969).unwrap()
        }

        let mut buffer = vec![0; 1500];
        let client = match socket.recv() {
            Ok((data, endpoint)) => {
                debug!(
                    "udp:6969 recv data: {:?} from {}",
                    str::from_utf8(data).unwrap(),
                    endpoint
                );
                buffer[..data.len()].copy_from_slice(data);
                Some((data.len(), endpoint))
            }
            Err(_) => None,
        };
        if let Some((len, endpoint)) = client {
            debug!(
                "udp:6969 send data: {:?}",
                str::from_utf8(&buffer[..len]).unwrap()
            );
            socket.send_slice(&buffer[..len], endpoint).unwrap();
        }

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if socket.is_active() && !tcp_active {
            debug!("connected");
        } else if !socket.is_active() && tcp_active {
            debug!("disconnected");
        }
        tcp_active = socket.is_active();

        if socket.may_recv() {
            let data = socket
                .recv(|data| {
                    let data = data.to_owned();
                    if !data.is_empty() {
                        debug!(
                            "recv data: {:?}",
                            str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)")
                        );
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
