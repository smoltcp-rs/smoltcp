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

use smoltcp::iface::{InterfaceBuilder, NeighborCache};
use smoltcp::phy::{wait as phy_wait, Medium, RawSocket};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{Ieee802154Pan, IpAddress, IpCidr};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);

    let device = RawSocket::new("wpan1", Medium::Ieee802154).unwrap();

    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

    let ieee802154_addr = smoltcp::wire::Ieee802154Address::Extended([
        0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    ]);
    let ip_addrs = [IpCidr::new(
        IpAddress::v6(0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242),
        64,
    )];

    let mut builder = InterfaceBuilder::new(device, vec![])
        .ip_addrs(ip_addrs)
        .pan_id(Ieee802154Pan(0xbeef));
    builder = builder
        .hardware_addr(ieee802154_addr.into())
        .neighbor_cache(neighbor_cache);
    let mut iface = builder.finalize();

    let udp_handle = iface.add_socket(udp_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // udp:6969: respond "hello"
        let socket = iface.get_socket::<UdpSocket>(udp_handle);
        if !socket.is_open() {
            socket.bind(6969).unwrap()
        }

        let client = match socket.recv() {
            Ok((data, endpoint)) => {
                debug!(
                    "udp:6969 recv data: {:?} from {}",
                    str::from_utf8(data).unwrap(),
                    endpoint
                );
                Some(endpoint)
            }
            Err(_) => None,
        };
        if let Some(endpoint) = client {
            let data = b"hello\n";
            debug!(
                "udp:6969 send data: {:?}",
                str::from_utf8(data.as_ref()).unwrap()
            );
            socket.send_slice(data, endpoint).unwrap();
        }

        phy_wait(fd, iface.poll_delay(timestamp)).expect("wait error");
    }
}
