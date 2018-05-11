#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use std::str;
use std::collections::BTreeMap;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache};
use smoltcp::socket::SocketSet;
use smoltcp::socket::{UdpSocketBuffer, UdpSocket, UdpPacketMetadata};
use smoltcp::time::Instant;
use smoltcp::phy::ClientDevice;

fn main() {
    let device = ClientDevice::new();

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp1_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
    let udp1_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
    let udp1_socket = UdpSocket::new(udp1_rx_buffer, udp1_tx_buffer);

    let udp2_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
    let udp2_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
    let udp2_socket = UdpSocket::new(udp2_rx_buffer, udp2_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 3), 24)];
    let mut iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let udp1_handle = sockets.add(udp1_socket);
    let udp2_handle = sockets.add(udp2_socket);

    loop {
        let timestamp = Instant::now();
        iface.poll(&mut sockets, timestamp).expect("poll error");

        // udp:6969: respond "hello"
        {
            let mut socket = sockets.get::<UdpSocket>(udp1_handle);
            if !socket.is_open() {
                socket.bind(6969).unwrap()
            }

            let client = match socket.recv() {
                Ok((data, endpoint)) => {
                    println!(
                        "udp:6969 recv data: {:?} from {}",
                        str::from_utf8(data.as_ref()).unwrap(),
                        endpoint
                    );
                    Some(endpoint)
                }
                Err(_) => None,
            };
            if let Some(endpoint) = client {
                let data = b"hello\n";
                println!(
                    "udp:6969 send data: {:?}",
                    str::from_utf8(data.as_ref()).unwrap()
                );
                socket.send_slice(data, endpoint).unwrap();
            }
        }

        // udp:6942: echo with reverse
        {
            let mut socket = sockets.get::<UdpSocket>(udp2_handle);
            if !socket.is_open() {
                socket.bind(6942).unwrap()
            }

            let mut rx_data = Vec::new();
            let client = match socket.recv() {
                Ok((data, endpoint)) => {
                    println!(
                        "udp:6969 recv data: {:?} from {}",
                        str::from_utf8(data.as_ref()).unwrap(),
                        endpoint
                    );
                    rx_data.extend_from_slice(data);
                    Some(endpoint)
                }
                Err(_) => None,
            };

            if let Some(endpoint) = client {
                if rx_data.len() > 0 {
                    let mut data = rx_data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                    data.reverse();
                    data.extend(b"\n");
                    println!(
                        "udp:6942 send data: {:?}",
                        str::from_utf8(data.as_ref()).unwrap()
                    );
                    socket.send_slice(&data, endpoint).unwrap();
                }
            }
        }
    }
}
