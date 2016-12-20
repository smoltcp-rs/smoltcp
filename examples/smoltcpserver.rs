#![feature(associated_consts)]
extern crate smoltcp;

use std::env;
use smoltcp::Error;
use smoltcp::phy::{Tracer, TapInterface};
use smoltcp::wire::{EthernetFrame, EthernetAddress, InternetAddress, InternetEndpoint};
use smoltcp::iface::{SliceArpCache, EthernetInterface};
use smoltcp::socket::{UdpSocket, AsSocket, UdpBuffer, UdpPacket};

fn main() {
    let ifname = env::args().nth(1).unwrap();

    let device = TapInterface::new(ifname.as_ref()).unwrap();
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device);
    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let hardware_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let mut protocol_addrs = [InternetAddress::ipv4([192, 168, 69, 1])];

    let listen_address = InternetAddress::ipv4([0, 0, 0, 0]);
    let endpoint = InternetEndpoint::new(listen_address, 6969);

    let udp_rx_buffer = UdpBuffer::new(vec![UdpPacket::new(vec![0; 2048])]);
    let udp_tx_buffer = UdpBuffer::new(vec![UdpPacket::new(vec![0; 2048])]);
    let udp_socket = UdpSocket::new(endpoint, udp_rx_buffer, udp_tx_buffer);

    let mut sockets = [udp_socket];
    let mut iface = EthernetInterface::new(device, arp_cache,
        hardware_addr, &mut protocol_addrs[..], &mut sockets[..]);

    loop {
        match iface.poll() {
            Ok(()) => (),
            Err(e) => println!("error {}", e)
        }

        let udp_socket = iface.sockets()[0].as_socket();
        let client = match udp_socket.recv() {
            Ok((endpoint, data)) => {
                println!("data {:?} from {}", data, endpoint);
                Some(endpoint)
            }
            Err(Error::Exhausted) => {
                None
            }
            Err(e) => {
                println!("error {}", e);
                None
            }
        };
        if let Some(endpoint) = client {
            udp_socket.send_slice(endpoint, "hihihi".as_bytes()).unwrap()
        }
    }
}
