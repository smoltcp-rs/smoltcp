#![feature(associated_consts, type_ascription)]
extern crate smoltcp;

use std::env;
use smoltcp::Error;
use smoltcp::phy::{Tracer, TapInterface};
use smoltcp::wire::{EthernetFrame, EthernetAddress, IpAddress, IpEndpoint};
use smoltcp::iface::{SliceArpCache, EthernetInterface};
use smoltcp::socket::AsSocket;
use smoltcp::socket::{UdpSocket, UdpSocketBuffer, UdpPacketBuffer};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

fn main() {
    let ifname = env::args().nth(1).unwrap();

    let device = TapInterface::new(ifname.as_ref()).unwrap();
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device);
    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let endpoint = IpEndpoint::new(IpAddress::default(), 6969);

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 2048])]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 2048])]);
    let udp_socket = UdpSocket::new(endpoint, udp_rx_buffer, udp_tx_buffer);

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 8192]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 8192]);
    let mut tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
    (tcp_socket.as_socket() : &mut TcpSocket).listen(endpoint);

    let hardware_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let protocol_addrs = [IpAddress::v4(192, 168, 69, 1)];
    let sockets = vec![udp_socket, tcp_socket];
    let mut iface = EthernetInterface::new(device, arp_cache,
        hardware_addr, protocol_addrs, sockets);

    loop {
        match iface.poll() {
            Ok(()) => (),
            Err(e) => println!("error {}", e)
        }

        {
            let udp_socket: &mut UdpSocket = iface.sockets()[0].as_socket();
            let udp_client = match udp_socket.recv() {
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
            if let Some(endpoint) = udp_client {
                udp_socket.send_slice(endpoint, "hihihi".as_bytes()).unwrap()
            }
        }

        let _tcp_socket: &mut TcpSocket = iface.sockets()[1].as_socket();
    }
}
