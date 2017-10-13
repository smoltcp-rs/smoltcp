#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;
extern crate byteorder;

mod utils;

use std::str::FromStr;
use std::time::Instant;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::Device;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, IpVersion, IpProtocol, IpAddress, IpCidr, Ipv4Address,
                    Ipv4Packet, Ipv4Repr, Icmpv4Repr, Icmpv4Packet, IgmpPacket, IgmpRepr};
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::socket::{SocketSet, RawSocket, RawSocketBuffer, RawPacketBuffer};
use std::collections::HashMap;
use byteorder::{ByteOrder, NetworkEndian};

fn main() {
    utils::setup_logging("warn");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches,
                                                 device,
                                                 /*loopback=*/
                                                 false);
    let device_caps = device.capabilities();
    let startup_time = Instant::now();

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let local_addr = Ipv4Address::new(192, 168, 69, 1);

    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_socket = RawSocket::new(IpVersion::Ipv4,
                                    IpProtocol::Icmp,
                                    raw_rx_buffer,
                                    raw_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addr = IpCidr::new(IpAddress::from(local_addr), 24);
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let mut iface = EthernetInterface::new(Box::new(device),
                                           Box::new(arp_cache) as Box<ArpCache>,
                                           ethernet_addr,
                                           [ip_addr],
                                           Some(default_v4_gw));
    iface.add_mac_multicast_ip_addr(Ipv4Address::new(225, 0, 0, 37));
    iface.add_mac_multicast_ip_addr(Ipv4Address::new(224, 0, 6, 150));
    iface.add_mac_multicast_ip_addr(Ipv4Address::new(224, 0, 0, 2));
    iface.add_mac_multicast_ip_addr(Ipv4Address::new(224, 0, 0, 22));
    
    println!("{}",iface.has_ip_mcast_addr(Ipv4Address::new(225, 0, 0, 37)));
    println!("{}",iface.has_ip_mcast_addr(Ipv4Address::new(224, 0, 6, 150)));
    println!("{}",iface.has_ip_mcast_addr(Ipv4Address::new(224, 0, 0, 2)));
    println!("{}",iface.has_ip_mcast_addr(Ipv4Address::new(224, 0, 0, 22)));

    let mut sockets = SocketSet::new(vec![]);
    let raw_handle = sockets.add(raw_socket);

    loop {
        {
            let mut socket = sockets.get::<RawSocket>(raw_handle);


			/*
            if socket.can_send() {
                NetworkEndian::write_u64(&mut echo_payload, timestamp_us);
                let icmp_repr = Icmpv4Repr::EchoRequest {
                    ident: 1,
                    seq_no,
                    data: &echo_payload,
                };
                let ipv4_repr = Ipv4Repr {
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: remote_addr,
                    protocol: IpProtocol::Icmp,
                    payload_len: icmp_repr.buffer_len(),
                };

                let raw_payload = socket
                    .send(ipv4_repr.buffer_len() + icmp_repr.buffer_len())
                    .unwrap();

                let mut ipv4_packet = Ipv4Packet::new(raw_payload);
                ipv4_repr.emit(&mut ipv4_packet, &device_caps.checksum);
                let mut icmp_packet = Icmpv4Packet::new(ipv4_packet.payload_mut());
                icmp_repr.emit(&mut icmp_packet, &device_caps.checksum);

                waiting_queue.insert(seq_no, timestamp);
                seq_no += 1;
                send_at += interval * 1000;
            }
            */

            if socket.can_recv() {
                let payload = socket.recv().unwrap();
                let ipv4_packet = Ipv4Packet::new(payload);
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &device_caps.checksum).unwrap();
                
                let igmp_packet = IgmpPacket::new(ipv4_packet.payload());
                println!("Got a new packet: {}", igmp_packet);
            }
        }


        let timestamp = utils::millis_since(startup_time);
        let _poll_at = iface.poll(&mut sockets, timestamp); // ignore the errors (or perhaps log them)
        phy_wait(fd, Some(1)).expect("wait error");
    }


}
