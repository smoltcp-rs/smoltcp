extern crate smoltcp;

use smoltcp::wire;
use smoltcp::phy::{self, LinkLayer, Device, RxToken, RawSocket};


use std::env;
use std::os::unix::io::AsRawFd;


fn handle_ip_packet(packet: &[u8]) {
    match wire::IpVersion::of_packet(&packet) {
        Ok(version) => match version {
            wire::IpVersion::Ipv4 => {
                println!("{}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
            },
            wire::IpVersion::Ipv6 => {
                println!("{}", &wire::PrettyPrinter::<wire::Ipv6Packet<&[u8]>>::new("", &packet));
            },
            _ => { }
        },
        Err(_) => { }
    }
}

fn handle_ethernet_frame(packet: &[u8]) {
    println!("{}", &wire::PrettyPrinter::<wire::EthernetFrame<&[u8]>>::new("", &packet));
}

fn handle_packet(link_layer: &LinkLayer, packet: &[u8]) {
    match link_layer {
        &LinkLayer::Null => {
            handle_ip_packet(&packet[4..]);
        },
        &LinkLayer::Eth => {
            handle_ethernet_frame(&packet[..]);
        },
        &LinkLayer::Ip => {
            handle_ip_packet(&packet[..]);
        }
    }
}

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut raw_socket = RawSocket::with_ifname(ifname.as_ref()).unwrap();

    let link_layer = raw_socket.link_layer();

    println!("Interface: {},  Data Link Type: {:?}\n", ifname, link_layer);
    let fd = raw_socket.as_raw_fd();

    loop {
        phy::wait(fd, None).unwrap();
        
        match raw_socket.receive() {
            Some((rx_token, _)) => {
                rx_token.consume(/*timestamp = */ 0, |buffer| {
                    handle_packet(&link_layer, &buffer[..]);
                    Ok(())
                }).unwrap();
            }
            None => {  }
        };
    }
}