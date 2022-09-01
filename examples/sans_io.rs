#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_mut)]
#![allow(clippy::collapsible_if)]

#[cfg(feature = "std")]
#[allow(dead_code)]
mod utils;

use std::io::{self, Write};

use smoltcp::iface::{FragmentsCache, InterfaceBuilder, Routes, SocketSet};
use smoltcp::phy::{sans_io::SansIO, Medium};
use smoltcp::socket::udp;
use std::collections::BTreeMap;

use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address};

fn main() {
    let mut device = SansIO::new(42, Medium::Ip);

    let src_endpoint = IpEndpoint::new(IpAddress::v4(192, 168, 2, 31), 1234);
    let dst_endpoint = IpEndpoint::new(IpAddress::v4(192, 168, 3, 32), 5678);
    let gateway_ip = Ipv4Address::new(192, 168, 2, 1);

    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(gateway_ip).unwrap();

    let mut ip_addrs = [IpCidr::new(src_endpoint.addr, 24)];
    let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
    let mut builder = InterfaceBuilder::new()
        .ip_addrs(ip_addrs)
        .ipv4_fragments_cache(ipv4_frag_cache);

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

    let client_socket = {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 65535]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 65535]);
        udp::Socket::new(rx, tx)
    };

    let mut sockets: [_; 1] = Default::default();
    let mut sockets = SocketSet::new(&mut sockets[..]);
    let client_handle = sockets.add(client_socket);

    iface
        .poll(smoltcp::time::Instant::now(), &mut device, &mut sockets)
        .unwrap();
    let mut socket = sockets.get_mut::<udp::Socket>(client_handle);

    socket.bind(src_endpoint.port).unwrap();

    const PHRASE: &[u8; 5] = b"Hello";
    const COUNT: usize = 10;
    let mut payload = [0_u8; PHRASE.len() * COUNT];
    for i in 0..COUNT {
        payload[(i * PHRASE.len())..(i + 1) * PHRASE.len()].clone_from_slice(PHRASE);
    }

    socket = sockets.get_mut::<udp::Socket>(client_handle);
    socket.send_slice(&payload, dst_endpoint).unwrap();

    iface
        .poll(smoltcp::time::Instant::now(), &mut device, &mut sockets)
        .unwrap();
    socket = sockets.get_mut::<udp::Socket>(client_handle);
    socket.close();

    loop {
        let packet = device.tx.pop_front();
        match packet {
            Some(packet) => {
                io::stdout().write_all(&packet).unwrap();
            }
            None => {
                break;
            }
        }
    }
}
