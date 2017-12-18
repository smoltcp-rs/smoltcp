#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;
extern crate byteorder;

mod utils;

use std::str::FromStr;
use std::collections::BTreeMap;
use std::time::Instant;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::Device;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr,
                    Ipv4Address, Icmpv4Repr, Icmpv4Packet};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::{SocketSet, IcmpSocket, IcmpSocketBuffer, IcmpPacketBuffer, IcmpEndpoint};
use std::collections::HashMap;
use byteorder::{ByteOrder, NetworkEndian};

fn main() {
    utils::setup_logging("warn");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    opts.optopt("c", "count", "Amount of echo request packets to send (default: 4)", "COUNT");
    opts.optopt("i", "interval",
                "Interval between successive packets sent (seconds) (default: 1)", "INTERVAL");
    opts.optopt("", "timeout",
                "Maximum wait duration for an echo response packet (seconds) (default: 5)",
                "TIMEOUT");
    free.push("ADDRESS");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);
    let device_caps = device.capabilities();
    let address  = Ipv4Address::from_str(&matches.free[0]).expect("invalid address format");
    let count    = matches.opt_str("count").map(|s| usize::from_str(&s).unwrap()).unwrap_or(4);
    let interval = matches.opt_str("interval").map(|s| u64::from_str(&s).unwrap()).unwrap_or(1);
    let timeout  = matches.opt_str("timeout").map(|s| u64::from_str(&s).unwrap()).unwrap_or(5);

    let startup_time = Instant::now();

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let remote_addr = address;
    let local_addr  = Ipv4Address::new(192, 168, 69, 1);

    let icmp_rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 256])]);
    let icmp_tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketBuffer::new(vec![0; 256])]);
    let icmp_socket = IcmpSocket::new(icmp_rx_buffer, icmp_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addr = IpCidr::new(IpAddress::from(local_addr), 24);
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .ip_addrs([ip_addr])
            .ipv4_gateway(default_v4_gw)
            .neighbor_cache(neighbor_cache)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let icmp_handle = sockets.add(icmp_socket);

    let mut send_at = 0;
    let mut seq_no = 0;
    let mut received = 0;
    let mut echo_payload = [0xffu8; 40];
    let mut waiting_queue = HashMap::new();
    let ident = 0x22b;
    let endpoint = IpAddress::Ipv4(remote_addr);

    loop {
        {
            let mut socket = sockets.get::<IcmpSocket>(icmp_handle);
            if !socket.is_open() {
                socket.bind(IcmpEndpoint::Ident(ident)).unwrap()
            }

            let timestamp = Instant::now().duration_since(startup_time);
            let timestamp_us = (timestamp.as_secs() * 1000000) +
                (timestamp.subsec_nanos() / 1000) as u64;

            if socket.can_send() && seq_no < count as u16 &&
                    send_at <= utils::millis_since(startup_time) {
                NetworkEndian::write_u64(&mut echo_payload, timestamp_us);
                let icmp_repr = Icmpv4Repr::EchoRequest {
                    ident: ident,
                    seq_no,
                    data: &echo_payload,
                };

                let icmp_payload = socket
                    .send(icmp_repr.buffer_len(), endpoint)
                    .unwrap();

                let mut icmp_packet = Icmpv4Packet::new(icmp_payload);
                icmp_repr.emit(&mut icmp_packet, &device_caps.checksum);

                waiting_queue.insert(seq_no, timestamp);
                seq_no += 1;
                send_at += interval * 1000;
            }

            if socket.can_recv() {
                let (payload, _) = socket.recv().unwrap();
                let icmp_packet = Icmpv4Packet::new(&payload);
                let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &device_caps.checksum).unwrap();

                if let Icmpv4Repr::EchoReply { seq_no, data, .. } = icmp_repr {
                    if let Some(_) = waiting_queue.get(&seq_no) {
                        let packet_timestamp_us = NetworkEndian::read_u64(data);
                        println!("{} bytes from {}: icmp_seq={}, time={:.3}ms",
                                 data.len(), remote_addr, seq_no,
                                 (timestamp_us - packet_timestamp_us) as f64 / 1000.0);
                        waiting_queue.remove(&seq_no);
                        received += 1;
                    }
                }
            }

            waiting_queue.retain(|seq, from| {
                if (timestamp - *from).as_secs() < timeout {
                    true
                } else {
                    println!("From {} icmp_seq={} timeout", remote_addr, seq);
                    false
                }
            });

            if seq_no == count as u16 && waiting_queue.is_empty() {
                break
            }
        }

        let timestamp = utils::millis_since(startup_time);

        let poll_at = iface.poll(&mut sockets, timestamp).expect("poll error");
        let resume_at = [poll_at, Some(send_at)].iter().flat_map(|x| *x).min();
        phy_wait(fd, resume_at.map(|at| at.saturating_sub(timestamp))).expect("wait error");
    }

    println!("--- {} ping statistics ---", remote_addr);
    println!("{} packets transmitted, {} received, {:.0}% packet loss",
             seq_no, received, 100.0 * (seq_no - received) as f64 / seq_no as f64);
}
