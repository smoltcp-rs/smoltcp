#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;
extern crate byteorder;

mod utils;

use std::str::{self, FromStr};
use std::time::{Duration, Instant};
use smoltcp::Error;
use smoltcp::wire::{EthernetAddress, IpVersion, IpProtocol, IpAddress,
                    Ipv4Address, Ipv4Packet, Ipv4Repr,
                    Icmpv4Repr, Icmpv4Packet};
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::socket::{AsSocket, SocketSet};
use smoltcp::socket::{RawSocket, RawSocketBuffer, RawPacketBuffer};
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
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);
    let address  = Ipv4Address::from_str(&matches.free[0]).expect("invalid address format");
    let count    = matches.opt_str("count").map(|s| usize::from_str(&s).unwrap()).unwrap_or(4);
    let interval = matches.opt_str("interval").map(|s| u64::from_str(&s).unwrap()).unwrap_or(1);
    let timeout  = matches.opt_str("timeout").map(|s| u64::from_str(&s).unwrap()).unwrap_or(5);

    let startup_time = Instant::now();

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let remote_addr = address;
    let local_addr  = Ipv4Address::new(192, 168, 69, 1);

    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Icmp,
                                    raw_rx_buffer, raw_tx_buffer);

    let hardware_addr  = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let mut iface = EthernetInterface::new(
        Box::new(device), Box::new(arp_cache) as Box<ArpCache>,
        hardware_addr, [IpAddress::from(local_addr)]);

    let mut sockets = SocketSet::new(vec![]);
    let raw_handle = sockets.add(raw_socket);

    let mut send_next = Duration::default();
    let mut seq_no = 0;
    let mut received = 0;
    let mut echo_payload = [0xffu8; 40];
    let mut waiting_queue = HashMap::new();

    loop {
        {
            let socket: &mut RawSocket = sockets.get_mut(raw_handle).as_socket();

            let timestamp = Instant::now().duration_since(startup_time);
            let timestamp_us = (timestamp.as_secs() * 1000000) +
                (timestamp.subsec_nanos() / 1000) as u64;

            if seq_no == count as u16 && waiting_queue.is_empty() {
                break;
            }

            if socket.can_send() && seq_no < count as u16 && send_next <= timestamp {
                NetworkEndian::write_u64(&mut echo_payload, timestamp_us);
                let icmp_repr = Icmpv4Repr::EchoRequest {
                    ident: 1,
                    seq_no,
                    data: &echo_payload,
                };
                let ipv4_repr = Ipv4Repr {
                    /*src_addr: Ipv4Address::UNSPECIFIED,*/
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: remote_addr,
                    protocol: IpProtocol::Icmp,
                    payload_len: icmp_repr.buffer_len(),
                };

                let raw_payload = socket
                    .send(ipv4_repr.buffer_len() + icmp_repr.buffer_len())
                    .unwrap();

                let mut ipv4_packet = Ipv4Packet::new(raw_payload);
                ipv4_repr.emit(&mut ipv4_packet);
                let mut icmp_packet = Icmpv4Packet::new(ipv4_packet.payload_mut());
                icmp_repr.emit(&mut icmp_packet);

                waiting_queue.insert(seq_no, timestamp);
                seq_no += 1;
                send_next += Duration::new(interval, 0);
            }

            if socket.can_recv() {
                let payload = socket.recv().unwrap();
                let ipv4_packet = Ipv4Packet::new(payload);
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet).unwrap();

                if ipv4_repr.src_addr == remote_addr && ipv4_repr.dst_addr == local_addr {
                    let icmp_packet = Icmpv4Packet::new(ipv4_packet.payload());
                    let icmp_repr = Icmpv4Repr::parse(&icmp_packet);

                    if let Ok(Icmpv4Repr::EchoReply { seq_no, data, .. }) = icmp_repr {
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
            }

            waiting_queue.retain(|seq, from| {
                if (timestamp - *from).as_secs() < timeout {
                    true
                } else {
                    println!("From {} icmp_seq={} timeout", remote_addr, seq);
                    false
                }
            })
        }

        let timestamp = Instant::now().duration_since(startup_time);
        let timestamp_ms = (timestamp.as_secs() * 1000) +
            (timestamp.subsec_nanos() / 1000000) as u64;
        match iface.poll(&mut sockets, timestamp_ms) {
            Ok(()) | Err(Error::Exhausted) => (),
            Err(e) => debug!("poll error: {}", e),
        }
    }

    println!("--- {} ping statistics ---", remote_addr);
    println!("{} packets transmitted, {} received, {:.0}% packet loss",
             seq_no, received, 100.0 * (seq_no - received) as f64 / seq_no as f64);
}
