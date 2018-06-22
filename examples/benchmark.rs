#[cfg(feature = "log")]
#[macro_use]
extern crate log;
#[cfg(feature = "log")]
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use std::cmp;
use std::collections::BTreeMap;
use std::sync::atomic::{Ordering, AtomicBool, ATOMIC_BOOL_INIT};
use std::thread;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::SocketSet;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::{Duration, Instant};

const AMOUNT: usize = 1_000_000_000;

enum Client { Reader, Writer }

fn client(kind: Client) {
    let port = match kind { Client::Reader => 1234, Client::Writer => 1235 };
    let mut stream = TcpStream::connect(("192.168.69.1", port)).unwrap();
    let mut buffer = vec![0; 1_000_000];

    let start = Instant::now();

    let mut processed = 0;
    while processed < AMOUNT {
        let length = cmp::min(buffer.len(), AMOUNT - processed);
        let result = match kind {
            Client::Reader => stream.read(&mut buffer[..length]),
            Client::Writer => stream.write(&buffer[..length]),
        };
        match result {
            Ok(0) => break,
            Ok(result) => {
                // print!("(P:{})", result);
                processed += result
            }
            Err(err) => panic!("cannot process: {}", err)
        }
    }

    let end = Instant::now();

    let elapsed = (end - start).total_millis() as f64 / 1000.0;

    println!("throughput: {:.3} Gbps", AMOUNT as f64 / elapsed / 0.125e9);

    CLIENT_DONE.store(true, Ordering::SeqCst);
}

static CLIENT_DONE: AtomicBool = ATOMIC_BOOL_INIT;

fn main() {
    #[cfg(feature = "log")]
    utils::setup_logging("info");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("MODE");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tap_options(&mut matches);
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);
    let mode = match matches.free[0].as_ref() {
        "reader" => Client::Reader,
        "writer" => Client::Writer,
        _ => panic!("invalid mode")
    };

    thread::spawn(move || client(mode));

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp2_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp2_socket = TcpSocket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);
    let default_timeout = Some(Duration::from_millis(1000));

    let mut processed = 0;
    while !CLIENT_DONE.load(Ordering::SeqCst) {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}",e);
            }
        }


        // tcp:1234: emit data
        {
            let mut socket = sockets.get::<TcpSocket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(1234).unwrap();
            }

            if socket.can_send() {
                if processed < AMOUNT {
                    let length = socket.send(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed);
                        (length, length)
                    }).unwrap();
                    processed += length;
                }
            }
        }

        // tcp:1235: sink data
        {
            let mut socket = sockets.get::<TcpSocket>(tcp2_handle);
            if !socket.is_open() {
                socket.listen(1235).unwrap();
            }

            if socket.can_recv() {
                if processed < AMOUNT {
                    let length = socket.recv(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed);
                        (length, length)
                    }).unwrap();
                    processed += length;
                }
            }
        }

        match iface.poll_at(&sockets, timestamp) {
            Some(poll_at) if timestamp < poll_at => {
                phy_wait(fd, Some(poll_at - timestamp)).expect("wait error");
            },
            Some(_) => (),
            None => {
                phy_wait(fd, default_timeout).expect("wait error");
            }
        }
    }
}
