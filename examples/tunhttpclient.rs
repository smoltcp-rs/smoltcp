#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate rand;
extern crate url;
extern crate smoltcp;

mod utils;

use smoltcp::phy::wait as phy_wait;
use std::str::{self, FromStr};
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use url::Url;
use smoltcp::wire::{Ipv4Address, Ipv6Address, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, InterfaceBuilder, Routes};
use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::phy::TunInterface;

fn main() {
    /*
        Usage:

        Create tun1:

        sudo ip tuntap add dev tun1 mode tun user `id -un`
        sudo ip link set dev tun1 up
        sudo ip addr add dev tun1 local 192.168.69.0 remote 192.168.69.1
        sudo iptables -t filter -I FORWARD -i tun1 -o eth0 -j ACCEPT
        sudo iptables -t filter -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        sudo iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
        sudo sysctl net.ipv4.ip_forward=1

        ./tunhttpclient 172.217.28.238 http://google.com

        You should get HTML from google (IP might change throughout history, ping to see)
    */
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("ADDRESS");
    free.push("URL");

    let mut matches = utils::parse_options(&opts, free);
    let device = TunInterface::new("tun1").unwrap();
    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/false);
    let address = IpAddress::from_str(&matches.free[0]).expect("invalid address format");
    let url = Url::parse(&matches.free[1]).expect("invalid url format");

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 1024]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 1024]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
                    IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
                    IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64)];
    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let default_v6_gw = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100);
    let mut routes_storage = [None; 2];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    routes.add_default_ipv6_route(default_v6_gw).unwrap();
    let mut iface = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs)
            .routes(routes)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    enum State { Connect, Request, Response };
    let mut state = State::Connect;

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}",e);
            }
        }

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);

            state = match state {
                State::Connect if !socket.is_active() => {
                    debug!("connecting");
                    let local_port = 49152 + rand::random::<u16>() % 16384;
                    socket.connect((address, url.port().unwrap_or(80)), local_port).unwrap();
                    State::Request
                }
                State::Request if socket.may_send() => {
                    debug!("sending request");
                    let http_get = "GET ".to_owned() + url.path() + " HTTP/1.1\r\n";
                    socket.send_slice(http_get.as_ref()).expect("cannot send");
                    let http_host = "Host: ".to_owned() + url.host_str().unwrap() + "\r\n";
                    socket.send_slice(http_host.as_ref()).expect("cannot send");
                    socket.send_slice(b"Connection: close\r\n").expect("cannot send");
                    socket.send_slice(b"\r\n").expect("cannot send");
                    State::Response
                }
                State::Response if socket.can_recv() => {
                    socket.recv(|data| {
                        println!("{}", str::from_utf8(data).unwrap_or("(invalid utf8)"));
                        (data.len(), ())
                    }).unwrap();
                    State::Response
                }
                State::Response if !socket.may_recv() => {
                    debug!("received complete response");
                    break
                }
                _ => state
            }
        }
        
        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
