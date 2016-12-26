#![feature(associated_consts, type_ascription)]
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate smoltcp;

use std::env;
use std::time::Instant;
use log::{LogLevelFilter, LogRecord};
use env_logger::{LogBuilder};

use smoltcp::Error;
use smoltcp::phy::{Tracer, TapInterface};
use smoltcp::wire::{EthernetFrame, EthernetAddress, IpAddress, IpEndpoint};
use smoltcp::wire::PrettyPrinter;
use smoltcp::iface::{SliceArpCache, EthernetInterface};
use smoltcp::socket::AsSocket;
use smoltcp::socket::{UdpSocket, UdpSocketBuffer, UdpPacketBuffer};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

fn main() {
    let startup_time = Instant::now();
    LogBuilder::new()
        .format(move |record: &LogRecord| {
            let elapsed = Instant::now().duration_since(startup_time);
            if record.target().starts_with("smoltcp::") {
                format!("\x1b[0m[{:6}.{:03}ms] ({}): {}\x1b[0m",
                        elapsed.as_secs(), elapsed.subsec_nanos() / 1000000,
                        record.target().replace("smoltcp::", ""), record.args())
            } else {
                format!("\x1b[32m[{:6}.{:03}ms] ({}): {}\x1b[0m",
                        elapsed.as_secs(), elapsed.subsec_nanos() / 1000000,
                        record.target(), record.args())
            }
        })
        .filter(None, LogLevelFilter::Trace)
        .init()
        .unwrap();

    fn trace_writer(printer: PrettyPrinter<EthernetFrame<&[u8]>>) {
        print!("\x1b[37m{}\x1b[0m", printer)
    }

    let ifname = env::args().nth(1).unwrap();

    let device = TapInterface::new(ifname.as_ref()).unwrap();
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device, trace_writer);
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
            Err(e) => debug!("poll error: {}", e)
        }

        {
            let socket: &mut UdpSocket = iface.sockets()[0].as_socket();
            let client = match socket.recv() {
                Ok((endpoint, data)) => {
                    debug!("udp recv data: {:?} from {}", data, endpoint);
                    Some(endpoint)
                }
                Err(Error::Exhausted) => {
                    None
                }
                Err(e) => {
                    debug!("udp recv error: {}", e);
                    None
                }
            };
            if let Some(endpoint) = client {
                let data = b"yo dawg";
                debug!("udp send data: {:?}", data);
                socket.send_slice(endpoint, data).unwrap()
            }
        }

        {
            let socket: &mut TcpSocket = iface.sockets()[1].as_socket();
            let data = {
                let mut data = socket.recv(128).to_owned();
                if data.len() > 0 {
                    debug!("tcp recv data: {:?}", &data[..]);
                    data = data.split(|&b| b == b'\n').next().unwrap().to_owned();
                    data.reverse();
                    data.extend(b"\n");
                }
                data
            };
            if data.len() > 0 {
                debug!("tcp send data: {:?}", &data[..]);
                socket.send_slice(&data[..]);
            }
        }
    }
}
