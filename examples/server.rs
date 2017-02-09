#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

use std::str::{self, FromStr};
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use log::{LogLevelFilter, LogRecord};
use env_logger::{LogBuilder};

use smoltcp::phy::{Tracer, FaultInjector, TapInterface};
use smoltcp::wire::{EthernetFrame, EthernetAddress, IpAddress};
use smoltcp::wire::PrettyPrinter;
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::socket::{AsSocket, SocketSet};
use smoltcp::socket::{UdpSocket, UdpSocketBuffer, UdpPacketBuffer};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

fn main() {
    let mut opts = getopts::Options::new();
    opts.optopt("", "drop-chance", "Chance of dropping a packet (%)", "CHANCE");
    opts.optopt("", "corrupt-chance", "Chance of corrupting a packet (%)", "CHANCE");
    opts.optflag("h", "help", "print this help menu");

    let matches = opts.parse(env::args().skip(1)).unwrap();
    if matches.opt_present("h") || matches.free.len() != 1 {
        let brief = format!("Usage: {} FILE [options]", env::args().nth(0).unwrap());
        print!("{}", opts.usage(&brief));
        return
    }
    let drop_chance    = u8::from_str(&matches.opt_str("drop-chance")
                                             .unwrap_or("0".to_string())).unwrap();
    let corrupt_chance = u8::from_str(&matches.opt_str("corrupt-chance")
                                             .unwrap_or("0".to_string())).unwrap();

    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();

    let startup_time = Instant::now();
    LogBuilder::new()
        .format(move |record: &LogRecord| {
            let elapsed = Instant::now().duration_since(startup_time);
            if record.target().starts_with("smoltcp::") {
                format!("\x1b[0m[{:6}.{:03}s] ({}): {}\x1b[0m",
                        elapsed.as_secs(), elapsed.subsec_nanos() / 1000000,
                        record.target().replace("smoltcp::", ""), record.args())
            } else {
                format!("\x1b[32m[{:6}.{:03}s] ({}): {}\x1b[0m",
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

    let device = TapInterface::new(&matches.free[0]).unwrap();
    let mut device = FaultInjector::new(device, seed);
    device.set_drop_chance(drop_chance);
    device.set_corrupt_chance(corrupt_chance);
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device, trace_writer);

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 64])]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 128])]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp2_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp2_socket = TcpSocket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let hardware_addr  = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let protocol_addrs = [IpAddress::v4(192, 168, 69, 1)];
    let mut iface      = EthernetInterface::new(
        Box::new(device), Box::new(arp_cache) as Box<ArpCache>,
        hardware_addr, protocol_addrs);

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle  = sockets.add(udp_socket);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);

    let mut tcp_6970_active = false;
    loop {
        // udp:6969: respond "yo dawg"
        {
            let socket: &mut UdpSocket = sockets.get_mut(udp_handle).as_socket();
            if socket.local_endpoint().is_unspecified() {
                socket.bind(6969)
            }

            let client = match socket.recv() {
                Ok((data, endpoint)) => {
                    debug!("udp:6969 recv data: {:?} from {}",
                           str::from_utf8(data.as_ref()).unwrap(), endpoint);
                    Some(endpoint)
                }
                Err(_) => None
            };
            if let Some(endpoint) = client {
                let data = b"yo dawg\n";
                debug!("udp:6969 send data: {:?}",
                       str::from_utf8(data.as_ref()).unwrap());
                socket.send_slice(data, Some(endpoint)).unwrap();
            }
        }

        // tcp:6969: respond "yo dawg"
        {
            let socket: &mut TcpSocket = sockets.get_mut(tcp1_handle).as_socket();
            if !socket.is_open() {
                socket.listen(6969).unwrap();
            }

            if socket.can_send() {
                let data = b"yo dawg\n";
                debug!("tcp:6969 send data: {:?}",
                       str::from_utf8(data.as_ref()).unwrap());
                socket.send_slice(data).unwrap();
                debug!("tcp:6969 close");
                socket.close();
            }
        }

        // tcp:6970: echo with reverse
        {
            let socket: &mut TcpSocket = sockets.get_mut(tcp2_handle).as_socket();
            if !socket.is_open() {
                socket.listen(6970).unwrap()
            }

            if socket.is_active() && !tcp_6970_active {
                debug!("tcp:6970 connected");
            } else if !socket.is_active() && tcp_6970_active {
                debug!("tcp:6970 disconnected");
            }
            tcp_6970_active = socket.is_active();

            if socket.may_recv() {
                let data = {
                    let mut data = socket.recv(128).unwrap().to_owned();
                    if data.len() > 0 {
                        debug!("tcp:6970 recv data: {:?}",
                               str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    data
                };
                if socket.can_send() && data.len() > 0 {
                    debug!("tcp:6970 send data: {:?}",
                           str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                debug!("tcp:6970 close");
                socket.close();
            }
        }

        let timestamp = Instant::now().duration_since(startup_time);
        let timestamp_ms = (timestamp.as_secs() * 1000) +
                           (timestamp.subsec_nanos() / 1000000) as u64;
        match iface.poll(&mut sockets, timestamp_ms) {
            Ok(()) => (),
            Err(e) => debug!("poll error: {}", e)
        }
    }
}
