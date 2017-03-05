///! For this example, a veth pair is necessary:
///! 
///!    ```
///!    sudo ip link add veth0 type veth peer name veth1
///!    sudo ip link set dev veth0 up
///!    sudo ip link set dev veth1 up
///!    ```
///!
///! The example must be built and the binary must be given permissions to use the interfaces:
///!    
///!    ```
///!    cargo build --example tcp_active_open
///!    sudo setcap cap_net_raw,cap_net_admin=eip target/debug/examples/tcp_active_open
///!
///! Start a server listening on 192.168.69.1:6970, that will accept any incoming connection,
///! answer it with a reverse payload, and close the connection:
///! 
///!    ```
///!    target/debug/examples/tcp_active_open server veth0
///!    ```
///! 
///! Start a client sending requests to this server:
///!
///!    ```
///!    target/debug/examples/tcp_active_open client veth1
///!    ```

#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

use std::str;
use std::env;
use std::time::Instant;
use log::{LogLevelFilter, LogRecord};
use env_logger::{LogBuilder};

use smoltcp::phy::{Tracer, Device, RawSocket};
use smoltcp::wire::{EthernetFrame, EthernetAddress, IpAddress, IpEndpoint};
use smoltcp::wire::PrettyPrinter;
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::socket::{AsSocket, SocketSet};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

lazy_static! {
    static ref STARTUP_TIME: Instant = {
        Instant::now()
    };
}

fn main() {
    lazy_static::initialize(&STARTUP_TIME);

    let mut opts = getopts::Options::new();
    opts.optflag("h", "help", "print this help menu");

    let matches = opts.parse(env::args().skip(1)).unwrap();
    if matches.opt_present("h") || matches.free.len() != 2 {
        let brief = format!("Usage: {} client|server FILE", env::args().nth(0).unwrap());
        print!("{}", opts.usage(&brief));
        return
    }

    LogBuilder::new()
        .format(move |record: &LogRecord| {
            let elapsed = Instant::now().duration_since(*STARTUP_TIME);
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

    let device = RawSocket::new(&matches.free[1]).unwrap();
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device, trace_writer);

    match &*matches.free[0] {
        "client" => run_client(device),
        "server" => run_server(device),
        _ => {
            let brief = format!("Usage: {} client|server FILE", env::args().nth(0).unwrap());
            print!("{}", opts.usage(&brief));
            return;
        }
    }
}

fn run_client<T: Device + 'static>(device: T) {
    let mut arp_cache = SliceArpCache::new(vec![Default::default(); 8]);
    let static_remote_ip = IpAddress::v4(192, 168, 69, 1);
    let static_remote_mac = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    arp_cache.fill(&static_remote_ip, &static_remote_mac);

    let socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 64]),
        TcpSocketBuffer::new(vec![0; 128]));

    let mut iface = EthernetInterface::new(
        Box::new(device),
        Box::new(arp_cache) as Box<ArpCache>,
        EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        [IpAddress::v4(192, 168, 69, 2)]);

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);

    loop {
        {
            let socket: &mut TcpSocket = sockets.get_mut(handle).as_socket();
            if !socket.is_open() {
                let local_endpoint = IpEndpoint { addr: IpAddress::v4(192, 168, 69, 2), port: 6979 };
                let remote_endpoint = IpEndpoint { addr: IpAddress::v4(192, 168, 69, 1), port: 6970 };
                socket.active_open(local_endpoint, remote_endpoint).unwrap();
            }

            if socket.can_send() && socket.may_send() {
                let data = b"yo dawg\n";
                info!("tcp:6969 send data: {:?}", str::from_utf8(data.as_ref()).unwrap());
                socket.send_slice(data).unwrap();
                info!("tcp:6969 close");
                socket.close();
            }
        }

        let timestamp = Instant::now().duration_since(*STARTUP_TIME);
        let timestamp_ms = (timestamp.as_secs() * 1000) + (timestamp.subsec_nanos() / 1000000) as u64;
        match iface.poll(&mut sockets, timestamp_ms) {
            Ok(()) => (),
            Err(e) => info!("poll error: {}", e)
        }
    }
}

fn run_server<T: Device + 'static>(device: T) {
    let socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0; 64]),
        TcpSocketBuffer::new(vec![0; 128]));

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);
    let mut iface = EthernetInterface::new(
        Box::new(device),
        Box::new(arp_cache) as Box<ArpCache>,
        EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        [IpAddress::v4(192, 168, 69, 1)]);

    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);

    let mut is_active = false;
    loop {
        {
            let socket: &mut TcpSocket = sockets.get_mut(handle).as_socket();
            if !socket.is_open() {
                socket.listen(6970).unwrap()
            }

            if socket.is_active() && !is_active {
                info!("tcp:6970 connected");
            } else if !socket.is_active() && is_active {
                info!("tcp:6970 disconnected");
            }
            is_active = socket.is_active();

            if socket.may_recv() {
                let data = {
                    let mut data = socket.recv(128).unwrap().to_owned();
                    if data.len() > 0 {
                        info!("tcp:6970 recv data: {:?}",
                               str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    data
                };
                if socket.can_send() && data.len() > 0 {
                    info!("tcp:6970 send data: {:?}",
                           str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                info!("tcp:6970 close");
                socket.close();
            }
        }

        let timestamp = Instant::now().duration_since(*STARTUP_TIME);
        let timestamp_ms = (timestamp.as_secs() * 1000) + (timestamp.subsec_nanos() / 1000000) as u64;
        match iface.poll(&mut sockets, timestamp_ms) {
            Ok(()) => (),
            Err(e) => info!("poll error: {}", e)
        }
    }
}
