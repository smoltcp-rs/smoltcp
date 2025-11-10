mod utils;

use log::info;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, Medium, wait as phy_wait};
use smoltcp::socket::tcp::{self, CongestionControl};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

const BUFFER_SIZE: usize = 6 * 1024 * 1024;
const DATA_SIZE: usize = 3 * 1024 * 1024 * 1024; // 3 GB total

fn parse_congestion_control(s: &str) -> CongestionControl {
    match s.to_lowercase().as_str() {
        "none" => CongestionControl::None,
        #[cfg(feature = "socket-tcp-reno")]
        "reno" => CongestionControl::Reno,
        #[cfg(feature = "socket-tcp-cubic")]
        "cubic" => CongestionControl::Cubic,
        #[cfg(feature = "socket-tcp-bbr")]
        "bbr" => CongestionControl::Bbr,
        _ => {
            eprintln!("Unknown congestion control algorithm: {}", s);
            eprintln!("Available options:");
            eprintln!("  none");
            #[cfg(feature = "socket-tcp-reno")]
            eprintln!("  reno");
            #[cfg(feature = "socket-tcp-cubic")]
            eprintln!("  cubic");
            #[cfg(feature = "socket-tcp-bbr")]
            eprintln!("  bbr");
            std::process::exit(1);
        }
    }
}

fn main() {
    utils::setup_logging("info");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    opts.optopt("c", "congestion", "Congestion control algorithm (none/reno/cubic/bbr)", "ALGO");
    opts.optopt("p", "port", "Port to listen on", "PORT");

    free.push(""); // Make port optional via flag

    let mut matches = utils::parse_options(&opts, vec![]);

    let cc_algo = parse_congestion_control(
        &matches.opt_str("c").unwrap_or_else(|| {
            #[cfg(feature = "socket-tcp-bbr")]
            { "bbr".to_string() }
            #[cfg(not(feature = "socket-tcp-bbr"))]
            #[cfg(feature = "socket-tcp-cubic")]
            { "cubic".to_string() }
            #[cfg(not(any(feature = "socket-tcp-bbr", feature = "socket-tcp-cubic")))]
            #[cfg(feature = "socket-tcp-reno")]
            { "reno".to_string() }
            #[cfg(not(any(feature = "socket-tcp-bbr", feature = "socket-tcp-cubic", feature = "socket-tcp-reno")))]
            { "none".to_string() }
        })
    );

    let port = matches.opt_str("p")
        .and_then(|s| u16::from_str(&s).ok())
        .unwrap_or(8000);

    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let mut device = utils::parse_middleware_options(&mut matches, device, false);

    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        Medium::Ieee802154 => todo!(),
    };
    config.random_seed = rand::random();

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24))
            .unwrap();
    });

    // Create TCP socket with large buffers
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]);
    let mut tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    // Set congestion control algorithm
    tcp_socket.set_congestion_control(cc_algo);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    info!("Performance Server");
    info!("==================");
    info!("Congestion Control: {:?}", cc_algo);
    info!("Listening on port: {}", port);
    info!("Buffer size: {} bytes", BUFFER_SIZE);
    info!("Total data to send: {} GB", DATA_SIZE / (1024 * 1024 * 1024));
    info!("");

    let mut bytes_sent = 0usize;
    let mut start_time: Option<Instant> = None;
    let mut last_report = Instant::now();
    let mut close_called = false;
    let mut close_time: Option<Instant> = None;

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

        // Listen for connections if not open
        if !socket.is_open() {
            socket.listen(port).unwrap();
            bytes_sent = 0;
            start_time = None;
        }

        // Track connection state
        if socket.is_active() && !close_called {
            if !start_time.is_some() {
                info!("Client connected");
                start_time = Some(timestamp);
                bytes_sent = 0;
                last_report = timestamp;
            }
        }

        // Exit after close and grace period
        if close_called {
            if let Some(close) = close_time {
                if (timestamp - close).total_millis() >= 1000 {
                    if let Some(start) = start_time {
                        let elapsed = (timestamp - start).total_millis() as f64 / 1000.0;
                        let throughput_gbps = (bytes_sent as f64 * 8.0) / elapsed / 1e9;
                        info!("");
                        info!("Test Complete");
                        info!("=============");
                        info!("Total sent: {:.2} MB", bytes_sent as f64 / 1e6);
                        info!("Time: {:.2} seconds", elapsed);
                        info!("Throughput: {:.3} Gbps", throughput_gbps);
                    }
                    break;
                }
            }
        }

        // Send data if connected
        if socket.can_send() && bytes_sent < DATA_SIZE {
            let sent = socket
                .send(|buffer| {
                    let to_send = std::cmp::min(buffer.len(), DATA_SIZE - bytes_sent);

                    // Fill buffer with timestamp every 8 bytes for latency measurement
                    let now_micros = timestamp.total_micros();
                    for chunk in buffer[..to_send].chunks_mut(8) {
                        let timestamp_bytes = now_micros.to_le_bytes();
                        let copy_len = std::cmp::min(chunk.len(), 8);
                        chunk[..copy_len].copy_from_slice(&timestamp_bytes[..copy_len]);
                    }

                    (to_send, to_send)
                })
                .unwrap();

            bytes_sent += sent;

            // Report progress every 5 seconds
            if (timestamp - last_report).total_millis() >= 5000 {
                if let Some(start) = start_time {
                    let elapsed = (timestamp - start).total_millis() as f64 / 1000.0;
                    if elapsed > 0.0 {
                        let throughput_gbps = (bytes_sent as f64 * 8.0) / elapsed / 1e9;
                        let progress = (bytes_sent as f64 / DATA_SIZE as f64) * 100.0;
                        info!("Progress: {:.1}% | {:.2} MB sent | {:.3} Gbps",
                              progress, bytes_sent as f64 / 1e6, throughput_gbps);
                    }
                }
                last_report = timestamp;
            }

            // Close after sending all data
            if bytes_sent >= DATA_SIZE && !close_called {
                info!("Finished sending {} bytes, closing connection", bytes_sent);
                socket.close();
                close_called = true;
                close_time = Some(timestamp);
            }
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
