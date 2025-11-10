mod utils;

use log::info;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, Medium, wait as phy_wait};
use smoltcp::socket::tcp::{self, CongestionControl, State};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

const BUFFER_SIZE: usize = 6 * 1024 * 1024;

struct LatencyStats {
    samples: Vec<i64>,
    sum: i64,
    count: usize,
    min: i64,
    max: i64,
}

impl LatencyStats {
    fn new() -> Self {
        LatencyStats {
            samples: Vec::new(),
            sum: 0,
            count: 0,
            min: i64::MAX,
            max: 0,
        }
    }

    fn add_sample(&mut self, latency_us: i64) {
        self.samples.push(latency_us);
        self.sum += latency_us;
        self.count += 1;
        self.min = self.min.min(latency_us);
        self.max = self.max.max(latency_us);
    }

    fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }

    fn percentile(&mut self, p: f64) -> i64 {
        if self.samples.is_empty() {
            return 0;
        }
        self.samples.sort_unstable();
        let idx = ((p / 100.0) * self.samples.len() as f64) as usize;
        self.samples[idx.min(self.samples.len() - 1)]
    }

    fn print_summary(&mut self) {
        if self.count == 0 {
            info!("No latency samples collected");
            return;
        }

        info!("");
        info!("Latency Statistics:");
        info!("  Samples: {}", self.count);
        info!("  Min:     {:.3} ms", self.min as f64 / 1000.0);
        info!("  Mean:    {:.3} ms", self.mean() / 1000.0);
        info!("  p50:     {:.3} ms", self.percentile(50.0) as f64 / 1000.0);
        info!("  p95:     {:.3} ms", self.percentile(95.0) as f64 / 1000.0);
        info!("  p99:     {:.3} ms", self.percentile(99.0) as f64 / 1000.0);
        info!("  Max:     {:.3} ms", self.max as f64 / 1000.0);
    }
}

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
    opts.optopt("s", "server", "Server address", "ADDRESS");
    opts.optopt("p", "port", "Server port", "PORT");

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

    let server_addr = IpAddress::from_str(
        &matches.opt_str("s").unwrap_or_else(|| "192.168.69.1".to_string())
    ).expect("invalid server address");

    let server_port = matches.opt_str("p")
        .and_then(|s| u16::from_str(&s).ok())
        .unwrap_or(8000);

    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let mut device = utils::parse_middleware_options(&mut matches, device, false);

    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        Medium::Ieee802154 => todo!(),
    };
    config.random_seed = rand::random();

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(192, 168, 69, 2), 24))
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

    info!("Performance Client");
    info!("==================");
    info!("Congestion Control: {:?}", cc_algo);
    info!("Connecting to: {}:{}", server_addr, server_port);
    info!("Buffer size: {} bytes", BUFFER_SIZE);
    info!("");

    // Connect to server
    let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
    socket.connect(iface.context(), (server_addr, server_port), 49500).unwrap();

    let mut bytes_received = 0usize;
    let mut start_time: Option<Instant> = None;
    let mut last_report = Instant::now();
    let mut tcp_active = false;
    let mut latency_stats = LatencyStats::new();
    let mut sample_interval = 0; // Sample every Nth chunk

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);

        // Track connection state
        if socket.is_active() && !tcp_active {
            info!("Connected to server");
            start_time = Some(timestamp);
            bytes_received = 0;
            last_report = timestamp;
            latency_stats = LatencyStats::new();
        } else if !socket.is_active() && tcp_active {
            if let Some(start) = start_time {
                let elapsed = (timestamp - start).total_millis() as f64 / 1000.0;
                let throughput_gbps = (bytes_received as f64 * 8.0) / elapsed / 1e9;
                info!("");
                info!("Connection closed");
                info!("==================");
                info!("Total received: {:.2} MB", bytes_received as f64 / 1e6);
                info!("Time: {:.2} seconds", elapsed);
                info!("Throughput: {:.3} Gbps", throughput_gbps);
                latency_stats.print_summary();
            }
            break;
        }
        tcp_active = socket.is_active();

        // Check if server has closed (received FIN)
        if socket.state() == State::CloseWait {
            // Server has closed its side, close our side too
            socket.close();
        }

        // Receive data
        if socket.may_recv() {
            let recv_result = socket.recv(|buffer| {
                let len = buffer.len();

                // Sample latency from timestamps in the data
                // Extract timestamp from every 100000th 8-byte chunk to minimize overhead
                if len >= 8 {
                    for chunk in buffer.chunks_exact(8) {
                        sample_interval += 1;
                        if sample_interval >= 100000 {
                            sample_interval = 0;

                            let mut ts_bytes = [0u8; 8];
                            ts_bytes.copy_from_slice(chunk);
                            let sent_time_us = i64::from_le_bytes(ts_bytes);
                            let now_us = timestamp.total_micros();

                            // Calculate one-way delay (approximation)
                            let latency_us = now_us - sent_time_us;

                            // Only record reasonable latency values (< 10 seconds)
                            if latency_us > 0 && latency_us < 10_000_000 {
                                latency_stats.add_sample(latency_us);
                            }
                            break; // Only sample once per recv
                        }
                    }
                }

                (len, len)
            }).unwrap();

            bytes_received += recv_result;

            // Report progress every 5 seconds
            if (timestamp - last_report).total_millis() >= 5000 {
                if let Some(start) = start_time {
                    let elapsed = (timestamp - start).total_millis() as f64 / 1000.0;
                    if elapsed > 0.0 {
                        let throughput_gbps = (bytes_received as f64 * 8.0) / elapsed / 1e9;
                        let avg_latency = latency_stats.mean() / 1000.0; // Convert to ms
                        info!("{:.2} MB received | {:.3} Gbps | Avg Latency: {:.3} ms",
                              bytes_received as f64 / 1e6, throughput_gbps, avg_latency);
                    }
                }
                last_report = timestamp;
            }
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
