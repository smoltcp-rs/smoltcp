mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::os::unix::io::AsRawFd;

#[cfg(any(
    feature = "proto-sixlowpan-fragmentation",
    feature = "proto-ipv4-fragmentation"
))]
use smoltcp::iface::FragmentsCache;
use smoltcp::iface::{InterfaceBuilder, NeighborCache, SocketSet};
use smoltcp::phy::{wait as phy_wait, Device, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let udp_rx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
        vec![0; 65535],
    );
    let udp_tx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
        vec![0; 65535],
    );
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp1_rx_buffer = tcp::SocketBuffer::new(vec![0; 64]);
    let tcp1_tx_buffer = tcp::SocketBuffer::new(vec![0; 128]);
    let tcp1_socket = tcp::Socket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = tcp::SocketBuffer::new(vec![0; 64]);
    let tcp2_tx_buffer = tcp::SocketBuffer::new(vec![0; 128]);
    let tcp2_socket = tcp::Socket::new(tcp2_rx_buffer, tcp2_tx_buffer);

    let tcp3_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp3_socket = tcp::Socket::new(tcp3_rx_buffer, tcp3_tx_buffer);

    let tcp4_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp4_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
    let tcp4_socket = tcp::Socket::new(tcp4_rx_buffer, tcp4_tx_buffer);

    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [
        IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
        IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
        IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
    ];

    let medium = device.capabilities().medium;
    let mut builder = InterfaceBuilder::new().ip_addrs(ip_addrs);

    builder = builder.random_seed(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    #[cfg(feature = "proto-ipv4-fragmentation")]
    let mut ipv4_out_packet_cache = [0u8; 10_000];
    #[cfg(feature = "proto-ipv4-fragmentation")]
    {
        let ipv4_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
        builder = builder
            .ipv4_fragments_cache(ipv4_frag_cache)
            .ipv4_out_packet_cache(&mut ipv4_out_packet_cache[..]);
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    let mut sixlowpan_out_packet_cache = [0u8; 1280];
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    {
        let sixlowpan_frag_cache = FragmentsCache::new(vec![], BTreeMap::new());
        builder = builder
            .sixlowpan_fragments_cache(sixlowpan_frag_cache)
            .sixlowpan_out_packet_cache(&mut sixlowpan_out_packet_cache[..]);
    }

    if medium == Medium::Ethernet {
        builder = builder
            .hardware_addr(ethernet_addr.into())
            .neighbor_cache(neighbor_cache);
    }
    let mut iface = builder.finalize(&mut device);

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);
    let tcp1_handle = sockets.add(tcp1_socket);
    let tcp2_handle = sockets.add(tcp2_socket);
    let tcp3_handle = sockets.add(tcp3_socket);
    let tcp4_handle = sockets.add(tcp4_socket);

    let mut tcp_6970_active = false;
    loop {
        let timestamp = Instant::now();
        match iface.poll(timestamp, &mut device, &mut sockets) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // udp:6969: respond "hello"
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(6969).unwrap()
        }

        let client = match socket.recv() {
            Ok((data, endpoint)) => {
                debug!("udp:6969 recv data: {:?} from {}", data, endpoint);
                let mut data = data.to_vec();
                data.reverse();
                Some((endpoint, data))
            }
            Err(_) => None,
        };
        if let Some((endpoint, data)) = client {
            debug!("udp:6969 send data: {:?} to {}", data, endpoint,);
            socket.send_slice(&data, endpoint).unwrap();
        }

        // tcp:6969: respond "hello"
        let socket = sockets.get_mut::<tcp::Socket>(tcp1_handle);
        if !socket.is_open() {
            socket.listen(6969).unwrap();
        }

        if socket.can_send() {
            debug!("tcp:6969 send greeting");
            writeln!(socket, "hello").unwrap();
            debug!("tcp:6969 close");
            socket.close();
        }

        // tcp:6970: echo with reverse
        let socket = sockets.get_mut::<tcp::Socket>(tcp2_handle);
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
            let data = socket
                .recv(|buffer| {
                    let recvd_len = buffer.len();
                    let mut data = buffer.to_owned();
                    if !data.is_empty() {
                        debug!("tcp:6970 recv data: {:?}", data);
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (recvd_len, data)
                })
                .unwrap();
            if socket.can_send() && !data.is_empty() {
                debug!("tcp:6970 send data: {:?}", data);
                socket.send_slice(&data[..]).unwrap();
            }
        } else if socket.may_send() {
            debug!("tcp:6970 close");
            socket.close();
        }

        // tcp:6971: sinkhole
        let socket = sockets.get_mut::<tcp::Socket>(tcp3_handle);
        if !socket.is_open() {
            socket.listen(6971).unwrap();
            socket.set_keep_alive(Some(Duration::from_millis(1000)));
            socket.set_timeout(Some(Duration::from_millis(2000)));
        }

        if socket.may_recv() {
            socket
                .recv(|buffer| {
                    if !buffer.is_empty() {
                        debug!("tcp:6971 recv {:?} octets", buffer.len());
                    }
                    (buffer.len(), ())
                })
                .unwrap();
        } else if socket.may_send() {
            socket.close();
        }

        // tcp:6972: fountain
        let socket = sockets.get_mut::<tcp::Socket>(tcp4_handle);
        if !socket.is_open() {
            socket.listen(6972).unwrap()
        }

        if socket.may_send() {
            socket
                .send(|data| {
                    if !data.is_empty() {
                        debug!("tcp:6972 send {:?} octets", data.len());
                        for (i, b) in data.iter_mut().enumerate() {
                            *b = (i % 256) as u8;
                        }
                    }
                    (data.len(), ())
                })
                .unwrap();
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
