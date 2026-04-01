mod utils;

use log::debug;
use std::fmt::Write;
use std::os::unix::io::AsRawFd;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Medium, wait as phy_wait};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

const LISTEN_PORT: u16 = 7000;
const BACKLOG_LEN: usize = 4;
const CONNECTION_SLOTS: usize = 4;

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
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 100))
        .unwrap();

    // Create one listener plus a fixed pool of TcpSocket connection slots.
    let mut sockets = SocketSet::new(vec![]);

    let mut backlog = [None; BACKLOG_LEN];
    let mut listener = tcp::listener::Listener::new(&mut backlog[..]);
    listener.listen(LISTEN_PORT).unwrap();
    let listener_handle = sockets.add(listener);

    let mut connection_handles = Vec::with_capacity(CONNECTION_SLOTS);
    for _ in 0..CONNECTION_SLOTS {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        connection_handles.push(sockets.add(socket));
    }

    let mut established = [false; CONNECTION_SLOTS];

    debug!("listening on tcp:{} using tcp::Listener", LISTEN_PORT);

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        // Move queued SYNs from the listener backlog into free TcpSocket slots.
        accept_queued_connections(&mut sockets, listener_handle, &connection_handles);

        // Service each accepted connection independently.
        for (index, handle) in connection_handles.iter().copied().enumerate() {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            let is_established = socket.state() == tcp::State::Established;

            if is_established && !established[index] {
                debug!("slot {} established", index);
                if socket.can_send() {
                    let greeting = format!(
                        "hello from tcp_listener: slot {} of {}\n",
                        index, CONNECTION_SLOTS
                    );
                    socket.send_slice(greeting.as_bytes()).unwrap();
                }
            } else if !socket.is_active() && established[index] {
                debug!("slot {} disconnected", index);
            }
            established[index] = is_established;

            if socket.may_recv() {
                let data = socket
                    .recv(|buffer| {
                        let len = buffer.len();
                        let data = buffer.to_vec();
                        (len, data)
                    })
                    .unwrap();

                if !data.is_empty() {
                    debug!("slot {} recv {} octets", index, data.len());
                    if socket.can_send() {
                        write!(socket, "slot {} echo: ", index).unwrap();
                        socket.send_slice(&data).unwrap();
                    }
                }
            } else if socket.may_send() {
                socket.close();
            }
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}

fn accept_queued_connections(
    sockets: &mut SocketSet<'_>,
    listener_handle: SocketHandle,
    connection_handles: &[SocketHandle],
) {
    loop {
        // Check for a free socket slot BEFORE popping from the backlog,
        // so that pending SYNs are not lost when all slots are busy.
        let Some((slot_index, handle)) = connection_handles
            .iter()
            .copied()
            .enumerate()
            .find(|(_, handle)| !sockets.get::<tcp::Socket>(*handle).is_open())
        else {
            break; // All slots busy; leave remaining SYNs in the backlog.
        };

        let pending = {
            let listener = sockets.get_mut::<tcp::listener::Listener>(listener_handle);
            listener.accept()
        };
        let Some(pending) = pending else {
            break; // Backlog is empty.
        };

        let socket = sockets.get_mut::<tcp::Socket>(handle);
        socket.accept(pending).unwrap();
        debug!(
            "accepted {} into slot {} of {}",
            pending.remote,
            slot_index,
            connection_handles.len()
        );
    }
}
