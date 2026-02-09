//! Raw Ethernet example
//!
//! This example opens a raw Ethernet socket on a TAP interface and:
//! - sends one Ethernet II frame per second;
//! - receives frames matching a selected EtherType filter.
//!
//! Quick start:
//!
//! ```sh
//! sudo ip tuntap add dev tap0 mode tap user "$USER"
//! sudo ip link set dev tap0 up
//! cargo run --example raw_ethernet -- --tap tap0 --ethertype 0x88b5
//! ```
//!
//! Important:
//! - A single TAP endpoint does not loop packets back to itself.
//! - To observe `recv`, use two TAP interfaces bridged together and run this example on both.
//!
//! Two-endpoint setup:
//!
//! ```sh
//! sudo ip tuntap add dev tap0 mode tap user "$USER"
//! sudo ip tuntap add dev tap1 mode tap user "$USER"
//! sudo ip link add br0 type bridge
//! sudo ip link set br0 up
//! sudo ip link set tap0 master br0
//! sudo ip link set tap1 master br0
//! sudo ip link set tap0 up
//! sudo ip link set tap1 up
//! ```
//!
//! Then run in two terminals:
//!
//! ```sh
//! cargo run --example raw_ethernet -- --tap tap0 --ethertype 0x88b5
//! cargo run --example raw_ethernet -- --tap tap1 --ethertype 0x88b5
//! ```
//!
//! Optional flags:
//! - `--src aa:bb:cc:dd:ee:ff`
//! - `--dst aa:bb:cc:dd:ee:ff`
//! - `--payload "text"`
//!
mod utils;

use std::os::unix::io::AsRawFd;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::wait as phy_wait;
use smoltcp::socket::raw_ethernet;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr};

fn parse_ethertype(input: &str) -> Result<u16, String> {
    let s = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    u16::from_str_radix(s, 16).map_err(|_| format!("invalid ethertype: {input}"))
}

fn parse_mac(input: &str) -> Result<EthernetAddress, String> {
    let mut out = [0u8; 6];
    let mut count = 0usize;

    for part in input.split(':') {
        if count >= 6 {
            return Err(format!("invalid MAC address: {input}"));
        }
        if part.len() != 2 {
            return Err(format!("invalid MAC address: {input}"));
        }
        out[count] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("invalid MAC address octet '{part}' in {input}"))?;
        count += 1;
    }

    if count != 6 {
        return Err(format!("invalid MAC address: {input}"));
    }

    Ok(EthernetAddress(out))
}

fn main() {
    utils::setup_logging("info");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    opts.optopt(
        "",
        "ethertype",
        "EtherType in hex (for filter and emitted frame), default 0x88b5",
        "HEX",
    );
    opts.optopt(
        "",
        "dst",
        "Destination MAC as aa:bb:cc:dd:ee:ff, default ff:ff:ff:ff:ff:ff",
        "MAC",
    );
    opts.optopt(
        "",
        "src",
        "Source MAC as aa:bb:cc:dd:ee:ff, default 02:00:00:00:00:01",
        "MAC",
    );
    opts.optopt(
        "",
        "payload",
        "ASCII payload to emit periodically, default 'smoltcp raw ethernet'",
        "TEXT",
    );

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);
    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let ethertype = matches
        .opt_str("ethertype")
        .as_deref()
        .map(parse_ethertype)
        .transpose()
        .expect("invalid --ethertype")
        .unwrap_or(0x88b5);
    let dst = matches
        .opt_str("dst")
        .as_deref()
        .map(parse_mac)
        .transpose()
        .expect("invalid --dst")
        .unwrap_or(EthernetAddress::BROADCAST);
    let src = matches
        .opt_str("src")
        .as_deref()
        .map(parse_mac)
        .transpose()
        .expect("invalid --src")
        .unwrap_or(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));

    let payload = matches
        .opt_str("payload")
        .unwrap_or_else(|| "smoltcp raw ethernet".to_string())
        .into_bytes();

    let mut config = Config::new(src.into());
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let rx_buffer = raw_ethernet::PacketBuffer::new(
        vec![raw_ethernet::PacketMetadata::EMPTY; 8],
        vec![0; 1536 * 8],
    );
    let tx_buffer = raw_ethernet::PacketBuffer::new(
        vec![raw_ethernet::PacketMetadata::EMPTY; 8],
        vec![0; 1536 * 8],
    );
    let raw_socket = raw_ethernet::Socket::new(
        Some(EthernetProtocol::Unknown(ethertype)),
        rx_buffer,
        tx_buffer,
    );

    let mut sockets = SocketSet::new(vec![]);
    let raw_handle = sockets.add(raw_socket);

    let mut next_tx_at = Instant::from_millis(0);

    println!("raw ethernet example started: ethertype=0x{ethertype:04x}, src={src}, dst={dst}");

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        {
            let socket = sockets.get_mut::<raw_ethernet::Socket>(raw_handle);

            if socket.can_send() && timestamp >= next_tx_at {
                let frame_len = EthernetFrame::<&[u8]>::header_len() + payload.len();
                let frame_buf = socket.send(frame_len).expect("send buffer full");
                let mut frame = EthernetFrame::new_unchecked(frame_buf);

                EthernetRepr {
                    src_addr: src,
                    dst_addr: dst,
                    ethertype: EthernetProtocol::Unknown(ethertype),
                }
                .emit(&mut frame);
                frame.payload_mut().copy_from_slice(&payload);

                println!("sent {} bytes", frame_len);
                next_tx_at = timestamp + Duration::from_secs(1);
            }

            while socket.can_recv() {
                let data = socket.recv().expect("recv should succeed");
                let frame = EthernetFrame::new_checked(data).expect("malformed frame from socket");
                println!(
                    "recv {} bytes: src={} dst={} ethertype={} payload={:x?}",
                    data.len(),
                    frame.src_addr(),
                    frame.dst_addr(),
                    frame.ethertype(),
                    frame.payload()
                );
            }
        }

        let delay = iface
            .poll_delay(timestamp, &sockets)
            .unwrap_or(Duration::from_millis(100));
        phy_wait(fd, Some(delay)).expect("wait error");
    }
}
