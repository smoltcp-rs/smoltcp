use smoltcp::phy::{Device, RxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetFrame, PrettyPrinter};
use smoltcp_device_unix::{wait as phy_wait, RawSocket};
use std::env;
use std::os::unix::io::AsRawFd;

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref(), smoltcp::phy::Medium::Ethernet).unwrap();
    loop {
        phy_wait(socket.as_raw_fd(), None).unwrap();
        let (rx_token, _) = socket.receive(Instant::now()).unwrap();
        rx_token.consume(|buffer| {
            println!(
                "{}",
                PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer)
            );
        })
    }
}
