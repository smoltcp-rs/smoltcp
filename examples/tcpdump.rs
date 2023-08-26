use smoltcp::phy::{self, Device, RawSocket, RxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetFrame, PrettyPrinter};
use std::env;
#[cfg(target_family = "unix")]
use std::os::unix::io::AsRawFd;

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref(), smoltcp::phy::Medium::Ethernet).unwrap();
    loop {
        phy::wait(socket.as_raw_fd(), None).unwrap();
        let (rx_token, _) = socket.receive(Instant::now()).unwrap();
        rx_token.consume(|buffer| {
            println!(
                "{}",
                PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer)
            );
        })
    }
}
