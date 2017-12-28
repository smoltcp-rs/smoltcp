extern crate smoltcp;

use std::env;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::wire::{PrettyPrinter, EthernetFrame};

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref()).unwrap();
    loop {
        phy_wait(socket.as_raw_fd(), None).unwrap();
        let (rx_token, _) = socket.receive().unwrap();
        rx_token.consume(/*timestamp = */ 0, |buffer| {
            println!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
            Ok(())
        }).unwrap();
    }
}
