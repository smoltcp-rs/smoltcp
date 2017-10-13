extern crate smoltcp;

use std::env;
use smoltcp::phy::{Device, RawSocket};
use smoltcp::wire::{EthernetFrame, PrettyPrinter};

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref()).unwrap();
    loop {
        match socket.receive(/*timestamp=*/0) {
            Ok(buffer) => {
                print!("{}",PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer))
            },
            Err(e) => {/* do nothing*/}
        }
    }
}
