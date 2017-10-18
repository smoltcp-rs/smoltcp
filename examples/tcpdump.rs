extern crate smoltcp;

use std::env;
use smoltcp::phy::{Device, RxToken, RawSocket};
use smoltcp::wire::{PrettyPrinter, EthernetFrame};

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref()).unwrap();
    loop {
        let (rx_token, _) = socket.receive().unwrap();
        rx_token.consume(/*timestamp = */ 0, |buffer| {
            print!("{}", PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &buffer));
            Ok(())
        }).unwrap();
    }
}
