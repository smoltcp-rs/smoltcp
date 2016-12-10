extern crate smoltcp;

use std::env;
use smoltcp::phy::{Device, RawSocket};
use smoltcp::wire::{PrettyPrinter, EthernetFrame};

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref()).unwrap();
    loop {
        socket.recv(|buffer| {
            print!("{}", PrettyPrinter::<EthernetFrame<_>>::new("", &buffer))
        })
    }
}
