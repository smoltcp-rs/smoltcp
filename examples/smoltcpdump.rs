extern crate smoltcp;

use std::env;
use smoltcp::phy::{Device, RawSocket};
use smoltcp::wire::{EthernetFrame, EthernetProtocolType, ArpPacket};

fn print_frame(buffer: &[u8]) -> Result<(), ()> {
    let frame = try!(EthernetFrame::new(&buffer[..]));
    println!("{}", frame);

    match frame.ethertype() {
        EthernetProtocolType::Arp => {
            let packet = try!(ArpPacket::new(frame.payload()));
            println!("| {}", packet);
        },
        _ => ()
    }

    Ok(())
}

fn main() {
    let ifname = env::args().nth(1).unwrap();
    let mut socket = RawSocket::new(ifname.as_ref()).unwrap();
    loop {
        socket.recv(|buffer| {
            match print_frame(buffer) {
                Ok(())  => (),
                Err(()) => println!("buffer too small")
            }
        })
    }
}
