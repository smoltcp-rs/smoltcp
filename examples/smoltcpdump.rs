extern crate smoltcp;

use std::{env, io};
use smoltcp::wire::{EthernetFrame, EthernetProtocolType, ArpPacket};
use smoltcp::interface::RawSocket;

fn get<T>(result: Result<T, ()>) -> io::Result<T> {
    result.map_err(|()| io::Error::new(io::ErrorKind::InvalidData,
                                       "buffer too small"))
          .into()
}

fn print_frame(socket: &mut RawSocket) -> io::Result<()> {
    let buffer = try!(socket.capture());

    let frame = try!(get(EthernetFrame::new(&buffer[..])));
    println!("{}", frame);

    match frame.ethertype() {
        EthernetProtocolType::Arp => {
            let packet = try!(get(ArpPacket::new(frame.payload())));
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
        match print_frame(&mut socket) {
            Ok(()) => (),
            Err(e) => println!("Cannot print frame: {}", e)
        }
    }
}
