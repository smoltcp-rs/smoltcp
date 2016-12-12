#![feature(associated_consts)]
extern crate smoltcp;

use std::env;
use smoltcp::phy::{Device, TapInterface};
use smoltcp::wire::{PrettyPrinter, EthernetFrame, EthernetAddress};
use smoltcp::iface::{ProtocolAddress, SliceArpCache, EthernetInterface};

struct TracingDevice<T: Device>(T);

impl<T: Device> Device for TracingDevice<T> {
    fn mtu(&self) -> usize {
        self.0.mtu()
    }

    fn recv<R, F: FnOnce(&[u8]) -> R>(&self, handler: F) -> R {
        self.0.recv(|buffer| {
            print!("{}", PrettyPrinter::<EthernetFrame<_>>::new("<- ", &buffer));
            handler(buffer)
        })
    }

    fn send<R, F: FnOnce(&mut [u8]) -> R>(&self, len: usize, handler: F) -> R {
        self.0.send(len, |buffer| {
            let result = handler(buffer);
            print!("{}", PrettyPrinter::<EthernetFrame<_>>::new("-> ", &buffer));
            result
        })
    }
}

fn main() {
    let ifname = env::args().nth(1).unwrap();

    let hardware_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let protocol_addrs = [ProtocolAddress::ipv4([192, 168, 69, 1])];

    let device = TapInterface::new(ifname.as_ref()).unwrap();
    let device = TracingDevice(device);

    let mut arp_cache_data = [Default::default(); 8];
    let arp_cache = SliceArpCache::new(&mut arp_cache_data);
    let mut iface = EthernetInterface::new(device, arp_cache);

    iface.set_hardware_addr(hardware_addr);
    iface.set_protocol_addrs(&protocol_addrs);

    loop {
        match iface.poll() {
            Ok(()) => (),
            Err(e) => println!("{}", e)
        }
    }
}
