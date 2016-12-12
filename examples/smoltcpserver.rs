#![feature(associated_consts)]
extern crate smoltcp;

use std::env;
use smoltcp::phy::{Tracer, TapInterface};
use smoltcp::wire::{EthernetFrame, EthernetAddress};
use smoltcp::iface::{ProtocolAddress, SliceArpCache, EthernetInterface};

fn main() {
    let ifname = env::args().nth(1).unwrap();

    let hardware_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let protocol_addrs = [ProtocolAddress::ipv4([192, 168, 69, 1])];

    let device = TapInterface::new(ifname.as_ref()).unwrap();
    let device = Tracer::<_, EthernetFrame<&[u8]>>::new(device);

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
