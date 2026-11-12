//! A TCP connect to an on-link address that never answers ARP must not stop
//! traffic through the gateway once the gateway's neighbor cache entry expires.
use std::collections::VecDeque;

use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, IpCidr,
    Ipv4Address, Ipv4Packet,
};

const ME: Ipv4Address = Ipv4Address::new(192, 168, 1, 39);
const GATEWAY: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
const SILENT_LAN_HOST: Ipv4Address = Ipv4Address::new(192, 168, 1, 250);
const REMOTE: Ipv4Address = Ipv4Address::new(93, 184, 216, 34);
const MY_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 39]);
const GATEWAY_MAC: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 1]);

#[derive(Default)]
struct Wire {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.push(frame);
        result
    }
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let frame = self.inbound.pop_front()?;
        Some((Rx(frame), Tx(&mut self.outbound)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

fn gateway_arp_reply() -> Vec<u8> {
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: GATEWAY_MAC,
        source_protocol_addr: GATEWAY,
        target_hardware_addr: MY_MAC,
        target_protocol_addr: ME,
    };
    let mut frame = vec![0; 14 + arp.buffer_len()];
    let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
    ethernet.set_dst_addr(MY_MAC);
    ethernet.set_src_addr(GATEWAY_MAC);
    ethernet.set_ethertype(EthernetProtocol::Arp);
    arp.emit(&mut ArpPacket::new_unchecked(ethernet.payload_mut()));
    frame
}

/// The gateway is learned at start, a connect to an unused on-link address
/// starts at 1 s, and a connect to a remote host starts later,
/// after the gateway's 60 s entry has expired. The gateway answers every ARP
/// request; the LAN address answers none. Returns when the first SYN to the
/// remote host left, in ms.
fn first_remote_syn_ms(remote_connect_ms: i64) -> Option<i64> {
    let mut wire = Wire::default();
    let mut iface = Interface::new(Config::new(MY_MAC.into()), &mut wire, Instant::ZERO);
    iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(ME.into(), 24)).unwrap());
    iface.routes_mut().add_default_ipv4_route(GATEWAY).unwrap();
    let mut storage: [SocketStorage; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut storage[..]);
    let socket = || {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1024]),
            tcp::SocketBuffer::new(vec![0; 1024]),
        )
    };
    let silent = sockets.add(socket());
    let remote = sockets.add(socket());
    wire.inbound.push_back(gateway_arp_reply());

    for ms in 0..remote_connect_ms + 30_000 {
        if ms == 1_000 {
            sockets
                .get_mut::<tcp::Socket>(silent)
                .connect(iface.context(), (SILENT_LAN_HOST, 1883), 49152)
                .unwrap();
        }
        if ms == remote_connect_ms {
            sockets
                .get_mut::<tcp::Socket>(remote)
                .connect(iface.context(), (REMOTE, 443), 49153)
                .unwrap();
        }
        iface.poll(Instant::from_millis(ms), &mut wire, &mut sockets);
        for frame in std::mem::take(&mut wire.outbound) {
            let ethernet = EthernetFrame::new_checked(&frame[..]).unwrap();
            match ethernet.ethertype() {
                EthernetProtocol::Arp => {
                    let arp = ArpRepr::parse(&ArpPacket::new_checked(ethernet.payload()).unwrap());
                    if let Ok(ArpRepr::EthernetIpv4 {
                        target_protocol_addr: GATEWAY,
                        ..
                    }) = arp
                    {
                        wire.inbound.push_back(gateway_arp_reply());
                    }
                }
                EthernetProtocol::Ipv4 => {
                    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
                    if ip.dst_addr() == REMOTE {
                        return Some(ms);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[test]
fn a_silent_lan_host_does_not_starve_the_gateway() {
    for remote_connect_ms in [150_000, 150_250, 150_500, 150_999] {
        let sent = first_remote_syn_ms(remote_connect_ms);
        assert!(
            sent.is_some_and(|ms| ms - remote_connect_ms <= 2_000),
            "connect at {remote_connect_ms} ms: first SYN to the remote host at {sent:?} ms, want within 2 s"
        );
    }
}
