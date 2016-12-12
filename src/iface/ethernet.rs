use Error;
use phy::Device;
use wire::{EthernetAddress, EthernetProtocolType, EthernetFrame};
use wire::{ArpPacket, ArpRepr, ArpOperation};
use super::{ProtocolAddress, ArpCache};

/// An Ethernet network interface.
#[derive(Debug)]
pub struct Interface<'a, DeviceT: Device, ArpCacheT: ArpCache> {
    device:         DeviceT,
    arp_cache:      ArpCacheT,
    hardware_addr:  EthernetAddress,
    protocol_addrs: &'a [ProtocolAddress]
}

impl<'a, DeviceT: Device, ArpCacheT: ArpCache> Interface<'a, DeviceT, ArpCacheT> {
    /// Create a network interface using the provided network device.
    ///
    /// The newly created interface uses hardware address `00-00-00-00-00-00` and
    /// has no assigned protocol addresses.
    pub fn new(device: DeviceT, arp_cache: ArpCacheT) -> Interface<'a, DeviceT, ArpCacheT> {
        Interface {
            device:         device,
            arp_cache:      arp_cache,
            hardware_addr:  EthernetAddress([0x00; 6]),
            protocol_addrs: &[]
        }
    }

    /// Get the hardware address of the interface.
    pub fn hardware_addr(&self) -> EthernetAddress {
        self.hardware_addr
    }

    /// Set the hardware address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    pub fn set_hardware_addr(&mut self, addr: EthernetAddress) {
        if addr.is_multicast() {
            panic!("hardware address {} is not unicast", addr)
        }

        self.hardware_addr = addr
    }

    /// Get the protocol addresses of the interface.
    pub fn protocol_addrs(&self) -> &'a [ProtocolAddress] {
        self.protocol_addrs
    }

    /// Set the protocol addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses is not unicast.
    pub fn set_protocol_addrs(&mut self, addrs: &'a [ProtocolAddress]) {
        for addr in addrs {
            if !addr.is_unicast() {
                panic!("protocol address {} is not unicast", addr)
            }
        }

        self.protocol_addrs = addrs
    }

    /// Checks whether the interface has the given protocol address assigned.
    pub fn has_protocol_addr<T: Into<ProtocolAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.protocol_addrs.iter().any(|&probe| probe == addr)
    }

    /// Receive and process a packet, if available.
    pub fn poll(&mut self) -> Result<(), Error> {
        enum Response {
            Nop,
            Arp(ArpRepr)
        }

        let response = try!(self.device.recv(|buffer| {
            let frame = try!(EthernetFrame::new(buffer));
            match frame.ethertype() {
                EthernetProtocolType::Arp => {
                    let packet = try!(ArpPacket::new(frame.payload()));
                    let repr = try!(ArpRepr::parse(&packet));
                    match repr {
                        ArpRepr::EthernetIpv4 {
                            operation: ArpOperation::Request,
                            source_hardware_addr, source_protocol_addr,
                            target_protocol_addr, ..
                        } => {
                            if self.has_protocol_addr(target_protocol_addr) {
                                Ok(Response::Arp(ArpRepr::EthernetIpv4 {
                                    operation: ArpOperation::Reply,
                                    source_hardware_addr: self.hardware_addr,
                                    source_protocol_addr: target_protocol_addr,
                                    target_hardware_addr: source_hardware_addr,
                                    target_protocol_addr: source_protocol_addr
                                }))
                            } else {
                                Ok(Response::Nop)
                            }
                        },
                        _ => Err(Error::Unrecognized)
                    }
                },
                _ => Err(Error::Unrecognized)
            }
        }));

        // TODO: accurately calculate the outgoing packet size?
        let size = self.device.mtu();

        match response {
            Response::Nop => Ok(()),
            Response::Arp(repr) => {
                self.device.send(size, |buffer| {
                    let mut frame = try!(EthernetFrame::new(buffer));
                    frame.set_source(self.hardware_addr);
                    frame.set_destination(match repr {
                        ArpRepr::EthernetIpv4 { target_hardware_addr, .. } => target_hardware_addr,
                        _ => unreachable!()
                    });

                    let mut packet = try!(ArpPacket::new(frame.payload_mut()));
                    repr.emit(&mut packet);

                    Ok(())
                })
            }
        }
    }
}
