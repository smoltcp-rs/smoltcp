use phy::Device;
use wire::EthernetAddress;
use super::{ProtocolAddress, ArpCache};

/// An Ethernet network interface.
#[derive(Debug)]
pub struct Interface<DeviceT: Device, ArpCacheT: ArpCache> {
    device:        DeviceT,
    arp_cache:     ArpCacheT,
    hardware_addr: EthernetAddress,
}

impl<DeviceT: Device, ArpCacheT: ArpCache> Interface<DeviceT, ArpCacheT> {
    /// Create a network interface using the provided network device.
    ///
    /// The newly created interface uses hardware address `00-00-00-00-00-00` and
    /// has no assigned protocol addresses.
    pub fn new(device: DeviceT, arp_cache: ArpCacheT) -> Interface<DeviceT, ArpCacheT> {
        Interface {
            device:        device,
            arp_cache:     arp_cache,
            hardware_addr: EthernetAddress([0x00; 6])
        }
    }

    /// Get the hardware address of the interface.
    pub fn hardware_addr(&self) -> EthernetAddress {
        self.hardware_addr
    }

    /// Set the hardware address of the interface.
    ///
    /// # Panics
    /// This function panics if `addr` is not unicast.
    pub fn set_hardware_addr(&mut self, addr: EthernetAddress) {
        if addr.is_multicast() { panic!("hardware address should be unicast") }
        self.hardware_addr = addr
    }
}
