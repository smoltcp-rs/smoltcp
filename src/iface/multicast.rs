use crate::{
    config::IFACE_MAX_MULTICAST_DUPLICATION_COUNT,
    phy::PacketMeta,
    wire::{HardwareAddress, Ipv6Repr},
};

use super::packet::{IpPayloadType, PacketV6};

pub struct MulticastMetadata {
    ll_send_to: heapless::Vec<HardwareAddress, IFACE_MAX_MULTICAST_DUPLICATION_COUNT>,
    packet_metadata: PacketMeta,
    header: Ipv6Repr,
    ip_payload_type: IpPayloadType,
}

impl MulticastMetadata {
    pub(crate) fn new(
        packet_metadata: PacketMeta,
        packet: &PacketV6<'_>,
        ll_send_to: heapless::Vec<HardwareAddress, IFACE_MAX_MULTICAST_DUPLICATION_COUNT>,
    ) -> Self {
        Self {
            packet_metadata,
            ll_send_to,
            header: *packet.header(),
            ip_payload_type: packet.payload().payload_type(),
        }
    }

    pub fn finished(&self) -> bool {
        self.ll_send_to.is_empty()
    }

    pub fn pop_next_ll_addr(&mut self) -> Option<HardwareAddress> {
        self.ll_send_to.pop()
    }

    pub fn header(&self) -> &Ipv6Repr {
        &self.header
    }

    pub fn meta(&self) -> PacketMeta {
        self.packet_metadata
    }

    pub fn payload_type(&self) -> IpPayloadType {
        self.ip_payload_type.clone()
    }
}
