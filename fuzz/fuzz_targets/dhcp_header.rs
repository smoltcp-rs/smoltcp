#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::{DhcpPacket, DhcpRepr};

fuzz_target!(|data: &[u8]| {
    let _ = match DhcpPacket::new_checked(data) {
        Ok(packet) => match DhcpRepr::parse(packet) {
            Ok(dhcp_repr) => {
                let mut dhcp_payload = vec![0; dhcp_repr.buffer_len()];
                match DhcpPacket::new_checked(&mut dhcp_payload[..]) {
                    Ok(mut dhcp_packet) => Some(dhcp_repr.emit(&mut dhcp_packet)),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        },
        Err(_) => None,
    };
});
