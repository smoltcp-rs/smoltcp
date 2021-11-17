#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::{Ipv6Address, SixlowpanUdpPacket, SixlowpanUdpRepr};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, arbitrary::Arbitrary)]
pub struct AddressFuzzer(pub [u8; 16]);

impl From<AddressFuzzer> for Ipv6Address {
    fn from(val: AddressFuzzer) -> Self {
        Ipv6Address(val.0)
    }
}

#[derive(Debug, arbitrary::Arbitrary)]
struct SixlowpanUdpPacketFuzzer<'a> {
    data: &'a [u8],
    src_addr: AddressFuzzer,
    dst_addr: AddressFuzzer,
    checksum: Option<u16>,
}

fuzz_target!(|fuzz: SixlowpanUdpPacketFuzzer| {
    if let Ok(ref frame) = SixlowpanUdpPacket::new_checked(fuzz.data) {
        if let Ok(repr) = SixlowpanUdpRepr::parse(
            frame,
            &fuzz.src_addr.into(),
            &fuzz.dst_addr.into(),
            fuzz.checksum,
        ) {
            let payload = frame.payload();
            let mut buffer = vec![0; repr.header_len() + payload.len()];

            let mut frame = SixlowpanUdpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(
                &mut frame,
                &fuzz.src_addr.into(),
                &fuzz.dst_addr.into(),
                payload.len(),
                |b| b.copy_from_slice(payload),
            );
        }
    };
});
