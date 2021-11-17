#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::{Ieee802154Address, SixlowpanIphcPacket, SixlowpanIphcRepr};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, arbitrary::Arbitrary)]
pub enum AddressFuzzer {
    Absent,
    Short([u8; 2]),
    Extended([u8; 8]),
}

impl From<AddressFuzzer> for Ieee802154Address {
    fn from(val: AddressFuzzer) -> Self {
        match val {
            AddressFuzzer::Absent => Ieee802154Address::Absent,
            AddressFuzzer::Short(b) => Ieee802154Address::Short(b),
            AddressFuzzer::Extended(b) => Ieee802154Address::Extended(b),
        }
    }
}

#[derive(Debug, arbitrary::Arbitrary)]
struct SixlowpanIphcPacketFuzzer<'a> {
    data: &'a [u8],
    ll_src_addr: Option<AddressFuzzer>,
    ll_dst_addr: Option<AddressFuzzer>,
}

fuzz_target!(|fuzz: SixlowpanIphcPacketFuzzer| {
    if let Ok(ref frame) = SixlowpanIphcPacket::new_checked(fuzz.data) {
        if let Ok(repr) = SixlowpanIphcRepr::parse(
            frame,
            fuzz.ll_src_addr.map(Into::into),
            fuzz.ll_dst_addr.map(Into::into),
        ) {
            let mut buffer = vec![0; repr.buffer_len()];

            let mut frame = SixlowpanIphcPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut frame);
        }
    };
});
