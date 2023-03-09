#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::{phy::ChecksumCapabilities, wire::*};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, arbitrary::Arbitrary)]
pub struct IpAddressFuzzer {
    addr: [u8; 16],
}

impl From<IpAddressFuzzer> for IpAddress {
    fn from(val: IpAddressFuzzer) -> Self {
        IpAddress::Ipv6(Ipv6Address::from_bytes(&val.addr))
    }
}

#[derive(Debug, arbitrary::Arbitrary)]
struct RplPacketFuzzer<'a> {
    data: &'a [u8],
    src_addr: IpAddressFuzzer,
    dst_addr: IpAddressFuzzer,
}

fuzz_target!(|data: RplPacketFuzzer| {
    println!("{:0x?}", data.data);
    println!("{:0x?}", data.src_addr);
    println!("{:0x?}", data.dst_addr);

    if let Ok(packet) = Icmpv6Packet::new_checked(data.data) {
        if let Ok(repr @ Icmpv6Repr::Rpl(_)) = Icmpv6Repr::parse(
            &data.src_addr.into(),
            &data.dst_addr.into(),
            &packet,
            &ChecksumCapabilities::ignored(),
        ) {
            let mut buffer = vec![0u8; repr.buffer_len()];
            repr.emit(
                &data.src_addr.into(),
                &data.dst_addr.into(),
                &mut Icmpv6Packet::new_unchecked(&mut buffer[..]),
                &ChecksumCapabilities::ignored(),
            );
        }
    }
});
