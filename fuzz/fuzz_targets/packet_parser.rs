#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate smoltcp;

fuzz_target!(|data: &[u8]| {
    use smoltcp::wire::*;
    format!("{}", PrettyPrinter::<EthernetFrame<&'static [u8]>>::new("", &data));
});
