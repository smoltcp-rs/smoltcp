#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::{Ieee802154Frame, Ieee802154Repr};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = Ieee802154Frame::new_checked(data) {
        if let Ok(repr) = Ieee802154Repr::parse(frame) {
            // The buffer len returns only the length required for emitting the header
            // and does not take into account the length of the payload.
            let mut buffer = vec![0; repr.buffer_len()];

            // NOTE: unchecked because the checked version checks if the addressing mode field
            // is valid or not. The addressing mode field is required for calculating the length of
            // the header, which is used in `check_len`.
            let mut frame = Ieee802154Frame::new_unchecked(&mut buffer[..]);
            repr.emit(&mut frame);
        }
    };
});
