#![feature(range_contains, associated_consts, const_fn)]
#![no_std]

extern crate byteorder;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;
#[cfg(feature = "std")]
extern crate libc;

pub mod phy;
pub mod wire;
pub mod iface;
