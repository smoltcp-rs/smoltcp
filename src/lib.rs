#![feature(range_contains, associated_consts)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

extern crate byteorder;

pub mod phy;
pub mod wire;
