#![allow(unsafe_code)]

use std::vec::Vec;
use std::slice;
use Result;
use phy::{self, Device, DeviceCapabilities};
use std::io::{Error, ErrorKind};
use time::Instant;
use libc::{c_void, memcpy};
use std::{io, mem};

extern "C" {
    // to match C signatures
    static ethdriver_buf: *mut c_void;
    fn ethdriver_tx(len: i32) -> i32;
    fn ethdriver_rx(len: *mut i32) -> i32;
}

/// A backend for smoltcp, to be called from its `phy` module
/// Transmits a slice from the client application by copying data
/// into `ethdriver_buf` and consequently calling `ethdriver_tx()`
/// Returns either number of transmitted bytes or an error
fn sel4_eth_transmit(buf: &mut [u8]) -> io::Result<i32> {
    unsafe {
        let local_buf_ptr = mem::transmute::<*mut u8, *mut c_void>(buf.as_mut_ptr());
        assert!(!ethdriver_buf.is_null());
        memcpy(ethdriver_buf, local_buf_ptr, buf.len());
        match ethdriver_tx(buf.len() as i32) {
            -1 => Err(Error::new(ErrorKind::Other, "ethdriver_tx error")),
            _ => Ok(buf.len() as i32),
        }
    }
}

/// A backend for smoltcp, to be called from its `phy` module
/// Attempt to receive data from the ethernet driver
/// Call `ethdriver_rx` and cast the results.
/// Returns either a vector of received bytes, or an error
fn sel4_eth_receive() -> io::Result<Vec<u8>> {
    let mut len = 0;
    unsafe {
        if ethdriver_rx(&mut len) == -1 {
            return Err(Error::new(ErrorKind::Other, "ethdriver_rx no data received"));
        }

        assert!(!ethdriver_buf.is_null());
        // create a slice of length `len` from `ethdriver_buf`
        let local_buf_ptr = mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
        let slice = slice::from_raw_parts(local_buf_ptr, len as usize);

        // instead of dealing with the borrow checker, copy slice in to a vector
        let mut vec = Vec::new();
        vec.extend_from_slice(slice);
        Ok(vec)
    }
}

/// A sel4 camkes device.
#[derive(Debug)]
pub struct Sel4Device {}

impl Sel4Device {
    pub fn new() -> Sel4Device {
        Sel4Device {}
    }
}

impl<'a> Device<'a> for Sel4Device {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match sel4_eth_receive() {
            Ok(buf) => {
                if buf.len() > 0 {
                    let rx = RxToken { buffer: buf };
                    let tx = TxToken {};
                    Some((rx, tx))
                } else {
                    None
                }
            }
            Err(_err) => {
            	None
            }
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {})
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: Instant, f: F) -> Result<R> {
        f(&self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        sel4_eth_transmit(buffer.as_mut_slice()).unwrap();
        result
    }
}
