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
    fn client_buf(client_id: i32) -> *mut c_void;
    fn client_tx(len: i32) -> i32;
    fn client_rx(len: *mut i32) -> i32;
}

/// A backend for smoltcp, to be called from its `phy` module
/// Transmits a slice from the client application by copying data
/// into `ethdriver_buf` and consequently calling `ethdriver_tx()`
/// Returns either number of transmitted bytes or an error
fn sel4_client_transmit(buf: &mut [u8]) -> io::Result<i32> {
    unsafe {
        let local_buf_ptr = mem::transmute::<*mut u8, *mut c_void>(buf.as_mut_ptr());
        assert!(!client_buf(1).is_null());
        memcpy(client_buf(1), local_buf_ptr, buf.len());
        match client_tx(buf.len() as i32) {
            -1 => Err(Error::new(ErrorKind::Other, "client_tx error")),
            _ => Ok(buf.len() as i32),
        }
    }
}

/// A backend for smoltcp, to be called from its `phy` module
/// Attempt to receive data from the ethernet driver
/// Call `ethdriver_rx` and cast the results.
/// Returns either a vector of received bytes, or an error
fn sel4_client_receive() -> io::Result<Vec<u8>> {
    let mut len = 0;
    unsafe {
        if client_rx(&mut len) == -1 {
            return Err(Error::new(ErrorKind::Other, "client_rx no data received"));
        }

        assert!(!client_buf(1).is_null());
        // create a slice of length `len` from `ethdriver_buf`
        let local_buf_ptr = mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = slice::from_raw_parts(local_buf_ptr, len as usize);

        // instead of dealing with the borrow checker, copy slice in to a vector
        let mut vec = Vec::new();
        vec.extend_from_slice(slice);
        Ok(vec)
    }
}

/// A sel4 camkes device.
#[derive(Debug)]
pub struct ClientDevice {}

impl ClientDevice {
    pub fn new() -> ClientDevice {
        ClientDevice {}
    }
}

impl<'a> Device<'a> for ClientDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match sel4_client_receive() {
            Ok(buf) => {
                if buf.len() > 0 {
                    let rx = RxToken { buffer: buf };
                    let tx = TxToken {};
                    Some((rx, tx))
                } else {
                    None
                }
            }
            Err(_err) => None,
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
        sel4_client_transmit(buffer.as_mut_slice()).unwrap();
        result
    }
}
