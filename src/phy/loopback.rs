use core::mem::swap;
use core::cell::RefCell;
#[cfg(feature = "std")]
use std::rc::Rc;
#[cfg(feature = "alloc")]
use alloc::rc::Rc;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::collections::VecDeque;
#[cfg(feature = "collections")]
use collections::{Vec, VecDeque};

use {Error, Result};
use super::{Device, DeviceLimits};

/// A loopback device.
#[derive(Debug)]
pub struct Loopback(Rc<RefCell<VecDeque<Vec<u8>>>>);

impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new() -> Loopback {
        Loopback(Rc::new(RefCell::new(VecDeque::new())))
    }
}

impl Device for Loopback {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn limits(&self) -> DeviceLimits {
        DeviceLimits {
            max_transmission_unit: 65535,
            ..DeviceLimits::default()
        }
    }

    fn receive(&mut self, _timestamp: u64) -> Result<Self::RxBuffer> {
        match self.0.borrow_mut().pop_front() {
            Some(packet) => Ok(packet),
            None => Err(Error::Exhausted)
        }
    }

    fn transmit(&mut self, _timestamp: u64, length: usize) -> Result<Self::TxBuffer> {
        let mut buffer = Vec::new();
        buffer.resize(length, 0);
        Ok(TxBuffer {
            queue:  self.0.clone(),
            buffer: buffer
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer {
    queue:  Rc<RefCell<VecDeque<Vec<u8>>>>,
    buffer: Vec<u8>
}

impl AsRef<[u8]> for TxBuffer {
    fn as_ref(&self) -> &[u8] { self.buffer.as_ref() }
}

impl AsMut<[u8]> for TxBuffer {
    fn as_mut(&mut self) -> &mut [u8] { self.buffer.as_mut() }
}

impl Drop for TxBuffer {
    fn drop(&mut self) {
        let mut buffer = Vec::new();
        swap(&mut buffer, &mut self.buffer);
        self.queue.borrow_mut().push_back(buffer)
    }
}
