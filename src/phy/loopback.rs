use core::cell::RefCell;
#[cfg(feature = "std")]
use std::rc::Rc;
#[cfg(feature = "alloc")]
use alloc::rc::Rc;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::{Vec, VecDeque};

use Result;
use super::{Device, DeviceCapabilities};
use phy;

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
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.0.borrow_mut().pop_front().map(|buffer| {
            let rx = RxToken {buffer: buffer};
            let tx = TxToken {queue: self.0.clone()};
            (rx, tx)
        })       
    }


    fn transmit(&mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            queue:  self.0.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl<'a> phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        f(&self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken {
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, _timestamp: u64, len: usize, f: F) -> R {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.queue.borrow_mut().push_back(buffer);
        result
    }
}
