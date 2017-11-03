#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::{Vec, VecDeque};

use Result;
use phy::{self, Device, DeviceCapabilities};

/// A loopback device.
#[derive(Debug)]
pub struct Loopback {
    queue: VecDeque<Vec<u8>>,
}

impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new() -> Loopback {
        Loopback {
            queue: VecDeque::new(),
        }
    }
}

impl<'a> Device<'a> for Loopback {
    type RxToken = RxToken;
    type TxToken = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer: buffer };
            let tx = TxToken { queue: &mut self.queue };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            queue: &mut self.queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        f(&self.buffer)
    }
}

#[doc(hidden)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: u64, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
