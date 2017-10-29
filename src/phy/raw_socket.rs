use std::cell::RefCell;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use Result;
use super::{sys, DeviceCapabilities, Device};
use phy;

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
    mtu:    usize
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let mut lower = sys::RawSocketDesc::new(name)?;
        lower.bind_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(RawSocket {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu
        })
    }
}

impl<'a> Device<'a> for RawSocket {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let rx = RxToken { lower: self.lower.clone(), mtu: self.mtu };
        let tx = TxToken { lower: self.lower.clone() };
        Some((rx, tx))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
    mtu:    usize,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        let size = lower.recv(&mut buffer[..]).unwrap();
        buffer.resize(size, 0);
        f(&mut buffer)
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, _timestamp: u64, len: usize, f: F)
        -> Result<R>
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let ret = f(&mut buffer);
        lower.send(&mut buffer[..]).unwrap();
        ret
    }
}
