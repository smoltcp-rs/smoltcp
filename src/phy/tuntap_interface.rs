use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use crate::Result;
use crate::phy::{self, sys, DeviceCapabilities, Device, Medium};
use crate::time::Instant;

/// A virtual TUN (IP) or TAP (Ethernet) interface.
#[derive(Debug)]
pub struct TunTapInterface {
    lower:  Rc<RefCell<sys::TunTapInterfaceDesc>>,
    mtu:    usize,
    medium: Medium,
}

impl AsRawFd for TunTapInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl TunTapInterface {
    /// Attaches to a TUN/TAP interface called `name`, or creates it if it does not exist.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str, medium: Medium) -> io::Result<TunTapInterface> {
        let mut lower = sys::TunTapInterfaceDesc::new(name, medium)?;
        lower.attach_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(TunTapInterface {
            lower: Rc::new(RefCell::new(lower)),
            mtu,
            medium,
        })
    }
}

impl<'a> Device<'a> for TunTapInterface {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken { lower: self.lower.clone() };
                Some((rx, tx))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                None
            }
            Err(err) => panic!("{}", err)
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<sys::TunTapInterfaceDesc>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.send(&buffer[..]).unwrap();
        result
    }
}
