use std::cell::RefCell;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use {Error, Result};
use super::{sys, DeviceCapabilities, Device};
use phy;

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  Rc<RefCell<sys::TapInterfaceDesc>>,
    mtu:    usize
}

impl AsRawFd for TapInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl TapInterface {
    /// Attaches to a TAP interface called `name`, or creates it if it does not exist.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str) -> io::Result<TapInterface> {
        let mut lower = sys::TapInterfaceDesc::new(name)?;
        lower.attach_interface()?;
        let mtu = lower.interface_mtu()?;
        Ok(TapInterface {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu
        })
    }
}

impl<'a> Device<'a> for TapInterface {
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
        let tx = TxToken { lower: self.lower.clone(), };
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
    lower: Rc<RefCell<sys::TapInterfaceDesc>>,
    mtu:   usize,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                f(&buffer)
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                Err(Error::Exhausted)
            }
            Err(err) => panic!("{}", err)
        }
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<sys::TapInterfaceDesc>>,
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
