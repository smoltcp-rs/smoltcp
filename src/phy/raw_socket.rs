use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

use Result;
use phy::{self, sys, DeviceCapabilities, Device};
use time::Instant;

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
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: Instant, f: F) -> Result<R> {
        f(&self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, _timestamp: Instant, len: usize, f: F)
        -> Result<R>
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.send(&buffer[..]).unwrap();
        result
    }
}
