use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use {Error, Result};
use super::{sys, Device, DeviceCapabilities};


/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower: Rc<RefCell<sys::RawSocketDesc>>,
    mtu:   usize,
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
            mtu:   mtu,
        })
    }
}

impl Device for RawSocket {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: u64) -> Result<Self::RxBuffer> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.recv(&mut buffer[..]) {
          Ok(size) => {
            buffer.resize(size, 0);
            Ok(buffer)
          },
          Err(e) => {
            Err(Error::IOError)
          }
        }
    }

    fn transmit(&mut self, _timestamp: u64, length: usize) -> Result<Self::TxBuffer> {
        Ok(TxBuffer {
            lower:  self.lower.clone(),
            buffer: vec![0; length],
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
    buffer: Vec<u8>,
}

impl AsRef<[u8]> for TxBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl AsMut<[u8]> for TxBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl Drop for TxBuffer {
    fn drop(&mut self) {
        let mut lower = self.lower.borrow_mut();
        lower.send(&mut self.buffer[..]).unwrap();
    }
}
