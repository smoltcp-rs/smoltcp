use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;

use Error;
use super::{sys, Device};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
    mtu:    usize
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let mut lower = try!(sys::RawSocketDesc::new(name));
        try!(lower.bind_interface());
        let mtu = try!(lower.interface_mtu());
        Ok(RawSocket {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   mtu
        })
    }
}

impl Device for RawSocket {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn mtu(&self) -> usize { self.mtu }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        let size = lower.recv(&mut buffer[..]).unwrap();
        buffer.resize(size, 0);
        Ok(buffer)
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error> {
        Ok(TxBuffer {
            lower:  self.lower.clone(),
            buffer: vec![0; length]
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer {
    lower:  Rc<RefCell<sys::RawSocketDesc>>,
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
        let mut lower = self.lower.borrow_mut();
        lower.send(&mut self.buffer[..]).unwrap();
    }
}
