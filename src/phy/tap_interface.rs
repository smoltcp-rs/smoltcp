use std::cell::RefCell;
use std::vec::Vec;
use std::rc::Rc;
use std::io;

use Error;
use super::{sys, Device};

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  Rc<RefCell<sys::TapInterfaceDesc>>,
    mtu:    usize
}

impl TapInterface {
    /// Attaches to a TAP interface called `name`, or creates it if it does not exist.
    ///
    /// If `name` is a persistent interface configured with UID of the current user,
    /// no special privileges are needed. Otherwise, this requires superuser privileges
    /// or a corresponding capability set on the executable.
    pub fn new(name: &str) -> io::Result<TapInterface> {
        let mut lower = try!(sys::TapInterfaceDesc::new(name));
        try!(lower.attach_interface());
        Ok(TapInterface {
            lower: Rc::new(RefCell::new(lower)),
            mtu:   1536 // FIXME: get the real value somehow
        })
    }
}

impl Device for TapInterface {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn mtu(&self) -> usize { self.mtu }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        lower.recv(&mut buffer[..]).unwrap();
        Ok(buffer)
    }

    fn transmit(&mut self, len: usize) -> Result<Self::TxBuffer, Error> {
        Ok(TxBuffer {
            lower:  self.lower.clone(),
            buffer: vec![0; len]
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer {
    lower:  Rc<RefCell<sys::TapInterfaceDesc>>,
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
