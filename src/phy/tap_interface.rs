use std::cell::RefCell;
use std::vec::Vec;
use std::io;
use super::{sys, Device};

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  RefCell<sys::TapInterfaceDesc>,
    buffer: RefCell<Vec<u8>>
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

        let mut buffer = Vec::new();
        buffer.resize(1536, 0);
        Ok(TapInterface {
            lower:  RefCell::new(lower),
            buffer: RefCell::new(buffer)
        })
    }
}

impl Device for TapInterface {
    fn mtu(&self) -> usize {
        let buffer = self.buffer.borrow();
        buffer.len()
    }

    fn recv<R, F: FnOnce(&[u8]) -> R>(&self, handler: F) -> R {
        let mut lower  = self.lower.borrow_mut();
        let mut buffer = self.buffer.borrow_mut();
        let len = lower.recv(&mut buffer[..]).unwrap();
        handler(&buffer[..len])
    }

    fn send<R, F: FnOnce(&mut [u8]) -> R>(&self, len: usize, handler: F) -> R {
        let mut lower  = self.lower.borrow_mut();
        let mut buffer = self.buffer.borrow_mut();
        let result = handler(&mut buffer[..len]);
        lower.send(&buffer[..len]).unwrap();
        result
    }
}
