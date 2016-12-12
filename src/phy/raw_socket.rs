use std::cell::RefCell;
use std::vec::Vec;
use std::io;
use super::{sys, Device};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower:  RefCell<sys::RawSocketDesc>,
    buffer: RefCell<Vec<u8>>
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let mut lower = try!(sys::RawSocketDesc::new(name));
        try!(lower.bind_interface());

        let mut buffer = Vec::new();
        buffer.resize(try!(lower.interface_mtu()), 0);
        Ok(RawSocket {
            lower:  RefCell::new(lower),
            buffer: RefCell::new(buffer)
        })
    }
}

impl Device for RawSocket {
    fn mtu(&self) -> usize {
        let mut lower = self.lower.borrow_mut();
        lower.interface_mtu().unwrap()
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
