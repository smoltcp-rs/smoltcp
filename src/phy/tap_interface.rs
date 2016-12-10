use std::{vec, io};
use super::{sys, Device};

/// A virtual Ethernet interface.
#[derive(Debug)]
pub struct TapInterface {
    lower:  sys::TapInterfaceDesc,
    buffer: vec::Vec<u8>
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

        let mut buffer = vec::Vec::new();
        buffer.resize(Self::MTU, 0);
        Ok(TapInterface {
            lower:  lower,
            buffer: buffer
        })
    }
}

impl Device for TapInterface {
    const MTU: usize = 1536;

    fn recv<F: FnOnce(&[u8])>(&mut self, handler: F) {
        let len = self.lower.recv(&mut self.buffer[..]).unwrap();
        handler(&self.buffer[..len])
    }

    fn send<F: FnOnce(&mut [u8])>(&mut self, len: usize, handler: F) {
        handler(&mut self.buffer[..len]);
        self.lower.send(&self.buffer[..len]).unwrap();
    }
}
