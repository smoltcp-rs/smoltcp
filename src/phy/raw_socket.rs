use std::{vec, io};
use super::{sys, Device};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct RawSocket {
    lower:  sys::RawSocketDesc,
    buffer: vec::Vec<u8>
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let mut lower = try!(sys::RawSocketDesc::new(name));
        try!(lower.bind_interface());

        let mut buffer = vec::Vec::new();
        buffer.resize(try!(lower.interface_mtu()), 0);
        Ok(RawSocket {
            lower:  lower,
            buffer: buffer
        })
    }
}

impl Device for RawSocket {
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
