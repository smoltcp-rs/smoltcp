//! Access to networking hardware.
//!
//! The `phy` module provides an interface for sending and receiving frames
//! through a physical (or perhaps virtualized) network device, [Device](trait.Device.html),
//! as well as some useful implementations of that trait.
//!
//! Currently the only implementation, [RawSocket](struct.RawSocket.html), is based on
//! Unix raw sockets, and only works on Linux.

#[cfg(all(unix, feature = "std"))]
mod raw_socket;

/// An interface for sending and receiving raw network frames.
///
/// It is expected that a `Device` implementation would allocate memory for both sending
/// and receiving packets from memory pools; hence, the stack borrows the buffer for a packet
/// that it is about to receive, as well for a packet that it is about to send, from the device.
pub trait Device {
    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the MTU.
    /// In practice, MTU will fall between 64 and 9216 octets.
    const MTU: usize;

    /// Receives a frame.
    ///
    /// It is expected that a `recv` implementation, once a packet is written to memory
    /// through DMA, would gain ownership of the underlying buffer, provide it for parsing,
    /// and then return it to the network device.
    fn recv<F: FnOnce(&[u8])>(&mut self, handler: F);

    /// Transmits a frame.
    ///
    /// It is expected that a `send` implementation would gain ownership of a buffer with
    /// the requested size, provide it for emission, and then schedule it to be read from
    /// memory by the network device.
    ///
    /// # Panics
    /// This function may panic if `size` is larger than `MTU`.
    fn send<F: FnOnce(&mut [u8])>(&mut self, size: usize, handler: F);
}

#[cfg(all(unix, feature = "std"))]
pub use self::raw_socket::RawSocket;
