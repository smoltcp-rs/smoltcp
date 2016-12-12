//! Access to networking hardware.
//!
//! The `phy` module deals with the *network devices*. It provides an interface
//! for transmitting and receiving frames, [Device](trait.Device.html),
//! as well as an implementations of that trait that uses the host OS,
//! [RawSocket](struct.RawSocket.html) and [TapInterface](struct.TapInterface.html).

#[cfg(feature = "std")]
mod sys;

#[cfg(feature = "std")]
mod raw_socket;
#[cfg(all(feature = "std", target_os = "linux"))]
mod tap_interface;

#[cfg(feature = "std")]
pub use self::raw_socket::RawSocket;
#[cfg(all(feature = "std", target_os = "linux"))]
pub use self::tap_interface::TapInterface;

/// An interface for sending and receiving raw network frames.
///
/// It is expected that a `Device` implementation would allocate memory for both sending
/// and receiving packets from memory pools; hence, the stack borrows the buffer for a packet
/// that it is about to receive, as well for a packet that it is about to send, from the device.
pub trait Device {
    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the MTU.
    /// In practice, MTU will fall between 576 (for IPv4) or 1280 (for IPv6) and 9216 octets.
    fn mtu(&self) -> usize;

    /// Receives a frame.
    ///
    /// It is expected that a `recv` implementation, once a packet is written to memory
    /// through DMA, would gain ownership of the underlying buffer, provide it for parsing,
    /// and then return it to the network device.
    ///
    /// # Panics
    /// This function may panic if called recursively.
    fn recv<R, F: FnOnce(&[u8]) -> R>(&self, handler: F) -> R;

    /// Transmits a frame.
    ///
    /// It is expected that a `send` implementation would gain ownership of a buffer with
    /// the requested length, provide it for emission, and then schedule it to be read from
    /// memory by the network device.
    ///
    /// # Panics
    /// This function may panic if `len` is larger than `MTU`, or if called recursively.
    fn send<R, F: FnOnce(&mut [u8]) -> R>(&self, len: usize, handler: F) -> R;
}
