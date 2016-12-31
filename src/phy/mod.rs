//! Access to networking hardware.
//!
//! The `phy` module deals with the *network devices*. It provides an interface
//! for transmitting and receiving frames, [Device](trait.Device.html),
//! as well as an implementations of that trait that uses the host OS,
//! [RawSocket](struct.RawSocket.html) and [TapInterface](struct.TapInterface.html).

use Error;

#[cfg(feature = "use_std")]
mod sys;

mod tracer;
mod fault_injector;
#[cfg(feature = "use_std")]
mod raw_socket;
#[cfg(all(feature = "use_std", target_os = "linux"))]
mod tap_interface;

pub use self::tracer::Tracer;
pub use self::fault_injector::FaultInjector;
#[cfg(feature = "use_std")]
pub use self::raw_socket::RawSocket;
#[cfg(all(feature = "use_std", target_os = "linux"))]
pub use self::tap_interface::TapInterface;

/// An interface for sending and receiving raw network frames.
///
/// It is expected that a `Device` implementation would allocate memory for both sending
/// and receiving packets from memory pools; hence, the stack borrows the buffer for a packet
/// that it is about to receive, as well for a packet that it is about to send, from the device.
pub trait Device {
    type RxBuffer: AsRef<[u8]>;
    type TxBuffer: AsRef<[u8]> + AsMut<[u8]>;

    /// Get maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the MTU.
    /// In practice, MTU will fall between 576 (for IPv4) or 1280 (for IPv6) and 9216 octets.
    fn mtu(&self) -> usize;

    /// Receive a frame.
    ///
    /// It is expected that a `receive` implementation, once a packet is written to memory
    /// through DMA, would gain ownership of the underlying buffer, provide it for parsing,
    /// and return it to the network device once it is dropped.
    fn receive(&mut self) -> Result<Self::RxBuffer, Error>;

    /// Transmit a frame.
    ///
    /// It is expected that a `transmit` implementation would gain ownership of a buffer with
    /// the requested length, provide it for emission, and schedule it to be read from
    /// memory by the network device once it is dropped.
    fn transmit(&mut self, len: usize) -> Result<Self::TxBuffer, Error>;
}
