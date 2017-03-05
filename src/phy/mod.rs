//! Access to networking hardware.
//!
//! The `phy` module deals with the *network devices*. It provides a trait
//! for transmitting and receiving frames, [Device](trait.Device.html),
//! as well as an implementations of that trait that uses the host OS,
//! [RawSocket](struct.RawSocket.html) and [TapInterface](struct.TapInterface.html).
//!
//! It also provides the _middleware interfaces_ [Tracer](struct.Tracer.html) and
//! [FaultInjector](struct.FaultInjector.html), to facilitate debugging.
//!
// https://github.com/rust-lang/rust/issues/38740
//! <h1 id="examples" class="section-header"><a href="#examples">Examples</a></h1>
//!
//! An implementation of the [Device](trait.Device.html) trait for a simple hardware
//! Ethernet controller could look as follows:
//!
/*!
```rust
use std::slice;
use smoltcp::Error;
use smoltcp::phy::Device;

const TX_BUFFERS: [*mut u8; 2] = [0x10000000 as *mut u8, 0x10001000 as *mut u8];
const RX_BUFFERS: [*mut u8; 2] = [0x10002000 as *mut u8, 0x10003000 as *mut u8];

fn rx_full() -> bool {
    /* platform-specific code to check if an incoming packet has arrived */
    false
}

fn rx_setup(buf: *mut u8, length: &mut usize) {
    /* platform-specific code to receive a packet into a buffer */
}

fn tx_empty() -> bool {
    /* platform-specific code to check if the outgoing packet was sent */
    false
}

fn tx_setup(buf: *const u8, length: usize) {
    /* platform-specific code to send a buffer with a packet */
}

struct EthernetDevice {
    tx_next: usize,
    rx_next: usize
}

impl Device for EthernetDevice {
    type RxBuffer = &'static [u8];
    type TxBuffer = EthernetTxBuffer;

    fn mtu(&self) -> usize { 1536 }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        if rx_full() {
            let index = self.rx_next;
            self.rx_next = (self.rx_next + 1) % RX_BUFFERS.len();
            let mut length = 0;
            rx_setup(RX_BUFFERS[self.rx_next], &mut length);
            Ok(unsafe {
                slice::from_raw_parts(RX_BUFFERS[index], length)
            })
        } else {
            Err(Error::Exhausted)
        }
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error> {
        if tx_empty() {
            let index = self.tx_next;
            self.tx_next = (self.tx_next + 1) % TX_BUFFERS.len();
            Ok(EthernetTxBuffer(unsafe {
                slice::from_raw_parts_mut(TX_BUFFERS[index], length)
            }))
        } else {
            Err(Error::Exhausted)
        }
    }
}

struct EthernetTxBuffer(&'static mut [u8]);

impl AsRef<[u8]> for EthernetTxBuffer {
    fn as_ref(&self) -> &[u8] { self.0 }
}

impl AsMut<[u8]> for EthernetTxBuffer {
    fn as_mut(&mut self) -> &mut [u8] { self.0 }
}

impl Drop for EthernetTxBuffer {
    fn drop(&mut self) { tx_setup(self.0.as_ptr(), self.0.len()) }
}
```
*/

use Error;

#[cfg(feature = "std")]
mod sys;

mod tracer;
mod fault_injector;
#[cfg(feature = "std")]
mod raw_socket;
#[cfg(all(feature = "std", target_os = "linux"))]
mod tap_interface;

pub use self::tracer::Tracer;
pub use self::fault_injector::FaultInjector;
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
    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error>;
}
