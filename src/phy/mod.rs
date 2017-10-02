//! Access to networking hardware.
//!
//! The `phy` module deals with the *network devices*. It provides a trait
//! for transmitting and receiving frames, [Device](trait.Device.html)
//! and implementations of it:
//!
//!   * the [_loopback_](struct.Loopback.html), for zero dependency testing;
//!   * _middleware_ [Tracer](struct.Tracer.html) and
//!     [FaultInjector](struct.FaultInjector.html), to facilitate debugging;
//!   * _adapters_ [RawSocket](struct.RawSocket.html) and
//!     [TapInterface](struct.TapInterface.html), to transmit and receive frames
//!     on the host OS.
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
use smoltcp::{Error, Result};
use smoltcp::phy::{DeviceCapabilities, Device};

const TX_BUFFERS: [*mut u8; 2] = [0x10000000 as *mut u8, 0x10001000 as *mut u8];
const RX_BUFFERS: [*mut u8; 2] = [0x10002000 as *mut u8, 0x10003000 as *mut u8];

fn rx_full() -> bool {
    /* platform-specific code to check if an incoming packet has arrived */
    false
}

fn rx_setup(_buf: *mut u8, _length: &mut usize) {
    /* platform-specific code to receive a packet into a buffer */
}

fn tx_empty() -> bool {
    /* platform-specific code to check if an outgoing packet can be sent */
    false
}

fn tx_setup(_buf: *const u8, _length: usize) {
    /* platform-specific code to send a buffer with a packet */
}

# #[allow(dead_code)]
pub struct EthernetDevice {
    tx_next: usize,
    rx_next: usize
}

impl Device for EthernetDevice {
    type RxBuffer = &'static [u8];
    type TxBuffer = EthernetTxBuffer;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(2);
        caps
    }

    fn receive(&mut self, _timestamp: u64) -> Result<Self::RxBuffer> {
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

    fn transmit(&mut self, _timestamp: u64, length: usize) -> Result<Self::TxBuffer> {
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

pub struct EthernetTxBuffer(&'static mut [u8]);

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

use Result;

#[cfg(any(feature = "phy-raw_socket", feature = "phy-tap_interface"))]
mod sys;

mod tracer;
mod fault_injector;
mod pcap_writer;
#[cfg(any(feature = "std", feature = "alloc"))]
mod loopback;
#[cfg(feature = "phy-raw_socket")]
mod raw_socket;
#[cfg(all(feature = "phy-tap_interface", target_os = "linux"))]
mod tap_interface;

#[cfg(any(feature = "phy-raw_socket", feature = "phy-tap_interface"))]
pub use self::sys::wait;

pub use self::tracer::Tracer;
pub use self::fault_injector::FaultInjector;
pub use self::pcap_writer::{PcapLinkType, PcapMode, PcapSink, PcapWriter};
#[cfg(any(feature = "std", feature = "alloc"))]
pub use self::loopback::Loopback;
#[cfg(any(feature = "phy-raw_socket"))]
pub use self::raw_socket::RawSocket;
#[cfg(all(feature = "phy-tap_interface", target_os = "linux"))]
pub use self::tap_interface::TapInterface;

/// A tracer device for Ethernet frames.
pub type EthernetTracer<T> = Tracer<T, super::wire::EthernetFrame<&'static [u8]>>;

/// A description of device capabilities.
///
/// Higher-level protocols may achieve higher throughput or lower latency if they consider
/// the bandwidth or packet size limitations.
#[derive(Debug, Clone, Default)]
pub struct DeviceCapabilities {
    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    ///
    /// For Ethernet, MTU will fall between 576 (for IPv4) or 1280 (for IPv6) and 9216 octets.
    pub max_transmission_unit: usize,

    /// Maximum burst size, in terms of MTU.
    ///
    /// The network device is unable to send or receive bursts large than the value returned
    /// by this function.
    ///
    /// If `None`, there is no fixed limit on burst size, e.g. if network buffers are
    /// dynamically allocated.
    pub max_burst_size: Option<usize>,

    /// Only present to prevent people from trying to initialize every field of DeviceLimits,
    /// which would not let us add new fields in the future.
    dummy: ()
}

/// An interface for sending and receiving raw network frames.
///
/// It is expected that a `Device` implementation would allocate memory for both sending
/// and receiving packets from memory pools; hence, the stack borrows the buffer for a packet
/// that it is about to receive, as well for a packet that it is about to send, from the device.
pub trait Device {
    type RxBuffer: AsRef<[u8]>;
    type TxBuffer: AsRef<[u8]> + AsMut<[u8]>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;

    /// Receive a frame.
    ///
    /// It is expected that a `receive` implementation, once a packet is written to memory
    /// through DMA, would gain ownership of the underlying buffer, provide it for parsing,
    /// and return it to the network device once it is dropped.
    fn receive(&mut self, timestamp: u64) -> Result<Self::RxBuffer>;

    /// Transmit a frame.
    ///
    /// It is expected that a `transmit` implementation would gain ownership of a buffer with
    /// the requested length, provide it for emission, and schedule it to be read from
    /// memory by the network device once it is dropped.
    fn transmit(&mut self, timestamp: u64, length: usize) -> Result<Self::TxBuffer>;
}
