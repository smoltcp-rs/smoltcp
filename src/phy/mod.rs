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
use smoltcp::Result;
use smoltcp::phy::{self, DeviceCapabilities, Device};

struct StmPhy {
    rx_buffer: [u8; 1536],
    tx_buffer: [u8; 1536],
}

impl<'a> StmPhy {
    fn new() -> StmPhy {
        StmPhy {
            rx_buffer: [0; 1536],
            tx_buffer: [0; 1536],
        }
    }
}

impl<'a> phy::Device<'a> for StmPhy {
    type RxToken = StmPhyRxToken<'a>;
    type TxToken = StmPhyTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        Some((StmPhyRxToken(&mut self.rx_buffer[..]),
              StmPhyTxToken(&mut self.tx_buffer[..])))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(StmPhyTxToken(&mut self.tx_buffer[..]))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(1);
        caps
    }
}

struct StmPhyRxToken<'a>(&'a [u8]);

impl<'a> phy::RxToken for StmPhyRxToken<'a> {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        // TODO: receive packet into buffer
        let ret = f(self.0);
        println!("rx called");
        ret
    }
}

struct StmPhyTxToken<'a>(&'a mut [u8]);

impl<'a> phy::TxToken for StmPhyTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, _timestamp: u64, len: usize, f: F)
        -> Result<R>
    {
        let ret = f(&mut self.0[..len]);
        println!("tx called {}", len);
        // TODO: send packet out
        ret
    }
}

fn main() {
    use smoltcp::phy::{TxToken, RxToken};

    let mut phy = StmPhy::new();
    if let Some(tx_token) = phy.transmit() {
        tx_token.consume(0, 40, |buf| {
            println!("got tx buf len {}", buf.len());
            Ok(())
        });
    }
    if let Some((rx_token, tx_token)) = phy.receive() {
        rx_token.consume(0, |buf| {
            println!("got rx buf");
            Ok(())
        });
        tx_token.consume(0, 80, |buf| {
            println!("got tx buf len {}", buf.len());
            Ok(())
        });
    }
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

/// A description of checksum behavior for a particular protocol.
#[derive(Debug, Clone, Copy)]
pub enum Checksum {
    /// Verify checksum when receiving and compute checksum when sending.
    Both,
    /// Verify checksum when receiving.
    Rx,
    /// Compute checksum before sending.
    Tx,
    /// Ignore checksum completely.
    None,
}

impl Default for Checksum {
    fn default() -> Checksum {
        Checksum::Both
    }
}

impl Checksum {
    /// Returns whether checksum should be verified when receiving.
    pub fn rx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Rx => true,
            _ => false
        }
    }

    /// Returns whether checksum should be verified when sending.
    pub fn tx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Tx => true,
            _ => false
        }
    }
}

/// A description of checksum behavior for every supported protocol.
#[derive(Debug, Clone, Default)]
pub struct ChecksumCapabilities {
    pub ipv4: Checksum,
    pub udpv4: Checksum,
    pub tcpv4: Checksum,
    pub icmpv4: Checksum,
    dummy: (),
}

impl ChecksumCapabilities {
    /// Checksum behavior that results in not computing or verifying checksums
    /// for any of the supported protocols.
    pub fn ignored() -> Self {
        ChecksumCapabilities {
            ipv4: Checksum::None,
            udpv4: Checksum::None,
            tcpv4: Checksum::None,
            icmpv4: Checksum::None,
            ..Self::default()
        }
    }
}

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

    /// The set of protocols for which checksum can be computed in hardware.
    pub checksum: ChecksumCapabilities,

    /// Only present to prevent people from trying to initialize every field of DeviceLimits,
    /// which would not let us add new fields in the future.
    dummy: ()
}

/// An interface for sending and receiving raw network frames.
///
/// The interface is based on _tokens_, which are types that allow to receive/transmit a
/// single packet. The `receive` and `transmit` functions only construct such tokens, the
/// real sending/receiving operation are performed when the tokens are consumed.
pub trait Device<'a> {
    type RxToken: RxToken + 'a;
    type TxToken: TxToken + 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    ///
    /// The additional transmit token makes it possible to generate a reply packet based
    /// on the contents of the received packet. For example, this makes it possible to
    /// handle arbitrarily large ICMP echo ("ping") requests, where the all received bytes
    /// need to be sent back, without heap allocation.
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)>;

    /// Construct a transmit token.
    fn transmit(&'a mut self) -> Option<Self::TxToken>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;
}

/// A token to receive a single network packet.
pub trait RxToken {
    /// Consumes the token to receive a single network packet.
    ///
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, timestamp: u64, f: F) -> Result<R>;
}

/// A token to transmit a single network packet.
pub trait TxToken {
    /// Consumes the token to send a single network packet.
    ///
    /// This method constructs a transmit buffer of size `len` and calls the passed
    /// closure `f` with a mutable reference to that buffer. The closure should construct
    /// a valid network packet (e.g. an ethernet packet) in the buffer. When the closure
    /// returns, the transmit buffer is sent out.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, timestamp: u64, len: usize, f: F)
        -> Result<R>;
}
