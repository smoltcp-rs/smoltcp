/*! Access to networking hardware.

The `phy` module deals with the *network devices*. It provides a trait
for transmitting and receiving frames, [Device][smoltcp_device::Device]
and implementations of it:

  * the [_loopback_](struct.Loopback.html), for zero dependency testing;
  * _middleware_ [Tracer](struct.Tracer.html) and
    [FaultInjector](struct.FaultInjector.html), to facilitate debugging;
  * _adapters_ [RawSocket](struct.RawSocket.html) and
    [TunTapInterface](struct.TunTapInterface.html), to transmit and receive frames
    on the host OS.
*/
#![cfg_attr(
    feature = "medium-ethernet",
    doc = r##"
# Examples

An implementation of the [Device](trait.Device.html) trait for a simple hardware
Ethernet controller could look as follows:

```rust
use smoltcp::phy::{self, DeviceCapabilities, Device, Medium};
use smoltcp::time::Instant;

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

impl phy::Device for StmPhy {
    type RxToken<'a> = StmPhyRxToken<'a> where Self: 'a;
    type TxToken<'a> = StmPhyTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        Some((StmPhyRxToken(&mut self.rx_buffer[..]),
              StmPhyTxToken(&mut self.tx_buffer[..])))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(StmPhyTxToken(&mut self.tx_buffer[..]))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct StmPhyRxToken<'a>(&'a mut [u8]);

impl<'a> phy::RxToken for StmPhyRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
        where F: FnOnce(& [u8]) -> R
    {
        // TODO: receive packet into buffer
        let result = f(&self.0);
        println!("rx called");
        result
    }
}

struct StmPhyTxToken<'a>(&'a mut [u8]);

impl<'a> phy::TxToken for StmPhyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
        where F: FnOnce(&mut [u8]) -> R
    {
        let result = f(&mut self.0[..len]);
        println!("tx called {}", len);
        // TODO: send packet out
        result
    }
}
```
"##
)]

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
mod sys;

mod fault_injector;
#[cfg(feature = "alloc")]
mod fuzz_injector;
#[cfg(feature = "alloc")]
mod loopback;
mod pcap_writer;
#[cfg(all(feature = "phy-raw_socket", unix))]
mod raw_socket;
mod tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
mod tuntap_interface;

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
pub use self::sys::wait;

pub use self::fault_injector::FaultInjector;
#[cfg(feature = "alloc")]
pub use self::fuzz_injector::{FuzzInjector, Fuzzer};
#[cfg(feature = "alloc")]
pub use self::loopback::Loopback;
pub use self::pcap_writer::{PcapLinkType, PcapMode, PcapSink, PcapWriter};
#[cfg(all(feature = "phy-raw_socket", unix))]
pub use self::raw_socket::RawSocket;
pub use self::tracer::{Tracer, TracerDirection, TracerPacket};
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
pub use self::tuntap_interface::TunTapInterface;

pub use smoltcp_device::*;
