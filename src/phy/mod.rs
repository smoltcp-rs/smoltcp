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

For information about implementing [Device], refer to the [`smoltcp_device`] crate.
*/

mod fault_injector;
#[cfg(feature = "alloc")]
mod fuzz_injector;
#[cfg(feature = "alloc")]
mod loopback;
mod pcap_writer;
mod tracer;

pub use self::fault_injector::FaultInjector;
#[cfg(feature = "alloc")]
pub use self::fuzz_injector::{FuzzInjector, Fuzzer};
#[cfg(feature = "alloc")]
pub use self::loopback::Loopback;
pub use self::pcap_writer::{PcapLinkType, PcapMode, PcapSink, PcapWriter};
pub use self::tracer::{Tracer, TracerDirection, TracerPacket};

pub use smoltcp_device::*;
