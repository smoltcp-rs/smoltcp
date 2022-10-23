use crate::phy::{self, Device, DeviceCapabilities};
use crate::time::Instant;
use crate::Result;

// This could be fixed once associated consts are stable.
const MTU: usize = 1536;

/// Represents a fuzzer. It is expected to replace bytes in the packet with fuzzed data.
pub trait Fuzzer {
    /// Modify a single packet with fuzzed data.
    fn fuzz_packet(&self, packet_data: &mut [u8]);
}

/// A fuzz injector device.
///
/// A fuzz injector is a device that alters packets traversing through it according to the
/// directions of a guided fuzzer. It is designed to support fuzzing internal state machines inside
/// smoltcp, and is not for production use.
#[allow(unused)]
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FuzzInjector<D: Device, FTx: Fuzzer, FRx: Fuzzer> {
    inner: D,
    fuzz_tx: FTx,
    fuzz_rx: FRx,
}

#[allow(unused)]
impl<D: Device, FTx: Fuzzer, FRx: Fuzzer> FuzzInjector<D, FTx, FRx> {
    /// Create a fuzz injector device.
    pub fn new(inner: D, fuzz_tx: FTx, fuzz_rx: FRx) -> FuzzInjector<D, FTx, FRx> {
        FuzzInjector {
            inner,
            fuzz_tx,
            fuzz_rx,
        }
    }

    /// Return the underlying device, consuming the fuzz injector.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: Device, FTx, FRx> Device for FuzzInjector<D, FTx, FRx>
where
    FTx: Fuzzer,
    FRx: Fuzzer,
{
    type RxToken<'a> = RxToken<'a, D::RxToken<'a>, FRx>
    where
        Self: 'a;
    type TxToken<'a> = TxToken<'a, D::TxToken<'a>, FTx>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = self.inner.capabilities();
        if caps.max_transmission_unit > MTU {
            caps.max_transmission_unit = MTU;
        }
        caps
    }

    fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let &mut Self {
            ref mut inner,
            ref fuzz_rx,
            ref fuzz_tx,
        } = self;
        inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken {
                fuzzer: fuzz_rx,
                token: rx_token,
            };
            let tx = TxToken {
                fuzzer: fuzz_tx,
                token: tx_token,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        let &mut Self {
            ref mut inner,
            fuzz_rx: _,
            ref fuzz_tx,
        } = self;
        inner.transmit().map(|token| TxToken {
            fuzzer: fuzz_tx,
            token: token,
        })
    }
}

#[doc(hidden)]
pub struct RxToken<'a, Rx: phy::RxToken, F: Fuzzer + 'a> {
    fuzzer: &'a F,
    token: Rx,
}

impl<'a, Rx: phy::RxToken, FRx: Fuzzer> phy::RxToken for RxToken<'a, Rx, FRx> {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { fuzzer, token } = self;
        token.consume(timestamp, |buffer| {
            fuzzer.fuzz_packet(buffer);
            f(buffer)
        })
    }
}

#[doc(hidden)]
pub struct TxToken<'a, Tx: phy::TxToken, F: Fuzzer + 'a> {
    fuzzer: &'a F,
    token: Tx,
}

impl<'a, Tx: phy::TxToken, FTx: Fuzzer> phy::TxToken for TxToken<'a, Tx, FTx> {
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { fuzzer, token } = self;
        token.consume(timestamp, len, |buf| {
            let result = f(buf);
            fuzzer.fuzz_packet(buf);
            result
        })
    }
}
