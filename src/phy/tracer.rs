use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceCapabilities, Device};
use phy;

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: Device, P: PrettyPrint> {
    inner:     D,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<D: Device, P: PrettyPrint> Tracer<D, P> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: u64, printer: PrettyPrinter<P>)) -> Tracer<D, P> {
        Tracer {
            inner:   inner,
            writer:  writer
        }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: Device, P: PrettyPrint> Device for Tracer<D, P> {
    type RxToken = RxToken<D::RxToken, P>;
    type TxToken = TxToken<D::TxToken, P>;

    fn capabilities(&self) -> DeviceCapabilities { self.inner.capabilities() }

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken { token: rx_token, writer: self.writer };
            let tx = TxToken { token: tx_token, writer: self.writer };
            (rx, tx) // TODO is copying `writer` desired?
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken> {
        self.inner.transmit().map(|tx_token| {
            TxToken { token: tx_token, writer: self.writer }
        })
    }
}

#[doc(hidden)]
pub struct RxToken<T: phy::RxToken, P: PrettyPrint> {
    token:     T,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<T: phy::RxToken, P: PrettyPrint> phy::RxToken for RxToken<T, P> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        let Self {token, writer} = self;
        let timestamp = 0; // TODO
        token.consume(|buffer| {
            writer(timestamp, PrettyPrinter::<P>::new("<- ", &buffer));
            f(buffer)
        })
    }
}

#[doc(hidden)]
pub struct TxToken<T: phy::TxToken, P: PrettyPrint> {
    token:     T,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<T: phy::TxToken, P: PrettyPrint> phy::TxToken for TxToken<T, P> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let Self {token, writer} = self;
        let timestamp = 0; // TODO
        token.consume(len, |buffer| {
            let result = f(buffer);
            writer(timestamp, PrettyPrinter::<P>::new("-> ", &buffer));
            result
        })
    }
}
