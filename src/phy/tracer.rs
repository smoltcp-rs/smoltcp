use Result;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceCapabilities, Device};
use phy;

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: for<'a> Device<'a>, P: PrettyPrint> {
    inner:      D,
    writer:     fn(u64, PrettyPrinter<P>),
}

impl<D: for<'a> Device<'a>, P: PrettyPrint> Tracer<D, P> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: u64, printer: PrettyPrinter<P>)) -> Tracer<D, P> {
        Tracer {
            inner:   inner,
            writer:  writer,
        }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<'a, D, P> Device<'a> for Tracer<D, P>
    where D: for<'b> Device<'b>,
          P: PrettyPrint + 'a,
{
    type RxToken = RxToken<<D as Device<'a>>::RxToken, P>;
    type TxToken = TxToken<<D as Device<'a>>::TxToken, P>;

    fn capabilities(&self) -> DeviceCapabilities { self.inner.capabilities() }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let &mut Self { ref mut inner, writer, .. } = self;
        inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken { token: rx_token, writer: writer };
            let tx = TxToken { token: tx_token, writer: writer };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut inner, writer } = self;
        inner.transmit().map(|tx_token| {
            TxToken { token: tx_token, writer: writer }
        })
    }
}

#[doc(hidden)]
pub struct RxToken<T: phy::RxToken, P: PrettyPrint> {
    token:     T,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<T: phy::RxToken, P: PrettyPrint> phy::RxToken for RxToken<T, P> {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, timestamp: u64, f: F) -> Result<R> {
        let Self { token, writer } = self;
        token.consume(timestamp, |buffer| {
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
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, timestamp: u64, len: usize, f: F) -> R {
        let Self { token, writer } = self;
        token.consume(timestamp, len, |buffer| {
            let result = f(buffer);
            writer(timestamp, PrettyPrinter::<P>::new("-> ", &buffer));
            result
        })
    }
}
