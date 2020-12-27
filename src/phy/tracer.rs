use crate::Result;
use crate::wire::pretty_print::{PrettyPrint, PrettyPrinter};
use crate::phy::{self, DeviceCapabilities, Device};
use crate::time::Instant;

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: for<'a> Device<'a>, P: PrettyPrint> {
    inner:  D,
    writer: fn(Instant, PrettyPrinter<P>),
}

impl<D: for<'a> Device<'a>, P: PrettyPrint> Tracer<D, P> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: Instant, printer: PrettyPrinter<P>)) -> Tracer<D, P> {
        Tracer { inner, writer }
    }

    /// Get a reference to the underlying device.
    ///
    /// Even if the device offers reading through a standard reference, it is inadvisable to
    /// directly read from the device as doing so will circumvent the tracing.
    pub fn get_ref(&self) -> &D {
        &self.inner
    }

    /// Get a mutable reference to the underlying device.
    ///
    /// It is inadvisable to directly read from the device as doing so will circumvent the tracing.
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.inner
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
            let rx = RxToken { token: rx_token, writer };
            let tx = TxToken { token: tx_token, writer };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut inner, writer } = self;
        inner.transmit().map(|tx_token| {
            TxToken { token: tx_token, writer }
        })
    }
}

#[doc(hidden)]
pub struct RxToken<Rx: phy::RxToken, P: PrettyPrint> {
    token:     Rx,
    writer:    fn(Instant, PrettyPrinter<P>)
}

impl<Rx: phy::RxToken, P: PrettyPrint> phy::RxToken for RxToken<Rx, P> {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let Self { token, writer } = self;
        token.consume(timestamp, |buffer| {
            writer(timestamp, PrettyPrinter::<P>::new("<- ", &buffer));
            f(buffer)
        })
    }
}

#[doc(hidden)]
pub struct TxToken<Tx: phy::TxToken, P: PrettyPrint> {
    token:     Tx,
    writer:    fn(Instant, PrettyPrinter<P>)
}

impl<Tx: phy::TxToken, P: PrettyPrint> phy::TxToken for TxToken<Tx, P> {
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let Self { token, writer } = self;
        token.consume(timestamp, len, |buffer| {
            let result = f(buffer);
            writer(timestamp, PrettyPrinter::<P>::new("-> ", &buffer));
            result
        })
    }
}
