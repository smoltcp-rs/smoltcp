use Result;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceLimits, Device};

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
    type RxBuffer = D::RxBuffer;
    type TxBuffer = TxBuffer<D::TxBuffer, P>;

    fn limits(&self) -> DeviceLimits { self.inner.limits() }

    fn receive(&mut self, timestamp: u64) -> Result<Self::RxBuffer> {
        let buffer = self.inner.receive(timestamp)?;
        (self.writer)(timestamp, PrettyPrinter::<P>::new("<- ", &buffer));
        Ok(buffer)
    }

    fn transmit(&mut self, timestamp: u64, length: usize) -> Result<Self::TxBuffer> {
        let buffer = self.inner.transmit(timestamp, length)?;
        Ok(TxBuffer { buffer, timestamp, writer: self.writer })
    }
}

#[doc(hidden)]
pub struct TxBuffer<B: AsRef<[u8]> + AsMut<[u8]>, P: PrettyPrint> {
    buffer:    B,
    timestamp: u64,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<B: AsRef<[u8]> + AsMut<[u8]>, P: PrettyPrint> AsRef<[u8]> for TxBuffer<B, P> {
    fn as_ref(&self) -> &[u8] { self.buffer.as_ref() }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>, P: PrettyPrint> AsMut<[u8]> for TxBuffer<B, P> {
    fn as_mut(&mut self) -> &mut [u8] { self.buffer.as_mut() }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>, P: PrettyPrint> Drop for TxBuffer<B, P> {
    fn drop(&mut self) {
        (self.writer)(self.timestamp, PrettyPrinter::<P>::new("-> ", &self.buffer));
    }
}
