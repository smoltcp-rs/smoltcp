use Error;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceLimits, Device};

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: Device, P: PrettyPrint> {
    lower:     D,
    writer:    fn(u64, PrettyPrinter<P>)
}

impl<D: Device, P: PrettyPrint> Tracer<D, P> {
    /// Create a tracer device.
    pub fn new(lower: D, writer: fn(timestamp: u64, printer: PrettyPrinter<P>)) -> Tracer<D, P> {
        Tracer {
            lower:   lower,
            writer:  writer
        }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_lower(self) -> D {
        self.lower
    }
}

impl<D: Device, P: PrettyPrint> Device for Tracer<D, P> {
    type RxBuffer = D::RxBuffer;
    type TxBuffer = TxBuffer<D::TxBuffer, P>;

    fn limits(&self) -> DeviceLimits { self.lower.limits() }

    fn receive(&mut self, timestamp: u64) -> Result<Self::RxBuffer, Error> {
        let buffer = self.lower.receive(timestamp)?;
        (self.writer)(timestamp, PrettyPrinter::<P>::new("<- ", &buffer));
        Ok(buffer)
    }

    fn transmit(&mut self, timestamp: u64, length: usize) -> Result<Self::TxBuffer, Error> {
        let buffer = self.lower.transmit(timestamp, length)?;
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
