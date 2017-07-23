use Error;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::{DeviceLimits, Device};

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<T: Device, U: PrettyPrint> {
    lower:     T,
    writer:    fn(u64, PrettyPrinter<U>)
}

impl<T: Device, U: PrettyPrint> Tracer<T, U> {
    /// Create a tracer device.
    pub fn new(lower: T, writer: fn(timestamp: u64, printer: PrettyPrinter<U>)) -> Tracer<T, U> {
        Tracer {
            lower:   lower,
            writer:  writer
        }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_lower(self) -> T {
        self.lower
    }
}

impl<T: Device, U: PrettyPrint> Device for Tracer<T, U> {
    type RxBuffer = T::RxBuffer;
    type TxBuffer = TxBuffer<T::TxBuffer, U>;

    fn limits(&self) -> DeviceLimits { self.lower.limits() }

    fn receive(&mut self, timestamp: u64) -> Result<Self::RxBuffer, Error> {
        let buffer = self.lower.receive(timestamp)?;
        (self.writer)(timestamp, PrettyPrinter::<U>::new("<- ", &buffer));
        Ok(buffer)
    }

    fn transmit(&mut self, timestamp: u64, length: usize) -> Result<Self::TxBuffer, Error> {
        let buffer = self.lower.transmit(timestamp, length)?;
        Ok(TxBuffer { buffer, timestamp, writer: self.writer })
    }
}

#[doc(hidden)]
pub struct TxBuffer<T: AsRef<[u8]>, U: PrettyPrint> {
    buffer:    T,
    timestamp: u64,
    writer:    fn(u64, PrettyPrinter<U>)
}

impl<T: AsRef<[u8]>, U: PrettyPrint> AsRef<[u8]>
        for TxBuffer<T, U> {
    fn as_ref(&self) -> &[u8] { self.buffer.as_ref() }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>, U: PrettyPrint> AsMut<[u8]>
        for TxBuffer<T, U> {
    fn as_mut(&mut self) -> &mut [u8] { self.buffer.as_mut() }
}

impl<T: AsRef<[u8]>, U: PrettyPrint> Drop for TxBuffer<T, U> {
    fn drop(&mut self) {
        (self.writer)(self.timestamp, PrettyPrinter::<U>::new("-> ", &self.buffer));
    }
}
