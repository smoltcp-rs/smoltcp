use Error;
use wire::pretty_print::{PrettyPrint, PrettyPrinter};
use super::Device;

/// A tracer device.
///
/// A tracer is a device that prints all packets traversing it
/// to the standard output, and delegates to another device otherwise.
pub struct Tracer<T: Device, U: PrettyPrint> {
    lower:   T,
    writer:  fn(PrettyPrinter<U>)
}

impl<T: Device, U: PrettyPrint> Tracer<T, U> {
    /// Create a tracer device.
    pub fn new(lower: T, writer: fn(PrettyPrinter<U>)) -> Tracer<T, U> {
        Tracer {
            lower:   lower,
            writer:  writer
        }
    }

    /// Create a tracer device, printing to standard output.
    #[cfg(feature = "std")]
    pub fn new_stdout(lower: T) -> Tracer<T, U> {
        fn writer<U: PrettyPrint>(printer: PrettyPrinter<U>) {
            print!("{}", printer)
        }

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

    fn mtu(&self) -> usize { self.lower.mtu() }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        let buffer = try!(self.lower.receive());
        (self.writer)(PrettyPrinter::<U>::new("<- ", &buffer));
        Ok(buffer)
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error> {
        let buffer = try!(self.lower.transmit(length));
        Ok(TxBuffer {
            buffer:  buffer,
            writer:  self.writer
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer<T: AsRef<[u8]>, U: PrettyPrint> {
    buffer:  T,
    writer:  fn(PrettyPrinter<U>)
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
        (self.writer)(PrettyPrinter::<U>::new("-> ", &self.buffer));
    }
}
