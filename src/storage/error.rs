use managed::ManagedSlice;

use crate::Error;
use crate::storage::RingBuffer;

/// A buffer for transient errors.
///
/// When errors are not inspected, they are simply overwritten if the underlying storage does not
/// contain enough space.
#[derive(Debug)]
pub struct ErrorBuffer<'a> {
    storage: RingBuffer<'a, Error>,
    /// Counts the number of errors never inspected.
    discarded: usize,
    /// Counter of all errors having entered the buffer.
    number: usize,
}

impl<'a> ErrorBuffer<'a> {
    /// Create a buffer that doesn't record any events.
    pub fn no_errors() -> Self {
        ErrorBuffer {
            storage: RingBuffer::new(ManagedSlice::Borrowed(&mut [])),
            discarded: 0,
            number: 0,
        }
    }

    pub fn push(&mut self, error: Error) {
        self.number += 1;
        match next_slot(&mut self.storage) {
            None => self.discarded += 1,
            Some(Ok(slot)) => *slot = error,
            Some(Err(slot)) => {
                self.discarded += 1;
                *slot = error;
            },
        }
    }

    /// Retrieve the oldest error.
    pub fn pop(&mut self) -> Option<Error> {
        self.storage.dequeue_one().ok().cloned()
    }

    /// Reset the underlying ring buffer and all other counters.
    pub fn clear(&mut self) {
        self.storage.clear();
        self.discarded = 0;
        self.number = 0;
    }

    /// How many errors were discarded due to full buffer.
    pub fn discarded(&self) -> usize {
        self.discarded
    }

    /// Current number of errors in the buffer.
    ///
    /// When more errors are pushed into the buffer than can be stored in its capacity then the
    /// oldest errors are simply discarded.
    pub fn unhandled(&self) -> usize {
        self.storage.len()
    }

    /// Report the total number of errors.
    ///
    /// This is the sum of discarded and unhandled errors.
    pub fn total_errors(&self) -> usize {
        self.number
    }

    /// Capacity of the buffer.
    pub fn capacity(&mut self) -> usize {
        self.storage.capacity()
    }
}

/// Get a reference to the next slot into which to put an error.
fn next_slot<'a: 'b, 'b, T>(storage: &'b mut RingBuffer<'a, T>)
    -> Option<Result<&'b mut T, &'b mut T>>
{
    let constructor: fn(&'b mut T) -> Result<&'b mut T, &'b mut T>;
    if storage.is_full() {
        let _ =  storage.dequeue_one();
        constructor = Err;
    } else {
        constructor = Ok;
    }

    storage.enqueue_one()
        .ok()
        .map(constructor)
}
