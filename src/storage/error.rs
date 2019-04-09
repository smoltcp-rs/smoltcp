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

    /// Create a buffer that stores the last few errors in a slice.
    pub fn new<T>(buffer: T) -> Self
        where T: Into<ManagedSlice<'a, Error>>
    {
        ErrorBuffer {
            storage: RingBuffer::new(buffer),
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

    /// Absorbing the error and return the `ok` value.
    pub fn ok<T, E>(&mut self, result: Result<T, E>) -> Option<T> 
        where E: Into<Error>
    {
        result.map_err(|err| self.push(err.into())).ok()
    }

    /// Handle the error and otherwise just continue.
    pub fn catch<E>(&mut self, result: Result<(), E>)
        where E: Into<Error>
    {
        result.unwrap_or_else(|err| self.push(err.into()))
    }

    /// Retrieve the oldest error.
    pub fn pop(&mut self) -> Option<Error> {
        self.storage.dequeue_one().ok().cloned()
    }

    /// Handle all remaining errors.
    pub fn consume_with<F>(&mut self, mut f: F)
        where F: FnMut(Error, usize),
    {
        let mut start = self.number - self.storage.len();
        while !self.storage.is_empty() {
            let (dequeued, ()) = self.storage.dequeue_many_with(|slice| {
                let all = slice.len();
                slice.iter().cloned().zip(start..).for_each(|(err, num)| f(err, num));
                (all, ())
            });
            start += dequeued;
        }
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
