use managed::{Managed, ManagedSlice};

use {Error, Result};
use super::Resettable;

/// A ring buffer.
#[derive(Debug)]
pub struct RingBuffer<'a, T: 'a> {
    storage: ManagedSlice<'a, T>,
    read_at: usize,
    length:  usize,
}

impl<'a, T: 'a> RingBuffer<'a, T> {
    /// Create a ring buffer with the given storage.
    ///
    /// During creation, every element in `storage` is reset.
    pub fn new<S>(storage: S) -> RingBuffer<'a, T>
        where S: Into<ManagedSlice<'a, T>>,
    {
        RingBuffer {
            storage: storage.into(),
            read_at: 0,
            length:  0,
        }
    }

    /// Clear the ring buffer.
    pub fn clear(&mut self) {
        self.read_at = 0;
        self.length  = 0;
    }

    /// Clear the ring buffer, and reset every element.
    pub fn reset(&mut self)
            where T: Resettable {
        self.clear();
        for elem in self.storage.iter_mut() {
            elem.reset();
        }
    }

    /// Return the current number of elements in the ring buffer.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Return the maximum number of elements in the ring buffer.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Return the number of elements that can be added to the ring buffer.
    pub fn window(&self) -> usize {
        self.capacity() - self.len()
    }

    /// Query whether the buffer is empty.
    pub fn empty(&self) -> bool {
        self.len() == 0
    }

    /// Query whether the buffer is full.
    pub fn full(&self) -> bool {
        self.window() == 0
    }
}

// This is the "discrete" ring buffer interface: it operates with single elements,
// and boundary conditions (empty/full) are errors.
impl<'a, T: 'a> RingBuffer<'a, T> {
    /// Call `f` with a single buffer element, and enqueue the element if `f`
    /// returns successfully, or return `Err(Error::Exhausted)` if the buffer is full.
    pub fn try_enqueue<'b, R, F>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut T) -> Result<R> {
        if self.full() { return Err(Error::Exhausted) }

        let index = (self.read_at + self.length) % self.capacity();
        match f(&mut self.storage[index]) {
            Ok(result) => {
                self.length += 1;
                Ok(result)
            }
            Err(error) => Err(error)
        }
    }

    /// Enqueue a single element into the buffer, and return a pointer to it,
    /// or return `Err(Error::Exhausted)` if the buffer is full.
    pub fn enqueue<'b>(&'b mut self) -> Result<&'b mut T> {
        self.try_enqueue(Ok)
    }

    /// Call `f` with a buffer element, and dequeue the element if `f` returns successfully, or
    /// return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn try_dequeue<'b, R, F>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut T) -> Result<R> {
        if self.empty() { return Err(Error::Exhausted) }

        let next_at = (self.read_at + 1) % self.capacity();
        match f(&mut self.storage[self.read_at]) {
            Ok(result) => {
                self.length -= 1;
                self.read_at = next_at;
                Ok(result)
            }
            Err(error) => Err(error)
        }
    }

    /// Dequeue an element from the buffer, and return a mutable reference to it, or return
    /// `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<&mut T> {
        self.try_dequeue(Ok)
    }
}

// This is the "continuous" ring buffer interface: it operates with element slices,
// and boundary conditions (empty/full) simply result in empty slices.
impl<'a, T: 'a> RingBuffer<'a, T> {
    fn clamp_writer(&self, mut size: usize) -> (usize, usize) {
        let write_at = (self.read_at + self.length) % self.capacity();
        // We can't enqueue more than there is free space.
        let free = self.capacity() - self.length;
        if size > free { size = free }
        // We can't contiguously enqueue past the beginning of the storage.
        let until_end = self.capacity() - write_at;
        if size > until_end { size = until_end }

        (write_at, size)
    }

    pub(crate) fn enqueue_slice<'b>(&'b mut self, size: usize) -> &'b mut [T] {
        let (write_at, size) = self.clamp_writer(size);
        self.length += size;
        &mut self.storage[write_at..write_at + size]
    }

    pub(crate) fn enqueue_slice_all(&mut self, data: &[T])
            where T: Copy {
        let data = {
            let mut dest = self.enqueue_slice(data.len());
            let (data, rest) = data.split_at(dest.len());
            dest.copy_from_slice(data);
            rest
        };
        // Retry, in case we had a wraparound.
        let mut dest = self.enqueue_slice(data.len());
        let (data, _) = data.split_at(dest.len());
        dest.copy_from_slice(data);
    }

    fn clamp_reader(&self, offset: usize, mut size: usize) -> (usize, usize) {
        let read_at = (self.read_at + offset) % self.capacity();
        // We can't read past the end of the queued data.
        if offset > self.length { return (read_at, 0) }
        // We can't dequeue more than was queued.
        let clamped_length = self.length - offset;
        if size > clamped_length { size = clamped_length }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.capacity() - read_at;
        if size > until_end { size = until_end }

        (read_at, size)
    }

    pub(crate) fn dequeue_slice(&mut self, size: usize) -> &[T] {
        let (read_at, size) = self.clamp_reader(0, size);
        self.read_at = (self.read_at + size) % self.capacity();
        self.length -= size;
        &self.storage[read_at..read_at + size]
    }

    pub(crate) fn peek(&self, offset: usize, size: usize) -> &[T] {
        let (read_at, size) = self.clamp_reader(offset, size);
        &self.storage[read_at..read_at + size]
    }
}

impl<'a, T: 'a> From<ManagedSlice<'a, T>> for RingBuffer<'a, T> {
    fn from(slice: ManagedSlice<'a, T>) -> RingBuffer<'a, T> {
        RingBuffer::new(slice)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SIZE: usize = 5;

    #[test]
    pub fn test_buffer() {
        let mut buf = RingBuffer::new(vec![0; SIZE]);
        assert!(buf.empty());
        assert!(!buf.full());
        assert_eq!(buf.dequeue(), Err(Error::Exhausted));

        buf.enqueue().unwrap();
        assert!(!buf.empty());
        assert!(!buf.full());

        for i in 1..SIZE {
            *buf.enqueue().unwrap() = i;
            assert!(!buf.empty());
        }
        assert!(buf.full());
        assert_eq!(buf.enqueue(), Err(Error::Exhausted));

        for i in 0..SIZE {
            assert_eq!(*buf.dequeue().unwrap(), i);
            assert!(!buf.full());
        }
        assert_eq!(buf.dequeue(), Err(Error::Exhausted));
        assert!(buf.empty());
    }

    #[test]
    pub fn test_buffer_try() {
        let mut buf = RingBuffer::new(vec![0; SIZE]);
        assert!(buf.empty());
        assert!(!buf.full());
        assert_eq!(buf.try_dequeue(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));

        buf.try_enqueue(|e| Ok(e)).unwrap();
        assert!(!buf.empty());
        assert!(!buf.full());

        for i in 1..SIZE {
            buf.try_enqueue(|e| Ok(*e = i)).unwrap();
            assert!(!buf.empty());
        }
        assert!(buf.full());
        assert_eq!(buf.try_enqueue(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));

        for i in 0..SIZE {
            assert_eq!(buf.try_dequeue(|e| Ok(*e)).unwrap(), i);
            assert!(!buf.full());
        }
        assert_eq!(buf.try_dequeue(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));
        assert!(buf.empty());
    }
}
