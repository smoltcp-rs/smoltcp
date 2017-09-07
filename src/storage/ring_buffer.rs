use core::cmp;
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

    /// Return the maximum number of elements in the ring buffer.
    pub fn capacity(&self) -> usize {
        self.storage.len()
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

    /// Set the current number of elements in the ring buffer.
    ///
    /// The newly added elements (if any) retain their old value.
    ///
    /// # Panics
    /// This function panics if the new length is greater than capacity.
    pub fn set_len(&mut self, length: usize) {
        assert!(length <= self.capacity());
        self.length = length
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
    pub fn enqueue_one_with<'b, R, F>(&'b mut self, f: F) -> Result<R>
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

    /// Enqueue a single element into the buffer, and return a reference to it,
    /// or return `Err(Error::Exhausted)` if the buffer is full.
    ///
    /// This function is a shortcut for `ring_buf.enqueue_one_with(Ok)`.
    pub fn enqueue_one<'b>(&'b mut self) -> Result<&'b mut T> {
        self.enqueue_one_with(Ok)
    }

    /// Call `f` with a single buffer element, and dequeue the element if `f`
    /// returns successfully, or return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue_one_with<'b, R, F>(&'b mut self, f: F) -> Result<R>
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

    /// Dequeue an element from the buffer, and return a reference to it,
    /// or return `Err(Error::Exhausted)` if the buffer is empty.
    ///
    /// This function is a shortcut for `ring_buf.dequeue_one_with(Ok)`.
    pub fn dequeue_one(&mut self) -> Result<&mut T> {
        self.dequeue_one_with(Ok)
    }
}

// This is the "continuous" ring buffer interface: it operates with element slices,
// and boundary conditions (empty/full) simply result in empty slices.
impl<'a, T: 'a> RingBuffer<'a, T> {
    /// Call `f` with the largest contiguous slice of unallocated buffer elements,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// This function panics if the amount of elements returned by `f` is larger
    /// than the size of the slice passed into it.
    pub fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
            where F: FnOnce(&'b mut [T]) -> (usize, R) {
        let write_at = (self.read_at + self.length) % self.capacity();
        let max_size = cmp::min(self.window(), self.capacity() - write_at);
        let (size, result) = f(&mut self.storage[write_at..write_at + max_size]);
        assert!(size <= max_size);
        self.length += size;
        (size, result)
    }

    /// Enqueue a slice of elements up to the given size into the buffer,
    /// and return a reference to them.
    ///
    /// This function may return a slice smaller than the given size
    /// if the free space in the buffer is not contiguous.
    pub fn enqueue_many<'b>(&'b mut self, size: usize) -> &'b mut [T] {
        self.enqueue_many_with(|buf| {
            let size = cmp::min(size, buf.len());
            (size, &mut buf[..size])
        }).1
    }

    /// Enqueue as many elements from the given slice into the buffer as possible,
    /// and return the amount of elements that could fit.
    pub fn enqueue_slice(&mut self, data: &[T]) -> usize
            where T: Copy {
        let (size_1, data) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, &data[size..])
        });
        let (size_2, ()) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, ())
        });
        size_1 + size_2
    }

    /// Call `f` with the largest contiguous slice of allocated buffer elements,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// This function panics if the amount of elements returned by `f` is larger
    /// than the size of the slice passed into it.
    pub fn dequeue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
            where F: FnOnce(&'b mut [T]) -> (usize, R) {
        let capacity = self.capacity();
        let max_size = cmp::min(self.len(), capacity - self.read_at);
        let (size, result) = f(&mut self.storage[self.read_at..self.read_at + max_size]);
        assert!(size <= max_size);
        self.read_at = (self.read_at + size) % capacity;
        self.length -= size;
        (size, result)
    }

    /// Dequeue a slice of elements up to the given size from the buffer,
    /// and return a reference to them.
    ///
    /// This function may return a slice smaller than the given size
    /// if the allocated space in the buffer is not contiguous.
    pub fn dequeue_many<'b>(&'b mut self, size: usize) -> &'b mut [T] {
        self.dequeue_many_with(|buf| {
            let size = cmp::min(size, buf.len());
            (size, &mut buf[..size])
        }).1
    }

    /// Dequeue as many elements from the buffer into the given slice as possible,
    /// and return the amount of elements that could fit.
    pub fn dequeue_slice(&mut self, data: &mut [T]) -> usize
            where T: Copy {
        let (size_1, data) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, &mut data[size..])
        });
        let (size_2, ()) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, ())
        });
        size_1 + size_2
    }
}

// This is the "random access" ring buffer interface: it operates with element slices,
// and allows to access elements of the buffer that are not adjacent to its head or tail.
impl<'a, T: 'a> RingBuffer<'a, T> {
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

    #[test]
    pub fn test_buffer_length_changes() {
        let mut ring = RingBuffer::new(vec![0; 2]);
        assert!(ring.empty());
        assert!(!ring.full());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 2);

        ring.set_len(1);
        assert!(!ring.empty());
        assert!(!ring.full());
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 1);

        ring.set_len(2);
        assert!(!ring.empty());
        assert!(ring.full());
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 0);
    }

    #[test]
    pub fn test_buffer_enqueue_dequeue_one_with() {
        let mut ring = RingBuffer::new(vec![0; 5]);
        assert_eq!(ring.dequeue_one_with(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));

        ring.enqueue_one_with(|e| Ok(e)).unwrap();
        assert!(!ring.empty());
        assert!(!ring.full());

        for i in 1..5 {
            ring.enqueue_one_with(|e| Ok(*e = i)).unwrap();
            assert!(!ring.empty());
        }
        assert!(ring.full());
        assert_eq!(ring.enqueue_one_with(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));

        for i in 0..5 {
            assert_eq!(ring.dequeue_one_with(|e| Ok(*e)).unwrap(), i);
            assert!(!ring.full());
        }
        assert_eq!(ring.dequeue_one_with(|_| unreachable!()) as Result<()>,
                   Err(Error::Exhausted));
        assert!(ring.empty());
    }

    #[test]
    pub fn test_buffer_enqueue_dequeue_one() {
        let mut ring = RingBuffer::new(vec![0; 5]);
        assert_eq!(ring.dequeue_one(), Err(Error::Exhausted));

        ring.enqueue_one().unwrap();
        assert!(!ring.empty());
        assert!(!ring.full());

        for i in 1..5 {
            *ring.enqueue_one().unwrap() = i;
            assert!(!ring.empty());
        }
        assert!(ring.full());
        assert_eq!(ring.enqueue_one(), Err(Error::Exhausted));

        for i in 0..5 {
            assert_eq!(*ring.dequeue_one().unwrap(), i);
            assert!(!ring.full());
        }
        assert_eq!(ring.dequeue_one(), Err(Error::Exhausted));
        assert!(ring.empty());
    }

    #[test]
    pub fn test_buffer_enqueue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12);
            buf[0..2].copy_from_slice(b"ab");
            (2, true)
        }), (2, true));
        assert_eq!(ring.len(), 2);
        assert_eq!(&ring.storage[..], b"ab..........");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 2);
            buf[0..4].copy_from_slice(b"cdXX");
            (2, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"abcdXX......");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 4);
            buf[0..4].copy_from_slice(b"efgh");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for i in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 8);
            buf[0..4].copy_from_slice(b"ijkl");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 4);
            buf[0..4].copy_from_slice(b"abcd");
            (4, ())
        });
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");

        for i in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcd....ijkl");
    }

    #[test]
    pub fn test_buffer_enqueue_many() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        ring.enqueue_many(8).copy_from_slice(b"abcdefgh");
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        ring.enqueue_many(8).copy_from_slice(b"ijkl");
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");
    }

    #[test]
    pub fn test_buffer_enqueue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefgh"), 8);
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for i in 0..4 {
            *ring.dequeue_one().unwrap() = b'.';
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        assert_eq!(ring.enqueue_slice(b"ijklabcd"), 8);
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");
    }

    #[test]
    pub fn test_buffer_dequeue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        assert_eq!(ring.dequeue_many_with(|buf| {
            assert_eq!(buf.len(), 12);
            assert_eq!(buf, b"abcdefghijkl");
            buf[..4].copy_from_slice(b"....");
            (4, true)
        }), (4, true));
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"efghijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"........ijkl");

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);
        assert_eq!(ring.len(), 8);

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"ijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"abcd");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 0);
        assert_eq!(&ring.storage[..], b"............");
    }

    #[test]
    pub fn test_buffer_dequeue_many() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        {
            let mut buf = ring.dequeue_many(8);
            assert_eq!(buf, b"abcdefgh");
            buf.copy_from_slice(b"........");
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"........ijkl");

        {
            let mut buf = ring.dequeue_many(8);
            assert_eq!(buf, b"ijkl");
            buf.copy_from_slice(b"....");
        }
        assert_eq!(ring.len(), 0);
        assert_eq!(&ring.storage[..], b"............");
    }

    #[test]
    pub fn test_buffer_dequeue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"abcdefgh");
            assert_eq!(ring.len(), 4);
        }

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"ijklabcd");
            assert_eq!(ring.len(), 0);
        }
    }
}
