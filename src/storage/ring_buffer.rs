use managed::ManagedSlice;

use {Error, Result};
use super::Resettable;

/// A ring buffer.
#[derive(Debug)]
pub struct RingBuffer<'a, T: 'a + Resettable> {
    storage: ManagedSlice<'a, T>,
    read_at: usize,
    length: usize,
}

impl<'a, T: 'a + Resettable> RingBuffer<'a, T> {
    /// Create a ring buffer with the given storage.
    ///
    /// During creation, every element in `storage` is reset.
    pub fn new<S>(storage: S) -> RingBuffer<'a, T>
        where S: Into<ManagedSlice<'a, T>>,
    {
        let mut storage = storage.into();
        for elem in storage.iter_mut() {
            elem.reset();
        }

        RingBuffer {
            storage: storage,
            read_at: 0,
            length:  0,
        }
    }

    fn mask(&self, index: usize) -> usize {
        index % self.storage.len()
    }

    fn incr(&self, index: usize) -> usize {
        self.mask(index + 1)
    }

    /// Query whether the buffer is empty.
    pub fn empty(&self) -> bool {
        self.length == 0
    }

    /// Query whether the buffer is full.
    pub fn full(&self) -> bool {
        self.length == self.storage.len()
    }

    /// Get capacity of the underlying storage.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Get the number of elements in the buffer
    pub fn len(&self) -> usize {
        self.length
    }

    /// Enqueue an element into the buffer, and return a pointer to it, or return
    /// `Err(Error::Exhausted)` if the buffer is full.
    pub fn enqueue<'b>(&'b mut self) -> Result<&'b mut T> {
        if self.full() { return Err(Error::Exhausted) }

        let index = self.mask(self.read_at + self.length);
        self.length += 1;
        Ok(&mut self.storage[index])
    }

    /// Call `f` with a buffer element, and enqueue the element if `f` returns successfully, or
    /// return `Err(Error::Exhausted)` if the buffer is full.
    pub fn try_enqueue<'b, R, F>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut T) -> Result<R> {
        if self.full() { return Err(Error::Exhausted) }

        let index = self.mask(self.read_at + self.length);
        match f(&mut self.storage[index]) {
            Ok(result) => {
                self.length += 1;
                Ok(result)
            }
            Err(error) => Err(error)
        }
    }

    /// Dequeue an element from the buffer, and return a mutable reference to it, or return
    /// `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<&mut T> {
        if self.empty() { return Err(Error::Exhausted) }

        let read_at = self.read_at;
        self.length -= 1;
        self.read_at = self.incr(self.read_at);
        Ok(&mut self.storage[read_at])
    }

    /// Call `f` with a buffer element, and dequeue the element if `f` returns successfully, or
    /// return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn try_dequeue<'b, R, F>(&'b mut self, f: F) -> Result<R>
            where F: FnOnce(&'b mut T) -> Result<R> {
        if self.empty() { return Err(Error::Exhausted) }

        let next_at = self.incr(self.read_at);
        match f(&mut self.storage[self.read_at]) {
            Ok(result) => {
                self.length -= 1;
                self.read_at = next_at;
                Ok(result)
            }
            Err(error) => Err(error)
        }
    }

    /// Expand the underlying storage to fit `additional` more elements,
    /// panic if the storage cannot be expanded.
    pub fn reserve_exact(&mut self, additional: usize)
        where T: Copy + Default {
        match self.storage {
            ManagedSlice::Borrowed(_) => {
                panic!("Cannot expand a ring_buffer in not-owned memory")
            }
            #[cfg(any(feature = "std", feature = "collections"))]
            ManagedSlice::Owned(ref mut storage) => {
                storage.reserve(additional);
                for _ in 0..additional {
                    storage.push(Default::default());
                }
            }
        }
        #[cfg(any(feature = "std", feature = "collections"))]
        {
            if self.length != 0 && self.storage.len() > 1 {
                let end = (self.read_at + self.length) % (self.storage.len() - additional);
                if end <= self.read_at {
                    for j in self.length - end..self.length {
                        self.storage[self.mask(self.read_at + j)] =
                            self.storage[self.mask(self.read_at + j + additional)];
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    impl Resettable for usize {
        fn reset(&mut self) {
            *self = 0;
        }
    }

    const SIZE: usize = 5;

    fn buffer() -> RingBuffer<'static, usize> {
        let mut storage = vec![];
        for i in 0..SIZE {
            storage.push(i + 10);
        }

        RingBuffer::new(storage)
    }

    #[test]
    pub fn test_buffer() {
        let mut buf = buffer();
        assert!(buf.empty());
        assert!(!buf.full());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.dequeue(), Err(Error::Exhausted));

        buf.enqueue().unwrap();
        assert!(!buf.empty());
        assert!(!buf.full());
        assert_eq!(buf.len(), 1);

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
        assert_eq!(buf.len(), 0);
        assert!(buf.empty());
    }

    #[test]
    pub fn test_buffer_try() {
        let mut buf = buffer();
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

    #[test]
    pub fn test_buffer_reserve() {
        let mut buf = RingBuffer::new(vec![]);
        assert_eq!(buf.capacity(), 0);
        assert_eq!(buf.len(), 0);
        assert!(buf.empty());
        assert!(buf.full());
        assert_eq!(buf.enqueue(), Err(Error::Exhausted));

        buf.reserve_exact(1);
        assert_eq!(buf.capacity(), 1);
        assert_eq!(buf.len(), 0);

        *buf.enqueue().unwrap() = 123;
        assert!(!buf.empty());
        assert!(buf.full());
        assert_eq!(buf.capacity(), 1);
        assert_eq!(buf.len(), 1);

        assert_eq!(*buf.dequeue().unwrap(), 123);
        assert!(buf.empty());
        assert!(!buf.full());
        assert_eq!(buf.capacity(), 1);
        assert_eq!(buf.len(), 0);

        *buf.enqueue().unwrap() = 123;
        assert!(buf.full());

        buf.reserve_exact(5);
        assert!(!buf.full());
        assert!(!buf.empty());
        assert_eq!(buf.capacity(), 6);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    pub fn test_buffer_reserve_2() {
        let mut buf = buffer();
        for i in 0..SIZE {
            *buf.enqueue().unwrap() = i;
        }
        assert!(buf.full());
        for i in 0..SIZE/2 {
            assert_eq!(*buf.dequeue().unwrap(), i);
        }
        for i in SIZE..SIZE+SIZE/2 {
            *buf.enqueue().unwrap() = i;
        }
        buf.reserve_exact(SIZE);
        for i in SIZE/2..SIZE+SIZE/2 {
            assert_eq!(*buf.dequeue().unwrap(), i);
        }

        assert!(buf.empty());
        assert_eq!(buf.capacity(), 2*SIZE);
        assert_eq!(buf.len(), 0);
    }
}
