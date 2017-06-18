use managed::Managed;
use storage::Resettable;

/// A ring buffer.
#[derive(Debug)]
pub struct RingBuffer<'a, T: 'a> {
    storage: Managed<'a, [T]>,
    read_at: usize,
    length: usize,
}

impl<'a, T: 'a> RingBuffer<'a, T> {
    /// Create a ring buffer with the given storage.
    ///
    /// During creation, every element in `storage` is reset.
    pub fn new<S>(storage: S) -> RingBuffer<'a, T>
        where S: Into<Managed<'a, [T]>>, T: Resettable,
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

    /// Enqueue an element into the buffer, and return a pointer to it, or return
    /// `Err(())` if the buffer is full.
    pub fn enqueue(&mut self) -> Result<&mut T, ()> {
        if self.full() {
            Err(())
        } else {
            let index = self.mask(self.read_at + self.length);
            let result = &mut self.storage[index];
            self.length += 1;
            Ok(result)
        }
    }

    /// Dequeue an element from the buffer, and return a pointer to it, or return
    /// `Err(())` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<&T, ()> {
        if self.empty() {
            Err(())
        } else {
            self.length -= 1;
            let result = &self.storage[self.read_at];
            self.read_at = self.incr(self.read_at);
            Ok(result)
        }
    }

    /// Dequeue an element from the buffer, and return a mutable reference to it, or return
    /// `Err(())` if the buffer is empty.
    pub fn dequeue_mut(&mut self) -> Result<&mut T, ()> {
        if self.empty() {
            Err(())
        } else {
            self.length -= 1;
            let read_at = self.read_at;
            self.read_at = self.incr(self.read_at);
            let result = &mut self.storage[read_at];
            Ok(result)
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

    #[test]
    pub fn test_buffer() {
        const TEST_BUFFER_SIZE: usize = 5;
        let mut storage = vec![];
        for i in 0..TEST_BUFFER_SIZE {
            storage.push(i + 10);
        }

        let mut ring_buffer = RingBuffer::new(&mut storage[..]);
        assert!(ring_buffer.empty());
        assert!(!ring_buffer.full());
        assert_eq!(ring_buffer.dequeue(), Err(()));
        ring_buffer.enqueue().unwrap();
        assert!(!ring_buffer.empty());
        assert!(!ring_buffer.full());
        for i in 1..TEST_BUFFER_SIZE {
            *ring_buffer.enqueue().unwrap() = i;
            assert!(!ring_buffer.empty());
        }
        assert!(ring_buffer.full());
        assert_eq!(ring_buffer.enqueue(), Err(()));

        for i in 0..TEST_BUFFER_SIZE {
            assert_eq!(*ring_buffer.dequeue().unwrap(), i);
            assert!(!ring_buffer.full());
        }
        assert_eq!(ring_buffer.dequeue(), Err(()));
        assert!(ring_buffer.empty());
    }
}
