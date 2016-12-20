use Managed;

/// A TCP stream ring buffer.
#[derive(Debug)]
pub struct SocketBuffer<'a> {
    storage: Managed<'a, [u8]>,
    read_at: usize,
    length:  usize
}

impl<'a> SocketBuffer<'a> {
    /// Create a packet buffer with the given storage.
    pub fn new<T>(storage: T) -> SocketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        SocketBuffer {
            storage: storage.into(),
            read_at: 0,
            length:  0
        }
    }

    /// Enqueue a slice of octets up to the given size into the buffer, and return a pointer
    /// to the slice.
    ///
    /// The returned slice may be shorter than requested, as short as an empty slice,
    /// if there is not enough contiguous free space in the buffer.
    pub fn enqueue(&mut self, mut size: usize) -> &mut [u8] {
        let write_at = (self.read_at + self.length) % self.storage.len();
        // We can't enqueue more than there is free space.
        let free = self.storage.len() - self.length;
        if size > free { size = free }
        // We can't contiguously enqueue past the beginning of the storage.
        let until_end = self.storage.len() - write_at;
        if size > until_end { size = until_end }

        self.length += size;
        &mut self.storage[write_at..write_at + size]
    }

    /// Dequeue a slice of octets up to the given size from the buffer, and return a pointer
    /// to the slice.
    ///
    /// The returned slice may be shorter than requested, as short as an empty slice,
    /// if there is not enough contiguous filled space in the buffer.
    pub fn dequeue(&mut self, mut size: usize) -> &[u8] {
        let read_at = self.read_at;
        // We can't dequeue more than was queued.
        if size > self.length { size = self.length }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.storage.len() - self.read_at;
        if size > until_end { size = until_end }

        self.read_at = (self.read_at + size) % self.storage.len();
        self.length -= size;
        &self.storage[read_at..read_at + size]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = SocketBuffer::new(vec![0; 8]);       // ........
        buffer.enqueue(6).copy_from_slice(b"foobar");   // foobar..
        assert_eq!(buffer.dequeue(3), b"foo");          // ...bar..
        buffer.enqueue(6).copy_from_slice(b"ba");       // ...barba
        buffer.enqueue(4).copy_from_slice(b"zho");      // zhobarba
        assert_eq!(buffer.dequeue(6), b"barba");        // zho.....
        assert_eq!(buffer.dequeue(8), b"zho");          // ........
        buffer.enqueue(8).copy_from_slice(b"gefug");    // ...gefug
    }
}
