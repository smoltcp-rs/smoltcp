use managed::ManagedSlice;

use crate::{Error, Result};
use crate::storage::RingBuffer;

/// Size and header of a packet.
#[derive(Debug, Clone, Copy)]
pub struct PacketMetadata<H> {
    size:   usize,
    header: Option<H>
}

impl<H> PacketMetadata<H> {
    /// Empty packet description.
    pub const EMPTY: PacketMetadata<H> = PacketMetadata { size: 0, header: None };

    fn padding(size: usize) -> PacketMetadata<H> {
        PacketMetadata {
            size:   size,
            header: None
        }
    }

    fn packet(size: usize, header: H) -> PacketMetadata<H> {
        PacketMetadata {
            size:   size,
            header: Some(header)
        }
    }

    fn is_padding(&self) -> bool {
        self.header.is_none()
    }
}

/// An UDP packet ring buffer.
#[derive(Debug)]
pub struct PacketBuffer<'a, 'b, H: 'a> {
    metadata_ring: RingBuffer<'a, PacketMetadata<H>>,
    payload_ring:  RingBuffer<'b, u8>,
}

impl<'a, 'b, H> PacketBuffer<'a, 'b, H> {
    /// Create a new packet buffer with the provided metadata and payload storage.
    ///
    /// Metadata storage limits the maximum _number_ of packets in the buffer and payload
    /// storage limits the maximum _total size_ of packets.
    pub fn new<MS, PS>(metadata_storage: MS, payload_storage: PS) -> PacketBuffer<'a, 'b, H>
        where MS: Into<ManagedSlice<'a, PacketMetadata<H>>>,
              PS: Into<ManagedSlice<'b, u8>>,
    {
        PacketBuffer {
            metadata_ring: RingBuffer::new(metadata_storage),
            payload_ring:  RingBuffer::new(payload_storage),
        }
    }

    /// Query whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.metadata_ring.is_empty()
    }

    /// Query whether the buffer is full.
    pub fn is_full(&self) -> bool {
        self.metadata_ring.is_full()
    }

    // There is currently no enqueue_with() because of the complexity of managing padding
    // in case of failure.

    /// Enqueue a single packet with the given header into the buffer, and
    /// return a reference to its payload, or return `Err(Error::Exhausted)`
    /// if the buffer is full, or return `Err(Error::Truncated)` if the buffer
    /// does not have enough spare payload space.
    pub fn enqueue(&mut self, size: usize, header: H) -> Result<&mut [u8]> {
        if self.payload_ring.capacity() < size {
            return Err(Error::Truncated)
        }

        if self.metadata_ring.is_full() {
            return Err(Error::Exhausted)
        }

        let window = self.payload_ring.window();
        let contig_window = self.payload_ring.contiguous_window();

        if window < size {
            return Err(Error::Exhausted)
        } else if contig_window < size {
            if window - contig_window < size {
                // The buffer length is larger than the current contiguous window
                // and is larger than the contiguous window will be after adding
                // the padding necessary to circle around to the beginning of the
                // ring buffer.
                return Err(Error::Exhausted)
            } else {
                // Add padding to the end of the ring buffer so that the
                // contiguous window is at the beginning of the ring buffer.
                *self.metadata_ring.enqueue_one()? = PacketMetadata::padding(contig_window);
                self.payload_ring.enqueue_many(contig_window);
            }
        }

        *self.metadata_ring.enqueue_one()? = PacketMetadata::packet(size, header);

        let payload_buf = self.payload_ring.enqueue_many(size);
        debug_assert!(payload_buf.len() == size);
        Ok(payload_buf)
    }

    fn dequeue_padding(&mut self) {
        let Self { ref mut metadata_ring, ref mut payload_ring } = *self;

        let _ = metadata_ring.dequeue_one_with(|metadata| {
            if metadata.is_padding() {
                payload_ring.dequeue_many(metadata.size);
                Ok(()) // dequeue metadata
            } else {
                Err(Error::Exhausted) // don't dequeue metadata
            }
        });
    }

    /// Call `f` with a single packet from the buffer, and dequeue the packet if `f`
    /// returns successfully, or return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue_with<'c, R, F>(&'c mut self, f: F) -> Result<R>
            where F: FnOnce(&mut H, &'c mut [u8]) -> Result<R> {
        self.dequeue_padding();

        let Self { ref mut metadata_ring, ref mut payload_ring } = *self;

        metadata_ring.dequeue_one_with(move |metadata| {
            let PacketMetadata { ref mut header, size } = *metadata;

            payload_ring.dequeue_many_with(|payload_buf| {
                debug_assert!(payload_buf.len() >= size);

                match f(header.as_mut().unwrap(), &mut payload_buf[..size]) {
                    Ok(val)  => (size, Ok(val)),
                    Err(err) => (0,    Err(err)),
                }
            }).1
        })
    }

    /// Dequeue a single packet from the buffer, and return a reference to its payload
    /// as well as its header, or return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<(H, &mut [u8])> {
        self.dequeue_padding();

        let PacketMetadata { ref mut header, size } = *self.metadata_ring.dequeue_one()?;

        let payload_buf = self.payload_ring.dequeue_many(size);
        debug_assert!(payload_buf.len() == size);
        Ok((header.take().unwrap(), payload_buf))
    }

    /// Peek at a single packet from the buffer without removing it, and return a reference to
    /// its payload as well as its header, or return `Err(Error:Exhaused)` if the buffer is empty.
    ///
    /// This function otherwise behaves identically to [dequeue](#method.dequeue).
    pub fn peek(&mut self) -> Result<(&H, &[u8])> {
        self.dequeue_padding();

        if let Some(metadata) = self.metadata_ring.get_allocated(0, 1).first() {
            Ok((metadata.header.as_ref().unwrap(), self.payload_ring.get_allocated(0, metadata.size)))
        } else {
            Err(Error::Exhausted)
        }
    }

    /// Return the maximum number packets that can be stored.
    pub fn packet_capacity(&self) -> usize {
        self.metadata_ring.capacity()
    }

    /// Return the maximum number of bytes in the payload ring buffer.
    pub fn payload_capacity(&self) -> usize {
        self.payload_ring.capacity()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn buffer() -> PacketBuffer<'static, 'static, ()> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; 4],
                          vec![0u8; 16])
    }

    #[test]
    fn test_simple() {
        let mut buffer = buffer();
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.enqueue(16, ()), Err(Error::Exhausted));
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue(), Err(Error::Exhausted));
    }

    #[test]
    fn test_peek() {
        let mut buffer = buffer();
        assert_eq!(buffer.peek(), Err(Error::Exhausted));
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.peek().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.peek(), Err(Error::Exhausted));
    }

    #[test]
    fn test_padding() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert_eq!(buffer.dequeue().unwrap().1, &b"abcd"[..]);
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[test]
    fn test_padding_with_large_payload() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(12, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(12, ()).unwrap().copy_from_slice(b"abcdefghijkl");
    }

    #[test]
    fn test_dequeue_with() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert!(buffer.dequeue_with(|_, _| Err(Error::Unaddressable) as Result<()>).is_err());
        assert_eq!(buffer.metadata_ring.len(), 1);

        assert!(buffer.dequeue_with(|&mut (), payload| {
            assert_eq!(payload, &b"abcd"[..]);
            Ok(())
        }).is_ok());
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[test]
    fn test_metadata_full_empty() {
        let mut buffer = buffer();
        assert_eq!(buffer.is_empty(), true);
        assert_eq!(buffer.is_full(), false);
        assert!(buffer.enqueue(1, ()).is_ok());
        assert_eq!(buffer.is_empty(), false);
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert_eq!(buffer.is_full(), false);
        assert_eq!(buffer.is_empty(), false);
        assert!(buffer.enqueue(1, ()).is_ok());
        assert_eq!(buffer.is_full(), true);
        assert_eq!(buffer.is_empty(), false);
        assert_eq!(buffer.metadata_ring.len(), 4);
        assert_eq!(buffer.enqueue(1, ()), Err(Error::Exhausted));
    }

    #[test]
    fn test_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(16, ()), Err(Error::Exhausted));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_contiguous_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(8, ()), Err(Error::Exhausted));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_capacity_too_small() {
        let mut buffer = buffer();
        assert_eq!(buffer.enqueue(32, ()), Err(Error::Truncated));
    }

    #[test]
    fn test_contig_window_prioritized() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert!(buffer.enqueue(5, ()).is_ok());
    }
}
