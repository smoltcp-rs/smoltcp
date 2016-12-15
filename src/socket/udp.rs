use core::borrow::BorrowMut;

use Error;
use wire::{InternetAddress as Address, InternetProtocolType as ProtocolType};
use wire::{InternetEndpoint as Endpoint};
use wire::{UdpPacket, UdpRepr};
use socket::{Socket, PacketRepr};

/// A packet buffer.
///
/// The packet buffer interface allows enqueueing and dequeueing separate packets.
/// A packet is a sequence of octets and its associated endpoint.
pub trait Buffer {
    /// Enqueue a packet.
    ///
    /// This function allocates a sequence of octets the given size and associates
    /// the given endpoint with it, then calls `f`; if the buffer is full, it
    /// returns `Err(Error::Exhausted)` instead.
    fn enqueue<R, F>(&mut self, endpoint: Endpoint, size: usize, f: F) -> Result<R, Error>
        where F: FnOnce(&mut [u8]) -> Result<R, Error>;

    /// Dequeue a packet.
    ///
    /// This function calls `f` with the oldest enqueued packet; if the buffer is empty,
    /// it returns `Err(Error::Exhausted)` instead.
    fn dequeue<R, F>(&mut self, f: F) -> Result<R, Error>
        where F: FnOnce(Endpoint, &[u8]) -> Result<R, Error>;
}

/// A packet buffer that does not have any storage.
///
/// The null buffer rejects enqueue and dequeue operations with `Error::Exhausted`.
pub struct NullBuffer(());

impl NullBuffer {
    /// Create a null packet buffer.
    pub fn new() -> NullBuffer {
        NullBuffer(())
    }
}

impl Buffer for NullBuffer {
    fn enqueue<R, F>(&mut self, _endpoint: Endpoint, _size: usize, _f: F) -> Result<R, Error>
            where F: FnOnce(&mut [u8]) -> Result<R, Error> {
        Err(Error::Exhausted)
    }

    fn dequeue<R, F>(&mut self, _f: F) -> Result<R, Error>
            where F: FnOnce(Endpoint, &[u8]) -> Result<R, Error> {
        Err(Error::Exhausted)
    }
}

/// A packet buffer that only stores, at most, a single packet.
///
/// The unitary buffer uses a provided slice to store no more than one packet at any time.
/// If there is an enqueued packet, or if the requested size is larger than the storage size,
/// the unitary rejects the enqueue operation with `Error::Exhausted`.
pub struct UnitaryBuffer<T: BorrowMut<[u8]>> {
    endpoint: Endpoint,
    storage:  T,
    size:     usize
}

impl<T: BorrowMut<[u8]>> UnitaryBuffer<T> {
    /// Create an unitary packet buffer, using the given storage.
    pub fn new(storage: T) -> UnitaryBuffer<T> {
        UnitaryBuffer {
            endpoint: Default::default(),
            storage:  storage,
            size:     0
        }
    }
}

impl<T: BorrowMut<[u8]>> Buffer for UnitaryBuffer<T> {
    fn enqueue<R, F>(&mut self, endpoint: Endpoint, size: usize, f: F) -> Result<R, Error>
            where F: FnOnce(&mut [u8]) -> Result<R, Error> {
        let mut storage = self.storage.borrow_mut();
        match self.endpoint {
            Endpoint { addr: Address::Invalid, .. }
                    if size <= storage.len() => {
                // If `f` fails, don't enqueue the packet.
                let result = try!(f(&mut storage[..size]));
                self.endpoint = endpoint;
                Ok(result)
            },
            _ => {
                Err(Error::Exhausted)
            }
        }
    }

    fn dequeue<R, F>(&mut self, f: F) -> Result<R, Error>
            where F: FnOnce(Endpoint, &[u8]) -> Result<R, Error> {
        let storage = self.storage.borrow_mut();
        match self.endpoint {
            Endpoint { addr: Address::Invalid, .. } => {
                Err(Error::Exhausted)
            },
            _ => {
                // If `f` fails, still dequeue the packet.
                let result = f(self.endpoint, &storage[..self.size]);
                self.endpoint = Default::default();
                result
            }
        }
    }
}

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
pub struct UdpSocket<RxBufferT: Buffer, TxBufferT: Buffer> {
    endpoint:  Endpoint,
    rx_buffer: RxBufferT,
    tx_buffer: TxBufferT
}

impl<RxBufferT: Buffer, TxBufferT: Buffer> UdpSocket<RxBufferT, TxBufferT> {
    /// Create an UDP socket with the given buffers.
    pub fn new(endpoint: Endpoint,
               rx_buffer: RxBufferT,
               tx_buffer: TxBufferT) -> UdpSocket<RxBufferT, TxBufferT> {
        UdpSocket {
            endpoint:  endpoint,
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer
        }
    }

    /// Send a packet to a remote endpoint, without copying.
    pub fn send<R, F>(&mut self, endpoint: Endpoint, size: usize, f: F) -> Result<R, Error>
            where F: FnOnce(&mut [u8]) -> Result<R, Error> {
        self.tx_buffer.enqueue(endpoint, size, f)
    }

    /// Send a packet to remote endpoint, copying the given slice to the internal buffer.
    ///
    /// This function returns `Err(Error::Exhausted)` if the slice is larger than the internal
    /// buffer can accomodate.
    pub fn send_slice(&mut self, endpoint: Endpoint, data: &[u8]) -> Result<(), Error> {
        self.tx_buffer.enqueue(endpoint, data.len(), |buffer| {
            Ok(buffer.copy_from_slice(data))
        })
    }

    /// Receive a packet from a remote endpoint, without copying.
    pub fn recv<R, F>(&mut self, f: F) -> Result<R, Error>
            where F: FnOnce(Endpoint, &[u8]) -> Result<R, Error> {
        self.rx_buffer.dequeue(f)
    }

    /// Receive a packet from a remote endpoint, copying the given slice to the internal buffer.
    ///
    /// This function returns `Err(Error::Exhausted)` if the slice is smaller than the packet
    /// queued in the internal buffer.
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, Endpoint), Error> {
        self.rx_buffer.dequeue(|endpoint, buffer| {
            if data.len() < buffer.len() { return Err(Error::Exhausted) }
            data[..buffer.len()].copy_from_slice(buffer);
            Ok((buffer.len(), endpoint))
        })
    }
}

impl<RxBufferT: Buffer, TxBufferT: Buffer> Socket for UdpSocket<RxBufferT, TxBufferT> {
    fn collect(&mut self, src_addr: &Address, dst_addr: &Address,
               protocol: ProtocolType, payload: &[u8])
            -> Result<(), Error> {
        if protocol != ProtocolType::Udp { return Err(Error::Rejected) }

        let packet = try!(UdpPacket::new(payload));
        let repr = try!(UdpRepr::parse(&packet, src_addr, dst_addr));

        if repr.dst_port != self.endpoint.port { return Err(Error::Rejected) }
        if !self.endpoint.addr.is_unspecified() {
            if self.endpoint.addr != *dst_addr { return Err(Error::Rejected) }
        }

        let endpoint = Endpoint { addr: *src_addr, port: repr.src_port };
        self.rx_buffer.enqueue(endpoint, repr.payload.len(), |buffer| {
            Ok(buffer.copy_from_slice(repr.payload))
        })
    }

    fn dispatch(&mut self, f: &mut FnMut(&Address, &Address,
                                         ProtocolType, &PacketRepr) -> Result<(), Error>)
            -> Result<(), Error> {
        let src_endpoint = self.endpoint;
        self.tx_buffer.dequeue(|dst_endpoint, buffer| {
            f(&src_endpoint.addr,
              &dst_endpoint.addr,
              ProtocolType::Udp,
              &UdpRepr {
                src_port: src_endpoint.port,
                dst_port: dst_endpoint.port,
                payload:  buffer
            })
        })
    }
}

impl<'a> PacketRepr for UdpRepr<'a> {
    fn len(&self) -> usize {
        self.len()
    }

    fn emit(&self, src_addr: &Address, dst_addr: &Address, payload: &mut [u8]) {
        let mut packet = UdpPacket::new(payload).expect("undersized payload slice");
        self.emit(&mut packet, src_addr, dst_addr)
    }
}
