use Error;
use Managed;
use wire::{IpProtocol, IpEndpoint};
use wire::{UdpPacket, UdpRepr};
use socket::{Socket, IpRepr, IpPayload};

/// A buffered UDP packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    endpoint: IpEndpoint,
    size:     usize,
    payload:  Managed<'a, [u8]>
}

impl<'a> PacketBuffer<'a> {
    /// Create a buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        PacketBuffer {
            endpoint: IpEndpoint::UNSPECIFIED,
            size:     0,
            payload:  payload.into()
        }
    }

    fn as_ref<'b>(&'b self) -> &'b [u8] {
        &self.payload[..self.size]
    }

    fn as_mut<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.payload[..self.size]
    }
}

/// An UDP packet ring buffer.
#[derive(Debug)]
pub struct SocketBuffer<'a, 'b: 'a> {
    storage: Managed<'a, [PacketBuffer<'b>]>,
    read_at: usize,
    length:  usize
}

impl<'a, 'b> SocketBuffer<'a, 'b> {
    /// Create a packet buffer with the given storage.
    pub fn new<T>(storage: T) -> SocketBuffer<'a, 'b>
            where T: Into<Managed<'a, [PacketBuffer<'b>]>> {
        let mut storage = storage.into();
        for elem in storage.iter_mut() {
            elem.endpoint = Default::default();
            elem.size = 0;
        }

        SocketBuffer {
            storage: storage,
            read_at: 0,
            length:  0
        }
    }

    fn mask(&self, index: usize) -> usize {
        index % self.storage.len()
    }

    fn incr(&self, index: usize) -> usize {
        self.mask(index + 1)
    }

    fn empty(&self) -> bool {
        self.length == 0
    }

    fn full(&self) -> bool {
        self.length == self.storage.len()
    }

    /// Enqueue an element into the buffer, and return a pointer to it, or return
    /// `Err(Error::Exhausted)` if the buffer is full.
    pub fn enqueue(&mut self) -> Result<&mut PacketBuffer<'b>, Error> {
        if self.full() {
            Err(Error::Exhausted)
        } else {
            let index = self.mask(self.read_at + self.length);
            let result = &mut self.storage[index];
            self.length += 1;
            Ok(result)
        }
    }

    /// Dequeue an element from the buffer, and return a pointer to it, or return
    /// `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<&PacketBuffer<'b>, Error> {
        if self.empty() {
            Err(Error::Exhausted)
        } else {
            self.length -= 1;
            let result = &self.storage[self.read_at];
            self.read_at = self.incr(self.read_at);
            Ok(result)
        }
    }
}

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
pub struct UdpSocket<'a, 'b: 'a> {
    endpoint:  IpEndpoint,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>
}

impl<'a, 'b> UdpSocket<'a, 'b> {
    /// Create an UDP socket with the given buffers.
    pub fn new(endpoint: IpEndpoint,
               rx_buffer: SocketBuffer<'a, 'b>, tx_buffer: SocketBuffer<'a, 'b>)
            -> Socket<'a, 'b> {
        Socket::Udp(UdpSocket {
            endpoint:  endpoint,
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer
        })
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the size is greater than what
    /// the transmit buffer can accomodate.
    pub fn send(&mut self, endpoint: IpEndpoint, size: usize) -> Result<&mut [u8], Error> {
        let packet_buf = try!(self.tx_buffer.enqueue());
        packet_buf.endpoint = endpoint;
        packet_buf.size = size;
        net_trace!("udp:{}:{}: send {} octets",
                   self.endpoint, packet_buf.endpoint, packet_buf.size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packete to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, endpoint: IpEndpoint, data: &[u8]) -> Result<(), Error> {
        let buffer = try!(self.send(endpoint, data.len()));
        Ok(buffer.copy_from_slice(data))
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(IpEndpoint, &[u8]), Error> {
        let packet_buf = try!(self.rx_buffer.dequeue());
        net_trace!("udp:{}:{}: recv {} octets",
                   self.endpoint, packet_buf.endpoint, packet_buf.size);
        Ok((packet_buf.endpoint, &packet_buf.as_ref()[..packet_buf.size]))
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as copy the payload into the given slice.
    ///
    /// This function returns `Err(Error::Exhausted)` if the received packet has payload
    /// larger than the provided slice. See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(IpEndpoint, usize), Error> {
        let (endpoint, buffer) = try!(self.recv());
        if data.len() < buffer.len() { return Err(Error::Exhausted) }
        data[..buffer.len()].copy_from_slice(buffer);
        Ok((endpoint, buffer.len()))
    }

    /// See [Socket::collect](enum.Socket.html#method.collect).
    pub fn collect(&mut self, ip_repr: &IpRepr, payload: &[u8]) -> Result<(), Error> {
        if ip_repr.protocol() != IpProtocol::Udp { return Err(Error::Rejected) }

        let packet = try!(UdpPacket::new(payload));
        let repr = try!(UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr()));

        if repr.dst_port != self.endpoint.port { return Err(Error::Rejected) }
        if !self.endpoint.addr.is_unspecified() {
            if self.endpoint.addr != ip_repr.dst_addr() { return Err(Error::Rejected) }
        }

        let packet_buf = try!(self.rx_buffer.enqueue());
        packet_buf.endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        packet_buf.size = repr.payload.len();
        packet_buf.as_mut()[..repr.payload.len()].copy_from_slice(repr.payload);
        net_trace!("udp:{}:{}: collect {} octets",
                   self.endpoint, packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F>(&mut self, emit: &mut F) -> Result<(), Error>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<(), Error> {
        let packet_buf = try!(self.tx_buffer.dequeue());
        net_trace!("udp:{}:{}: dispatch {} octets",
                   self.endpoint, packet_buf.endpoint, packet_buf.size);
        let ip_repr = IpRepr::Unspecified {
            src_addr: self.endpoint.addr,
            dst_addr: packet_buf.endpoint.addr,
            protocol: IpProtocol::Udp
        };
        let payload = UdpRepr {
            src_port: self.endpoint.port,
            dst_port: packet_buf.endpoint.port,
            payload:  &packet_buf.as_ref()[..]
        };
        emit(&ip_repr, &payload)
    }
}

impl<'a> IpPayload for UdpRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.buffer_len()
    }

    fn emit(&self, repr: &IpRepr, payload: &mut [u8]) {
        let mut packet = UdpPacket::new(payload).expect("undersized payload");
        self.emit(&mut packet, &repr.src_addr(), &repr.dst_addr())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_buffer() {
        let mut storage = vec![];
        for _ in 0..5 {
            storage.push(PacketBuffer::new(vec![0]))
        }
        let mut buffer = SocketBuffer::new(&mut storage[..]);

        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(),  false);
        buffer.enqueue().unwrap().size = 1;
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(),  false);
        buffer.enqueue().unwrap().size = 2;
        buffer.enqueue().unwrap().size = 3;
        assert_eq!(buffer.dequeue().unwrap().size, 1);
        assert_eq!(buffer.dequeue().unwrap().size, 2);
        buffer.enqueue().unwrap().size = 4;
        buffer.enqueue().unwrap().size = 5;
        buffer.enqueue().unwrap().size = 6;
        buffer.enqueue().unwrap().size = 7;
        assert_eq!(buffer.enqueue().unwrap_err(), Error::Exhausted);
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(),  true);
        assert_eq!(buffer.dequeue().unwrap().size, 3);
        assert_eq!(buffer.dequeue().unwrap().size, 4);
        assert_eq!(buffer.dequeue().unwrap().size, 5);
        assert_eq!(buffer.dequeue().unwrap().size, 6);
        assert_eq!(buffer.dequeue().unwrap().size, 7);
        assert_eq!(buffer.dequeue().unwrap_err(), Error::Exhausted);
        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(),  false);
    }
}
