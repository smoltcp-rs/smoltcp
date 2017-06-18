use managed::Managed;

use Error;
use phy::DeviceLimits;
use wire::{IpProtocol, IpEndpoint};
use wire::{UdpPacket, UdpRepr};
use socket::{Socket, IpRepr, IpPayload};
use storage::ring_buffer::RingBuffer;
use storage::Resettable;

/// A buffered UDP packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    endpoint: IpEndpoint,
    size:     usize,
    payload:  Managed<'a, [u8]>
}

impl<'a> Resettable for PacketBuffer<'a> {
    fn reset(&mut self) {
        self.endpoint = Default::default();
        self.size = 0;
    }
}

impl<'a> PacketBuffer<'a> {
    /// Create a buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        PacketBuffer {
            endpoint: IpEndpoint::default(),
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
pub type SocketBuffer<'a, 'b : 'a> = RingBuffer<'a, PacketBuffer<'b>>;

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct UdpSocket<'a, 'b: 'a> {
    endpoint:  IpEndpoint,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    debug_id:  usize
}

impl<'a, 'b> UdpSocket<'a, 'b> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>,
               tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Udp(UdpSocket {
            endpoint:  IpEndpoint::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            debug_id:  0
        })
    }

    /// Return the debug identifier.
    pub fn debug_id(&self) -> usize {
        self.debug_id
    }

    /// Set the debug identifier.
    ///
    /// The debug identifier is a number printed in socket trace messages.
    /// It could as well be used by the user code.
    pub fn set_debug_id(&mut self, id: usize) {
        self.debug_id = id
    }

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpEndpoint {
        self.endpoint
    }

    /// Bind the socket to the given endpoint.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) {
        self.endpoint = endpoint.into()
    }

    /// Check whether the transmit buffer is full.
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.full()
    }

    /// Check whether the receive buffer is not empty.
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.empty()
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(())` if the size is greater than what
    /// the transmit buffer can accomodate.
    pub fn send(&mut self, size: usize, endpoint: IpEndpoint) -> Result<&mut [u8], ()> {
        let packet_buf = try!(self.tx_buffer.enqueue());
        packet_buf.endpoint = endpoint;
        packet_buf.size = size;
        net_trace!("[{}]{}:{}: buffer to send {} octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpEndpoint) -> Result<usize, ()> {
        let buffer = try!(self.send(data.len(), endpoint));
        let data = &data[..buffer.len()];
        buffer.copy_from_slice(data);
        Ok(data.len())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(())` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpEndpoint), ()> {
        let packet_buf = try!(self.rx_buffer.dequeue());
        net_trace!("[{}]{}:{}: receive {} buffered octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok((&packet_buf.as_ref()[..packet_buf.size], packet_buf.endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpEndpoint), ()> {
        let (buffer, endpoint) = try!(self.recv());
        data[..buffer.len()].copy_from_slice(buffer);
        Ok((buffer.len(), endpoint))
    }

    /// See [Socket::process](enum.Socket.html#method.process).
    pub fn process(&mut self, _timestamp: u64, ip_repr: &IpRepr,
                   payload: &[u8]) -> Result<(), Error> {
        if ip_repr.protocol() != IpProtocol::Udp { return Err(Error::Rejected) }

        let packet = try!(UdpPacket::new(&payload[..ip_repr.payload_len()]));
        let repr = try!(UdpRepr::parse(&packet, &ip_repr.src_addr(), &ip_repr.dst_addr()));

        if repr.dst_port != self.endpoint.port { return Err(Error::Rejected) }
        if !self.endpoint.addr.is_unspecified() {
            if self.endpoint.addr != ip_repr.dst_addr() { return Err(Error::Rejected) }
        }

        let packet_buf = try!(self.rx_buffer.enqueue().map_err(|()| Error::Exhausted));
        packet_buf.endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        packet_buf.size = repr.payload.len();
        packet_buf.as_mut()[..repr.payload.len()].copy_from_slice(repr.payload);
        net_trace!("[{}]{}:{}: receiving {} octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F, R>(&mut self, _timestamp: u64, _limits: &DeviceLimits,
                          emit: &mut F) -> Result<R, Error>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R, Error> {
        let packet_buf = try!(self.tx_buffer.dequeue().map_err(|()| Error::Exhausted));
        net_trace!("[{}]{}:{}: sending {} octets",
                   self.debug_id, self.endpoint,
                   packet_buf.endpoint, packet_buf.size);
        let repr = UdpRepr {
            src_port: self.endpoint.port,
            dst_port: packet_buf.endpoint.port,
            payload:  &packet_buf.as_ref()[..]
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr:    self.endpoint.addr,
            dst_addr:    packet_buf.endpoint.addr,
            protocol:    IpProtocol::Udp,
            payload_len: repr.buffer_len()
        };
        emit(&ip_repr, &repr)
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
        assert_eq!(buffer.enqueue().unwrap_err(), ());
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(),  true);
        assert_eq!(buffer.dequeue().unwrap().size, 3);
        assert_eq!(buffer.dequeue().unwrap().size, 4);
        assert_eq!(buffer.dequeue().unwrap().size, 5);
        assert_eq!(buffer.dequeue().unwrap().size, 6);
        assert_eq!(buffer.dequeue().unwrap().size, 7);
        assert_eq!(buffer.dequeue().unwrap_err(), ());
        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(),  false);
    }
}
