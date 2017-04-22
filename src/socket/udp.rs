use managed::Managed;

use Error;
use phy::DeviceLimits;
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
    pub fn enqueue(&mut self) -> Result<&mut PacketBuffer<'b>, ()> {
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
    pub fn dequeue(&mut self) -> Result<&PacketBuffer<'b>, ()> {
        if self.empty() {
            Err(())
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
#[derive(Debug)]
pub struct UdpSocket<'a, 'b: 'a> {
    local_endpoint: IpEndpoint,
    remote_endpoint: Option<IpEndpoint>,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    debug_id:  usize
}

impl<'a, 'b> UdpSocket<'a, 'b> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>,
               tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Udp(UdpSocket {
            local_endpoint: IpEndpoint::default(),
            remote_endpoint: None,
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
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    /// Bind the socket to the given endpoint.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) {
        self.local_endpoint = endpoint.into()
    }

    /// Check whether the transmit buffer is full.
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.full()
    }

    /// Check whether the receive buffer is not empty.
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.empty()
    }

    /// Check whether the socket is connected to a remote endpoint.
    pub fn is_connected(&self) -> bool {
        self.remote_endpoint.is_some()
    }

    /// Connects the socket to a remote endpoint, allowing to send (resp. receive) datagrams only to
    /// (resp. from) this endpoint. It is an error not to specify the remote IP address.
    pub fn connect<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<(), ()> {
        let endpoint = endpoint.into();
        if endpoint.addr.is_unspecified() {
            return Err(());
        }
        self.remote_endpoint = Some(endpoint);
        Ok(())
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(())` if the size is greater than what
    /// the transmit buffer can accomodate, or if an endpoint is specified while the socket is
    /// already connected to a remote endpoint.
    pub fn send(&mut self, size: usize, endpoint: Option<IpEndpoint>) -> Result<&mut [u8], ()> {
        let endpoint = match endpoint {
            Some(ep) => {
                if self.is_connected() {
                    return Err(());
                } else {
                    ep
                }
            },
            None => {
                if ! self.is_connected() {
                    return Err(());
                } else {
                    self.remote_endpoint.and_then(|ep| Some(ep.clone())).unwrap()
                }
            },
        };
        let packet_buf = try!(self.tx_buffer.enqueue());
        packet_buf.endpoint = endpoint;
        packet_buf.size = size;
        net_trace!("[{}]{}:{}: buffer to send {} octets",
                   self.debug_id, self.local_endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: Option<IpEndpoint>) -> Result<usize, ()> {
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
                   self.debug_id, self.local_endpoint,
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

        if repr.dst_port != self.local_endpoint.port { return Err(Error::Rejected) }
        if !self.local_endpoint.addr.is_unspecified() {
            if self.local_endpoint.addr != ip_repr.dst_addr() { return Err(Error::Rejected) }
        }

        // If a remote endpoint is specified, reject datagrams which source ip and source port
        // don't match the remote endpoint.
        if let Some(remote_endpoint) = self.remote_endpoint {
            // It's an error to have a remote endpoint with an unspecified address
            assert!(!remote_endpoint.is_unspecified());
            if remote_endpoint.addr != ip_repr.src_addr() || remote_endpoint.port != repr.src_port {
                return Err(Error::Rejected);
            }
        }

        let packet_buf = try!(self.rx_buffer.enqueue().map_err(|()| Error::Exhausted));
        packet_buf.endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        packet_buf.size = repr.payload.len();
        packet_buf.as_mut()[..repr.payload.len()].copy_from_slice(repr.payload);
        net_trace!("[{}]{}:{}: receiving {} octets",
                   self.debug_id, self.local_endpoint,
                   packet_buf.endpoint, packet_buf.size);
        Ok(())
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F, R>(&mut self, _timestamp: u64, _limits: &DeviceLimits,
                          emit: &mut F) -> Result<R, Error>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R, Error> {
        let packet_buf = try!(self.tx_buffer.dequeue().map_err(|()| Error::Exhausted));
        net_trace!("[{}]{}:{}: sending {} octets",
                   self.debug_id, self.local_endpoint,
                   packet_buf.endpoint, packet_buf.size);
        let repr = UdpRepr {
            src_port: self.local_endpoint.port,
            dst_port: packet_buf.endpoint.port,
            payload:  &packet_buf.as_ref()[..]
        };
        let ip_repr = IpRepr::Unspecified {
            src_addr:    self.local_endpoint.addr,
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
