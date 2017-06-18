use managed::Managed;

use Error;
use phy::DeviceLimits;
use wire::{IpProtocol, Ipv4Repr, Ipv4Packet};
use socket::{IpRepr, IpPayload, Socket};
use storage::ring_buffer::RingBuffer;
use storage::Resettable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    Ipv4,
    #[doc(hidden)]
    __Nonexhaustive,
}

/// A buffered raw IP packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    size: usize,
    payload: Managed<'a, [u8]>,
}

impl<'a> PacketBuffer<'a> {
    /// Create new buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
        where T: Into<Managed<'a, [u8]>>,
    {
        PacketBuffer {
            size: 0,
            payload: payload.into(),
        }
    }

    fn as_ref<'b>(&'b self) -> &'b [u8] {
        &self.payload[..self.size]
    }

    fn as_mut<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.payload[..self.size]
    }
}

impl<'a> Resettable for PacketBuffer<'a> {
    fn reset(&mut self) {
        self.size = 0;
    }
}

/// A raw IP packet ring buffer.
pub type SocketBuffer<'a, 'b: 'a> = RingBuffer<'a, PacketBuffer<'b>>;

/// A Raw IP socket
///
/// A raw socket is bound to a specifict IP protocol and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct RawSocket<'a, 'b: 'a> {
    payload_type: PayloadType,
    ip_protocol: IpProtocol,
    rx_buffer: SocketBuffer<'a, 'b>,
    tx_buffer: SocketBuffer<'a, 'b>,
    debug_id: usize,
}

impl<'a, 'b> RawSocket<'a, 'b> {
    /// Create a Raw IP socket with the given buffers, bound to the given IP protocol
    /// with the given IP address to be used as the default source address.
    pub fn new(rx_buffer: SocketBuffer<'a, 'b>, tx_buffer: SocketBuffer<'a, 'b>,
               ip_protocol: IpProtocol, payload_type: PayloadType) -> Socket<'a, 'b> {
        Socket::Raw(RawSocket {
            rx_buffer,
            tx_buffer,
            debug_id: 0,
            ip_protocol,
            payload_type,
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
        self.debug_id = id;
    }

    /// Return the IP protocol the socket is bound to.
    pub fn ip_protocol(&self) -> IpProtocol {
        self.ip_protocol
    }

    /// Check whether the transmit buffer is full.
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.full()
    }

    /// Check whether the receive buffer is not empty.
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.empty()
    }

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(())` if the size is greater than what
    /// the transmit buffer can accomodate.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], ()> {
        let packet_buf = self.tx_buffer.enqueue()?;
        packet_buf.size = size;
        net_trace!("[{}] proto {} buffer to send {} octets",
                   self.debug_id, self.ip_protocol, packet_buf.size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize, ()> {
        let buffer = self.send(data.len())?;
        let data = &data[..buffer.len()];
        buffer.copy_from_slice(data);
        Ok(data.len())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(())` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<&[u8], ()> {
        let packet_buf = self.rx_buffer.dequeue()?;
        net_trace!("[{}] proto {} receive {} buffered octets",
                   self.debug_id, self.ip_protocol, packet_buf.size);
        Ok(&packet_buf.as_ref()[..packet_buf.size])
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, ()> {
        let buffer = self.recv()?;
        data[..buffer.len()].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    /// See [Socket::process](enum.Socket.html#method.process).
    pub fn process(&mut self, _timestamp: u64, ip_repr: &IpRepr,
                   payload: &[u8]) -> Result<(), Error> {
        match self.payload_type {
            PayloadType::Ipv4 => {
                if ip_repr.protocol() != self.ip_protocol {
                    return Err(Error::Rejected);
                }
                let header_len = ip_repr.buffer_len();
                let packet_buf = self.rx_buffer.enqueue().map_err(|()| Error::Exhausted)?;
                packet_buf.size = header_len + payload.len();
                ip_repr.emit(&mut packet_buf.as_mut()[..header_len]);
                packet_buf.as_mut()[header_len..header_len + payload.len()]
                    .copy_from_slice(payload);
                net_trace!("[{}] proto {} receiving {} octets",
                           self.debug_id, self.ip_protocol, packet_buf.size);
                Ok(())
            }
            _ => Err(Error::Rejected),
        }
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub fn dispatch<F, R>(&mut self, _timestamp: u64, _limits: &DeviceLimits,
                          emit: &mut F) -> Result<R, Error>
        where F: FnMut(&IpRepr, &IpPayload) -> Result<R, Error>,
    {
        let mut packet_buf = self.tx_buffer.dequeue_mut().map_err(|()| Error::Exhausted)?;
        net_trace!("[{}] proto {} sending {} octets",
                   self.debug_id, self.ip_protocol, packet_buf.size);
        match self.payload_type {
            PayloadType::Ipv4 => {
                let mut ipv4_packet = Ipv4Packet::new(packet_buf.as_mut())?;
                ipv4_packet.fill_checksum();
                let ipv4_packet = Ipv4Packet::new(&*ipv4_packet.into_inner())?;
                let raw_repr = RawRepr(ipv4_packet.payload());
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet)?;
                emit(&IpRepr::Ipv4(ipv4_repr), &raw_repr)
            }
            _ => Err(Error::Unrecognized),
        }
    }
}

struct RawRepr<'a>(&'a [u8]);

impl<'a> IpPayload for RawRepr<'a> {
    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn emit(&self, _repr: &IpRepr, payload: &mut [u8]) {
        payload.copy_from_slice(self.0);
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
        assert_eq!(buffer.full(), false);
        buffer.enqueue().unwrap().size = 1;
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(), false);
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
        assert_eq!(buffer.full(), true);
        assert_eq!(buffer.dequeue().unwrap().size, 3);
        assert_eq!(buffer.dequeue().unwrap().size, 4);
        assert_eq!(buffer.dequeue().unwrap().size, 5);
        assert_eq!(buffer.dequeue().unwrap().size, 6);
        assert_eq!(buffer.dequeue().unwrap().size, 7);
        assert_eq!(buffer.dequeue().unwrap_err(), ());
        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(), false);
    }
}
