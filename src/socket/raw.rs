use managed::Managed;

use {Error, Result};
use phy::DeviceLimits;
use wire::{IpVersion, IpProtocol, Ipv4Repr, Ipv4Packet};
use socket::{IpRepr, IpPayload, Socket};
use storage::{Resettable, RingBuffer};

/// A buffered raw IP packet.
#[derive(Debug)]
pub struct PacketBuffer<'a> {
    size:    usize,
    payload: Managed<'a, [u8]>,
}

impl<'a> PacketBuffer<'a> {
    /// Create a buffered packet.
    pub fn new<T>(payload: T) -> PacketBuffer<'a>
            where T: Into<Managed<'a, [u8]>> {
        PacketBuffer {
            size:    0,
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

/// A raw IP socket.
///
/// A raw socket is bound to a specific IP protocol, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct RawSocket<'a, 'b: 'a> {
    debug_id:    usize,
    ip_version:  IpVersion,
    ip_protocol: IpProtocol,
    rx_buffer:   SocketBuffer<'a, 'b>,
    tx_buffer:   SocketBuffer<'a, 'b>,
}

impl<'a, 'b> RawSocket<'a, 'b> {
    /// Create a raw IP socket bound to the given IP version and datagram protocol,
    /// with the given buffers.
    pub fn new(ip_version: IpVersion, ip_protocol: IpProtocol,
               rx_buffer: SocketBuffer<'a, 'b>,
               tx_buffer: SocketBuffer<'a, 'b>) -> Socket<'a, 'b> {
        Socket::Raw(RawSocket {
            debug_id: 0,
            ip_version,
            ip_protocol,
            rx_buffer,
            tx_buffer,
        })
    }

    /// Return the debug identifier.
    #[inline]
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

    /// Return the IP version the socket is bound to.
    #[inline]
    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    /// Return the IP protocol the socket is bound to.
    #[inline]
    pub fn ip_protocol(&self) -> IpProtocol {
        self.ip_protocol
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.empty()
    }

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the size is greater than
    /// the transmit packet buffer size.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8]> {
        let packet_buf = self.tx_buffer.enqueue()?;
        packet_buf.size = size;
        net_trace!("[{}]:{}:{}: buffer to send {} octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);
        Ok(&mut packet_buf.as_mut()[..size])
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        let buffer = self.send(data.len())?;
        let data = &data[..buffer.len()];
        buffer.copy_from_slice(data);
        Ok(data.len())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<&[u8]> {
        let packet_buf = self.rx_buffer.dequeue()?;
        net_trace!("[{}]:{}:{}: receive {} buffered octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);
        Ok(&packet_buf.as_ref()[..packet_buf.size])
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.recv()?;
        data[..buffer.len()].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    pub(crate) fn process(&mut self, _timestamp: u64, ip_repr: &IpRepr,
                          payload: &[u8]) -> Result<()> {
        match self.ip_version {
            IpVersion::Ipv4 => {
                if ip_repr.protocol() != self.ip_protocol {
                    return Err(Error::Rejected);
                }
                let header_len = ip_repr.buffer_len();
                let packet_buf = self.rx_buffer.enqueue()?;
                packet_buf.size = header_len + payload.len();
                ip_repr.emit(&mut packet_buf.as_mut()[..header_len]);
                packet_buf.as_mut()[header_len..header_len + payload.len()]
                    .copy_from_slice(payload);
                net_trace!("[{}]:{}:{}: receiving {} octets",
                           self.debug_id, self.ip_version, self.ip_protocol,
                           packet_buf.size);
                Ok(())
            }
            IpVersion::__Nonexhaustive => unreachable!()
        }
    }

    /// See [Socket::dispatch](enum.Socket.html#method.dispatch).
    pub(crate) fn dispatch<F, R>(&mut self, _timestamp: u64, _limits: &DeviceLimits,
                                 emit: &mut F) -> Result<R>
            where F: FnMut(&IpRepr, &IpPayload) -> Result<R> {
        let mut packet_buf = self.tx_buffer.dequeue()?;
        net_trace!("[{}]:{}:{}: sending {} octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);

        match self.ip_version {
            IpVersion::Ipv4 => {
                let mut ipv4_packet = Ipv4Packet::new_checked(packet_buf.as_mut())?;
                ipv4_packet.fill_checksum();

                let ipv4_packet = Ipv4Packet::new(&*ipv4_packet.into_inner());
                let raw_repr = RawRepr(ipv4_packet.payload());
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet)?;
                emit(&IpRepr::Ipv4(ipv4_repr), &raw_repr)
            }
            IpVersion::__Nonexhaustive => unreachable!()
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
