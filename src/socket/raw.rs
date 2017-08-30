use core::cmp::min;
use managed::Managed;

use {Error, Result};
use wire::{IpVersion, IpProtocol, Ipv4Repr, Ipv4Packet};
use socket::{IpRepr, Socket};
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

    fn resize<'b>(&'b mut self, size: usize) -> Result<&'b mut Self> {
        if self.payload.len() >= size {
            self.size = size;
            Ok(self)
        } else {
            Err(Error::Truncated)
        }
    }
}

impl<'a> Resettable for PacketBuffer<'a> {
    fn reset(&mut self) {
        for i in 0..self.size {
            self.payload[i] = 0u8;
        }
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
    ///
    /// If the buffer is filled in a way that does not match the socket's
    /// IP version or protocol, the packet will be silently dropped.
    ///
    /// **Note:** The IP header is parsed and reserialized, and may not match
    /// the header actually transmitted bit for bit.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8]> {
        let packet_buf = self.tx_buffer.try_enqueue(|buf| buf.resize(size))?;
        net_trace!("[{}]:{}:{}: buffer to send {} octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);
        Ok(packet_buf.as_mut())
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<()> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    ///
    /// **Note:** The IP header is parsed and reserialized, and may not match
    /// the header actually received bit for bit.
    pub fn recv(&mut self) -> Result<&[u8]> {
        let packet_buf = self.rx_buffer.dequeue()?;
        net_trace!("[{}]:{}:{}: receive {} buffered octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);
        Ok(&packet_buf.as_ref())
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, payload: &[u8]) -> Result<()> {
        if ip_repr.version() != self.ip_version { return Err(Error::Rejected) }
        if ip_repr.protocol() != self.ip_protocol { return Err(Error::Rejected) }

        let header_len = ip_repr.buffer_len();
        let total_len = header_len + payload.len();
        let packet_buf = self.rx_buffer.try_enqueue(|buf| buf.resize(total_len))?;
        ip_repr.emit(&mut packet_buf.as_mut()[..header_len]);
        packet_buf.as_mut()[header_len..].copy_from_slice(payload);
        net_trace!("[{}]:{}:{}: receiving {} octets",
                   self.debug_id, self.ip_version, self.ip_protocol,
                   packet_buf.size);
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, emit: F) -> Result<()>
            where F: FnOnce((IpRepr, &[u8])) -> Result<()> {
        fn prepare(protocol: IpProtocol, buffer: &mut [u8]) -> Result<(IpRepr, &[u8])> {
            match IpVersion::of_packet(buffer.as_ref())? {
                IpVersion::Ipv4 => {
                    let mut packet = Ipv4Packet::new_checked(buffer.as_mut())?;
                    if packet.protocol() != protocol { return Err(Error::Unaddressable) }
                    packet.fill_checksum();

                    let packet = Ipv4Packet::new(&*packet.into_inner());
                    let ipv4_repr = Ipv4Repr::parse(&packet)?;
                    Ok((IpRepr::Ipv4(ipv4_repr), packet.payload()))
                }
                IpVersion::Unspecified => unreachable!(),
                IpVersion::__Nonexhaustive => unreachable!()
            }
        }

        let debug_id    = self.debug_id;
        let ip_protocol = self.ip_protocol;
        let ip_version  = self.ip_version;
        self.tx_buffer.try_dequeue(|packet_buf| {
            match prepare(ip_protocol, packet_buf.as_mut()) {
                Ok((ip_repr, raw_packet)) => {
                    net_trace!("[{}]:{}:{}: sending {} octets",
                               debug_id, ip_version, ip_protocol,
                               ip_repr.buffer_len() + raw_packet.len());
                    emit((ip_repr, raw_packet))
                }
                Err(error) => {
                    net_debug!("[{}]:{}:{}: dropping outgoing packet ({})",
                               debug_id, ip_version, ip_protocol,
                               error);
                    // Return Ok(()) so the packet is dequeued.
                    Ok(())
                }
            }
        })
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        if self.tx_buffer.empty() {
            None
        } else {
            Some(0)
        }
    }
}

#[cfg(test)]
mod test {
    use wire::{Ipv4Address, IpRepr, Ipv4Repr};
    use super::*;

    fn buffer(packets: usize) -> SocketBuffer<'static, 'static> {
        let mut storage = vec![];
        for _ in 0..packets {
            storage.push(PacketBuffer::new(vec![0; 24]))
        }
        SocketBuffer::new(storage)
    }

    fn socket(rx_buffer: SocketBuffer<'static, 'static>,
              tx_buffer: SocketBuffer<'static, 'static>)
            -> RawSocket<'static, 'static> {
        match RawSocket::new(IpVersion::Ipv4, IpProtocol::Unknown(63),
                             rx_buffer, tx_buffer) {
            Socket::Raw(socket) => socket,
            _ => unreachable!()
        }
    }

    const HEADER_REPR: IpRepr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address([10, 0, 0, 1]),
        dst_addr: Ipv4Address([10, 0, 0, 2]),
        protocol: IpProtocol::Unknown(63),
        payload_len: 4
    });
    const PACKET_BYTES: [u8; 24] = [
        0x45, 0x00, 0x00, 0x18,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x3f, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        0xaa, 0x00, 0x00, 0xff
    ];
    const PACKET_PAYLOAD: [u8; 4] = [
        0xaa, 0x00, 0x00, 0xff
    ];

    #[test]
    fn test_send_truncated() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(&[0; 32][..]), Err(Error::Truncated));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));

        assert!(socket.can_send());
        assert_eq!(socket.dispatch(|_| unreachable!()),
                   Err(Error::Exhausted));

        assert_eq!(socket.send_slice(&PACKET_BYTES[..]), Ok(()));
        assert_eq!(socket.send_slice(b""), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, ip_payload)| {
            assert_eq!(ip_repr, HEADER_REPR);
            assert_eq!(ip_payload, &PACKET_PAYLOAD);
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, ip_payload)| {
            assert_eq!(ip_repr, HEADER_REPR);
            assert_eq!(ip_payload, &PACKET_PAYLOAD);
            Ok(())
        }), Ok(()));
        assert!(socket.can_send());
    }

    #[test]
    fn test_send_illegal() {
        let mut socket = socket(buffer(0), buffer(1));

        let mut wrong_version = PACKET_BYTES.clone();
        Ipv4Packet::new(&mut wrong_version).set_version(5);

        assert_eq!(socket.send_slice(&wrong_version[..]), Ok(()));
        assert_eq!(socket.dispatch(|_| unreachable!()),
                   Ok(()));

        let mut wrong_protocol = PACKET_BYTES.clone();
        Ipv4Packet::new(&mut wrong_protocol).set_protocol(IpProtocol::Tcp);

        assert_eq!(socket.send_slice(&wrong_protocol[..]), Ok(()));
        assert_eq!(socket.dispatch(|_| unreachable!()),
                   Ok(()));
    }

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(0));
        assert!(!socket.can_recv());

        let mut cksumd_packet = PACKET_BYTES.clone();
        Ipv4Packet::new(&mut cksumd_packet).fill_checksum();

        assert_eq!(socket.recv(), Err(Error::Exhausted));
        assert_eq!(socket.process(&HEADER_REPR, &PACKET_PAYLOAD),
                   Ok(()));
        assert!(socket.can_recv());

        assert_eq!(socket.process(&HEADER_REPR, &PACKET_PAYLOAD),
                   Err(Error::Exhausted));
        assert_eq!(socket.recv(), Ok(&cksumd_packet[..]));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_recv_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.process(&HEADER_REPR, &PACKET_PAYLOAD),
                   Ok(()));

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok(4));
        assert_eq!(&slice, &PACKET_BYTES[..slice.len()]);
    }

    #[test]
    fn test_recv_truncated_packet() {
        let mut socket = socket(buffer(1), buffer(0));

        let mut buffer = vec![0; 128];
        buffer[..PACKET_BYTES.len()].copy_from_slice(&PACKET_BYTES[..]);

        assert_eq!(socket.process(&HEADER_REPR, &buffer),
                   Err(Error::Truncated));
    }
}
