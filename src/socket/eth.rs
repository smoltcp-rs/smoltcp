use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::phy::PacketMeta;
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;

use crate::storage::Empty;

use crate::wire::EthernetFrame;
use crate::wire::EthernetRepr;

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

impl From<crate::storage::Full> for SendError {
    fn from(_: crate::storage::Full) -> Self {
        Self::BufferFull
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl From<crate::storage::Empty> for RecvError {
    fn from(_: crate::storage::Empty) -> Self {
        Self::Exhausted
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// Metadata for a sent or received ETH packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EthMetadata {
    pub meta: PacketMeta,
}

impl core::fmt::Display for EthMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "packetmeta-id")]
        return write!(f, "PacketID: {:?}", self.meta);

        #[cfg(not(feature = "packetmeta-id"))]
        write!(f, "()")
    }
}

/// A Eth packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<EthMetadata>;

/// A Eth packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, EthMetadata>;

pub type Ethertype = u16;

/// A raw Ethernet socket.
///
/// A eth socket may be bound to a specific ethertype, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    ethertype: Option<Ethertype>,
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> Socket<'a> {
    /// Create a raw ETH socket bound to the given ethertype, with the given buffers.
    pub fn new(
        ethertype: Option<Ethertype>,
        rx_buffer: PacketBuffer<'a>,
        tx_buffer: PacketBuffer<'a>,
    ) -> Socket<'a> {
        Socket {
            ethertype,
            rx_buffer,
            tx_buffer,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the ethertype the socket is bound to.
    #[inline]
    pub fn ethertype(&self) -> Option<Ethertype> {
        self.ethertype
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    ///
    /// If the buffer is filled in a way that does not match the socket's
    /// ethertype, the packet will be silently dropped.
    pub fn send(
        &mut self,
        size: usize,
        meta: impl Into<EthMetadata>,
    ) -> Result<&mut [u8], SendError> {
        let meta = meta.into();
        let packet_buf = self
            .tx_buffer
            .enqueue(size, meta)?;

        net_trace!(
            "eth:{}: buffer to send {} octets",
            self.ethertype.unwrap_or(0),
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// Enqueue a packet to be send and pass the buffer to the provided closure.
    /// The closure then returns the size of the data written into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(
        &mut self,
        max_size: usize,
        meta: impl Into<EthMetadata>,
        f: F,
    ) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let meta = meta.into();
        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, meta, f)?;

        net_trace!(
            "eth:{}: buffer to send {} octets",
            self.ethertype.unwrap_or(0),
            size
        );

        Ok(size)
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(
        &mut self,
        data: &[u8],
        meta: impl Into<EthMetadata>,
    ) -> Result<(), SendError> {
        self.send(data.len(), meta)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], EthMetadata), RecvError> {
        let (meta, packet_buf) = self.rx_buffer.dequeue()?;

        net_trace!(
            "eth:{}: receive {} buffered octets",
            self.ethertype.unwrap_or(0),
            packet_buf.len()
        );
        Ok((packet_buf, meta))
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, EthMetadata), RecvError> {
        let (buffer, meta) = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, meta))
    }

    /// Peek at a packet in the receive buffer and return a pointer to the
    /// payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<(&[u8], &EthMetadata), RecvError> {
        let (meta, packet_buf) = self.rx_buffer.peek()?;

        net_trace!(
            "eth:{}: receive {} buffered octets",
            self.ethertype.unwrap_or(0),
            packet_buf.len()
        );

        Ok((packet_buf, meta))
    }

    /// Peek at a packet in the receive buffer, copy the payload into the given slice,
    /// and return the amount of octets copied without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, &EthMetadata), RecvError> {
        let (buffer, meta) = self.peek()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, meta))
    }

    /// Return the amount of octets queued in the transmit buffer.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// Return the amount of octets queued in the receive buffer.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    pub(crate) fn accepts(&self, eth_repr: &EthernetRepr) -> bool {
        match self.ethertype {
            Some(e) if e == eth_repr.ethertype.into() => true,
            Some(_) => false,
            None => true,
        }
    }

    pub(crate) fn process(
        &mut self,
        _cx: &mut Context,
        meta: PacketMeta,
        eth_repr: &EthernetRepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(eth_repr));

        let header_len = eth_repr.buffer_len();
        let total_len = header_len + payload.len();

        net_trace!(
            "eth:{}: receiving {} octets",
            self.ethertype.unwrap_or(0),
            total_len
        );

        let metadata = EthMetadata { meta };

        match self.rx_buffer.enqueue(total_len, metadata) {
            Ok(buf) => {
                let mut frame = EthernetFrame::new_checked(buf).expect("internal ethernet error");
                eth_repr.emit(&mut frame);
                frame.payload_mut().copy_from_slice(payload);
            }
            Err(_) => net_trace!(
                "eth:{}: buffer full, dropped incoming packet",
                self.ethertype.unwrap_or(0)
            ),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (EthernetRepr, &[u8])) -> Result<(), E>,
    {
        let ethertype = self.ethertype;
        let res = self.tx_buffer.dequeue_with(|meta, buffer| {
            #[allow(clippy::useless_asref)]
            let frame = match EthernetFrame::new_checked(buffer.as_ref()) {
                Ok(x) => x,
                Err(_) => {
                    net_trace!("eth: malformed ethernet frame in queue, dropping.");
                    return Ok(());
                }
            };
            let eth_repr = match EthernetRepr::parse(&frame) {
                Ok(r) => r,
                Err(_) => {
                    net_trace!("eth: malformed ethernet frame in queue, dropping.");
                    return Ok(());
                }
            };
            net_trace!("eth:{}: sending", ethertype.unwrap_or(0));
            emit(cx, meta.meta, (eth_repr, frame.payload()))
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => {
                #[cfg(feature = "async")]
                self.tx_waker.wake();
                Ok(())
            }
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::phy::Medium;
    use crate::tests::setup;
    use crate::time::Instant;
    use crate::wire::ethernet::EtherType;
    use crate::wire::{EthernetAddress, HardwareAddress};

    fn buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; packets], vec![0; 48 * packets])
    }

    const ETHER_TYPE: u16 = 0x1234;

    fn socket(
        rx_buffer: PacketBuffer<'static>,
        tx_buffer: PacketBuffer<'static>,
    ) -> Socket<'static> {
        Socket::new(Some(ETHER_TYPE), rx_buffer, tx_buffer)
    }

    #[rustfmt::skip]
    pub const PACKET_BYTES: [u8; 18] = [
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0xaa, 0xbb, 0xcc, 0x78, 0x90, 0x12,
        0x12, 0x34,
        0xaa, 0x00, 0x00, 0xff,
    ];
    pub const PACKET_RECEIVER: [u8; 6] = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
    pub const PACKET_SENDER: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x78, 0x90, 0x12];
    pub const PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_send() {
        let (mut iface, _, _) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(1), buffer(1));
        let dummymeta = EthMetadata {
            meta: PacketMeta {
                #[cfg(feature = "packetmeta-id")]
                id: 42,
            },
        };
        assert!(socket.can_send());
        assert_eq!(socket.send_slice(&PACKET_BYTES[..], dummymeta), Ok(()));
        assert_eq!(
            socket.send_slice(b"", dummymeta),
            Err(SendError::BufferFull)
        );
        assert!(!socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, _, (eth_repr, eth_payload)| {
                assert_eq!(eth_repr.ethertype, EtherType::from(ETHER_TYPE));
                assert_eq!(eth_payload, PACKET_PAYLOAD);
                Err(())
            }),
            Err(())
        );
        assert!(!socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, _, (eth_repr, eth_payload)| {
                assert_eq!(eth_repr.ethertype, EtherType::from(ETHER_TYPE));
                assert_eq!(eth_payload, PACKET_PAYLOAD);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert!(socket.can_send());
    }

    #[test]
    fn test_recv() {
        let (mut iface, _, _) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(1), buffer(1));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(RecvError::Exhausted));
        assert_eq!(socket.peek(), Err(RecvError::Exhausted));

        let pktmeta = PacketMeta {
            #[cfg(feature = "packetmeta-id")]
            id: 43,
        };

        let ethmeta = EthMetadata { meta: pktmeta };

        let frameinfo = EthernetRepr {
            src_addr: EthernetAddress::from_bytes(&PACKET_SENDER),
            dst_addr: EthernetAddress::from_bytes(&PACKET_RECEIVER),
            ethertype: ETHER_TYPE.into(),
        };

        assert!(socket.accepts(&frameinfo));
        socket.process(cx, pktmeta, &frameinfo, &PACKET_PAYLOAD);
        assert!(socket.can_recv());

        assert!(socket.accepts(&frameinfo));
        socket.process(cx, pktmeta, &frameinfo, &PACKET_PAYLOAD);

        assert_eq!(socket.peek(), Ok((&PACKET_BYTES[..], &ethmeta)));
        assert_eq!(socket.peek(), Ok((&PACKET_BYTES[..], &ethmeta)));
        assert_eq!(socket.recv(), Ok((&PACKET_BYTES[..], ethmeta)));
        assert!(!socket.can_recv());
        assert_eq!(socket.peek(), Err(RecvError::Exhausted));
    }

    #[test]
    fn test_loopback() {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
        let eth_socket = socket(buffer(3), buffer(3));
        let socket_handle = sockets.add(eth_socket);
        let now = Instant::ZERO;

        let ethmeta = EthMetadata {
            meta: PacketMeta {
                #[cfg(feature = "packetmeta-id")]
                id: 42,
            },
        };

        // send our test frame
        assert_eq!(iface.hardware_addr(), HardwareAddress::Ethernet(EthernetAddress::from_bytes(&PACKET_RECEIVER)));
        let socket = sockets.get_mut::<Socket>(socket_handle);
        assert!(socket.can_send());
        assert_eq!(socket.send_slice(&PACKET_BYTES[..], ethmeta), Ok(()));

        // run poll_egress()
        iface.poll(now, &mut device, &mut sockets);
        assert!(!sockets.get_mut::<Socket>(socket_handle).can_recv());

        loop {
            // some automatically triggered features like
            // mldv2_report_packet require some back and forth first.
            iface.poll(now, &mut device, &mut sockets);
            if device.tx_queue.is_empty() {
                break;
            }
            // do loopback manually
            device.rx_queue.push_back( device.tx_queue.pop_front().unwrap() );
        }

        // run socket_ingress()
        iface.poll(now, &mut device, &mut sockets);

        // receive our test frame
        let socket = sockets.get_mut::<Socket>(socket_handle);
        assert!(socket.can_recv());
        let received = socket.recv();
        assert!(received.is_ok());
        assert_eq!(received.unwrap().0, &PACKET_BYTES[..]);
    }
}
