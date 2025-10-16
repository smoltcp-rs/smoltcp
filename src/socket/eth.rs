use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
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

#[cfg(feature = "std")]
impl std::error::Error for RecvError {}

/// A Eth packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<()>;

/// A Eth packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, ()>;

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
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], SendError> {
        let packet_buf = self
            .tx_buffer
            .enqueue(size, ())
            .map_err(|_| SendError::BufferFull)?;

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
    pub fn send_with<F>(&mut self, max_size: usize, f: F) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, (), f)
            .map_err(|_| SendError::BufferFull)?;

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
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "eth:{}: receive {} buffered octets",
            self.ethertype.unwrap_or(0),
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// Peek at a packet in the receive buffer and return a pointer to the
    /// payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "eth:{}: receive {} buffered octets",
            self.ethertype.unwrap_or(0),
            packet_buf.len()
        );

        Ok(packet_buf)
    }

    /// Peek at a packet in the receive buffer, copy the payload into the given slice,
    /// and return the amount of octets copied without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.peek()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
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

    pub(crate) fn process(&mut self, _cx: &mut Context, eth_repr: &EthernetRepr, payload: &[u8]) {
        debug_assert!(self.accepts(eth_repr));

        let header_len = eth_repr.buffer_len();
        let total_len = header_len + payload.len();

        net_trace!(
            "eth:{}: receiving {} octets",
            self.ethertype.unwrap_or(0),
            total_len
        );

        match self.rx_buffer.enqueue(total_len, ()) {
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
        F: FnOnce(&mut Context, (EthernetRepr, &[u8])) -> Result<(), E>,
    {
        let ethertype = self.ethertype;
        let res = self.tx_buffer.dequeue_with(|&mut (), buffer| {
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
            emit(cx, (eth_repr, frame.payload()))
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
    use crate::wire::ethernet::EtherType;

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
        0xaa, 0xbb, 0xcc, 0x12, 0x34, 0x56,
        0xaa, 0xbb, 0xcc, 0x78, 0x90, 0x12,
        0x12, 0x34,
        0xaa, 0x00, 0x00, 0xff,
    ];
    pub const PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_send() {
        let (mut iface, _, _) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(1), buffer(1));
        assert!(socket.can_send());
        assert_eq!(socket.send_slice(&PACKET_BYTES[..]), Ok(()));
        assert_eq!(socket.send_slice(b""), Err(SendError::BufferFull));
        assert!(!socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, (eth_repr, eth_payload)| {
                assert_eq!(eth_repr.ethertype, EtherType::from(ETHER_TYPE));
                assert_eq!(eth_payload, PACKET_PAYLOAD);
                Err(())
            }),
            Err(())
        );
        assert!(!socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, (eth_repr, eth_payload)| {
                assert_eq!(eth_repr.ethertype, EtherType::from(ETHER_TYPE));
                assert_eq!(eth_payload, PACKET_PAYLOAD);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert!(socket.can_send());
    }
}
