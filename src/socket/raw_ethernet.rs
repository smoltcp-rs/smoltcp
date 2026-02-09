use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;

use crate::storage::Empty;
use crate::wire::{EthernetFrame, EthernetProtocol};

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

/// An Ethernet packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<()>;

/// An Ethernet packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, ()>;

/// A raw Ethernet socket.
///
/// A raw Ethernet socket can be optionally filtered by EtherType,
/// and owns transmit and receive packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    ethertype: Option<EthernetProtocol>,
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> Socket<'a> {
    /// Create a raw Ethernet socket bound to the given EtherType, with the given buffers.
    pub fn new(
        ethertype: Option<EthernetProtocol>,
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
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the EtherType the socket is bound to.
    #[inline]
    pub fn ethertype(&self) -> Option<EthernetProtocol> {
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

    /// Enqueue a frame to send, and return a pointer to its bytes.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], SendError> {
        let frame_buf = self
            .tx_buffer
            .enqueue(size, ())
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw-eth:{:?}: buffer to send {} octets",
            self.ethertype,
            frame_buf.len()
        );
        Ok(frame_buf)
    }

    /// Enqueue a frame to be sent and pass the buffer to the provided closure.
    pub fn send_with<F>(&mut self, max_size: usize, f: F) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, (), f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw-eth:{:?}: buffer to send {} octets",
            self.ethertype,
            size
        );

        Ok(size)
    }

    /// Enqueue a frame to send, and fill it from a slice.
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a frame and return a pointer to its bytes.
    pub fn recv(&mut self) -> Result<&[u8], RecvError> {
        let ((), frame_buf) = self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw-eth:{:?}: receive {} buffered octets",
            self.ethertype,
            frame_buf.len()
        );
        Ok(frame_buf)
    }

    /// Dequeue a frame and copy the frame bytes into the given slice.
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// Peek at a frame in the receive buffer without removing it.
    pub fn peek(&mut self) -> Result<&[u8], RecvError> {
        let ((), frame_buf) = self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw-eth:{:?}: receive {} buffered octets",
            self.ethertype,
            frame_buf.len()
        );

        Ok(frame_buf)
    }

    /// Peek at a frame in the receive buffer and copy it into the given slice.
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

    pub(crate) fn accepts(&self, frame: &EthernetFrame<&[u8]>) -> bool {
        if self
            .ethertype
            .is_some_and(|ethertype| ethertype != frame.ethertype())
        {
            return false;
        }

        true
    }

    pub(crate) fn process(&mut self, _cx: &mut Context, frame: &[u8]) {
        net_trace!(
            "raw-eth:{:?}: receiving {} octets",
            self.ethertype,
            frame.len()
        );

        match self.rx_buffer.enqueue(frame.len(), ()) {
            Ok(buf) => buf.copy_from_slice(frame),
            Err(_) => net_trace!(
                "raw-eth:{:?}: buffer full, dropped incoming frame",
                self.ethertype
            ),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    pub(crate) fn dispatch<F, E>(&mut self, _cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, &[u8]) -> Result<(), E>,
    {
        let ethertype = self.ethertype;
        let res = self.tx_buffer.dequeue_with(|&mut (), buffer| {
            let frame = match EthernetFrame::new_checked(&*buffer) {
                Ok(x) => x,
                Err(_) => {
                    net_trace!("raw-eth: malformed frame in queue, dropping.");
                    return Ok(());
                }
            };

            if ethertype.is_some_and(|bound| bound != frame.ethertype()) {
                net_trace!("raw-eth: sent frame with wrong ethertype, dropping.");
                return Ok(());
            }

            net_trace!("raw-eth:{:?}: sending", ethertype);
            emit(_cx, buffer)
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
    use crate::phy::Medium;
    use crate::tests::setup;
    use rstest::*;

    use super::*;
    use crate::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr};

    fn buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; packets], vec![0; 64 * packets])
    }

    fn frame_bytes(ethertype: EthernetProtocol) -> [u8; 18] {
        let mut bytes = [0u8; 18];
        let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
        EthernetRepr {
            src_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            dst_addr: EthernetAddress::BROADCAST,
            ethertype,
        }
        .emit(&mut frame);
        frame
            .payload_mut()
            .copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        bytes
    }

    #[rstest]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn test_send_dispatch(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();
        let mut socket = Socket::new(Some(EthernetProtocol::Ipv4), buffer(0), buffer(1));

        let tx = frame_bytes(EthernetProtocol::Ipv4);
        assert_eq!(socket.send_slice(&tx), Ok(()));

        assert_eq!(
            socket.dispatch(cx, |_, data| {
                assert_eq!(data, &tx);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
    }

    #[rstest]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn test_send_wrong_ethertype_dropped(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();
        let mut socket = Socket::new(Some(EthernetProtocol::Ipv6), buffer(0), buffer(1));

        let tx = frame_bytes(EthernetProtocol::Ipv4);
        assert_eq!(socket.send_slice(&tx), Ok(()));

        assert_eq!(socket.dispatch(cx, |_, _| unreachable!()), Ok::<_, ()>(()));
    }

    #[rstest]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    fn test_recv_process(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();
        let mut socket = Socket::new(Some(EthernetProtocol::Ipv4), buffer(1), buffer(0));

        let rx = frame_bytes(EthernetProtocol::Ipv4);
        let frame = EthernetFrame::new_checked(&rx[..]).unwrap();

        assert!(socket.accepts(&frame));
        socket.process(cx, &rx);

        assert_eq!(socket.recv(), Ok(&rx[..]));
    }

    #[test]
    fn test_accepts_filter() {
        let socket = Socket::new(Some(EthernetProtocol::Arp), buffer(1), buffer(1));
        let ipv4 = frame_bytes(EthernetProtocol::Ipv4);
        let arp = frame_bytes(EthernetProtocol::Arp);

        let ipv4_frame = EthernetFrame::new_checked(&ipv4[..]).unwrap();
        let arp_frame = EthernetFrame::new_checked(&arp[..]).unwrap();

        assert!(!socket.accepts(&ipv4_frame));
        assert!(socket.accepts(&arp_frame));
    }
}
