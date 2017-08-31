#[cfg(feature = "std")]
use std::cell::RefCell;
#[cfg(feature = "std")]
use std::io::Write;
use byteorder::{ByteOrder, NativeEndian};

use Result;
use super::{DeviceLimits, Device};

enum_with_unknown! {
    /// Captured packet header type.
    pub doc enum PcapLinkType(u32) {
        /// Ethernet frames
        Ethernet =   1,
        /// IPv4 or IPv6 packets (depending on the version field)
        Ip       = 101
    }
}

/// Packet capture mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapMode {
    /// Capture both received and transmitted packets.
    Both,
    /// Capture only received packets.
    RxOnly,
    /// Capture only transmitted packets.
    TxOnly
}

/// A packet capture sink.
pub trait PcapSink {
    /// Write data into the sink.
    fn write(&self, data: &[u8]);

    /// Write an `u16` into the sink, in native byte order.
    fn write_u16(&self, value: u16) {
        let mut bytes = [0u8; 2];
        NativeEndian::write_u16(&mut bytes, value);
        self.write(&bytes[..])
    }

    /// Write an `u32` into the sink, in native byte order.
    fn write_u32(&self, value: u32) {
        let mut bytes = [0u8; 4];
        NativeEndian::write_u32(&mut bytes, value);
        self.write(&bytes[..])
    }

    /// Write the libpcap global header into the sink.
    ///
    /// This method may be overridden e.g. if special synchronization is necessary.
    fn global_header(&self, link_type: PcapLinkType) {
        self.write_u32(0xa1b2c3d4);       // magic number
        self.write_u16(2);                // major version
        self.write_u16(4);                // minor version
        self.write_u32(0);                // timezone (= UTC)
        self.write_u32(0);                // accuracy (not used)
        self.write_u32(65535);            // maximum packet length
        self.write_u32(link_type.into()); // link-layer header type
    }

    /// Write the libpcap packet header into the sink.
    ///
    /// See also the note for [global_header](#method.global_header).
    fn packet_header(&self, timestamp: u64, length: usize) {
        assert!(length <= 65535);

        let (seconds, micros) = (timestamp / 1000, timestamp % 1000 * 1000);
        self.write_u32(seconds as u32);   // timestamp seconds
        self.write_u32(micros  as u32);   // timestamp microseconds
        self.write_u32(length  as u32);   // captured length
        self.write_u32(length  as u32);   // original length
    }

    /// Write the libpcap packet header followed by packet data into the sink.
    ///
    /// See also the note for [global_header](#method.global_header).
    fn packet(&self, timestamp: u64, packet: &[u8]) {
        self.packet_header(timestamp, packet.len());
        self.write(packet)
    }
}

impl<T: AsRef<PcapSink>> PcapSink for T {
    fn write(&self, data: &[u8]) {
        self.as_ref().write(data)
    }
}

#[cfg(feature = "std")]
impl<T: AsMut<Write>> PcapSink for RefCell<T> {
    fn write(&self, data: &[u8]) {
        self.borrow_mut().as_mut().write_all(data).expect("cannot write")
    }

    fn packet(&self, timestamp: u64, packet: &[u8]) {
        self.packet_header(timestamp, packet.len());
        PcapSink::write(self, packet);
        self.borrow_mut().as_mut().flush().expect("cannot flush")
    }
}

/// A packet capture writer device.
///
/// Every packet transmitted or received through this device is timestamped
/// and written (in the [libpcap] format) using the provided [sink].
/// Note that writes are fine-grained, and buffering is recommended.
///
/// The packet sink should be cheaply cloneable, as it is cloned on every
/// transmitted packet. For example, `&'a mut Vec<u8>` is cheaply cloneable
/// but `&std::io::File`
///
/// [libpcap]: https://wiki.wireshark.org/Development/LibpcapFileFormat
/// [sink]: trait.PcapSink.html
#[derive(Debug)]
pub struct PcapWriter<D: Device, S: PcapSink + Clone> {
    lower: D,
    sink:  S,
    mode:  PcapMode
}

impl<D: Device, S: PcapSink + Clone> PcapWriter<D, S> {
    /// Creates a packet capture writer.
    pub fn new(lower: D, sink: S, mode: PcapMode, link_type: PcapLinkType) -> PcapWriter<D, S> {
        sink.global_header(link_type);
        PcapWriter { lower, sink, mode }
    }
}

impl<D: Device, S: PcapSink + Clone> Device for PcapWriter<D, S> {
    type RxBuffer = D::RxBuffer;
    type TxBuffer = TxBuffer<D::TxBuffer, S>;

    fn limits(&self) -> DeviceLimits { self.lower.limits() }

    fn receive(&mut self, timestamp: u64) -> Result<Self::RxBuffer> {
        let buffer = self.lower.receive(timestamp)?;
        match self.mode {
            PcapMode::Both | PcapMode::RxOnly =>
                self.sink.packet(timestamp, buffer.as_ref()),
            PcapMode::TxOnly => ()
        }
        Ok(buffer)
    }

    fn transmit(&mut self, timestamp: u64, length: usize) -> Result<Self::TxBuffer> {
        let buffer = self.lower.transmit(timestamp, length)?;
        Ok(TxBuffer { buffer, timestamp, sink: self.sink.clone(), mode: self.mode })
    }
}

#[doc(hidden)]
pub struct TxBuffer<B: AsRef<[u8]> + AsMut<[u8]>, S: PcapSink> {
    buffer:    B,
    timestamp: u64,
    sink:      S,
    mode:      PcapMode
}

impl<B, S> AsRef<[u8]> for TxBuffer<B, S>
        where B: AsRef<[u8]> + AsMut<[u8]>, S: PcapSink {
    fn as_ref(&self) -> &[u8] { self.buffer.as_ref() }
}

impl<B, S> AsMut<[u8]> for TxBuffer<B, S>
        where B: AsRef<[u8]> + AsMut<[u8]>, S: PcapSink {
    fn as_mut(&mut self) -> &mut [u8] { self.buffer.as_mut() }
}

impl<B, S> Drop for TxBuffer<B, S>
        where B: AsRef<[u8]> + AsMut<[u8]>, S: PcapSink {
    fn drop(&mut self) {
        match self.mode {
            PcapMode::Both | PcapMode::TxOnly =>
                self.sink.packet(self.timestamp, self.as_ref()),
            PcapMode::RxOnly => ()
        }
    }
}
