use core::fmt;

use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;
use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

/// A tracer device.
///
/// A tracer is a device that pretty prints all packets traversing it
/// using the provided writer function, and then passes them to another
/// device.
pub struct Tracer<D: Device> {
    inner: D,
    writer: fn(Instant, Packet),
}

impl<D: Device> Tracer<D> {
    /// Create a tracer device.
    pub fn new(inner: D, writer: fn(timestamp: Instant, packet: Packet)) -> Tracer<D> {
        Tracer { inner, writer }
    }

    /// Get a reference to the underlying device.
    ///
    /// Even if the device offers reading through a standard reference, it is inadvisable to
    /// directly read from the device as doing so will circumvent the tracing.
    pub fn get_ref(&self) -> &D {
        &self.inner
    }

    /// Get a mutable reference to the underlying device.
    ///
    /// It is inadvisable to directly read from the device as doing so will circumvent the tracing.
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: Device> Device for Tracer<D> {
    type RxToken<'a> = RxToken<D::RxToken<'a>>
    where
        Self: 'a;
    type TxToken<'a> = TxToken<D::TxToken<'a>>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let medium = self.inner.capabilities().medium;
        self.inner.receive(timestamp).map(|(rx_token, tx_token)| {
            let rx = RxToken {
                token: rx_token,
                writer: self.writer,
                medium,
                timestamp,
            };
            let tx = TxToken {
                token: tx_token,
                writer: self.writer,
                medium,
                timestamp,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let medium = self.inner.capabilities().medium;
        self.inner.transmit(timestamp).map(|tx_token| TxToken {
            token: tx_token,
            medium,
            writer: self.writer,
            timestamp,
        })
    }
}

#[doc(hidden)]
pub struct RxToken<Rx: phy::RxToken> {
    token: Rx,
    writer: fn(Instant, Packet),
    medium: Medium,
    timestamp: Instant,
}

impl<Rx: phy::RxToken> phy::RxToken for RxToken<Rx> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.token.consume(|buffer| {
            (self.writer)(
                self.timestamp,
                Packet {
                    buffer,
                    medium: self.medium,
                    prefix: "<- ",
                },
            );
            f(buffer)
        })
    }

    fn meta(&self) -> phy::PacketMeta {
        self.token.meta()
    }
}

#[doc(hidden)]
pub struct TxToken<Tx: phy::TxToken> {
    token: Tx,
    writer: fn(Instant, Packet),
    medium: Medium,
    timestamp: Instant,
}

impl<Tx: phy::TxToken> phy::TxToken for TxToken<Tx> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.token.consume(len, |buffer| {
            let result = f(buffer);
            (self.writer)(
                self.timestamp,
                Packet {
                    buffer,
                    medium: self.medium,
                    prefix: "-> ",
                },
            );
            result
        })
    }

    fn set_meta(&mut self, meta: phy::PacketMeta) {
        self.token.set_meta(meta)
    }
}

pub struct Packet<'a> {
    buffer: &'a [u8],
    medium: Medium,
    prefix: &'static str,
}

impl<'a> fmt::Display for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut indent = PrettyIndent::new(self.prefix);
        match self.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => crate::wire::EthernetFrame::<&'static [u8]>::pretty_print(
                &self.buffer,
                f,
                &mut indent,
            ),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => match crate::wire::IpVersion::of_packet(self.buffer) {
                #[cfg(feature = "proto-ipv4")]
                Ok(crate::wire::IpVersion::Ipv4) => {
                    crate::wire::Ipv4Packet::<&'static [u8]>::pretty_print(
                        &self.buffer,
                        f,
                        &mut indent,
                    )
                }
                #[cfg(feature = "proto-ipv6")]
                Ok(crate::wire::IpVersion::Ipv6) => {
                    crate::wire::Ipv6Packet::<&'static [u8]>::pretty_print(
                        &self.buffer,
                        f,
                        &mut indent,
                    )
                }
                _ => f.write_str("unrecognized IP version"),
            },
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => Ok(()), // XXX
        }
    }
}
