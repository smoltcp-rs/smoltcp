use log::trace;
use socket::{SocketHandle, SocketSet, UdpSocket, UdpSocketBuffer};
use time::{Duration, Instant};
use wire::{
    IpAddress, IpEndpoint, SntpLeapIndicator, SntpPacket, SntpProtocolMode, SntpRepr, SntpStratum,
    SntpTimestamp,
};
use {Error, Result};

/// Default to one hour interval between requests.
const REQUEST_INTERVAL: u64 = 60 * 60;

/// Number of seconds between 1970 and Feb 7, 2036 06:28:16 UTC (epoch 1)
const DIFF_SEC_1970_2036: u32 = 2085978496;

/// IANA port for SNTP servers.
const SNTP_PORT: u16 = 123;

/// SNTPv4 client.
///
/// You must call `Client::poll()` after `Interface::poll()` to send
/// and receive SNTP packets.
pub struct Client {
    udp_handle: SocketHandle,
    ntp_server: IpAddress,
    /// When to send next request
    next_request: Instant,
}

impl Client {
    /// Create a new SNTPv4 client performing requests to the specified server.
    ///
    /// # Usage
    ///
    /// ```rust
    /// use smoltcp::socket::{SocketSet, UdpSocketBuffer, UdpPacketMetadata};
    /// use smoltcp::apps::sntp::Client;
    /// use smoltcp::time::Instant;
    /// use smoltcp::wire::IpAddress;
    ///
    /// let mut sockets = SocketSet::new(vec![]);
    /// let sntp_rx_buffer = UdpSocketBuffer::new(
    ///     [UdpPacketMetadata::EMPTY; 1],
    ///     vec![0; 128]
    /// );
    /// let sntp_tx_buffer = UdpSocketBuffer::new(
    ///     [UdpPacketMetadata::EMPTY; 1],
    ///     vec![0; 128]
    /// );
    /// let mut sntp = Client::new(
    ///     &mut sockets,
    ///     sntp_rx_buffer, sntp_tx_buffer,
    ///     IpAddress::v4(62, 112, 134, 4),
    ///     Instant::now()
    /// );
    /// ```
    pub fn new<'a, 'b, 'c>(
        sockets: &mut SocketSet<'a, 'b, 'c>,
        rx_buffer: UdpSocketBuffer<'b, 'c>,
        tx_buffer: UdpSocketBuffer<'b, 'c>,
        ntp_server: IpAddress,
        now: Instant,
    ) -> Self
    where
        'b: 'c,
    {
        let socket = UdpSocket::new(rx_buffer, tx_buffer);
        let udp_handle = sockets.add(socket);

        trace!("SNTP initialised");

        Client {
            udp_handle,
            ntp_server,
            next_request: now,
        }
    }

    /// Returns the duration until the next packet request.
    ///
    /// Useful for suspending execution after polling.
    pub fn next_poll(&self, now: Instant) -> Duration {
        self.next_request - now
    }

    /// Processes incoming packets, and sends SNTP requests when timeouts expire.
    ///
    /// If a valid response is received, the Unix timestamp (ie. seconds since
    /// epoch) corresponding to the received NTP timestamp is returned.
    pub fn poll(&mut self, sockets: &mut SocketSet, now: Instant) -> Result<Option<u32>> {
        let mut socket = sockets.get::<UdpSocket>(self.udp_handle);

        // Bind the socket if necessary
        if !socket.is_open() {
            socket.bind(IpEndpoint {
                addr: IpAddress::Unspecified,
                port: SNTP_PORT,
            })?;
        }

        // Process incoming packets
        let timestamp = match socket.recv() {
            Ok((payload, _)) => self.receive(payload, now),
            Err(Error::Exhausted) => None,
            Err(e) => return Err(e),
        };

        if timestamp.is_some() {
            Ok(timestamp)
        } else {
            // Send request if the timeout has expired
            if socket.can_send() && now >= self.next_request {
                self.request(&mut *socket, now)?;
            }
            Ok(None)
        }
    }

    /// Processes a response from the SNTP server.
    fn receive(&mut self, data: &[u8], now: Instant) -> Option<u32> {
        let sntp_packet = match SntpPacket::new_checked(data) {
            Ok(sntp_packet) => sntp_packet,
            Err(e) => {
                net_debug!("SNTP invalid pkt: {:?}", e);
                return None;
            }
        };
        let sntp_repr = match SntpRepr::parse(&sntp_packet) {
            Ok(sntp_repr) => sntp_repr,
            Err(e) => {
                net_debug!("SNTP error parsing pkt: {:?}", e);
                return None;
            }
        };

        if sntp_repr.protocol_mode != SntpProtocolMode::Server {
            net_debug!(
                "Invalid mode in SNTP response: {:?}",
                sntp_repr.protocol_mode
            );
            return None;
        }
        if sntp_repr.stratum == SntpStratum::KissOfDeath {
            net_debug!("SNTP kiss o' death received, updating delay");
            self.next_request = now + Duration::from_secs(REQUEST_INTERVAL);
            return None;
        }

        // Perform conversion from NTP timestamp to Unix timestamp
        let timestamp = sntp_repr
            .xmit_timestamp
            .sec
            .wrapping_add(DIFF_SEC_1970_2036);

        Some(timestamp)
    }

    /// Sends a request to the configured SNTP ntp_server.
    fn request(&mut self, socket: &mut UdpSocket, now: Instant) -> Result<()> {
        let sntp_repr = SntpRepr {
            leap_indicator: SntpLeapIndicator::NoWarning,
            version: 4,
            protocol_mode: SntpProtocolMode::Client,
            stratum: SntpStratum::KissOfDeath,
            poll_interval: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            ref_identifier: [0, 0, 0, 0],
            ref_timestamp: SntpTimestamp { sec: 0, frac: 0 },
            orig_timestamp: SntpTimestamp { sec: 0, frac: 0 },
            recv_timestamp: SntpTimestamp { sec: 0, frac: 0 },
            xmit_timestamp: SntpTimestamp { sec: 0, frac: 0 },
        };

        self.next_request = now + Duration::from_secs(REQUEST_INTERVAL);

        let endpoint = IpEndpoint {
            addr: self.ntp_server,
            port: SNTP_PORT,
        };

        net_trace!("SNTP send request to {}: {:?}", endpoint, sntp_repr);

        let mut packet = socket.send(sntp_repr.buffer_len(), endpoint)?;
        let mut sntp_packet = SntpPacket::new_unchecked(&mut packet);
        sntp_repr.emit(&mut sntp_packet)?;

        Ok(())
    }
}
