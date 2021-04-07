use crate::{Result, Error};
use crate::wire::{IpVersion, IpProtocol, IpEndpoint, IpAddress,
           Ipv4Cidr, Ipv4Address, Ipv4Packet, Ipv4Repr,
           UdpPacket, UdpRepr,
           DhcpPacket, DhcpRepr, DhcpMessageType};
use crate::wire::dhcpv4::field as dhcpv4_field;
use crate::socket::{SocketSet, SocketHandle, RawSocket, RawSocketBuffer};
use crate::phy::{Device, ChecksumCapabilities};
use crate::iface::Interface;
use crate::time::{Instant, Duration};
use super::{UDP_SERVER_PORT, UDP_CLIENT_PORT};

const DISCOVER_TIMEOUT: u64 = 10;
const REQUEST_TIMEOUT: u64 = 1;
const REQUEST_RETRIES: u16 = 15;
const DEFAULT_RENEW_INTERVAL: u32 = 60;
const PARAMETER_REQUEST_LIST: &[u8] = &[
    dhcpv4_field::OPT_SUBNET_MASK,
    dhcpv4_field::OPT_ROUTER,
    dhcpv4_field::OPT_DOMAIN_NAME_SERVER,
];

/// IPv4 configuration data returned by `client.poll()`
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config {
    pub address: Option<Ipv4Cidr>,
    pub router: Option<Ipv4Address>,
    pub dns_servers: [Option<Ipv4Address>; 3],
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RequestState {
    retry: u16,
    endpoint_ip: Ipv4Address,
    server_identifier: Ipv4Address,
    requested_ip: Ipv4Address,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RenewState {
    endpoint_ip: Ipv4Address,
    server_identifier: Ipv4Address,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ClientState {
    /// Discovering the DHCP server
    Discovering,
    /// Requesting an address
    Requesting(RequestState),
    /// Having an address, refresh it periodically
    Renew(RenewState),
}

pub struct Client {
    state: ClientState,
    raw_handle: SocketHandle,
    /// When to send next request
    next_egress: Instant,
    /// When any existing DHCP address will expire.
    lease_expiration: Option<Instant>,
    transaction_id: u32,
}

/// DHCP client with a RawSocket.
///
/// To provide memory for the dynamic IP address, configure your
/// `Interface` with one of `ip_addrs` and the `ipv4_gateway` being
/// `Ipv4Address::UNSPECIFIED`. You must also assign this `0.0.0.0/0`
/// while the client's state is `Discovering`. Hence, the `poll()`
/// method returns a corresponding `Config` struct in this case.
///
/// You must call `dhcp_client.poll()` after `iface.poll()` to send
/// and receive DHCP packets.
impl Client {
    /// # Usage
    /// ```rust
    /// use smoltcp::socket::{SocketSet, RawSocketBuffer, RawPacketMetadata};
    /// use smoltcp::dhcp::Dhcpv4Client;
    /// use smoltcp::time::Instant;
    ///
    /// let mut sockets = SocketSet::new(vec![]);
    /// let dhcp_rx_buffer = RawSocketBuffer::new(
    ///     [RawPacketMetadata::EMPTY; 1],
    ///     vec![0; 600]
    /// );
    /// let dhcp_tx_buffer = RawSocketBuffer::new(
    ///     [RawPacketMetadata::EMPTY; 1],
    ///     vec![0; 600]
    /// );
    /// let mut dhcp = Dhcpv4Client::new(
    ///     &mut sockets,
    ///     dhcp_rx_buffer, dhcp_tx_buffer,
    ///     Instant::now()
    /// );
    /// ```
    pub fn new<'a>(sockets: &mut SocketSet<'a>, rx_buffer: RawSocketBuffer<'a>, tx_buffer: RawSocketBuffer<'a>, now: Instant) -> Self
    {
        let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);
        let raw_handle = sockets.add(raw_socket);

        Client {
            state: ClientState::Discovering,
            raw_handle,
            next_egress: now,
            transaction_id: 1,
            lease_expiration: None,
        }
    }

    /// When to send next packet
    ///
    /// Useful for suspending execution after polling.
    pub fn next_poll(&self, now: Instant) -> Duration {
        self.next_egress - now
    }

    /// Process incoming packets on the contained RawSocket, and send
    /// DHCP requests when timeouts are ready.
    ///
    /// Applying the obtained network configuration is left to the
    /// user.
    ///
    /// A Config can be returned from any valid DHCP reply. The client
    /// performs no bookkeeping on configuration or their changes.
    pub fn poll<DeviceT>(&mut self,
                         iface: &mut Interface<DeviceT>, sockets: &mut SocketSet,
                         now: Instant
                        ) -> Result<Option<Config>>
    where
        DeviceT: for<'d> Device<'d>,
    {
        let checksum_caps = iface.device().capabilities().checksum;
        let mut raw_socket = sockets.get::<RawSocket>(self.raw_handle);

        // Process incoming
        let config = {
            match raw_socket.recv()
                .and_then(|packet| parse_udp(packet, &checksum_caps)) {
                    Ok((IpEndpoint {
                        addr: IpAddress::Ipv4(src_ip),
                        port: UDP_SERVER_PORT,
                    }, IpEndpoint {
                        addr: _,
                        port: UDP_CLIENT_PORT,
                    }, payload)) =>
                        self.ingress(iface, now, payload, &src_ip),
                    Ok(_) =>
                        return Err(Error::Unrecognized),
                    Err(Error::Exhausted) =>
                        None,
                    Err(e) =>
                        return Err(e),
                }
        };

        if config.is_some() {
            // Return a new config immediately so that addresses can
            // be configured that are required by egress().
            Ok(config)
        } else {
            // Send requests
            if raw_socket.can_send() && now >= self.next_egress {
                self.egress(iface, &mut *raw_socket, &checksum_caps, now)
            } else {
                Ok(None)
            }
        }
    }

    fn ingress<DeviceT>(&mut self,
                        iface: &mut Interface<DeviceT>, now: Instant,
                        data: &[u8], src_ip: &Ipv4Address
                       ) -> Option<Config>
    where
        DeviceT: for<'d> Device<'d>,
    {
        let dhcp_packet = match DhcpPacket::new_checked(data) {
            Ok(dhcp_packet) => dhcp_packet,
            Err(e) => {
                net_debug!("DHCP invalid pkt from {}: {:?}", src_ip, e);
                return None;
            }
        };
        let dhcp_repr = match DhcpRepr::parse(&dhcp_packet) {
            Ok(dhcp_repr) => dhcp_repr,
            Err(e) => {
                net_debug!("DHCP error parsing pkt from {}: {:?}", src_ip, e);
                return None;
            }
        };
        let mac = iface.ethernet_addr();
        if dhcp_repr.client_hardware_address != mac { return None }
        if dhcp_repr.transaction_id != self.transaction_id { return None }
        let server_identifier = match dhcp_repr.server_identifier {
            Some(server_identifier) => server_identifier,
            None => return None,
        };
        net_debug!("DHCP recv {:?} from {} ({})", dhcp_repr.message_type, src_ip, server_identifier);

        // once we receive the ack, we can pass the config to the user
        let config = if dhcp_repr.message_type == DhcpMessageType::Ack {
            let lease_duration = dhcp_repr.lease_duration.unwrap_or(DEFAULT_RENEW_INTERVAL * 2);
            self.lease_expiration = Some(now + Duration::from_secs(lease_duration.into()));

            // RFC 2131 indicates clients should renew a lease halfway through its expiration.
            self.next_egress = now + Duration::from_secs((lease_duration / 2).into());

            let address = dhcp_repr.subnet_mask
                .and_then(|mask| IpAddress::Ipv4(mask).to_prefix_len())
                .map(|prefix_len| Ipv4Cidr::new(dhcp_repr.your_ip, prefix_len));
            let router = dhcp_repr.router;
            let dns_servers = dhcp_repr.dns_servers
                .unwrap_or([None; 3]);
               Some(Config { address, router, dns_servers })
        } else {
            None
        };

        match self.state {
            ClientState::Discovering
                if dhcp_repr.message_type == DhcpMessageType::Offer =>
            {
                self.next_egress = now;
                let r_state = RequestState {
                    retry: 0,
                    endpoint_ip: *src_ip,
                    server_identifier,
                    requested_ip: dhcp_repr.your_ip // use the offered ip
                };
                Some(ClientState::Requesting(r_state))
            }
            ClientState::Requesting(ref r_state)
                if dhcp_repr.message_type == DhcpMessageType::Ack &&
                   server_identifier == r_state.server_identifier =>
            {
                let p_state = RenewState {
                    endpoint_ip: *src_ip,
                    server_identifier,
                };
                Some(ClientState::Renew(p_state))
            }
            _ => None
        }.map(|new_state| self.state = new_state);

        config
    }

    fn egress<DeviceT: for<'d> Device<'d>>(&mut self, iface: &mut Interface<DeviceT>, raw_socket: &mut RawSocket, checksum_caps: &ChecksumCapabilities, now: Instant) -> Result<Option<Config>> {
        // Reset after maximum amount of retries
        let retries_exceeded = match self.state {
            ClientState::Requesting(ref mut r_state) if r_state.retry >= REQUEST_RETRIES => {
                net_debug!("DHCP request retries exceeded, restarting discovery");
                true
            }
            _ => false
        };

        let lease_expired = self.lease_expiration.map_or(false, |expiration| now >= expiration);

        if lease_expired || retries_exceeded {
            self.reset(now);
            // Return a config now so that user code assigns the
            // 0.0.0.0/0 address, which will be used sending a DHCP
            // discovery packet in the next call to egress().
            return Ok(Some(Config {
                address: Some(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0)),
                router: None,
                dns_servers: [None; 3],
            }));
        }

        // Prepare sending next packet
        self.transaction_id += 1;
        let mac = iface.ethernet_addr();

        let mut dhcp_repr = DhcpRepr {
            message_type: DhcpMessageType::Discover,
            transaction_id: self.transaction_id,
            client_hardware_address: mac,
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: true,
            requested_ip: None,
            client_identifier: Some(mac),
            server_identifier: None,
            parameter_request_list: Some(PARAMETER_REQUEST_LIST),
            max_size: Some(raw_socket.payload_recv_capacity() as u16),
            lease_duration: None,
            dns_servers: None,
        };
        let mut send_packet = |iface, endpoint, dhcp_repr| {
            send_packet(iface, raw_socket, &endpoint, &dhcp_repr, checksum_caps)
                .map(|()| None)
        };


        match self.state {
            ClientState::Discovering => {
                self.next_egress = now + Duration::from_secs(DISCOVER_TIMEOUT);
                let endpoint = IpEndpoint {
                    addr: Ipv4Address::BROADCAST.into(),
                    port: UDP_SERVER_PORT,
                };
                net_trace!("DHCP send discover to {}: {:?}", endpoint, dhcp_repr);
                send_packet(iface, endpoint, dhcp_repr)
            }
            ClientState::Requesting(ref mut r_state) => {
                r_state.retry += 1;
                self.next_egress = now + Duration::from_secs(REQUEST_TIMEOUT);

                let endpoint = IpEndpoint {
                    addr: Ipv4Address::BROADCAST.into(),
                    port: UDP_SERVER_PORT,
                };
                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.broadcast = false;
                dhcp_repr.requested_ip = Some(r_state.requested_ip);
                dhcp_repr.server_identifier = Some(r_state.server_identifier);
                net_trace!("DHCP send request to {} = {:?}", endpoint, dhcp_repr);
                send_packet(iface, endpoint, dhcp_repr)
            }
            ClientState::Renew(ref mut p_state) => {
                self.next_egress = now + Duration::from_secs(DEFAULT_RENEW_INTERVAL.into());

                let endpoint = IpEndpoint {
                    addr: p_state.endpoint_ip.into(),
                    port: UDP_SERVER_PORT,
                };
                let client_ip = iface.ipv4_addr().unwrap_or(Ipv4Address::UNSPECIFIED);
                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.client_ip = client_ip;
                dhcp_repr.broadcast = false;
                net_trace!("DHCP send renew to {}: {:?}", endpoint, dhcp_repr);
                send_packet(iface, endpoint, dhcp_repr)
            }
        }
    }

    /// Reset state and restart discovery phase.
    ///
    /// Use this to speed up acquisition of an address in a new
    /// network if a link was down and it is now back up.
    ///
    /// You *must* configure a `0.0.0.0` address on your interface
    /// before the next call to `poll()`!
    pub fn reset(&mut self, now: Instant) {
        net_trace!("DHCP reset");
        self.state = ClientState::Discovering;
        self.next_egress = now;
        self.lease_expiration = None;
    }
}

fn send_packet<DeviceT: for<'d> Device<'d>>(iface: &mut Interface<DeviceT>, raw_socket: &mut RawSocket, endpoint: &IpEndpoint, dhcp_repr: &DhcpRepr, checksum_caps: &ChecksumCapabilities) -> Result<()> {
    let mut dhcp_payload_buf = [0; 320];
    assert!(dhcp_repr.buffer_len() <= dhcp_payload_buf.len());
    let dhcp_payload = &mut dhcp_payload_buf[0..dhcp_repr.buffer_len()];
    {
        let mut dhcp_packet = DhcpPacket::new_checked(&mut dhcp_payload[..])?;
        dhcp_repr.emit(&mut dhcp_packet)?;
    }

    let udp_repr = UdpRepr {
        src_port: UDP_CLIENT_PORT,
        dst_port: endpoint.port,
        payload: dhcp_payload,
    };

    let src_addr = iface.ipv4_addr().unwrap();
    let dst_addr = match endpoint.addr {
        IpAddress::Ipv4(addr) => addr,
        _ => return Err(Error::Illegal),
    };
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        protocol: IpProtocol::Udp,
        payload_len: udp_repr.buffer_len(),
        hop_limit: 64,
    };

    let mut packet = raw_socket.send(
        ipv4_repr.buffer_len() + udp_repr.buffer_len()
    )?;
    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        ipv4_repr.emit(&mut ipv4_packet, &checksum_caps);
    }
    {
        let mut udp_packet = UdpPacket::new_unchecked(
            &mut packet[ipv4_repr.buffer_len()..]
        );
        udp_repr.emit(&mut udp_packet,
                      &src_addr.into(), &dst_addr.into(),
                      checksum_caps);
    }
    Ok(())
}

fn parse_udp<'a>(data: &'a [u8], checksum_caps: &ChecksumCapabilities) -> Result<(IpEndpoint, IpEndpoint, &'a [u8])> {
    let ipv4_packet = Ipv4Packet::new_checked(data)?;
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
    let udp_packet = UdpPacket::new_checked(ipv4_packet.payload())?;
    let udp_repr = UdpRepr::parse(
        &udp_packet,
        &ipv4_repr.src_addr.into(), &ipv4_repr.dst_addr.into(),
        checksum_caps
    )?;
    let src = IpEndpoint {
        addr: ipv4_repr.src_addr.into(),
        port: udp_repr.src_port,
    };
    let dst = IpEndpoint {
        addr: ipv4_repr.dst_addr.into(),
        port: udp_repr.dst_port,
    };
    let data = udp_repr.payload;
    Ok((src, dst, data))
}
