use crate::socket::SocketHandle;
use crate::socket::{Context, SocketMeta};
use crate::time::{Duration, Instant};
use crate::wire::dhcpv4::field as dhcpv4_field;
use crate::wire::{
    DhcpMessageType, DhcpPacket, DhcpRepr, IpAddress, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Repr,
    UdpRepr, DHCP_CLIENT_PORT, DHCP_MAX_DNS_SERVER_COUNT, DHCP_SERVER_PORT, UDP_HEADER_LEN,
};
use crate::{Error, Result};

use super::{PollAt, Socket};

const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);

// timeout doubles every 2 tries.
// total time 5 + 5 + 10 + 10 + 20 = 50s
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_RETRIES: u16 = 5;

const MIN_RENEW_TIMEOUT: Duration = Duration::from_secs(60);

const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(120);

const PARAMETER_REQUEST_LIST: &[u8] = &[
    dhcpv4_field::OPT_SUBNET_MASK,
    dhcpv4_field::OPT_ROUTER,
    dhcpv4_field::OPT_DOMAIN_NAME_SERVER,
];

/// IPv4 configuration data provided by the DHCP server.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Config {
    /// IP address
    pub address: Ipv4Cidr,
    /// Router address, also known as default gateway. Does not necessarily
    /// match the DHCP server's address.
    pub router: Option<Ipv4Address>,
    /// DNS servers
    pub dns_servers: [Option<Ipv4Address>; DHCP_MAX_DNS_SERVER_COUNT],
}

/// Information on how to reach a DHCP server.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ServerInfo {
    /// IP address to use as destination in outgoing packets
    address: Ipv4Address,
    /// Server identifier to use in outgoing packets. Usually equal to server_address,
    /// but may differ in some situations (eg DHCP relays)
    identifier: Ipv4Address,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DiscoverState {
    /// When to send next request
    retry_at: Instant,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RequestState {
    /// When to send next request
    retry_at: Instant,
    /// How many retries have been done
    retry: u16,
    /// Server we're trying to request from
    server: ServerInfo,
    /// IP address that we're trying to request.
    requested_ip: Ipv4Address,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RenewState {
    /// Server that gave us the lease
    server: ServerInfo,
    /// Active network config
    config: Config,

    /// Renew timer. When reached, we will start attempting
    /// to renew this lease with the DHCP server.
    /// Must be less or equal than `expires_at`.
    renew_at: Instant,
    /// Expiration timer. When reached, this lease is no longer valid, so it must be
    /// thrown away and the ethernet interface deconfigured.
    expires_at: Instant,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ClientState {
    /// Discovering the DHCP server
    Discovering(DiscoverState),
    /// Requesting an address
    Requesting(RequestState),
    /// Having an address, refresh it periodically.
    Renewing(RenewState),
}

/// Return value for the `Dhcpv4Socket::poll` function
pub enum Event<'a> {
    /// Configuration has been lost (for example, the lease has expired)
    Deconfigured,
    /// Configuration has been newly acquired, or modified.
    Configured(&'a Config),
}

#[derive(Debug)]
pub struct Dhcpv4Socket {
    pub(crate) meta: SocketMeta,
    /// State of the DHCP client.
    state: ClientState,
    /// Set to true on config/state change, cleared back to false by the `config` function.
    config_changed: bool,
    /// xid of the last sent message.
    transaction_id: u32,

    /// Max lease duration. If set, it sets a maximum cap to the server-provided lease duration.
    /// Useful to react faster to IP configuration changes and to test whether renews work correctly.
    max_lease_duration: Option<Duration>,
}

/// DHCP client socket.
///
/// The socket acquires an IP address configuration through DHCP autonomously.
/// You must query the configuration with `.poll()` after every call to `Interface::poll()`,
/// and apply the configuration to the `Interface`.
impl Dhcpv4Socket {
    /// Create a DHCPv4 socket
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Dhcpv4Socket {
            meta: SocketMeta::default(),
            state: ClientState::Discovering(DiscoverState {
                retry_at: Instant::from_millis(0),
            }),
            config_changed: true,
            transaction_id: 1,
            max_lease_duration: None,
        }
    }

    pub fn max_lease_duration(&self) -> Option<Duration> {
        self.max_lease_duration
    }

    pub fn set_max_lease_duration(&mut self, max_lease_duration: Option<Duration>) {
        self.max_lease_duration = max_lease_duration;
    }

    pub(crate) fn poll_at(&self, _cx: &Context) -> PollAt {
        let t = match &self.state {
            ClientState::Discovering(state) => state.retry_at,
            ClientState::Requesting(state) => state.retry_at,
            ClientState::Renewing(state) => state.renew_at.min(state.expires_at),
        };
        PollAt::Time(t)
    }

    pub(crate) fn process(
        &mut self,
        cx: &Context,
        ip_repr: &Ipv4Repr,
        repr: &UdpRepr,
        payload: &[u8],
    ) -> Result<()> {
        let src_ip = ip_repr.src_addr;

        // This is enforced in interface.rs.
        assert!(repr.src_port == DHCP_SERVER_PORT && repr.dst_port == DHCP_CLIENT_PORT);

        let dhcp_packet = match DhcpPacket::new_checked(payload) {
            Ok(dhcp_packet) => dhcp_packet,
            Err(e) => {
                net_debug!("DHCP invalid pkt from {}: {:?}", src_ip, e);
                return Ok(());
            }
        };
        let dhcp_repr = match DhcpRepr::parse(&dhcp_packet) {
            Ok(dhcp_repr) => dhcp_repr,
            Err(e) => {
                net_debug!("DHCP error parsing pkt from {}: {:?}", src_ip, e);
                return Ok(());
            }
        };
        if dhcp_repr.client_hardware_address != cx.ethernet_address.unwrap() {
            return Ok(());
        }
        if dhcp_repr.transaction_id != self.transaction_id {
            return Ok(());
        }
        let server_identifier = match dhcp_repr.server_identifier {
            Some(server_identifier) => server_identifier,
            None => {
                net_debug!(
                    "DHCP ignoring {:?} because missing server_identifier",
                    dhcp_repr.message_type
                );
                return Ok(());
            }
        };

        net_debug!(
            "DHCP recv {:?} from {} ({})",
            dhcp_repr.message_type,
            src_ip,
            server_identifier
        );

        match (&mut self.state, dhcp_repr.message_type) {
            (ClientState::Discovering(_state), DhcpMessageType::Offer) => {
                if !dhcp_repr.your_ip.is_unicast() {
                    net_debug!("DHCP ignoring OFFER because your_ip is not unicast");
                    return Ok(());
                }

                self.state = ClientState::Requesting(RequestState {
                    retry_at: cx.now,
                    retry: 0,
                    server: ServerInfo {
                        address: src_ip,
                        identifier: server_identifier,
                    },
                    requested_ip: dhcp_repr.your_ip, // use the offered ip
                });
            }
            (ClientState::Requesting(state), DhcpMessageType::Ack) => {
                if let Some((config, renew_at, expires_at)) =
                    Self::parse_ack(cx.now, &dhcp_repr, self.max_lease_duration)
                {
                    self.config_changed = true;
                    self.state = ClientState::Renewing(RenewState {
                        server: state.server,
                        config,
                        renew_at,
                        expires_at,
                    });
                }
            }
            (ClientState::Requesting(_), DhcpMessageType::Nak) => {
                self.reset();
            }
            (ClientState::Renewing(state), DhcpMessageType::Ack) => {
                if let Some((config, renew_at, expires_at)) =
                    Self::parse_ack(cx.now, &dhcp_repr, self.max_lease_duration)
                {
                    state.renew_at = renew_at;
                    state.expires_at = expires_at;
                    if state.config != config {
                        self.config_changed = true;
                        state.config = config;
                    }
                }
            }
            (ClientState::Renewing(_), DhcpMessageType::Nak) => {
                self.reset();
            }
            _ => {
                net_debug!(
                    "DHCP ignoring {:?}: unexpected in current state",
                    dhcp_repr.message_type
                );
            }
        }

        Ok(())
    }

    fn parse_ack(
        now: Instant,
        dhcp_repr: &DhcpRepr,
        max_lease_duration: Option<Duration>,
    ) -> Option<(Config, Instant, Instant)> {
        let subnet_mask = match dhcp_repr.subnet_mask {
            Some(subnet_mask) => subnet_mask,
            None => {
                net_debug!("DHCP ignoring ACK because missing subnet_mask");
                return None;
            }
        };

        let prefix_len = match IpAddress::Ipv4(subnet_mask).to_prefix_len() {
            Some(prefix_len) => prefix_len,
            None => {
                net_debug!("DHCP ignoring ACK because subnet_mask is not a valid mask");
                return None;
            }
        };

        if !dhcp_repr.your_ip.is_unicast() {
            net_debug!("DHCP ignoring ACK because your_ip is not unicast");
            return None;
        }

        let mut lease_duration = dhcp_repr
            .lease_duration
            .map(|d| Duration::from_secs(d as _))
            .unwrap_or(DEFAULT_LEASE_DURATION);
        if let Some(max_lease_duration) = max_lease_duration {
            lease_duration = lease_duration.min(max_lease_duration);
        }

        // Cleanup the DNS servers list, keeping only unicasts/
        // TP-Link TD-W8970 sends 0.0.0.0 as second DNS server if there's only one configured :(
        let mut dns_servers = [None; DHCP_MAX_DNS_SERVER_COUNT];
        if let Some(received) = dhcp_repr.dns_servers {
            let mut i = 0;
            for addr in received.iter().flatten() {
                if addr.is_unicast() {
                    // This can never be out-of-bounds since both arrays have length DHCP_MAX_DNS_SERVER_COUNT
                    dns_servers[i] = Some(*addr);
                    i += 1;
                }
            }
        }
        let config = Config {
            address: Ipv4Cidr::new(dhcp_repr.your_ip, prefix_len),
            router: dhcp_repr.router,
            dns_servers: dns_servers,
        };

        // RFC 2131 indicates clients should renew a lease halfway through its expiration.
        let renew_at = now + lease_duration / 2;
        let expires_at = now + lease_duration;

        Some((config, renew_at, expires_at))
    }

    pub(crate) fn dispatch<F>(&mut self, cx: &Context, emit: F) -> Result<()>
    where
        F: FnOnce((Ipv4Repr, UdpRepr, DhcpRepr)) -> Result<()>,
    {
        // note: Dhcpv4Socket is only usable in ethernet mediums, so the
        // unwrap can never fail.
        let ethernet_addr = cx.ethernet_address.unwrap();

        // Worst case biggest IPv4 header length.
        // 0x0f * 4 = 60 bytes.
        const MAX_IPV4_HEADER_LEN: usize = 60;

        // We don't directly increment transaction_id because sending the packet
        // may fail. We only want to update state after succesfully sending.
        let next_transaction_id = self.transaction_id + 1;

        let mut dhcp_repr = DhcpRepr {
            message_type: DhcpMessageType::Discover,
            transaction_id: next_transaction_id,
            client_hardware_address: ethernet_addr,
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: true,
            requested_ip: None,
            client_identifier: Some(ethernet_addr),
            server_identifier: None,
            parameter_request_list: Some(PARAMETER_REQUEST_LIST),
            max_size: Some((cx.caps.ip_mtu() - MAX_IPV4_HEADER_LEN - UDP_HEADER_LEN) as u16),
            lease_duration: None,
            dns_servers: None,
        };

        let udp_repr = UdpRepr {
            src_port: DHCP_CLIENT_PORT,
            dst_port: DHCP_SERVER_PORT,
        };

        let mut ipv4_repr = Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::BROADCAST,
            protocol: IpProtocol::Udp,
            payload_len: 0, // filled right before emit
            hop_limit: 64,
        };

        match &mut self.state {
            ClientState::Discovering(state) => {
                if cx.now < state.retry_at {
                    return Err(Error::Exhausted);
                }

                // send packet
                net_debug!(
                    "DHCP send DISCOVER to {}: {:?}",
                    ipv4_repr.dst_addr,
                    dhcp_repr
                );
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit((ipv4_repr, udp_repr, dhcp_repr))?;

                // Update state AFTER the packet has been successfully sent.
                state.retry_at = cx.now + DISCOVER_TIMEOUT;
                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::Requesting(state) => {
                if cx.now < state.retry_at {
                    return Err(Error::Exhausted);
                }

                if state.retry >= REQUEST_RETRIES {
                    net_debug!("DHCP request retries exceeded, restarting discovery");
                    self.reset();
                    // return Ok so we get polled again
                    return Ok(());
                }

                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.broadcast = false;
                dhcp_repr.requested_ip = Some(state.requested_ip);
                dhcp_repr.server_identifier = Some(state.server.identifier);

                net_debug!(
                    "DHCP send request to {}: {:?}",
                    ipv4_repr.dst_addr,
                    dhcp_repr
                );
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit((ipv4_repr, udp_repr, dhcp_repr))?;

                // Exponential backoff: Double every 2 retries.
                state.retry_at = cx.now + (REQUEST_TIMEOUT << (state.retry as u32 / 2));
                state.retry += 1;

                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::Renewing(state) => {
                if state.expires_at <= cx.now {
                    net_debug!("DHCP lease expired");
                    self.reset();
                    // return Ok so we get polled again
                    return Ok(());
                }

                if cx.now < state.renew_at {
                    return Err(Error::Exhausted);
                }

                ipv4_repr.src_addr = state.config.address.address();
                ipv4_repr.dst_addr = state.server.address;
                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.client_ip = state.config.address.address();
                dhcp_repr.broadcast = false;

                net_debug!("DHCP send renew to {}: {:?}", ipv4_repr.dst_addr, dhcp_repr);
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit((ipv4_repr, udp_repr, dhcp_repr))?;

                // In both RENEWING and REBINDING states, if the client receives no
                // response to its DHCPREQUEST message, the client SHOULD wait one-half
                // of the remaining time until T2 (in RENEWING state) and one-half of
                // the remaining lease time (in REBINDING state), down to a minimum of
                // 60 seconds, before retransmitting the DHCPREQUEST message.
                state.renew_at = cx.now + MIN_RENEW_TIMEOUT.max((state.expires_at - cx.now) / 2);

                self.transaction_id = next_transaction_id;
                Ok(())
            }
        }
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Reset state and restart discovery phase.
    ///
    /// Use this to speed up acquisition of an address in a new
    /// network if a link was down and it is now back up.
    pub fn reset(&mut self) {
        net_trace!("DHCP reset");
        if let ClientState::Renewing(_) = &self.state {
            self.config_changed = true;
        }
        self.state = ClientState::Discovering(DiscoverState {
            retry_at: Instant::from_millis(0),
        });
    }

    /// Query the socket for configuration changes.
    ///
    /// The socket has an internal "configuration changed" flag. If
    /// set, this function returns the configuration and resets the flag.
    pub fn poll(&mut self) -> Option<Event<'_>> {
        if !self.config_changed {
            None
        } else if let ClientState::Renewing(state) = &self.state {
            self.config_changed = false;
            Some(Event::Configured(&state.config))
        } else {
            self.config_changed = false;
            Some(Event::Deconfigured)
        }
    }
}

impl<'a> Into<Socket<'a>> for Dhcpv4Socket {
    fn into(self) -> Socket<'a> {
        Socket::Dhcpv4(self)
    }
}
