use crate::iface::Context;
use crate::time::{Duration, Instant};
use crate::wire::dhcpv4::field as dhcpv4_field;
use crate::wire::HardwareAddress;
use crate::wire::{
    DhcpMessageType, DhcpPacket, DhcpRepr, IpAddress, IpProtocol, Ipv4Address, Ipv4Cidr, Ipv4Repr,
    UdpRepr, DHCP_CLIENT_PORT, DHCP_MAX_DNS_SERVER_COUNT, DHCP_SERVER_PORT, UDP_HEADER_LEN,
};
use crate::{Error, Result};

use super::PollAt;

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
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
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
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// Configuration has been lost (for example, the lease has expired)
    Deconfigured,
    /// Configuration has been newly acquired, or modified.
    Configured(Config),
}

#[derive(Debug)]
pub struct Dhcpv4Socket {
    /// State of the DHCP client.
    state: ClientState,
    /// Set to true on config/state change, cleared back to false by the `config` function.
    config_changed: bool,
    /// xid of the last sent message.
    transaction_id: u32,

    /// Max lease duration. If set, it sets a maximum cap to the server-provided lease duration.
    /// Useful to react faster to IP configuration changes and to test whether renews work correctly.
    max_lease_duration: Option<Duration>,

    /// Ignore NAKs.
    ignore_naks: bool,
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
            state: ClientState::Discovering(DiscoverState {
                retry_at: Instant::from_millis(0),
            }),
            config_changed: true,
            transaction_id: 1,
            max_lease_duration: None,
            ignore_naks: false,
        }
    }

    /// Get the configured max lease duration.
    ///
    /// See also [`Self::set_max_lease_duration()`]
    pub fn max_lease_duration(&self) -> Option<Duration> {
        self.max_lease_duration
    }

    /// Set the max lease duration.
    ///
    /// When set, the lease duration will be capped at the configured duration if the
    /// DHCP server gives us a longer lease. This is generally not recommended, but
    /// can be useful for debugging or reacting faster to network configuration changes.
    ///
    /// If None, no max is applied (the lease duration from the DHCP server is used.)
    pub fn set_max_lease_duration(&mut self, max_lease_duration: Option<Duration>) {
        self.max_lease_duration = max_lease_duration;
    }

    /// Get whether to ignore NAKs.
    ///
    /// See also [`Self::set_ignore_naks()`]
    pub fn ignore_naks(&self) -> bool {
        self.ignore_naks
    }

    /// Set whether to ignore NAKs.
    ///
    /// This is not compliant with the DHCP RFCs, since theoretically
    /// we must stop using the assigned IP when receiving a NAK. This
    /// can increase reliability on broken networks with buggy routers
    /// or rogue DHCP servers, however.
    pub fn set_ignore_naks(&mut self, ignore_naks: bool) {
        self.ignore_naks = ignore_naks;
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        let t = match &self.state {
            ClientState::Discovering(state) => state.retry_at,
            ClientState::Requesting(state) => state.retry_at,
            ClientState::Renewing(state) => state.renew_at.min(state.expires_at),
        };
        PollAt::Time(t)
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
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
        let hardware_addr = if let Some(HardwareAddress::Ethernet(addr)) = cx.hardware_addr() {
            addr
        } else {
            return Err(Error::Malformed);
        };

        if dhcp_repr.client_hardware_address != hardware_addr {
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
            "DHCP recv {:?} from {}: {:?}",
            dhcp_repr.message_type,
            src_ip,
            dhcp_repr
        );

        match (&mut self.state, dhcp_repr.message_type) {
            (ClientState::Discovering(_state), DhcpMessageType::Offer) => {
                if !dhcp_repr.your_ip.is_unicast() {
                    net_debug!("DHCP ignoring OFFER because your_ip is not unicast");
                    return Ok(());
                }

                self.state = ClientState::Requesting(RequestState {
                    retry_at: cx.now(),
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
                    Self::parse_ack(cx.now(), &dhcp_repr, self.max_lease_duration)
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
                if !self.ignore_naks {
                    self.reset();
                }
            }
            (ClientState::Renewing(state), DhcpMessageType::Ack) => {
                if let Some((config, renew_at, expires_at)) =
                    Self::parse_ack(cx.now(), &dhcp_repr, self.max_lease_duration)
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
                if !self.ignore_naks {
                    self.reset();
                }
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

        let prefix_len = match IpAddress::Ipv4(subnet_mask).prefix_len() {
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

    #[cfg(not(test))]
    fn random_transaction_id(cx: &mut Context) -> u32 {
        cx.rand().rand_u32()
    }

    #[cfg(test)]
    fn random_transaction_id(_cx: &mut Context) -> u32 {
        0x12345678
    }

    pub(crate) fn dispatch<F>(&mut self, cx: &mut Context, emit: F) -> Result<()>
    where
        F: FnOnce(&mut Context, (Ipv4Repr, UdpRepr, DhcpRepr)) -> Result<()>,
    {
        // note: Dhcpv4Socket is only usable in ethernet mediums, so the
        // unwrap can never fail.
        let ethernet_addr = if let Some(HardwareAddress::Ethernet(addr)) = cx.hardware_addr() {
            addr
        } else {
            return Err(Error::Malformed);
        };

        // Worst case biggest IPv4 header length.
        // 0x0f * 4 = 60 bytes.
        const MAX_IPV4_HEADER_LEN: usize = 60;

        // We don't directly modify self.transaction_id because sending the packet
        // may fail. We only want to update state after succesfully sending.
        let next_transaction_id = Self::random_transaction_id(cx);

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
            broadcast: false,
            requested_ip: None,
            client_identifier: Some(ethernet_addr),
            server_identifier: None,
            parameter_request_list: Some(PARAMETER_REQUEST_LIST),
            max_size: Some((cx.ip_mtu() - MAX_IPV4_HEADER_LEN - UDP_HEADER_LEN) as u16),
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
                if cx.now() < state.retry_at {
                    return Err(Error::Exhausted);
                }

                // send packet
                net_debug!(
                    "DHCP send DISCOVER to {}: {:?}",
                    ipv4_repr.dst_addr,
                    dhcp_repr
                );
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, (ipv4_repr, udp_repr, dhcp_repr))?;

                // Update state AFTER the packet has been successfully sent.
                state.retry_at = cx.now() + DISCOVER_TIMEOUT;
                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::Requesting(state) => {
                if cx.now() < state.retry_at {
                    return Err(Error::Exhausted);
                }

                if state.retry >= REQUEST_RETRIES {
                    net_debug!("DHCP request retries exceeded, restarting discovery");
                    self.reset();
                    // return Ok so we get polled again
                    return Ok(());
                }

                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.requested_ip = Some(state.requested_ip);
                dhcp_repr.server_identifier = Some(state.server.identifier);

                net_debug!(
                    "DHCP send request to {}: {:?}",
                    ipv4_repr.dst_addr,
                    dhcp_repr
                );
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, (ipv4_repr, udp_repr, dhcp_repr))?;

                // Exponential backoff: Double every 2 retries.
                state.retry_at = cx.now() + (REQUEST_TIMEOUT << (state.retry as u32 / 2));
                state.retry += 1;

                self.transaction_id = next_transaction_id;
                Ok(())
            }
            ClientState::Renewing(state) => {
                if state.expires_at <= cx.now() {
                    net_debug!("DHCP lease expired");
                    self.reset();
                    // return Ok so we get polled again
                    return Ok(());
                }

                if cx.now() < state.renew_at {
                    return Err(Error::Exhausted);
                }

                ipv4_repr.src_addr = state.config.address.address();
                ipv4_repr.dst_addr = state.server.address;
                dhcp_repr.message_type = DhcpMessageType::Request;
                dhcp_repr.client_ip = state.config.address.address();

                net_debug!("DHCP send renew to {}: {:?}", ipv4_repr.dst_addr, dhcp_repr);
                ipv4_repr.payload_len = udp_repr.header_len() + dhcp_repr.buffer_len();
                emit(cx, (ipv4_repr, udp_repr, dhcp_repr))?;

                // In both RENEWING and REBINDING states, if the client receives no
                // response to its DHCPREQUEST message, the client SHOULD wait one-half
                // of the remaining time until T2 (in RENEWING state) and one-half of
                // the remaining lease time (in REBINDING state), down to a minimum of
                // 60 seconds, before retransmitting the DHCPREQUEST message.
                state.renew_at =
                    cx.now() + MIN_RENEW_TIMEOUT.max((state.expires_at - cx.now()) / 2);

                self.transaction_id = next_transaction_id;
                Ok(())
            }
        }
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
    pub fn poll(&mut self) -> Option<Event> {
        if !self.config_changed {
            None
        } else if let ClientState::Renewing(state) = &self.state {
            self.config_changed = false;
            Some(Event::Configured(state.config))
        } else {
            self.config_changed = false;
            Some(Event::Deconfigured)
        }
    }
}

#[cfg(test)]
mod test {

    use std::ops::{Deref, DerefMut};

    use super::*;
    use crate::wire::EthernetAddress;

    // =========================================================================================//
    // Helper functions

    struct TestSocket {
        socket: Dhcpv4Socket,
        cx: Context<'static>,
    }

    impl Deref for TestSocket {
        type Target = Dhcpv4Socket;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    fn send(
        s: &mut TestSocket,
        timestamp: Instant,
        (ip_repr, udp_repr, dhcp_repr): (Ipv4Repr, UdpRepr, DhcpRepr),
    ) -> Result<()> {
        s.cx.set_now(timestamp);

        net_trace!("send: {:?}", ip_repr);
        net_trace!("      {:?}", udp_repr);
        net_trace!("      {:?}", dhcp_repr);

        let mut payload = vec![0; dhcp_repr.buffer_len()];
        dhcp_repr
            .emit(&mut DhcpPacket::new_unchecked(&mut payload))
            .unwrap();

        s.socket.process(&mut s.cx, &ip_repr, &udp_repr, &payload)
    }

    fn recv(s: &mut TestSocket, timestamp: Instant, reprs: &[(Ipv4Repr, UdpRepr, DhcpRepr)]) {
        s.cx.set_now(timestamp);

        let mut i = 0;

        while s.socket.poll_at(&mut s.cx) <= PollAt::Time(timestamp) {
            let _ = s
                .socket
                .dispatch(&mut s.cx, |_, (mut ip_repr, udp_repr, dhcp_repr)| {
                    assert_eq!(ip_repr.protocol, IpProtocol::Udp);
                    assert_eq!(
                        ip_repr.payload_len,
                        udp_repr.header_len() + dhcp_repr.buffer_len()
                    );

                    // We validated the payload len, change it to 0 to make equality testing easier
                    ip_repr.payload_len = 0;

                    net_trace!("recv: {:?}", ip_repr);
                    net_trace!("      {:?}", udp_repr);
                    net_trace!("      {:?}", dhcp_repr);

                    let got_repr = (ip_repr, udp_repr, dhcp_repr);
                    match reprs.get(i) {
                        Some(want_repr) => assert_eq!(want_repr, &got_repr),
                        None => panic!("Too many reprs emitted"),
                    }
                    i += 1;
                    Ok(())
                });
        }

        assert_eq!(i, reprs.len());
    }

    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, Ok(( ))));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), $repr), $result));
    }

    macro_rules! recv {
        ($socket:ident, $reprs:expr) => ({
            recv!($socket, time 0, $reprs);
        });
        ($socket:ident, time $time:expr, $reprs:expr) => ({
            recv(&mut $socket, Instant::from_millis($time), &$reprs);
        });
    }

    // =========================================================================================//
    // Constants

    const TXID: u32 = 0x12345678;

    const MY_IP: Ipv4Address = Ipv4Address([192, 168, 1, 42]);
    const SERVER_IP: Ipv4Address = Ipv4Address([192, 168, 1, 1]);
    const DNS_IP_1: Ipv4Address = Ipv4Address([1, 1, 1, 1]);
    const DNS_IP_2: Ipv4Address = Ipv4Address([1, 1, 1, 2]);
    const DNS_IP_3: Ipv4Address = Ipv4Address([1, 1, 1, 3]);
    const DNS_IPS: [Option<Ipv4Address>; DHCP_MAX_DNS_SERVER_COUNT] =
        [Some(DNS_IP_1), Some(DNS_IP_2), Some(DNS_IP_3)];
    const MASK_24: Ipv4Address = Ipv4Address([255, 255, 255, 0]);

    const MY_MAC: EthernetAddress = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);

    const IP_BROADCAST: Ipv4Repr = Ipv4Repr {
        src_addr: Ipv4Address::UNSPECIFIED,
        dst_addr: Ipv4Address::BROADCAST,
        protocol: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    };

    const IP_SERVER_BROADCAST: Ipv4Repr = Ipv4Repr {
        src_addr: SERVER_IP,
        dst_addr: Ipv4Address::BROADCAST,
        protocol: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    };

    const IP_RECV: Ipv4Repr = Ipv4Repr {
        src_addr: SERVER_IP,
        dst_addr: MY_IP,
        protocol: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    };

    const IP_SEND: Ipv4Repr = Ipv4Repr {
        src_addr: MY_IP,
        dst_addr: SERVER_IP,
        protocol: IpProtocol::Udp,
        payload_len: 0,
        hop_limit: 64,
    };

    const UDP_SEND: UdpRepr = UdpRepr {
        src_port: 68,
        dst_port: 67,
    };
    const UDP_RECV: UdpRepr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    const DHCP_DEFAULT: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Unknown(99),
        transaction_id: TXID,
        client_hardware_address: MY_MAC,
        client_ip: Ipv4Address::UNSPECIFIED,
        your_ip: Ipv4Address::UNSPECIFIED,
        server_ip: Ipv4Address::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: Ipv4Address::UNSPECIFIED,
        broadcast: false,
        requested_ip: None,
        client_identifier: None,
        server_identifier: None,
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: None,
    };

    const DHCP_DISCOVER: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Discover,
        client_identifier: Some(MY_MAC),
        parameter_request_list: Some(&[1, 3, 6]),
        max_size: Some(1432),
        ..DHCP_DEFAULT
    };

    const DHCP_OFFER: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Offer,
        server_ip: SERVER_IP,
        server_identifier: Some(SERVER_IP),

        your_ip: MY_IP,
        router: Some(SERVER_IP),
        subnet_mask: Some(MASK_24),
        dns_servers: Some(DNS_IPS),
        lease_duration: Some(1000),

        ..DHCP_DEFAULT
    };

    const DHCP_REQUEST: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Request,
        client_identifier: Some(MY_MAC),
        server_identifier: Some(SERVER_IP),
        max_size: Some(1432),

        requested_ip: Some(MY_IP),
        parameter_request_list: Some(&[1, 3, 6]),
        ..DHCP_DEFAULT
    };

    const DHCP_ACK: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Ack,
        server_ip: SERVER_IP,
        server_identifier: Some(SERVER_IP),

        your_ip: MY_IP,
        router: Some(SERVER_IP),
        subnet_mask: Some(MASK_24),
        dns_servers: Some(DNS_IPS),
        lease_duration: Some(1000),

        ..DHCP_DEFAULT
    };

    const DHCP_NAK: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Nak,
        server_ip: SERVER_IP,
        server_identifier: Some(SERVER_IP),
        ..DHCP_DEFAULT
    };

    const DHCP_RENEW: DhcpRepr = DhcpRepr {
        message_type: DhcpMessageType::Request,
        client_identifier: Some(MY_MAC),
        // NO server_identifier in renew requests, only in first one!
        client_ip: MY_IP,
        max_size: Some(1432),

        requested_ip: None,
        parameter_request_list: Some(&[1, 3, 6]),
        ..DHCP_DEFAULT
    };

    // =========================================================================================//
    // Tests

    fn socket() -> TestSocket {
        let mut s = Dhcpv4Socket::new();
        assert_eq!(s.poll(), Some(Event::Deconfigured));
        TestSocket {
            socket: s,
            cx: Context::mock(),
        }
    }

    fn socket_bound() -> TestSocket {
        let mut s = socket();
        s.state = ClientState::Renewing(RenewState {
            config: Config {
                address: Ipv4Cidr::new(MY_IP, 24),
                dns_servers: DNS_IPS,
                router: Some(SERVER_IP),
            },
            server: ServerInfo {
                address: SERVER_IP,
                identifier: SERVER_IP,
            },
            renew_at: Instant::from_secs(500),
            expires_at: Instant::from_secs(1000),
        });

        s
    }

    #[test]
    fn test_bind() {
        let mut s = socket();

        recv!(s, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        assert_eq!(s.poll(), None);
        send!(s, (IP_RECV, UDP_RECV, DHCP_OFFER));
        assert_eq!(s.poll(), None);
        recv!(s, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        assert_eq!(s.poll(), None);
        send!(s, (IP_RECV, UDP_RECV, DHCP_ACK));

        assert_eq!(
            s.poll(),
            Some(Event::Configured(Config {
                address: Ipv4Cidr::new(MY_IP, 24),
                dns_servers: DNS_IPS,
                router: Some(SERVER_IP),
            }))
        );

        match &s.state {
            ClientState::Renewing(r) => {
                assert_eq!(r.renew_at, Instant::from_secs(500));
                assert_eq!(r.expires_at, Instant::from_secs(1000));
            }
            _ => panic!("Invalid state"),
        }
    }

    #[test]
    fn test_discover_retransmit() {
        let mut s = socket();

        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        recv!(s, time 1_000, []);
        recv!(s, time 10_000, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        recv!(s, time 11_000, []);
        recv!(s, time 20_000, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);

        // check after retransmits it still works
        send!(s, time 20_000, (IP_RECV, UDP_RECV, DHCP_OFFER));
        recv!(s, time 20_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
    }

    #[test]
    fn test_request_retransmit() {
        let mut s = socket();

        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        send!(s, time 0, (IP_RECV, UDP_RECV, DHCP_OFFER));
        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 1_000, []);
        recv!(s, time 5_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 6_000, []);
        recv!(s, time 10_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 15_000, []);
        recv!(s, time 20_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);

        // check after retransmits it still works
        send!(s, time 20_000, (IP_RECV, UDP_RECV, DHCP_ACK));

        match &s.state {
            ClientState::Renewing(r) => {
                assert_eq!(r.renew_at, Instant::from_secs(20 + 500));
                assert_eq!(r.expires_at, Instant::from_secs(20 + 1000));
            }
            _ => panic!("Invalid state"),
        }
    }

    #[test]
    fn test_request_timeout() {
        let mut s = socket();

        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        send!(s, time 0, (IP_RECV, UDP_RECV, DHCP_OFFER));
        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 5_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 10_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 20_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        recv!(s, time 30_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);

        // After 5 tries and 70 seconds, it gives up.
        // 5 + 5 + 10 + 10 + 20 = 70
        recv!(s, time 70_000, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);

        // check it still works
        send!(s, time 60_000, (IP_RECV, UDP_RECV, DHCP_OFFER));
        recv!(s, time 60_000, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
    }

    #[test]
    fn test_request_nak() {
        let mut s = socket();

        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        send!(s, time 0, (IP_RECV, UDP_RECV, DHCP_OFFER));
        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_REQUEST)]);
        send!(s, time 0, (IP_SERVER_BROADCAST, UDP_RECV, DHCP_NAK));
        recv!(s, time 0, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
    }

    #[test]
    fn test_renew() {
        let mut s = socket_bound();

        recv!(s, []);
        assert_eq!(s.poll(), None);
        recv!(s, time 500_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        assert_eq!(s.poll(), None);

        match &s.state {
            ClientState::Renewing(r) => {
                // the expiration still hasn't been bumped, because
                // we haven't received the ACK yet
                assert_eq!(r.expires_at, Instant::from_secs(1000));
            }
            _ => panic!("Invalid state"),
        }

        send!(s, time 500_000, (IP_RECV, UDP_RECV, DHCP_ACK));
        assert_eq!(s.poll(), None);

        match &s.state {
            ClientState::Renewing(r) => {
                // NOW the expiration gets bumped
                assert_eq!(r.renew_at, Instant::from_secs(500 + 500));
                assert_eq!(r.expires_at, Instant::from_secs(500 + 1000));
            }
            _ => panic!("Invalid state"),
        }
    }

    #[test]
    fn test_renew_retransmit() {
        let mut s = socket_bound();

        recv!(s, []);
        recv!(s, time 500_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        recv!(s, time 749_000, []);
        recv!(s, time 750_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        recv!(s, time 874_000, []);
        recv!(s, time 875_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);

        // check it still works
        send!(s, time 875_000, (IP_RECV, UDP_RECV, DHCP_ACK));
        match &s.state {
            ClientState::Renewing(r) => {
                // NOW the expiration gets bumped
                assert_eq!(r.renew_at, Instant::from_secs(875 + 500));
                assert_eq!(r.expires_at, Instant::from_secs(875 + 1000));
            }
            _ => panic!("Invalid state"),
        }
    }

    #[test]
    fn test_renew_timeout() {
        let mut s = socket_bound();

        recv!(s, []);
        recv!(s, time 500_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        recv!(s, time 999_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        recv!(s, time 1_000_000, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
        match &s.state {
            ClientState::Discovering(_) => {}
            _ => panic!("Invalid state"),
        }
    }

    #[test]
    fn test_renew_nak() {
        let mut s = socket_bound();

        recv!(s, time 500_000, [(IP_SEND, UDP_SEND, DHCP_RENEW)]);
        send!(s, time 500_000, (IP_SERVER_BROADCAST, UDP_RECV, DHCP_NAK));
        recv!(s, time 500_000, [(IP_BROADCAST, UDP_SEND, DHCP_DISCOVER)]);
    }
}
