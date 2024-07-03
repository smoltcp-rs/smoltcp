use core::task::Waker;
use crate::iface::Context;
use crate::socket::{PollAt, WakerRegistration};
use crate::socket::slaac::SlaacState::Renewing;
use crate::time::{Duration, Instant};
use crate::wire::{DhcpPacket, DhcpRepr, IpProtocol, Ipv6Address, Ipv6Cidr, Ipv6Repr, NdiscRepr, UdpRepr};

#[derive(Debug)]
struct DiscoveringState {
    /// When to send next request
    retry_at: Instant,
}
struct RequestState {
    /// When to send next request
    retry_at: Instant,
    /// How many retries have been done
    router: Ipv6Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// IP address
    pub cdir: Ipv6Cidr,
    /// Router address, also known as default gateway
    pub router: Option<Ipv6Address>,
    /// DNS servers
    pub dns_servers: heapless::Vec<Ipv6Address, { crate::wire::dhcpv4::MAX_DNS_SERVER_COUNT }>,
}

#[derive(Debug)]
struct RenewState {
    // active network configuration
    config: Config,

    /// Renew timer. When reached, we will start attempting
    /// to configure a new IPv6 address
    ///
    /// Must be less or equal than `rebind_at`.
    renew_at: Instant,

    /// Expiration timer. When reached, this IPv6 address is no longer valid, so it must be
    /// thrown away and the ethernet interface deconfigured.
    expires_at: Instant,
}

#[derive(Debug)]
enum SlaacState {
    /// waiting for router advertisement
    Discovering(DiscoveringState),
    Renewing(RenewState),
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Event {
    /// Configuration has been lost (for example, the lease has expired)
    Deconfigured,
    /// Configuration has been newly acquired, or modified.
    Configured(Config),
}


#[derive(Debug)]
pub struct Socket {
    state: SlaacState,
    
    /// Waker registration
    #[cfg(feature = "async")]
    waker: WakerRegistration,
    /// Set to true on config/state change, cleared back to false by the `config` function.
    config_changed: bool,
}

impl Socket {
    pub fn new() -> Self {
        Self {
            state: SlaacState::Discovering(DiscoveringState {
                retry_at: Instant::from_secs(0),
            }),
            #[cfg(feature = "async")]
            waker: WakerRegistration::new(),
            config_changed: true,
        }
    }
}

impl Socket {
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &Ipv6Repr,
        ndisc: &NdiscRepr,
    ) {
        match (&mut self.state, ndisc) {
            (SlaacState::Discovering(state), NdiscRepr::RouterAdvert {router_lifetime, prefix_info, .. }) => {
                if let Some(prefix) = prefix_info {
                    self.config_changed();
                    self.state = Renewing(RenewState {
                        config: Config {
                            cdir: Ipv6Cidr::new(prefix.prefix, prefix.prefix_len),
                            router: None,
                            dns_servers: Default::default(),
                        },
                        renew_at: cx.now() + *router_lifetime / 2,
                        expires_at: cx.now() + *router_lifetime,
                    });
                } else {
                    // does not contain prefix?!
                }
            }
            (SlaacState::Renewing(_), _) => {}
            _ => {}
        }
    }
    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
        where
            F: FnOnce(&mut Context, (Ipv6Repr, NdiscRepr)) -> Result<(), E>,
    {
        match &mut self.state {
            SlaacState::Discovering(state) => {
                state.retry_at = cx.now() + Duration::from_secs(5);
            }
            SlaacState::Renewing(state) => {
                state.expires_at = cx.now() + Duration::from_secs(5);
            }
        }
        Ok(())
    }
}

impl Socket {
    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        let t = match &self.state {
            SlaacState::Discovering(discover) => discover.retry_at,
            SlaacState::Renewing(renew) => renew.renew_at,
        };
        PollAt::Time(t)
    }

    /// Query the socket for configuration changes.
    ///
    /// The socket has an internal "configuration changed" flag. If
    /// set, this function returns the configuration and resets the flag.
    pub fn poll(&mut self) -> Option<Event> {
        if !self.config_changed {
            return None
        }
        if let SlaacState::Renewing(state) = &self.state {
            self.config_changed = false;
            Some(Event::Configured(Config {
                cdir: state.config.cdir,
                router: state.config.router,
                dns_servers: state.config.dns_servers.clone()
            }))
        } else {
            self.config_changed = false;
            Some(Event::Deconfigured)
        }
    }

    /// This function _must_ be called when the configuration provided to the
    /// interface, changes. It will update the `config_changed` field
    /// so that a subsequent call to `poll` will yield an event, and wake a possible waker.
    pub(crate) fn config_changed(&mut self) {
        self.config_changed = true;
        #[cfg(feature = "async")]
        self.waker.wake();
    }

    #[cfg(feature = "async")]
    pub fn register_waker(&mut self, waker: &Waker) {
        self.waker.register(waker)
    }
}