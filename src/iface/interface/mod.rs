// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

#[cfg(test)]
mod tests;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "medium-ieee802154")]
mod ieee802154;

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "proto-rpl")]
mod rpl;

#[cfg(feature = "proto-igmp")]
mod igmp;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
mod udp;

#[cfg(feature = "proto-igmp")]
pub use igmp::MulticastError;

use super::packet::*;

use core::result::Result;
use heapless::{LinearMap, Vec};

#[cfg(feature = "_proto-fragmentation")]
use super::fragmentation::FragKey;
#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
use super::fragmentation::{Fragmenter, FragmentsBuffer};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::socket_set::SocketSet;
#[cfg(feature = "proto-rpl")]
use super::RplConfig;
use crate::config::{
    IFACE_MAX_ADDR_COUNT, IFACE_MAX_MULTICAST_GROUP_COUNT,
    IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT,
};
use crate::iface::Routes;
use crate::phy::PacketMeta;
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}
use check;

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface {
    pub(crate) inner: InterfaceInner,
    fragments: FragmentsBuffer,
    fragmenter: Fragmenter,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: NeighborCache,
    hardware_addr: HardwareAddress,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_id: u16,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context:
        Vec<SixlowpanAddressContext, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    ip_addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: LinearMap<Ipv4Address, (), IFACE_MAX_MULTICAST_GROUP_COUNT>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,

    #[cfg(feature = "proto-rpl")]
    rpl: super::Rpl,
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub pan_id: Option<Ieee802154Pan>,

    #[cfg(feature = "proto-rpl")]
    pub rpl_config: Option<RplConfig>,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            hardware_addr,
            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,
            #[cfg(feature = "proto-rpl")]
            rpl_config: None,
        }
    }
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the [`Config::hardware_address`] does not match
    /// the medium of the device.
    pub fn new<D>(config: Config, device: &mut D, now: Instant) -> Self
    where
        D: Device + ?Sized,
    {
        let caps = device.capabilities();
        assert_eq!(
            config.hardware_addr.medium(),
            caps.medium,
            "The hardware address does not match the medium of the interface."
        );

        let mut rand = Rand::new(config.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = rand.rand_u16();
            if tag != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-ipv4")]
        let mut ipv4_id;

        #[cfg(feature = "proto-ipv4")]
        loop {
            ipv4_id = rand.rand_u16();
            if ipv4_id != 0 {
                break;
            }
        }

        Interface {
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-sixlowpan")]
                decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],

                #[cfg(feature = "_proto-fragmentation")]
                assembler: PacketAssemblerSet::new(),
                #[cfg(feature = "_proto-fragmentation")]
                reassembly_timeout: Duration::from_secs(60),
            },
            fragmenter: Fragmenter::new(),
            inner: InterfaceInner {
                now,
                caps,
                hardware_addr: config.hardware_addr,
                ip_addrs: Vec::new(),
                #[cfg(feature = "proto-ipv4")]
                any_ip: false,
                routes: Routes::new(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: NeighborCache::new(),
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: LinearMap::new(),
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: config.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_id,
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: Vec::new(),
                rand,

                #[cfg(feature = "proto-rpl")]
                rpl: super::Rpl::new(config.rpl_config.unwrap(), now),
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&self) -> &InterfaceInner {
        &self.inner
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context_mut(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        self.inner.hardware_addr
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = addr;
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.inner.ipv6_addr()
    }

    /// Get an address from the interface that could be used as source address. For IPv4, this is
    /// the first IPv4 address from the list of addresses. For IPv6, the address is based on the
    /// destination address and uses RFC6724 for selecting the source address.
    pub fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.inner.get_source_address(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. This is the first
    /// IPv4 address from the list of addresses in the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        self.inner.get_source_address_ipv4(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. The selection is
    /// based on RFC6724.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        self.inner.get_source_address_ipv6(dst_addr)
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr, IFACE_MAX_ADDR_COUNT>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_neighbor_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// AnyIP allowins packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [`routes`](Self::routes) specifies one of
    /// the interface's [`ip_addrs`](Self::ip_addrs) as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    #[cfg(feature = "proto-ipv4")]
    pub fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Get whether AnyIP is enabled.
    ///
    /// See [`set_any_ip`](Self::set_any_ip) for details on AnyIP
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(&self) -> bool {
        self.inner.any_ip
    }

    /// Get the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.reassembly_timeout
    }

    /// Set the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        if timeout > Duration::from_secs(60) {
            net_debug!("RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds");
        }
        self.fragments.reassembly_timeout = timeout;
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    pub fn poll<D>(
        &mut self,
        timestamp: Instant,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.fragments.assembler.remove_expired(timestamp);

        match self.inner.caps.medium {
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 =>
            {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                if self.sixlowpan_egress(device) {
                    return true;
                }
            }
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
            _ =>
            {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                if self.ipv4_egress(device) {
                    return true;
                }
            }
        }

        #[cfg(feature = "proto-rpl")]
        self.poll_rpl(device);

        let mut readiness_may_have_changed = false;

        loop {
            let mut did_something = false;
            did_something |= self.socket_ingress(device, sockets);
            did_something |= self.socket_egress(device, sockets);

            #[cfg(feature = "proto-igmp")]
            {
                did_something |= self.igmp_egress(device);
            }

            if did_something {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }

        readiness_may_have_changed
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        if !self.fragmenter.is_empty() {
            return Some(Instant::from_millis(0));
        }

        #[cfg(feature = "proto-rpl")]
        let poll_at_rpl = self.poll_at_rpl();

        let inner = &mut self.inner;
        let poll_at = sockets.items().filter_map(move |item| {
            let socket_poll_at = item.socket.poll_at(inner);
            match item
                .meta
                .poll_at(socket_poll_at, |ip_addr| inner.has_neighbor(&ip_addr))
            {
                PollAt::Ingress => None,
                PollAt::Time(instant) => Some(instant),
                PollAt::Now => Some(Instant::from_millis(0)),
            }
        });

        #[cfg(feature = "proto-rpl")]
        let poll_at = poll_at.chain(core::iter::once(poll_at_rpl));

        poll_at.min()
    }

    #[cfg(feature = "proto-rpl")]
    fn poll_rpl<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        use crate::iface::interface::rpl::create_source_routing_header;

        fn transmit<D>(
            ctx: &mut InterfaceInner,
            device: &mut D,
            packet: IpPacket,
            fragmenter: &mut Fragmenter,
        ) -> bool
        where
            D: Device + ?Sized,
        {
            let Some(tx_token) = device.transmit(ctx.now) else {
                return false;
            };

            match ctx.dispatch_ip(tx_token, PacketMeta::default(), packet, fragmenter) {
                Ok(()) => true,
                Err(e) => {
                    net_debug!("failed to send packet: {:?}", e);
                    false
                }
            }
        }

        let Interface {
            inner: ctx,
            fragmenter,
            ..
        } = self;

        // When we are not the root and we are not part of any DODAG, make sure to transmit
        // a DODAG Information Solicitation (DIS) message. Only transmit this message when
        // the DIS timer is expired.
        if !ctx.rpl.is_root && ctx.rpl.dodag.is_none() && ctx.now >= ctx.rpl.dis_expiration {
            net_trace!("transmitting RPL DIS");
            ctx.rpl.dis_expiration = ctx.now + Duration::from_secs(60);

            let dis = RplRepr::DodagInformationSolicitation(RplDis {
                options: Default::default(),
            });
            let icmp_rpl = Icmpv6Repr::Rpl(dis);

            let ipv6_repr = Ipv6Repr {
                src_addr: ctx.ipv6_addr().unwrap(),
                dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_rpl.buffer_len(),
                hop_limit: 64,
            };

            return transmit(
                ctx,
                device,
                IpPacket::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp_rpl)),
                fragmenter,
            );
        }

        let our_addr = ctx.ipv6_addr().unwrap();
        let Some(dodag) = &mut ctx.rpl.dodag else {
            return false;
        };

        // Remove stale relations and increment the DTSN when we actually removed
        // a relation. This means that a node forgot to retransmit a DAO on time.
        #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if dodag.relations.purge(ctx.now) {
            use crate::iface::rpl::ModeOfOperation;
            if match ctx.rpl.mode_of_operation {
                #[cfg(feature = "rpl-mop-1")]
                ModeOfOperation::NonStoringMode if ctx.rpl.is_root => true,
                #[cfg(feature = "rpl-mop-2")]
                ModeOfOperation::StoringMode => true,
                #[cfg(feature = "rpl-mop-3")]
                ModeOfOperation::StoringModeWithMulticast => true,
                _ => false,
            } && dodag.dtsn_incremented_at < dodag.dio_timer.next_expiration()
            {
                net_trace!("incrementing DTSN");
                dodag.dtsn_incremented_at = dodag.dio_timer.next_expiration();
                dodag.dtsn.increment();
            }
        }

        // Schedule a DAO before the route will expire.
        if let Some(parent_address) = dodag.parent {
            let parent = dodag.parent_set.find(&parent_address).unwrap();

            // If we did not hear from our parent for some time,
            // remove our parent. Ideally, we should check if we could find another parent.
            if parent.last_heard < ctx.now - dodag.dio_timer.max_expiration() * 2 {
                dodag.remove_parent(ctx.rpl.mode_of_operation, our_addr, &ctx.rpl.of, ctx.now);

                net_trace!("transmitting DIO (INFINITE rank)");
                let mut options = heapless::Vec::new();
                options.push(ctx.rpl.dodag_configuration()).unwrap();

                let icmp = Icmpv6Repr::Rpl(ctx.rpl.dodag_information_object(options));

                let ipv6_repr = Ipv6Repr {
                    src_addr: ctx.ipv6_addr().unwrap(),
                    dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                };

                return transmit(
                    ctx,
                    device,
                    IpPacket::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp)),
                    fragmenter,
                );
            }

            if dodag.dao_expiration <= ctx.now {
                dodag.schedule_dao(ctx.rpl.mode_of_operation, our_addr, parent_address, ctx.now);
            }
        }

        // Transmit any DAO-ACK that are queued.
        #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if !dodag.dao_acks.is_empty() {
            // Transmit all the DAO-ACKs that are still queued.
            net_trace!("transmit DAO-ACK");

            let (mut dst_addr, seq) = dodag.dao_acks.pop().unwrap();
            let rpl_instance_id = dodag.instance_id;
            let icmp = Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObjectAck(RplDaoAck {
                rpl_instance_id,
                sequence: seq.value(),
                status: 0,
                dodag_id: if rpl_instance_id.is_local() {
                    Some(dodag.id)
                } else {
                    None
                },
            }));

            // A DAO-ACK always goes down. In MOP1, both Hop-by-Hop option and source
            // routing header MAY be included. However, a source routing header must always
            // be included when it is going down.
            use crate::iface::RplModeOfOperation;
            let routing = if matches!(
                ctx.rpl.mode_of_operation,
                RplModeOfOperation::NonStoringMode
            ) && ctx.rpl.is_root
            {
                net_trace!("creating source routing header to {}", dst_addr);
                if let Some((source_route, new_dst_addr)) =
                    create_source_routing_header(ctx, our_addr, dst_addr)
                {
                    dst_addr = new_dst_addr;
                    Some(source_route)
                } else {
                    None
                }
            } else {
                None
            };

            let ip_packet = super::ip_packet::Ipv6Packet {
                header: Ipv6Repr {
                    src_addr: ctx.ipv6_addr().unwrap(),
                    dst_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                },
                hop_by_hop: None,
                routing,
                payload: IpPayload::Icmpv6(icmp),
            };
            return transmit(ctx, device, IpPacket::Ipv6(ip_packet), fragmenter);
        }

        // Transmit any DAO that are queued.
        #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if !dodag.daos.is_empty() {
            // Remove DAOs that have been transmitted 3 times and did not get acknowledged.
            // TODO: we should be able to remove the parent when it was actually not acknowledged
            // after 3 times. This means that there is no valid path to the parent.
            dodag.daos.retain(|dao| dao.sent_count < 4);

            // Go over each queued DAO and check if they need to be transmitted.
            dodag.daos.iter_mut().for_each(|dao| {
                if !dao.needs_sending {
                    let Some(next_tx) = dao.next_tx else {
                        dao.next_tx = Some(ctx.now + dodag.dio_timer.min_expiration());
                        return;
                    };

                    if next_tx < ctx.now {
                        dao.needs_sending = true;
                    }
                }
            });

            if let Some(dao) = dodag.daos.iter_mut().find(|dao| dao.needs_sending) {
                dao.next_tx = Some(ctx.now + Duration::from_secs(60));
                dao.sent_count += 1;
                dao.needs_sending = false;
                let dst_addr = dao.to;

                let icmp = Icmpv6Repr::Rpl(dao.as_rpl_dao_repr());

                let mut options = heapless::Vec::new();
                options
                    .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                        down: ctx.rpl.is_root,
                        rank_error: false,
                        forwarding_error: false,
                        instance_id: dodag.instance_id,
                        sender_rank: dodag.rank.raw_value(),
                    }))
                    .unwrap();

                let hbh = Ipv6HopByHopRepr { options };

                let ip_packet = super::ip_packet::Ipv6Packet {
                    header: Ipv6Repr {
                        src_addr: our_addr,
                        dst_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: icmp.buffer_len(),
                        hop_limit: 64,
                    },
                    hop_by_hop: Some(hbh),
                    routing: None,
                    payload: IpPayload::Icmpv6(icmp),
                };
                net_trace!("transmitting DAO");
                return transmit(ctx, device, IpPacket::Ipv6(ip_packet), fragmenter);
            }
        }

        // When we are part of a DODAG, we should check if our DIO Trickle timer
        // expired. If it expires, a DODAG Information Object (DIO) should be
        // transmitted.
        if (ctx.rpl.is_root || dodag.parent.is_some())
            && dodag.dio_timer.poll(ctx.now, &mut ctx.rand)
        {
            net_trace!("transmitting DIO");

            let mut options = heapless::Vec::new();
            options.push(ctx.rpl.dodag_configuration()).unwrap();

            let icmp = Icmpv6Repr::Rpl(ctx.rpl.dodag_information_object(options));

            let ipv6_repr = Ipv6Repr {
                src_addr: our_addr,
                dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp.buffer_len(),
                hop_limit: 64,
            };

            return transmit(
                ctx,
                device,
                IpPacket::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp)),
                fragmenter,
            );
        }

        false
    }

    #[cfg(feature = "proto-rpl")]
    fn poll_at_rpl(&mut self) -> Instant {
        let ctx = self.context();

        if let Some(dodag) = &ctx.rpl.dodag {
            if !dodag.daos.is_empty() || !dodag.dao_acks.is_empty() {
                Instant::from_millis(0)
            } else {
                dodag.dio_timer.poll_at()
            }
        } else {
            ctx.rpl.dis_expiration
        }
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let mut processed_any = false;

        while let Some((rx_token, tx_token)) = device.receive(self.inner.now) {
            let rx_meta = rx_token.meta();
            rx_token.consume(|frame| {
                if frame.is_empty() {
                    return;
                }

                match self.inner.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        if let Some(packet) = self.inner.process_ethernet(
                            sockets,
                            rx_meta,
                            frame,
                            &mut self.fragments,
                        ) {
                            if let Err(err) =
                                self.inner.dispatch(tx_token, packet, &mut self.fragmenter)
                            {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => {
                        if let Some(packet) =
                            self.inner
                                .process_ip(sockets, rx_meta, frame, &mut self.fragments)
                        {
                            if let Err(err) = self.inner.dispatch_ip(
                                tx_token,
                                PacketMeta::default(),
                                packet,
                                &mut self.fragmenter,
                            ) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        if let Some(packet) = self.inner.process_ieee802154(
                            sockets,
                            rx_meta,
                            frame,
                            &mut self.fragments,
                        ) {
                            if let Err(err) = self.inner.dispatch_ip(
                                tx_token,
                                PacketMeta::default(),
                                packet,
                                &mut self.fragmenter,
                            ) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        }
                    }
                }
                processed_any = true;
            });
        }

        processed_any
    }

    fn socket_egress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let _caps = device.capabilities();

        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        let mut emitted_any = false;
        for item in sockets.items_mut() {
            if !item
                .meta
                .egress_permitted(self.inner.now, |ip_addr| self.inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut respond = |inner: &mut InterfaceInner, meta: PacketMeta, response: Packet| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                let t = device.transmit(inner.now).ok_or_else(|| {
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                inner
                    .dispatch_ip(t, meta, response, &mut self.fragmenter)
                    .map_err(EgressError::Dispatch)?;

                emitted_any = true;

                Ok(())
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut self.inner, |inner, (ip, raw)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Raw(raw)),
                    )
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, response| match response {
                        #[cfg(feature = "proto-ipv4")]
                        (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ipv4_repr, IpPayload::Icmpv4(icmpv4_repr)),
                        ),
                        #[cfg(feature = "proto-ipv6")]
                        (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmpv6_repr)),
                        ),
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    })
                }
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, meta, (ip, udp, payload)| {
                        respond(inner, meta, Packet::new(ip, IpPayload::Udp(udp, payload)))
                    })
                }
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(&mut self.inner, |inner, (ip, tcp)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Tcp(tcp)),
                    )
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => {
                    socket.dispatch(&mut self.inner, |inner, (ip, udp, dhcp)| {
                        respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ip, IpPayload::Dhcpv4(udp, dhcp)),
                        )
                    })
                }
                #[cfg(feature = "socket-dns")]
                Socket::Dns(socket) => socket.dispatch(&mut self.inner, |inner, (ip, udp, dns)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Udp(udp, dns)),
                    )
                }),
            };

            match result {
                Err(EgressError::Exhausted) => break, // Device buffer full.
                Err(EgressError::Dispatch(_)) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        self.inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                }
                Ok(()) => {}
            }
        }
        emitted_any
    }
}

impl InterfaceInner {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(|a| a.into()),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => Some(self.get_source_address_ipv6(addr).into()),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false` when using IPv4.
    fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) => {
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS
                    || self.ipv4_multicast_groups.get(&key).is_some()
            }
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_NODES) => true,
            #[cfg(feature = "proto-rpl")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES) => true,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => self.has_solicited_node(addr),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ip_payload: &'frame [u8],
        frag: &'frame mut FragmentsBuffer,
    ) -> Option<Packet<'frame>> {
        match IpVersion::of_packet(ip_payload) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(ip_payload));

                self.process_ipv4(sockets, meta, &ipv4_packet, frag)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(ip_payload));
                self.process_ipv6(None, sockets, meta, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| raw::Socket::downcast_mut(&mut i.socket))
        {
            if raw_socket.accepts(ip_repr) {
                raw_socket.process(self, ip_repr, ip_payload);
                handled_by_raw_socket = true;
            }
        }
        handled_by_raw_socket
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => {
                self.dispatch_ip(tx_token, PacketMeta::default(), packet, frag)
            }
        }
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        // Send directly.
        // note: no need to use `self.is_broadcast()` to check for subnet-local broadcast addrs
        //       here because `in_same_network` will already return true.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        // Route via a router.
        self.routes.lookup(addr, timestamp)
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Some(_routed_addr) => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            None => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        fragmenter: &mut Fragmenter,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
    where
        Tx: TxToken,
    {
        if self.is_broadcast(dst_addr) {
            let hardware_addr = match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x01,
                        0x00,
                        0x5e,
                        b[1] & 0x7F,
                        b[2],
                        b[3],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => unreachable!(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x33, 0x33, b[12], b[13], b[14], b[15],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self
            .route(dst_addr, self.now)
            .ok_or(DispatchError::NoRoute)?;

        #[cfg(feature = "proto-rpl")]
        let dst_addr = if let IpAddress::Ipv6(dst_addr) = dst_addr {
            if let Some(next_hop) = self
                .rpl
                .dodag
                .as_ref()
                .unwrap()
                .relations
                .find_next_hop(dst_addr)
            {
                if next_hop == self.ipv6_addr().unwrap() {
                    dst_addr.into()
                } else {
                    net_trace!("next hop {}", next_hop);
                    next_hop.into()
                }
            } else {
                dst_addr.into()
            }
        } else {
            dst_addr
        };

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => {
                net_debug!("neighbor {} pending", dst_addr);
                return Err(DispatchError::NeighborPending);
            }
            NeighborAnswer::NotFound => match (src_addr, dst_addr) {
                #[cfg(feature = "proto-ipv4")]
                (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                    net_debug!(
                        "address {} not in neighbor cache, sending ARP request",
                        dst_addr
                    );
                    let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                    let arp_repr = ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Request,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: src_addr,
                        target_hardware_addr: EthernetAddress::BROADCAST,
                        target_protocol_addr: dst_addr,
                    };

                    if let Err(e) =
                        self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                            frame.set_dst_addr(EthernetAddress::BROADCAST);
                            frame.set_ethertype(EthernetProtocol::Arp);

                            arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                        })
                    {
                        net_debug!("Failed to dispatch ARP request: {:?}", e);
                        return Err(DispatchError::NeighborPending);
                    }
                }

                #[cfg(all(feature = "proto-ipv6", feature = "proto-rpl"))]
                (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                    if let Some(parent) = self.rpl.dodag.as_ref().unwrap().parent {
                        if let NeighborAnswer::Found(hardware_addr) =
                            self.neighbor_cache.lookup(&parent.into(), self.now)
                        {
                            return Ok((hardware_addr, tx_token));
                        }
                    }
                }

                #[cfg(all(feature = "proto-ipv6", not(feature = "proto-rpl")))]
                (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                    net_debug!(
                        "address {} not in neighbor cache, sending Neighbor Solicitation",
                        dst_addr
                    );

                    let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                        target_addr: dst_addr,
                        lladdr: Some(self.hardware_addr.into()),
                    });

                    let packet = Packet::new_ipv6(
                        Ipv6Repr {
                            src_addr,
                            dst_addr: dst_addr.solicited_node(),
                            next_header: IpProtocol::Icmpv6,
                            payload_len: solicit.buffer_len(),
                            hop_limit: 0xff,
                        },
                        IpPayload::Icmpv6(solicit),
                    );

                    if let Err(e) =
                        self.dispatch_ip(tx_token, PacketMeta::default(), packet, fragmenter)
                    {
                        net_debug!("Failed to dispatch NDISC solicit: {:?}", e);
                        return Err(DispatchError::NeighborPending);
                    }
                }

                #[allow(unreachable_patterns)]
                _ => (),
            },
        }

        // The request got dispatched, limit the rate on the cache.
        net_debug!("request dispatched, limiting rate on cache");
        self.neighbor_cache.limit_rate(self.now);
        Err(DispatchError::NeighborPending)
    }

    fn flush_neighbor_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        self.neighbor_cache.flush()
    }

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError> {
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.caps.medium, Medium::Ieee802154) {
            let (addr, tx_token) = self.lookup_hardware_addr(
                tx_token,
                &ip_repr.src_addr(),
                &ip_repr.dst_addr(),
                frag,
            )?;
            let addr = addr.ieee802154_or_panic();

            self.dispatch_ieee802154(addr, tx_token, meta, packet, frag);
            return Ok(());
        }

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ipv4_id = self.next_ipv4_frag_ident();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        #[cfg(feature = "medium-ethernet")]
        let (dst_hardware_addr, mut tx_token) = match self.caps.medium {
            Medium::Ethernet => {
                match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                    frag,
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    (_, _) => unreachable!(),
                }
            }
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }

            Ok(())
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, mut tx_buffer: &mut [u8]| {
            repr.emit(&mut tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        let total_ip_len = ip_repr.buffer_len();

        match &mut ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(repr) => {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                if total_ip_len > self.caps.max_transmission_unit {
                    #[cfg(feature = "proto-ipv4-fragmentation")]
                    {
                        net_debug!("start fragmentation");

                        // Calculate how much we will send now (including the Ethernet header).
                        let tx_len = self.caps.max_transmission_unit;

                        let ip_header_len = repr.buffer_len();
                        let first_frag_ip_len = self.caps.ip_mtu();

                        if frag.buffer.len() < total_ip_len {
                            net_debug!(
                                "Fragmentation buffer is too small, at least {} needed. Dropping",
                                total_ip_len
                            );
                            return Ok(());
                        }

                        #[cfg(feature = "medium-ethernet")]
                        {
                            frag.ipv4.dst_hardware_addr = dst_hardware_addr;
                        }

                        // Save the total packet len (without the Ethernet header, but with the first
                        // IP header).
                        frag.packet_len = total_ip_len;

                        // Save the IP header for other fragments.
                        frag.ipv4.repr = *repr;

                        // Save how much bytes we will send now.
                        frag.sent_bytes = first_frag_ip_len;

                        // Modify the IP header
                        repr.payload_len = first_frag_ip_len - repr.buffer_len();

                        // Emit the IP header to the buffer.
                        emit_ip(&ip_repr, &mut frag.buffer);

                        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut frag.buffer[..]);
                        frag.ipv4.ident = ipv4_id;
                        ipv4_packet.set_ident(ipv4_id);
                        ipv4_packet.set_more_frags(true);
                        ipv4_packet.set_dont_frag(false);
                        ipv4_packet.set_frag_offset(0);

                        if caps.checksum.ipv4.tx() {
                            ipv4_packet.fill_checksum();
                        }

                        // Transmit the first packet.
                        tx_token.consume(tx_len, |mut tx_buffer| {
                            #[cfg(feature = "medium-ethernet")]
                            if matches!(self.caps.medium, Medium::Ethernet) {
                                emit_ethernet(&ip_repr, tx_buffer)?;
                                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                            }

                            // Change the offset for the next packet.
                            frag.ipv4.frag_offset = (first_frag_ip_len - ip_header_len) as u16;

                            // Copy the IP header and the payload.
                            tx_buffer[..first_frag_ip_len]
                                .copy_from_slice(&frag.buffer[..first_frag_ip_len]);

                            Ok(())
                        })
                    }

                    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                    {
                        net_debug!("Enable the `proto-ipv4-fragmentation` feature for fragmentation support.");
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    // No fragmentation is required.
                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer)?;
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                        Ok(())
                    })
                }
            }
            // We don't support IPv6 fragmentation yet.
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) => tx_token.consume(total_len, |mut tx_buffer| {
                #[cfg(feature = "medium-ethernet")]
                if matches!(self.caps.medium, Medium::Ethernet) {
                    emit_ethernet(&ip_repr, tx_buffer)?;
                    tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                }

                emit_ip(&ip_repr, tx_buffer);
                Ok(())
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
