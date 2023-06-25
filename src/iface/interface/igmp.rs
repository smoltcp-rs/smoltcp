use super::{check, IgmpReportState, Interface, InterfaceInner, IpPacket};
use crate::phy::{Device, PacketMeta};
use crate::time::{Duration, Instant};
use crate::wire::*;

use core::result::Result;

/// Error type for `join_multicast_group`, `leave_multicast_group`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MulticastError {
    /// The hardware device transmit buffer is full. Try again later.
    Exhausted,
    /// The table of joined multicast groups is already full.
    GroupTableFull,
    /// IPv6 multicast is not yet supported.
    Ipv6NotSupported,
}

impl core::fmt::Display for MulticastError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            MulticastError::Exhausted => write!(f, "Exhausted"),
            MulticastError::GroupTableFull => write!(f, "GroupTableFull"),
            MulticastError::Ipv6NotSupported => write!(f, "Ipv6NotSupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MulticastError {}

impl Interface {
    /// Add an address to a list of subscribed multicast IP addresses.
    ///
    /// Returns `Ok(announce_sent)` if the address was added successfully, where `annouce_sent`
    /// indicates whether an initial immediate announcement has been sent.
    pub fn join_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool, MulticastError>
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        match addr.into() {
            IpAddress::Ipv4(addr) => {
                let is_not_new = self
                    .inner
                    .ipv4_multicast_groups
                    .insert(addr, ())
                    .map_err(|_| MulticastError::GroupTableFull)?
                    .is_some();
                if is_not_new {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_report_packet(IgmpVersion::Version2, addr)
                {
                    // Send initial membership report
                    let tx_token = device
                        .transmit(timestamp)
                        .ok_or(MulticastError::Exhausted)?;

                    // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                    self.inner
                        .dispatch_ip(tx_token, PacketMeta::default(), pkt, &mut self.fragmenter)
                        .unwrap();

                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
            _ => Err(MulticastError::Ipv6NotSupported),
        }
    }

    /// Remove an address from the subscribed multicast IP addresses.
    ///
    /// Returns `Ok(leave_sent)` if the address was removed successfully, where `leave_sent`
    /// indicates whether an immediate leave packet has been sent.
    pub fn leave_multicast_group<D, T: Into<IpAddress>>(
        &mut self,
        device: &mut D,
        addr: T,
        timestamp: Instant,
    ) -> Result<bool, MulticastError>
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        match addr.into() {
            IpAddress::Ipv4(addr) => {
                let was_not_present = self.inner.ipv4_multicast_groups.remove(&addr).is_none();
                if was_not_present {
                    Ok(false)
                } else if let Some(pkt) = self.inner.igmp_leave_packet(addr) {
                    // Send group leave packet
                    let tx_token = device
                        .transmit(timestamp)
                        .ok_or(MulticastError::Exhausted)?;

                    // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                    self.inner
                        .dispatch_ip(tx_token, PacketMeta::default(), pkt, &mut self.fragmenter)
                        .unwrap();

                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Multicast is not yet implemented for other address families
            #[allow(unreachable_patterns)]
            _ => Err(MulticastError::Ipv6NotSupported),
        }
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_multicast_group(addr)
    }

    /// Depending on `igmp_report_state` and the therein contained
    /// timeouts, send IGMP membership reports.
    pub(crate) fn igmp_egress<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        match self.inner.igmp_report_state {
            IgmpReportState::ToSpecificQuery {
                version,
                timeout,
                group,
            } if self.inner.now >= timeout => {
                if let Some(pkt) = self.inner.igmp_report_packet(version, group) {
                    // Send initial membership report
                    if let Some(tx_token) = device.transmit(self.inner.now) {
                        // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                        self.inner
                            .dispatch_ip(tx_token, PacketMeta::default(), pkt, &mut self.fragmenter)
                            .unwrap();
                    } else {
                        return false;
                    }
                }

                self.inner.igmp_report_state = IgmpReportState::Inactive;
                true
            }
            IgmpReportState::ToGeneralQuery {
                version,
                timeout,
                interval,
                next_index,
            } if self.inner.now >= timeout => {
                let addr = self
                    .inner
                    .ipv4_multicast_groups
                    .iter()
                    .nth(next_index)
                    .map(|(addr, ())| *addr);

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.inner.igmp_report_packet(version, addr) {
                            // Send initial membership report
                            if let Some(tx_token) = device.transmit(self.inner.now) {
                                // NOTE(unwrap): packet destination is multicast, which is always routable and doesn't require neighbor discovery.
                                self.inner
                                    .dispatch_ip(
                                        tx_token,
                                        PacketMeta::default(),
                                        pkt,
                                        &mut self.fragmenter,
                                    )
                                    .unwrap();
                            } else {
                                return false;
                            }
                        }

                        let next_timeout = (timeout + interval).max(self.inner.now);
                        self.inner.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: next_timeout,
                            interval,
                            next_index: next_index + 1,
                        };
                        true
                    }

                    None => {
                        self.inner.igmp_report_state = IgmpReportState::Inactive;
                        false
                    }
                }
            }
            _ => false,
        }
    }
}

impl InterfaceInner {
    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false`.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            IpAddress::Ipv4(key) => {
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS
                    || self.ipv4_multicast_groups.get(&key).is_some()
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    pub(super) fn process_igmp<'frame>(
        &mut self,
        ipv4_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let igmp_packet = check!(IgmpPacket::new_checked(ip_payload));
        let igmp_repr = check!(IgmpRepr::parse(&igmp_packet));

        // FIXME: report membership after a delay
        match igmp_repr {
            IgmpRepr::MembershipQuery {
                group_addr,
                version,
                max_resp_time,
            } => {
                // General query
                if group_addr.is_unspecified()
                    && ipv4_repr.dst_addr == Ipv4Address::MULTICAST_ALL_SYSTEMS
                {
                    // Are we member in any groups?
                    if self.ipv4_multicast_groups.iter().next().is_some() {
                        let interval = match version {
                            IgmpVersion::Version1 => Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = self.ipv4_multicast_groups.len() as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: self.now + interval,
                            interval,
                            next_index: 0,
                        };
                    }
                } else {
                    // Group-specific query
                    if self.has_multicast_group(group_addr) && ipv4_repr.dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version,
                            timeout: self.now + timeout,
                            group: group_addr,
                        };
                    }
                }
            }
            // Ignore membership reports
            IgmpRepr::MembershipReport { .. } => (),
            // Ignore hosts leaving groups
            IgmpRepr::LeaveGroup { .. } => (),
        }

        None
    }
}
