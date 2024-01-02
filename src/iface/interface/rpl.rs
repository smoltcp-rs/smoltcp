use super::*;

#[cfg(feature = "rpl-mop-1")]
use crate::wire::Ipv6RoutingRepr;

#[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
use crate::wire::{Ipv6HopByHopRepr, Ipv6OptionRepr, RplDao, RplDaoAck};

use crate::iface::rpl::*;
use heapless::Vec;

impl Interface {
    pub(super) fn poll_rpl<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        fn transmit<D>(
            ctx: &mut InterfaceInner,
            device: &mut D,
            packet: Packet,
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
                Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp_rpl)),
                fragmenter,
            );
        }

        let our_addr = ctx.ipv6_addr().unwrap();
        let Some(dodag) = &mut ctx.rpl.dodag else {
            return false;
        };

        flush_relations(ctx.rpl.mode_of_operation, dodag, ctx.rpl.is_root, ctx.now);

        // Schedule a DAO before the route will expire.
        if let Some(parent_address) = dodag.parent {
            let parent = dodag.parent_set.find(&parent_address).unwrap();

            // If we did not hear from our parent for some time,
            // remove our parent. Ideally, we should check if we could find another parent.
            if parent.last_heard < ctx.now - dodag.dio_timer.max_expiration() * 2 {
                dodag.remove_parent(
                    ctx.rpl.mode_of_operation,
                    our_addr,
                    &ctx.rpl.of,
                    ctx.now,
                    &mut ctx.rand,
                );

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

                ctx.rpl.dodag = None;
                ctx.rpl.dis_expiration = ctx.now + Duration::from_secs(5);

                return transmit(
                    ctx,
                    device,
                    Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp)),
                    fragmenter,
                );
            }

            #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
            if dodag.dao_expiration <= ctx.now {
                dodag.schedule_dao(ctx.rpl.mode_of_operation, our_addr, parent_address, ctx.now);
            }
        }

        // Transmit any DAO-ACK that are queued.
        #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if !dodag.dao_acks.is_empty() {
            // Transmit all the DAO-ACKs that are still queued.
            net_trace!("transmit DAO-ACK");

            #[allow(unused_mut)]
            let (mut dst_addr, sequence) = dodag.dao_acks.pop().unwrap();
            let rpl_instance_id = dodag.instance_id;
            let icmp = Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObjectAck(RplDaoAck {
                rpl_instance_id,
                sequence,
                status: 0,
                dodag_id: if rpl_instance_id.is_local() {
                    Some(dodag.id)
                } else {
                    None
                },
            }));

            let mut options = heapless::Vec::new();
            options
                .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                    down: true,
                    rank_error: false,
                    forwarding_error: false,
                    instance_id: ctx.rpl.dodag.as_ref().unwrap().instance_id,
                    sender_rank: ctx.rpl.dodag.as_ref().unwrap().rank.raw_value(),
                }))
                .unwrap();
            #[allow(unused_mut)]
            let mut hop_by_hop = Some(Ipv6HopByHopRepr { options });

            // A DAO-ACK always goes down. In MOP1, both Hop-by-Hop option and source
            // routing header MAY be included. However, a source routing header must always
            // be included when it is going down.
            #[cfg(feature = "rpl-mop-1")]
            let routing = if matches!(ctx.rpl.mode_of_operation, ModeOfOperation::NonStoringMode)
                && ctx.rpl.is_root
            {
                net_trace!("creating source routing header to {}", dst_addr);
                if let Some((source_route, new_dst_addr)) =
                    create_source_routing_header(ctx, our_addr, dst_addr)
                {
                    hop_by_hop = None;
                    dst_addr = new_dst_addr;
                    Some(source_route)
                } else {
                    None
                }
            } else {
                None
            };

            #[cfg(not(feature = "rpl-mop-1"))]
            let routing = None;

            let ip_packet = PacketV6 {
                header: Ipv6Repr {
                    src_addr: ctx.ipv6_addr().unwrap(),
                    dst_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                },
                hop_by_hop,
                routing,
                payload: IpPayload::Icmpv6(icmp),
            };
            return transmit(ctx, device, Packet::Ipv6(ip_packet), fragmenter);
        }

        // Transmit any DAO that are queued.
        #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if !dodag.daos.is_empty() {
            // Remove DAOs that have been transmitted 3 times and did not get acknowledged.
            // TODO: we should be able to remove the parent when it was actually not acknowledged
            // after 3 times. This means that there is no valid path to the parent.
            dodag.daos.retain(|dao| {
                (!dao.is_no_path && dao.sent_count < 4) || (dao.is_no_path && dao.sent_count == 0)
            });

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
                        sender_rank: dao.rank.raw_value(),
                    }))
                    .unwrap();

                let hbh = Ipv6HopByHopRepr { options };

                let ip_packet = PacketV6 {
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
                return transmit(ctx, device, Packet::Ipv6(ip_packet), fragmenter);
            }
        }

        // When we are part of a DODAG, we should check if our DIO Trickle timer
        // expired. If it expires, a DODAG Information Object (DIO) should be
        // transmitted.
        if (ctx.rpl.is_root || dodag.parent.is_some())
            && dodag.dio_timer.poll(ctx.now, &mut ctx.rand)
        {
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
                Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmp)),
                fragmenter,
            );
        }

        false
    }

    pub(super) fn poll_at_rpl(&mut self) -> Instant {
        let ctx = self.context();

        if let Some(dodag) = &ctx.rpl.dodag {
            #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
            if !dodag.daos.is_empty() || !dodag.dao_acks.is_empty() {
                return Instant::from_millis(0);
            }

            dodag.dio_timer.poll_at()
        } else {
            ctx.rpl.dis_expiration
        }
    }
}

/// Flush old relations. When a relation was removed, we increment the DTSN, which will trigger
/// DAO's from our children.
fn flush_relations(
    mode_of_operation: ModeOfOperation,
    dodag: &mut Dodag,
    _is_root: bool,
    now: Instant,
) {
    // Remove stale relations and increment the DTSN when we actually removed
    // a relation. This means that a node forgot to retransmit a DAO on time.
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    if dodag.relations.flush(now)
        && match mode_of_operation {
            #[cfg(feature = "rpl-mop-1")]
            ModeOfOperation::NonStoringMode if _is_root => true,
            #[cfg(feature = "rpl-mop-2")]
            ModeOfOperation::StoringMode => true,
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => true,
            _ => false,
        }
    //&& dodag.dtsn_incremented_at < dodag.dio_timer.next_expiration()
    {
        net_trace!("incrementing DTSN");
        // FIXME: maybe this is not needed and we always increment the DTSN when we removed a
        // relation from the relation table.
        //dodag.dtsn_incremented_at = dodag.dio_timer.next_expiration();
        dodag.dtsn.increment();
    }
}

impl InterfaceInner {
    /// Get a reference to the RPL configuration.
    pub fn rpl(&self) -> &crate::iface::rpl::Rpl {
        &self.rpl
    }

    /// Process an incoming RPL packet.
    pub(super) fn process_rpl<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<Packet<'output>> {
        match repr {
            RplRepr::DodagInformationSolicitation(dis) => self.process_rpl_dis(ip_repr, dis),
            RplRepr::DodagInformationObject(dio) => self.process_rpl_dio(ip_repr, dio),
            #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
            RplRepr::DestinationAdvertisementObject(dao) => self.process_rpl_dao(ip_repr, dao),
            #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
            RplRepr::DestinationAdvertisementObjectAck(dao_ack) => {
                self.process_rpl_dao_ack(ip_repr, dao_ack)
            }
            #[allow(unreachable_patterns)]
            _ => {
                net_trace!("packet not supported in curent MOP");
                None
            }
        }
    }

    /// Process an incoming RPL DIS packet.
    pub(super) fn process_rpl_dis<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        dis: RplDis<'payload>,
    ) -> Option<Packet<'output>> {
        // We cannot handle a DIS when we are not part of any DODAG.
        let Some(dodag) = &mut self.rpl.dodag else {
            return None;
        };

        // Options that are expected: Pad1, PadN, Solicited Information.
        for opt in dis.options {
            // RFC6550 section 8.3:
            // The solicited information option is used for filtering incoming DIS
            // packets. This option will contain predicates, which we need to match on.
            // When we match all to requested predicates, then we answer with a DIO,
            // otherwise we just drop the packet.
            if let RplOptionRepr::SolicitedInformation(info) = opt {
                if (info.version_predicate && dodag.version_number != info.version_number)
                    || (info.dodag_id_predicate && dodag.id != info.dodag_id)
                    || (info.instance_id_predicate && dodag.instance_id != info.rpl_instance_id)
                {
                    net_trace!("predicates did not match, dropping packet");
                    return None;
                }
            }
        }

        // When receiving a unicast DIS message, we should respond with a unicast DIO,
        // containing the DODAG Information option, without resetting the Trickle timer.
        if ip_repr.dst_addr.is_unicast() {
            net_trace!("unicast DIS, sending unicast DIO");

            let mut options = Vec::new();
            _ = options.push(self.rpl.dodag_configuration());

            let dio = Icmpv6Repr::Rpl(self.rpl.dodag_information_object(options));

            Some(Packet::new_ipv6(
                Ipv6Repr {
                    src_addr: self.ipv6_addr().unwrap(),
                    dst_addr: ip_repr.src_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: dio.buffer_len(),
                    hop_limit: 64,
                },
                IpPayload::Icmpv6(dio),
            ))
        } else {
            net_trace!("received DIS, resetting trickle timer");

            // Resest the trickle timer (section 8.3)
            dodag.dio_timer.hear_inconsistency(self.now, &mut self.rand);

            None
        }
    }

    /// Process an incoming RPL DIO packet.
    pub(super) fn process_rpl_dio<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        dio: RplDio<'payload>,
    ) -> Option<Packet<'output>> {
        let mut dodag_configuration = None;

        // Options that are expected: Pad1, PadN, DAG Metric Container, Routing Information, DODAG
        // Configuration and Prefix Information.
        for opt in dio.options {
            match opt {
                RplOptionRepr::DagMetricContainer => {
                    // NOTE(thvdveld): We don't support DAG Metric containers yet. They contain
                    // information about node, link or path metrics specified in RFC6551. The
                    net_trace!("Dag Metric Container Option not yet supported");
                }
                RplOptionRepr::RouteInformation { .. } => {
                    // The root of a DODAG is responsible for setting the option values.

                    // NOTE: RIOT and Contiki-NG don't implement the handling of the route
                    // information option. smoltcp does not handle prefic information
                    // packets, neither does it handle the route information packets from
                    // RFC4191. Therefore, the infrastructure is not in place for handling
                    // this option in RPL. This is considered future work!
                    net_trace!("Route Information Option not yet supported");
                }
                // The root of a DODAG is responsible for setting the option values.
                // This information is propagated down the DODAG unchanged.
                RplOptionRepr::PrefixInformation { .. } => {
                    // FIXME(thvdveld): handle a prefix information option.
                    net_trace!("Prefix Information Option not yet supported");
                }
                // The dodag configuration option contains information about trickle timer,
                // default route lifetime, objective code point, etc.
                RplOptionRepr::DodagConfiguration(
                    conf @ RplDodagConfiguration {
                        objective_code_point,
                        ..
                    },
                ) => {
                    // If we are not part of a network, and the OCP is not the same as
                    // ours, then we don't accept the DIO packet.
                    if self.rpl.dodag.is_none()
                        && objective_code_point != self.rpl.of.objective_code_point()
                    {
                        net_trace!("dropping packet, OCP is not compatible");
                        return None;
                    }

                    dodag_configuration = Some(conf);
                }
                _ => {}
            }
        }

        let sender_rank = Rank::new(dio.rank, self.rpl.of.min_hop_rank_increase());

        // Accept DIO if not part of DODAG
        // ===============================
        // If we are not part of a DODAG, check the MOP and OCP. If they are the same as
        // ours, we copy the fields of the DIO and the DODAG Configuration. If we cannot
        // check the OCP (because the DODAG Configuration option is missing), then we
        // transmit a unicast DIS to the sender of the DIO we received. The sender MUST
        // respond with a unicast DIO with the option present.
        if !self.rpl.is_root
            && self.rpl.dodag.is_none()
            && ModeOfOperation::from(dio.mode_of_operation) == self.rpl.mode_of_operation
            && sender_rank != Rank::INFINITE
        {
            let Some(dodag_conf) = dodag_configuration else {
                // Send a unicast DIS.
                net_trace!("sending unicast DIS (to ask for DODAG Conf. option)");

                let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation(RplDis {
                    options: Default::default(),
                }));

                return Some(Packet::new_ipv6(
                    Ipv6Repr {
                        src_addr: self.ipv6_addr().unwrap(),
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: icmp.buffer_len(),
                        hop_limit: 64,
                    },
                    IpPayload::Icmpv6(icmp),
                ));
            };

            net_trace!(
                "accepting new RPL conf (grounded={} pref={} version={} InstanceID={:?} DODAGID={})",
                dio.grounded,
                dio.dodag_preference,
                dio.version_number,
                dio.rpl_instance_id,
                dio.dodag_id
            );

            self.rpl
                .of
                .set_min_hop_rank_increase(dodag_conf.minimum_hop_rank_increase);
            self.rpl
                .of
                .set_max_rank_increase(dodag_conf.max_rank_increase);

            let dodag = Dodag {
                instance_id: dio.rpl_instance_id,
                id: dio.dodag_id,
                version_number: dio.version_number,
                preference: dio.dodag_preference,
                rank: Rank::INFINITE,
                dio_timer: TrickleTimer::new(
                    dodag_conf.dio_interval_min as u32,
                    dodag_conf.dio_interval_min as u32 + dodag_conf.dio_interval_doublings as u32,
                    dodag_conf.dio_redundancy_constant as usize,
                ),
                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                dao_expiration: crate::time::Instant::ZERO,
                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                dao_seq_number: RplSequenceCounter::default(),
                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                dao_acks: Default::default(),
                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                daos: Default::default(),
                parent: None,
                without_parent: Some(self.now),
                authentication_enabled: dodag_conf.authentication_enabled,
                path_control_size: dodag_conf.path_control_size,
                dtsn: RplSequenceCounter::default(),
                dtsn_incremented_at: self.now,
                default_lifetime: dodag_conf.default_lifetime,
                lifetime_unit: dodag_conf.lifetime_unit,
                grounded: dio.grounded,
                parent_set: Default::default(),
                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                relations: Default::default(),
            };

            self.rpl.dodag = Some(dodag);
        }

        // The sender rank might be updated by the configuration option.
        let sender_rank = Rank::new(dio.rank, self.rpl.of.min_hop_rank_increase());

        let our_addr = self.ipv6_addr().unwrap();
        let dodag = self.rpl.dodag.as_mut()?;

        // Check DIO validity
        // ==================
        // We check if we can accept the DIO message:
        // 1. The RPL instance is the same as our RPL instance.
        // 2. The DODAG ID must be the same as our DODAG ID.
        // 3. The version number must be the same or higher than ours.
        // 4. The Mode of Operation must be the same as our Mode of Operation.
        // 5. The Objective Function must be the same as our Ojbective ObjectiveFunction,
        //    which we already checked.
        if dio.rpl_instance_id != dodag.instance_id
            || dio.dodag_id != dodag.id
            || dio.version_number < dodag.version_number
            || ModeOfOperation::from(dio.mode_of_operation) != self.rpl.mode_of_operation
        {
            net_trace!(
                "dropping DIO packet (different INSTANCE ID/DODAG ID/MOP/lower Version Number)"
            );
            return None;
        }

        // Global repair
        // =============
        // If the Version number is higher than ours, we need to clear our parent set,
        // remove our parent and reset our rank.
        //
        // When we are the root, we change the version number to one higher than the
        // received one. Then we reset the Trickle timer, such that the information is
        // propagated in the network.
        if dio.version_number > dodag.version_number {
            net_trace!("version number higher than ours");

            if self.rpl.is_root {
                net_trace!("(root) using new version number + 1");

                dodag.version_number = dio.version_number;
                dodag.version_number.increment();

                net_trace!("(root) resetting Trickle timer");
                // Reset the trickle timer.
                dodag.dio_timer.hear_inconsistency(self.now, &mut self.rand);
                return None;
            } else {
                net_trace!("resetting parent set, resetting rank, removing parent");

                dodag.version_number = dio.version_number;

                // Clear the parent set, .
                dodag.parent_set.clear();

                // We do NOT send a No-path DAO.
                let _ = dodag.remove_parent(
                    self.rpl.mode_of_operation,
                    our_addr,
                    &self.rpl.of,
                    self.now,
                    &mut self.rand,
                );

                let dio = Icmpv6Repr::Rpl(self.rpl.dodag_information_object(Default::default()));

                // Transmit a DIO with INFINITE rank, but with an updated Version number.
                // Everyone knows they have to leave the network and form a new one.
                return Some(Packet::new_ipv6(
                    Ipv6Repr {
                        src_addr: self.ipv6_addr().unwrap(),
                        dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: dio.buffer_len(),
                        hop_limit: 64,
                    },
                    IpPayload::Icmpv6(dio),
                ));
            }
        }

        if Some(ip_repr.src_addr) == dodag.parent {
            // If our parent transmits a DIO with an infinite rank, than it means that our
            // parent is leaving the network. Thus we should deselect it as our parent.
            // If there is no parent in the parent set, we also detach from the network by
            // sending a DIO with an infinite rank.
            if Rank::new(dio.rank, self.rpl.of.min_hop_rank_increase()) == Rank::INFINITE {
                net_trace!("parent leaving, removing parent");

                // Don't need to send a no-path DOA when parent is leaving.
                let _ = dodag.remove_parent(
                    self.rpl.mode_of_operation,
                    our_addr,
                    &self.rpl.of,
                    self.now,
                    &mut self.rand,
                );

                if dodag.parent.is_some() {
                    dodag.dio_timer.hear_inconsistency(self.now, &mut self.rand);
                } else {
                    net_trace!("no potential parents, leaving network");

                    // DIO with INFINITE rank.
                    let dio =
                        Icmpv6Repr::Rpl(self.rpl.dodag_information_object(Default::default()));

                    return Some(Packet::new_ipv6(
                        Ipv6Repr {
                            src_addr: self.ipv6_addr().unwrap(),
                            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                            next_header: IpProtocol::Icmpv6,
                            payload_len: dio.buffer_len(),
                            hop_limit: 64,
                        },
                        IpPayload::Icmpv6(dio),
                    ));
                }
            } else {
                // Update the time we last heard our parent.
                let Some(parent) = dodag.parent_set.find_mut(&dodag.parent.unwrap()) else {
                    unreachable!();
                };

                parent.last_heard = self.now;

                // RFC 6550 section 9.6:
                // If a node hears one of its parents increase the DTSN, the node MUST
                // schedule a DAO. In non-storing mode, a node should increment its own DTSN.
                if dio.dtsn > parent.dtsn {
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    {
                        net_trace!("DTSN increased, scheduling DAO");
                        dodag.dao_expiration = self.now;
                    }

                    #[cfg(feature = "rpl-mop-1")]
                    if matches!(self.rpl.mode_of_operation, ModeOfOperation::NonStoringMode) {
                        dodag.dtsn.increment();
                    }
                }

                // When we are not the root, we hear a consistency when the DIO message is from
                // our parent and is valid. The validity of the message should be checked when we
                // reach this line.
                dodag.dio_timer.hear_consistency();

                return None;
            }
        }

        // Add node to parent set
        // ======================
        // If the rank is smaller than ours, the instance id and the mode of operation is
        // the same as ours,, we can add the sender to our parent set.
        if sender_rank < dodag.rank && !self.rpl.is_root {
            if let Err(parent) = dodag.parent_set.add(Parent::new(
                ip_repr.src_addr,
                sender_rank,
                dio.version_number,
                dio.dtsn,
                dodag.id,
                self.now,
            )) {
                net_trace!("failed to add {} to parent set", parent.address);
            }

            // Select parent
            // =============
            // Send a no-path DAO to our old parent.
            // Select and schedule DAO to new parent.
            dodag.find_new_parent(
                self.rpl.mode_of_operation,
                our_addr,
                &self.rpl.of,
                self.now,
                &mut self.rand,
            );
        }

        // Trickle Consistency
        // ===================
        // We should increment the Trickle timer counter for a valid DIO message,
        // when we are the root, and the rank that is advertised in the DIO message is
        // not infinite (so we received a valid DIO from a child).
        if self.rpl.is_root && sender_rank != Rank::INFINITE {
            dodag.dio_timer.hear_consistency();
        }

        None
    }

    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(super) fn process_rpl_dao<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        dao: RplDao<'payload>,
    ) -> Option<Packet<'output>> {
        let our_addr = self.ipv6_addr().unwrap();
        let dodag = self.rpl.dodag.as_mut()?;

        // Check validity of the DAO
        if dodag.instance_id != dao.rpl_instance_id && Some(dodag.id) != dao.dodag_id {
            net_trace!("dropping DAO, wrong DODAG ID/INSTANCE ID");
            return None;
        }

        #[cfg(feature = "rpl-mop-0")]
        if matches!(
            self.rpl.mode_of_operation,
            ModeOfOperation::NoDownwardRoutesMaintained
        ) {
            net_trace!("dropping DAO, MOP0 does not support it");
            return None;
        }

        #[cfg(feature = "rpl-mop-1")]
        if matches!(self.rpl.mode_of_operation, ModeOfOperation::NonStoringMode)
            && !self.rpl.is_root
        {
            net_trace!("dropping DAO, MOP1 and not root");
            return None;
        }

        let mut targets: Vec<Ipv6Address, 8> = Vec::new();

        // Expected options: Pad1, PadN, RPL Target, Transit Information, RPL Target Descriptor.
        for opt in &dao.options {
            match opt {
                RplOptionRepr::RplTarget(target) => {
                    // FIXME: we only take care of IPv6 addresses.
                    // However, a RPL target can also be a prefix or a multicast group.
                    // When receiving such a message, it might break our implementation.
                    targets
                        .push(Ipv6Address::from_bytes(&target.prefix))
                        .unwrap();
                }
                RplOptionRepr::TransitInformation(transit) => {
                    if transit.path_lifetime == 0 {
                        // Remove all targets from the relation list since we received a NO-PATH
                        // DAO.
                        for target in &targets {
                            net_trace!("remove {} relation (NO-PATH)", target);
                            dodag.relations.remove_relation(*target);
                        }
                    } else {
                        let next_hop = match self.rpl.mode_of_operation {
                            #[cfg(feature = "rpl-mop-0")]
                            ModeOfOperation::NoDownwardRoutesMaintained => unreachable!(),
                            #[cfg(feature = "rpl-mop-1")]
                            ModeOfOperation::NonStoringMode => transit.parent_address.unwrap(),
                            #[cfg(feature = "rpl-mop-2")]
                            ModeOfOperation::StoringMode => ip_repr.src_addr,
                            #[cfg(feature = "rpl-mop-3")]
                            ModeOfOperation::StoringModeWithMulticast => ip_repr.src_addr,
                            #[allow(unreachable_patterns)]
                            _ => unreachable!(),
                        };

                        for target in &targets {
                            net_trace!("adding {} => {} relation", target, next_hop);
                            dodag.relations.add_relation(
                                *target,
                                next_hop,
                                self.now,
                                crate::time::Duration::from_secs(
                                    transit.path_lifetime as u64 * dodag.lifetime_unit as u64,
                                ),
                            );
                        }

                        targets.clear();
                    }
                }
                _ => {}
            }
        }

        net_trace!("RPL relations:");
        for relation in dodag.relations.iter() {
            net_trace!("  {}", relation);
        }

        // Schedule a DAO-ACK if an ACK is requested.
        if dao.expect_ack
            && dodag
                .dao_acks
                .push((ip_repr.src_addr, dao.sequence))
                .is_err()
        {
            net_trace!("unable to schedule DAO-ACK for {}", dao.sequence);
        }

        // Transmit a DAO to our parent if we are not the root.
        if !self.rpl.is_root {
            let icmp = dodag.destination_advertisement_object(dao.options);

            let mut options = heapless::Vec::new();
            options
                .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                    down: false,
                    rank_error: false,
                    forwarding_error: false,
                    instance_id: dodag.instance_id,
                    sender_rank: dodag.rank.raw_value(),
                }))
                .unwrap();

            let hbh = Ipv6HopByHopRepr { options };

            let packet = PacketV6 {
                header: Ipv6Repr {
                    src_addr: our_addr,
                    dst_addr: dodag.parent.unwrap(),
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                },
                hop_by_hop: Some(hbh),
                routing: None,
                payload: IpPayload::Icmpv6(Icmpv6Repr::Rpl(icmp)),
            };

            return Some(Packet::Ipv6(packet));
        }

        None
    }

    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(super) fn process_rpl_dao_ack<'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        dao_ack: RplDaoAck,
    ) -> Option<Packet<'output>> {
        let RplDaoAck {
            rpl_instance_id,
            sequence,
            status,
            dodag_id,
        } = dao_ack;

        let dodag = self.rpl.dodag.as_mut()?;

        if rpl_instance_id == dodag.instance_id
            && (dodag_id == Some(dodag.id) || dodag_id.is_none())
        {
            dodag
                .daos
                .retain(|dao| !(dao.to == ip_repr.src_addr && dao.sequence == sequence));

            if status == 0 {
                net_trace!("DAO {} acknowledged", sequence);
            } else {
                // FIXME: the node should do something correct here.
                net_trace!("ACK status was {}", status);
            }
        }

        None
    }

    pub(super) fn process_rpl_hopbyhop(
        &mut self,
        mut hbh: RplHopByHopRepr,
    ) -> Result<RplHopByHopRepr, Error> {
        let sender_rank = Rank::new(hbh.sender_rank, self.rpl.of.min_hop_rank_increase());

        // Check for inconsistencies (see 11.2.2.2), which are:
        //  - If the packet is going down, and the sender rank is higher or equal as ours.
        //  - If the packet is going up, and the sender rank is lower or equal as ours.
        //
        //  NOTE: the standard says that one rank error is not a critical error and that the packet
        //  can continue traveling through the DODAG. When the bit is set and another inconsistency
        //  is detected, the packet should be dropped. One case this might help is when the DODAG
        //  is moving to a new Version number. However, the standard does not define when a new
        //  Version number should be used. Therefore, we immediately drop the packet when a Rank
        //  error is detected, or when the bit was already set.
        let rank = self.rpl.dodag.as_ref().unwrap().rank;
        if hbh.rank_error || (hbh.down && rank <= sender_rank) || (!hbh.down && rank >= sender_rank)
        {
            net_trace!("RPL HBH: inconsistency detected, resetting trickle timer, dropping packet");
            hbh.rank_error = true;
            self.rpl
                .dodag
                .as_mut()
                .unwrap()
                .dio_timer
                .hear_inconsistency(self.now, &mut self.rand);
            return Err(Error);
        }

        Ok(hbh)
    }
}

/// Create a source routing header based on RPL relation information.
#[cfg(feature = "rpl-mop-1")]
pub(crate) fn create_source_routing_header(
    ctx: &super::InterfaceInner,
    our_addr: Ipv6Address,
    dst_addr: Ipv6Address,
) -> Option<(Ipv6RoutingRepr, Ipv6Address)> {
    let Some(dodag) = &ctx.rpl.dodag else {
        unreachable!()
    };

    let mut route = Vec::<Ipv6Address, { crate::config::RPL_RELATIONS_BUFFER_COUNT }>::new();
    _ = route.push(dst_addr);

    let mut next = dst_addr;

    loop {
        let next_hop = dodag.relations.find_next_hop(next);
        if let Some(next_hop) = next_hop {
            net_trace!("  via {}", next_hop);
            if next_hop == our_addr {
                break;
            }

            if route.push(next_hop).is_err() {
                net_trace!("could not add hop to route buffer");
                return None;
            }

            next = next_hop;
        } else {
            net_trace!("no route found, last next hop is {}", next);
            return None;
        }
    }

    let segments_left = route.len() - 1;

    if segments_left == 0 {
        net_trace!("no source routing needed, node is neighbor");
        None
    } else {
        // Create the route list for the source routing header
        let mut addresses = Vec::new();
        for addr in route[..segments_left].iter().rev() {
            _ = addresses.push(*addr);
        }

        Some((
            Ipv6RoutingRepr::Rpl {
                segments_left: segments_left as u8,
                cmpr_i: 0,
                cmpr_e: 0,
                pad: 0,
                addresses,
            },
            route[segments_left],
        ))
    }
}
