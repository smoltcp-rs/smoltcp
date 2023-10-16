use super::*;
use crate::iface::rpl::*;

impl InterfaceInner {
    pub fn rpl(&self) -> &Rpl {
        &self.rpl
    }

    /// Process an incoming RPL packet.
    pub(super) fn process_rpl<'output, 'payload: 'output>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        match repr {
            RplRepr::DodagInformationSolicitation { .. } => self.process_rpl_dis(ip_repr, repr),
            RplRepr::DodagInformationObject { .. } => {
                self.process_rpl_dio(src_ll_addr, ip_repr, repr)
            }
            RplRepr::DestinationAdvertisementObject { .. } => {
                self.process_rpl_dao(ip_repr, repr)
            }
            RplRepr::DestinationAdvertisementObjectAck { .. } => {
                self.process_rpl_dao_ack(ip_repr, repr)
            }
        }
    }

    /// Process an incoming RPL DIS packet.
    //
    // When processing a DIS packet, we first check if the Solicited Information is present. This
    // option has predicates that we need to match on. It is used as a filtering mechanism.
    //
    // When receiving and validating a DIS message, we need to reset our Trickle timer. More
    // information can be found in RFC6550 8.3.
    //
    // When receiving a unicast DIS message, we should respond with a unicast DIO message, instead
    // of a multicast message.
    pub(super) fn process_rpl_dis<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let RplRepr::DodagInformationSolicitation { options } = repr else {
            return None;
        };

        // If we are not part of a DODAG we cannot respond with a DIO.
        let dodag = self.rpl.dodag.as_mut()?;
        let instance = self.rpl.instance.as_ref()?;

        // Process options
        // ===============
        for opt in &options {
            match opt {
                // Skip padding
                RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),

                // The solicited information option is used for filtering incoming DIS
                // packets. This option will contain predicates, which we need to match on.
                // When we match all to requested predicates, then we answer with a DIO,
                // otherwise we just drop the packet. See section 8.3 for more information.
                RplOptionRepr::SolicitedInformation {
                    rpl_instance_id,
                    version_predicate,
                    instance_id_predicate,
                    dodag_id_predicate,
                    dodag_id,
                    version_number,
                } => {
                    if (*version_predicate
                        && dodag.version_number != SequenceCounter::new(*version_number))
                        || (*dodag_id_predicate && dodag.id != *dodag_id)
                        || (*instance_id_predicate && instance.id != *rpl_instance_id)
                    {
                        net_trace!("predicates did not match, dropping packet");
                        return None;
                    }
                }
                _ => net_trace!("received invalid option, continuing"),
            }
        }

        // When receiving a unicast DIS message, we should respond with a unicast DIO,
        // containing the DODAG Information option, without resetting the Trickle timer.
        if ip_repr.dst_addr.is_unicast() {
            net_trace!("unicast DIS, sending unicast DIO");

            let mut options = heapless::Vec::new();
            options.push(self.rpl.dodag_configuration()).unwrap();

            let dio = Icmpv6Repr::Rpl(self.rpl.dodag_information_object(options));

            Some(IpPacket::new_ipv6(
                Ipv6Repr {
                    src_addr: self.ipv6_addr().unwrap(),
                    dst_addr: ip_repr.dst_addr,
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
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let RplRepr::DodagInformationObject {
            rpl_instance_id,
            version_number,
            rank,
            grounded,
            mode_of_operation,
            dodag_preference,
            dtsn,
            dodag_id,
            options,
        } = repr
        else {
            return None;
        };

        let mut dodag_configuration = None;

        // Process options
        // ===============
        for opt in &options {
            match opt {
                // Skip padding
                RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),

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
                RplOptionRepr::DodagConfiguration {
                    objective_code_point,
                    ..
                } => {
                    // If we are not part of a network, and the OCP is not the same as
                    // ours, then we don't accept the DIO packet.
                    if self.rpl.dodag.is_none()
                        && *objective_code_point != self.rpl.of.objective_code_point()
                    {
                        net_trace!("dropping packet, OCP is not compatible");
                        return None;
                    }

                    dodag_configuration = Some(opt);
                }
                // The root of a DODAG is responsible for setting the option values.
                // This information is propagated down the DODAG unchanged.
                RplOptionRepr::PrefixInformation { .. } => {
                    // FIXME(thvdveld): handle a prefix information option.
                    net_trace!("Prefix Information Option not yet supported");
                }
                _ => net_trace!("received invalid option, continuing"),
            }
        }

        let sender_rank = Rank::new(rank, self.rpl.of.min_hop_rank_increase());

        // Accept DIO if not part of DODAG
        // ===============================
        // If we are not part of a DODAG, check the MOP and OCP. If they are the same as
        // ours, we copy the fields of the DIO and the DODAG Configuration. If we cannot
        // check the OCP (because the DODAG Configuration option is missing), then we
        // transmit a unicast DIS to the sender of the DIO we received. The sender MUST
        // respond with a unicast DIO with the option present.
        if !self.rpl.is_root
            && self.rpl.dodag.is_none()
            && ModeOfOperation::from(mode_of_operation) == self.rpl.mode_of_operation
            && sender_rank != Rank::INFINITE
        {
            let Some(RplOptionRepr::DodagConfiguration {
                authentication_enabled,
                path_control_size,
                dio_interval_doublings,
                dio_interval_min,
                dio_redundancy_constant,
                max_rank_increase,
                minimum_hop_rank_increase,
                default_lifetime,
                lifetime_unit,
                ..
            }) = dodag_configuration
            else {
                // Send a unicast DIS.
                net_trace!("sending unicast DIS (to ask for DODAG Conf. option)");

                let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation {
                    options: Default::default(),
                });

                return Some(IpPacket::new_ipv6(
                    Ipv6Repr {
                        src_addr: self.ipv6_addr().unwrap(),
                        dst_addr: ip_repr.dst_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: icmp.buffer_len(),
                        hop_limit: 64,
                    },
                    IpPayload::Icmpv6(icmp),
                ));
            };

            net_trace!(
                "accepting new RPL conf (grounded={} pref={} version={} InstanceID={:?} DODAGID={})",
                grounded,
                dodag_preference,
                version_number,
                rpl_instance_id,
                dodag_id
            );

            self.rpl
                .of
                .set_min_hop_rank_increase(*minimum_hop_rank_increase);
            self.rpl.of.set_max_rank_increase(*max_rank_increase);

            let instance = Instance {
                id: rpl_instance_id,
            };
            let dodag = Dodag {
                id: dodag_id,
                version_number: SequenceCounter::new(version_number),
                preference: dodag_preference,
                rank: Rank::INFINITE,
                dio_timer: TrickleTimer::new(
                    *dio_interval_min as u32,
                    *dio_interval_min as u32 + *dio_interval_doublings as u32,
                    *dio_redundancy_constant as usize,
                ),
                dao_expiration: Instant::ZERO,
                parent: None,
                without_parent: Some(self.now),
                authentication_enabled: *authentication_enabled,
                path_control_size: *path_control_size,
                dtsn: SequenceCounter::default(),
                default_lifetime: *default_lifetime,
                lifetime_unit: *lifetime_unit,
                grounded,
                dao_seq_number: SequenceCounter::default(),
                dao_acks: Default::default(),
                daos: Default::default(),
                parent_set: Default::default(),
                relations: Default::default(),
            };

            self.rpl.instance = Some(instance);
            self.rpl.dodag = Some(dodag);
        }

        // The sender rank might be updated by the configuration option.
        let sender_rank = Rank::new(rank, self.rpl.of.min_hop_rank_increase());

        let our_addr = self.ipv6_addr().unwrap();
        if let (Some(instance), Some(dodag)) = (self.rpl.instance, &mut self.rpl.dodag) {
            // Check DIO validity
            // ==================
            // We check if we can accept the DIO message:
            // 1. The RPL instance is the same as our RPL instance.
            // 2. The DODAG ID must be the same as our DODAG ID.
            // 3. The version number must be the same or higher than ours.
            // 4. The Mode of Operation must be the same as our Mode of Operation.
            // 5. The Objective Function must be the same as our Ojbective ObjectiveFunction,
            //    which we already checked.
            if rpl_instance_id != instance.id
                || dodag.id != dodag_id
                || version_number < dodag.version_number.value()
                || ModeOfOperation::from(mode_of_operation) != self.rpl.mode_of_operation
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
            if SequenceCounter::new(version_number) > dodag.version_number {
                net_trace!("version number higher than ours");

                if self.rpl.is_root {
                    net_trace!("(root) using new version number + 1");

                    dodag.version_number = SequenceCounter::new(version_number);
                    dodag.version_number.increment();

                    net_trace!("(root) resetting Trickle timer");
                    // Reset the trickle timer.
                    dodag.dio_timer.hear_inconsistency(self.now, &mut self.rand);
                    return None;
                } else {
                    net_trace!("resetting parent set, resetting rank, removing parent");

                    dodag.version_number = SequenceCounter::new(version_number);

                    // Clear the parent set, .
                    dodag.parent_set.clear();

                    // We do NOT send a No-path DAO.
                    let _ = dodag.remove_parent(
                        self.rpl.mode_of_operation,
                        our_addr,
                        &self.rpl.of,
                        self.now,
                    );

                    let dio =
                        Icmpv6Repr::Rpl(self.rpl.dodag_information_object(Default::default()));

                    // Transmit a DIO with INFINITE rank, but with an updated Version number.
                    // Everyone knows they have to leave the network and form a new one.
                    return Some(IpPacket::new_ipv6(
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

            // Add the sender to our neighbor cache.
            self.neighbor_cache.fill_with_expiration(
                ip_repr.src_addr.into(),
                src_ll_addr.unwrap(),
                self.now + dodag.dio_timer.max_expiration() * 2,
            );

            // Remove parent if parent has INFINITE rank
            // =========================================
            // If our parent transmits a DIO with an infinite rank, than it means that our
            // parent is leaving the network. Thus we should deselect it as our parent.
            // If there is no parent in the parent set, we also detach from the network by
            // sending a DIO with an infinite rank.
            if Some(ip_repr.src_addr) == dodag.parent {
                if Rank::new(rank, self.rpl.of.min_hop_rank_increase()) == Rank::INFINITE {
                    net_trace!("parent leaving, removing parent");

                    // Don't need to send a no-path DOA when parent is leaving.
                    let _ = dodag.remove_parent(
                        self.rpl.mode_of_operation,
                        our_addr,
                        &self.rpl.of,
                        self.now,
                    );

                    if dodag.parent.is_some() {
                        dodag.dio_timer.hear_inconsistency(self.now, &mut self.rand);
                    } else {
                        net_trace!("no potential parents, leaving network");

                        // DIO with INFINITE rank.
                        let dio =
                            Icmpv6Repr::Rpl(self.rpl.dodag_information_object(Default::default()));

                        return Some(IpPacket::new_ipv6(
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
                    // DTSN increased, so we need to transmit a DAO.
                    if SequenceCounter::new(dtsn) > dodag.dtsn {
                        net_trace!("DTSN increased, scheduling DAO");
                        dodag.dao_expiration = self.now;
                    }

                    dodag
                        .parent_set
                        .find_mut(&dodag.parent.unwrap())
                        .unwrap()
                        .last_heard = self.now;

                    // Trickle Consistency
                    // ===================
                    // When we are not the root, we hear a consistency when the DIO message is from
                    // our parent and is valid. The validity of the message should be checked when we
                    // reach this line.
                    net_trace!("hearing consistency");
                    dodag.dio_timer.hear_consistency();

                    return None;
                }
            }

            // Add node to parent set
            // ======================
            // If the rank is smaller than ours, the instance id and the mode of operation is
            // the same as ours,, we can add the sender to our parent set.
            if sender_rank < dodag.rank && !self.rpl.is_root {
                net_trace!("adding {} to parent set", ip_repr.src_addr);

                dodag.parent_set.add(
                    ip_repr.src_addr,
                    Parent::new(
                        sender_rank,
                        SequenceCounter::new(version_number),
                        dodag.id,
                        self.now,
                    ),
                );

                // Select parent
                // =============
                // Send a no-path DAO to our old parent.
                // Select and schedule DAO to new parent.
                dodag.find_new_parent(self.rpl.mode_of_operation, our_addr, &self.rpl.of, self.now);
            }

            // Trickle Consistency
            // ===================
            // We should increment the Trickle timer counter for a valid DIO message,
            // when we are the root, and the rank that is advertised in the DIO message is
            // not infinite (so we received a valid DIO from a child).
            if self.rpl.is_root && sender_rank != Rank::INFINITE {
                net_trace!("hearing consistency");
                dodag.dio_timer.hear_consistency();
            }

            None
        } else {
            None
        }
    }

    pub(super) fn process_rpl_dao<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let RplRepr::DestinationAdvertisementObject {
            rpl_instance_id,
            expect_ack,
            sequence,
            dodag_id,
            ref options,
        } = repr
        else {
            return None;
        };

        let our_addr = self.ipv6_addr().unwrap();
        let instance = self.rpl.instance.as_ref()?;
        let dodag = self.rpl.dodag.as_mut()?;

        // Check validity of the DAO
        // =========================
        if instance.id != rpl_instance_id && Some(dodag.id) != dodag_id {
            net_trace!("dropping DAO, wrong DODAG ID/INSTANCE ID");
            return None;
        }

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
            net_trace!("forwarding DAO to root");
            let mut options = heapless::Vec::new();
            options
                .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                    down: false,
                    rank_error: false,
                    forwarding_error: false,
                    instance_id: instance.id,
                    sender_rank: dodag.rank.raw_value(),
                }))
                .unwrap();

            let hbh = Ipv6HopByHopRepr { options };

            return Some(IpPacket::Ipv6(Ipv6Packet {
                header: ip_repr,
                hop_by_hop: Some(hbh),
                routing: None,
                payload: IpPayload::Icmpv6(Icmpv6Repr::Rpl(repr)),
            }));
        }

        let mut child = None;
        let mut lifetime = None;
        let mut p_sequence = None;
        let mut prefix_length = None;
        let mut parent = None;

        // Process options
        // ===============
        for opt in options {
            match opt {
                //skip padding
                RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),
                RplOptionRepr::RplTarget {
                    prefix_length: pl,
                    prefix,
                } => {
                    prefix_length = Some(*pl);
                    child = Some(*prefix);
                }
                RplOptionRepr::TransitInformation {
                    path_sequence,
                    path_lifetime,
                    parent_address,
                    ..
                } => {
                    lifetime = Some(*path_lifetime);
                    p_sequence = Some(*path_sequence);
                    parent = match self.rpl.mode_of_operation {
                        ModeOfOperation::NoDownwardRoutesMaintained => unreachable!(),

                        #[cfg(feature = "rpl-mop-1")]
                        ModeOfOperation::NonStoringMode => {
                            if let Some(parent_address) = parent_address {
                                Some(*parent_address)
                            } else {
                                net_debug!("Parent Address required for MOP1, dropping packet");
                                return None;
                            }
                        }

                        #[cfg(feature = "rpl-mop-2")]
                        ModeOfOperation::StoringMode => Some(ip_repr.src_addr),

                        #[cfg(feature = "rpl-mop-3")]
                        ModeOfOperation::StoringModeWithMulticast => Some(ip_repr.src_addr),
                    };
                }
                RplOptionRepr::RplTargetDescriptor { .. } => {
                    net_trace!("Target Descriptor Option not yet supported");
                }
                _ => net_trace!("received invalid option, continuing"),
            }
        }

        // Remove stale relations.
        dodag.relations.purge(self.now);

        if let (
            Some(child),
            Some(lifetime),
            Some(_path_sequence),
            Some(_prefix_length),
            Some(parent),
        ) = (child, lifetime, p_sequence, prefix_length, parent)
        {
            if lifetime == 0 {
                net_trace!("remove {} => {} relation (NO-PATH)", child, parent);
                dodag.relations.remove_relation(child);
            } else {
                net_trace!("adding {} => {} relation", child, parent);

                //Create the relation with the child and parent addresses extracted from the options
                dodag.relations.add_relation(
                    child,
                    parent,
                    self.now + Duration::from_secs(lifetime as u64 * dodag.lifetime_unit as u64),
                );

                net_trace!("RPL relations:");
                for relation in dodag.relations.iter() {
                    net_trace!("  {}", relation);
                }
            }

            // Schedule an ACK if requested and the DAO was for us.
            if expect_ack && ip_repr.dst_addr == our_addr {
                dodag
                    .dao_acks
                    .push((ip_repr.src_addr, SequenceCounter::new(sequence)))
                    .unwrap();
            }

            #[cfg(feature = "rpl-mop-2")]
            if matches!(self.rpl.mode_of_operation, ModeOfOperation::StoringMode)
                && !self.rpl.is_root
            {
                net_trace!("forwarding relation information to parent");

                // Send message upward.
                let mut options = heapless::Vec::new();
                options
                    .push(RplOptionRepr::RplTarget {
                        prefix_length: _prefix_length,
                        prefix: child,
                    })
                    .unwrap();
                options
                    .push(RplOptionRepr::TransitInformation {
                        external: false,
                        path_control: 0,
                        path_sequence: _path_sequence,
                        path_lifetime: lifetime,
                        parent_address: None,
                    })
                    .unwrap();

                let dao_seq_number = dodag.dao_seq_number;
                let icmp = Icmpv6Repr::Rpl(
                    self.rpl
                        .destination_advertisement_object(dao_seq_number, options),
                );

                let dodag = self.rpl.dodag.as_mut()?;

                // Selecting new parent (so new information).
                dodag.dao_seq_number.increment();

                return Some(IpPacket::new_ipv6(
                    Ipv6Repr {
                        src_addr: our_addr,
                        dst_addr: dodag.parent.unwrap(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: icmp.buffer_len(),
                        hop_limit: 64,
                    },
                    IpPayload::Icmpv6(icmp),
                ));
            }
        } else {
            net_trace!("not all required info received for adding relation");
        }

        None
    }

    pub(super) fn process_rpl_dao_ack<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let RplRepr::DestinationAdvertisementObjectAck {
            rpl_instance_id,
            sequence,
            status,
            dodag_id,
        } = repr
        else {
            return None;
        };

        let instance = self.rpl.instance.as_ref()?;
        let dodag = self.rpl.dodag.as_mut()?;

        if rpl_instance_id == instance.id && (dodag_id == Some(dodag.id) || dodag_id.is_none()) {
            dodag.daos.retain(|dao| {
                !(dao.to == ip_repr.src_addr
                    && dao.sequence == Some(SequenceCounter::new(sequence)))
            });

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

        if hbh.rank_error {
            net_trace!("RPL HBH: contains rank error, resetting trickle timer, dropping packet");

            self.rpl
                .dodag
                .as_mut()
                .unwrap()
                .dio_timer
                .hear_inconsistency(self.now, &mut self.rand);
            return Err(Error);
        }

        // Check for inconsistencies (see 11.2.2.2), which are:
        //  - If the packet is going down, and the sender rank is higher or equal as ours.
        //  - If the packet is going up, and the sender rank is lower or equal as ours.
        let rank = self.rpl.dodag.as_ref().unwrap().rank;
        if (hbh.down && rank <= sender_rank) || (!hbh.down && rank >= sender_rank) {
            net_trace!("RPL HBH: inconsistency detected, setting Rank-Error");
            hbh.rank_error = true;
        }

        Ok(hbh)
    }

    //fn remove_parent<'options>(&mut self) -> RplRepr<'options> {
    //self.rpl.parent_address = None;
    //self.rpl.parent_rank = None;
    //self.rpl.parent_preference = None;
    //self.rpl.parent_last_heard = None;
    //self.rpl.rank = Rank::INFINITE;

    //self.rpl.dodag_information_object(heapless::Vec::new())
    //}

    //fn select_preferred_parent<'options>(&mut self) -> Option<IpPacket<'options>> {
    //if let Some(preferred_parent) =
    //of0::ObjectiveFunction0::preferred_parent(&self.rpl_parent_set)
    //{
    //// Accept the preferred parent as new parent when we don't have a
    //// parent yet, or when we have a parent, but its rank is lower than
    //// the preferred parent, or when the rank is the same but the preference is
    //// higher.
    //if !self.rpl.has_parent()
    //|| preferred_parent.rank.dag_rank() < self.rpl.parent_rank.unwrap().dag_rank()
    //{
    //net_trace!(
    //"RPL DIO: selecting {} as new parent",
    //preferred_parent.ip_addr
    //);
    //self.rpl.parent_last_heard = Some(self.now);

    //// Schedule a DAO after we send a no-path dao.
    //net_trace!("RPL DIO: scheduling DAO");
    //self.rpl.dao_expiration = self.now;

    //// In case of MOP1, MOP2 and (maybe) MOP3, a DAO packet needs to be
    //// transmitted with this information.
    //return self.select_parent(self.rpl.parent_address, &preferred_parent);
    //}
    //}

    //None
    //}

    //fn select_parent<'options>(
    //&mut self,
    //old_parent: Option<Ipv6Address>,
    //parent: &Parent,
    //) -> Option<IpPacket<'options>> {
    //let no_path = if let Some(old_parent) = old_parent {
    //self.no_path_dao(old_parent)
    //} else {
    //// If there was no old parent, then we don't need to transmit a no-path DAO.
    //None
    //};

    //self.rpl.parent_address = Some(parent.ip_addr);
    //self.rpl.parent_rank = Some(parent.rank);

    //// Recalculate our rank when updating our parent.
    //self.rpl.rank = of0::ObjectiveFunction0::new_rank(self.rpl.rank, parent.rank);

    //// Reset the trickle timer.
    //let min = self.rpl.dio_timer.min_expiration();
    //self.rpl.dio_timer.reset(min, self.now, &mut self.rand);

    //no_path
    //}

    //fn no_path_dao<'options>(&mut self, old_parent: Ipv6Address) -> Option<IpPacket<'options>> {
    //let src_addr = self.ipv6_addr().unwrap();

    //if self.rpl.mode_of_operation == ModeOfOperation::NoDownwardRoutesMaintained {
    //return None;
    //}

    //#[cfg(feature = "rpl-mop-1")]
    //if self.rpl.mode_of_operation == ModeOfOperation::NonStoringMode {
    //return None;
    //}

    //let mut options = heapless::Vec::new();
    //options
    //.push(RplOptionRepr::RplTarget {
    //prefix_length: 64,
    //prefix: src_addr,
    //})
    //.unwrap();
    //options
    //.push(RplOptionRepr::TransitInformation {
    //external: false,
    //path_control: 0,
    //path_sequence: 0,
    //path_lifetime: 0, // no-path lifetime
    //parent_address: None,
    //})
    //.unwrap();

    //let icmp = Icmpv6Repr::Rpl(
    //self.rpl
    //.destination_advertisement_object(self.rpl.dao_seq_number, options),
    //);

    //self.rpl
    //.daos
    //.push(Dao {
    //needs_sending: false,
    //sent_at: Some(self.now),
    //sent_count: 1,
    //to: old_parent,
    //child: src_addr,
    //parent: None,
    //sequence: Some(self.rpl.dao_seq_number),
    //})
    //.unwrap();

    //self.rpl.dao_seq_number.increment();

    //Some(IpPacket::new(
    //Ipv6Repr {
    //src_addr,
    //dst_addr: old_parent,
    //next_header: IpProtocol::Icmpv6,
    //payload_len: icmp.buffer_len(),
    //hop_limit: 64,
    //},
    //icmp,
    //))
    //}
}
