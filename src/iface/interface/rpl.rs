use super::check;
use super::InterfaceInner;
use super::IpPacket;

use crate::iface::rpl::*;
use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "proto-rpl")]
    pub(super) fn process_rpl<'frame>(
        &mut self,
        ll_addr: HardwareAddress,
        ip_repr: Ipv6Repr,
        repr: RplRepr,
    ) -> Option<IpPacket<'frame>> {
        net_trace!("Receiving {}", repr);

        let now = self.now();

        match repr {
            RplRepr::DodagInformationSolicitation { options } => {
                let InterfaceInner { rand, rpl, now, .. } = self;

                for opt in &options {
                    match opt {
                        // Skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),
                        // This option is used for filtering.
                        RplOptionRepr::SolicitedInformation {
                            rpl_instance_id,
                            version_predicate,
                            instance_id_predicate,
                            dodag_id_predicate,
                            dodag_id,
                            version_number,
                        } => {
                            // Section 8.3:
                            //    o  When a node receives a multicast DIS with a Solicited Information
                            //       option and the node matches all of the predicates in the Solicited
                            //       Information option, unless a DIS flag restricts this behavior.
                            // We check if the predicates are matched. I they don't match we do not
                            // reset the Trickle timer.

                            if (*version_predicate
                                && rpl.version_number != SequenceCounter::new(*version_number))
                                || (*instance_id_predicate && rpl.instance_id != *rpl_instance_id)
                                || (*dodag_id_predicate && rpl.dodag_id != Some(*dodag_id))
                            {
                                return None;
                            }
                        }
                        _ => net_trace!("Received invalid option"),
                    }
                }

                if ip_repr.dst_addr.is_unicast() {
                    // TODO(diana): we should respond to source with a unicast DIO message.
                    // It is used for probiing purposes.
                    return None;
                }

                // Section 8.3:
                //    o  When a node receives a multicast DIS message without a Solicited
                //       Information option, unless a DIS flag restricts this behavior.
                // We reset the Trickle timer.
                rpl.dio_timer.hear_inconsistent(*now, rand);

                None
            }

            RplRepr::DodagInformationObject {
                rank,
                rpl_instance_id,
                version_number,
                grounded,
                mode_of_operation,
                dodag_preference,
                dodag_id,
                options,
                ..
            } => {
                let mut dio_rank = Rank::new(rank, consts::DEFAULT_MIN_HOP_RANK_INCREASE);
                let mut ocp = None;

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
                            minimum_hop_rank_increase,
                            objective_code_point,
                            ..
                        } => {
                            // The dodag configuration option contains information about how the DODAG
                            // operates.

                            dio_rank.min_hop_rank_increase = *minimum_hop_rank_increase;
                            ocp = Some(objective_code_point);
                            self.rpl.update_dodag_conf(opt);
                        }
                        // The root of a DODAG is responsible for setting the option values.
                        // This information is propagated down the DODAG unchanged.
                        RplOptionRepr::PrefixInformation { .. } => {
                            // FIXME(thvdveld): handle a prefix information option.
                            net_trace!("Prefix Information Option not yet supported");
                        }
                        _ => net_trace!("Received invalid option."),
                    }
                }

                // We check if we can accept the DIO message:
                // 1. The RPL instance is the same as our RPL instance.
                // 2. The DODAG ID must be the same as our DODAG ID, unless we haven't selected
                //    one.
                // 3. The version number must be the same as our version number.
                // 4. The Mode of Operation must be the same as our Mode of Operation.
                // 5. The Objective Function must be the same as our Ojbective Function.
                if rpl_instance_id == self.rpl.instance_id
                    && match self.rpl.dodag_id {
                        Some(our_dodag_id) if our_dodag_id == dodag_id => true,
                        None => true,
                        _ => false,
                    }
                {
                    if version_number != self.rpl.version_number.value() {
                        if self.rpl.is_root {
                            // Reset the DIO trickle timer.
                            let InterfaceInner { rand, rpl, now, .. } = self;
                            rpl.dio_timer.hear_inconsistent(*now, rand);
                        } else {
                            // TODO(thvdveld): if a node that is not the root receives a DIO packet with
                            // a different Version Number, then global repair should be triggered
                            // somehow.

                            // For now we ignore the packet when we are a leaf node when the
                            // version number does not matches ours.
                        }
                        return None;
                    }

                    if (ModeOfOperation::from(mode_of_operation) != self.rpl.mode_of_operation)
                        || (ocp != Some(&self.rpl.ocp))
                    {
                        // We ignore the packet if the Mode of Operation is not the same as ours.
                        // We also ignore the packet if the objective function is different.
                        return None;
                    }

                    // NOTE(thvdveld): this won't work when a custom MinHopRankIncrease value is
                    // used, since the INFINITE rank is constructued with the default value from
                    // the RFC.
                    if Some(ip_repr.src_addr) == self.rpl.parent_address
                        && Rank::new(rank, self.rpl.rank.min_hop_rank_increase) == Rank::INFINITE
                    {
                        // Reset the DIO trickle timer.
                        let InterfaceInner { rand, rpl, now, .. } = self;
                        rpl.dio_timer.hear_inconsistent(*now, rand);

                        self.rpl.parent_address = None;
                        self.rpl.parent_rank = None;
                        self.rpl.parent_preference = None;
                        self.rpl.parent_last_heard = None;
                        self.rpl.rank = Rank::INFINITE;

                        let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationObject {
                            rpl_instance_id: self.rpl.instance_id,
                            version_number: self.rpl.version_number.value(),
                            rank: Rank::INFINITE.raw_value(),
                            grounded: self.rpl.grounded,
                            mode_of_operation: self.rpl.mode_of_operation.into(),
                            dodag_preference: self.rpl.dodag_preference,
                            dtsn: self.rpl.dtsn.value(),
                            dodag_id: self.rpl.dodag_id.unwrap(),
                            options: heapless::Vec::new(),
                        });

                        return Some(IpPacket::Icmpv6((
                            Ipv6Repr {
                                src_addr: self.ipv6_addr().unwrap(),
                                dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                                next_header: IpProtocol::Icmpv6,
                                payload_len: icmp.buffer_len(),
                                hop_limit: 64,
                            },
                            icmp,
                        )));
                    }

                    // Update our RPL values from the DIO message:
                    self.rpl.grounded = grounded;
                    self.rpl.mode_of_operation = mode_of_operation.into();
                    self.rpl.dodag_preference = dodag_preference;
                    self.rpl.version_number = SequenceCounter::new(version_number);
                    self.rpl.instance_id = rpl_instance_id;
                    self.rpl.dodag_id = Some(dodag_id);

                    // Add the Neighbor to our RPL neighbor table.
                    // TODO(thvdveld): check if this is the right place for adding a node to the
                    // neighbour table.
                    self.rpl.neighbor_table.add_neighbor(
                        RplNeighbor::new(
                            ll_addr,
                            ip_repr.src_addr,
                            dio_rank.into(),
                            dodag_preference.into(),
                        ),
                        now,
                    );

                    // NOTE: we take twice the maximum value the DIO timer can be. This is because
                    // Contiki's Trickle timer can have a maximum value of 1.5 times of the
                    // theoretical maximum value. We didn't look into why this is in Contiki.
                    //
                    // TODO(thvdveld): with the trickle counter timer, DIO messages may not be sent
                    // anymore by neighbours. Thus, the following would not work:
                    self.rpl
                        .neighbor_table
                        .purge(self.now, self.rpl.dio_timer.max_expiration() * 2);

                    // Check if the DIO message is comming from a neighbor that could be our new
                    // parent. For this, the DIO rank must be smaller than ours.
                    if dio_rank < self.rpl.rank {
                        // Check for a preferred parent:
                        if let Some(preferred_parent) =
                            ObjectiveFunction0::preferred_parent(&self.rpl.neighbor_table)
                        {
                            // Accept the preferred parent as new parent when we don't have a
                            // parent yet, or when we have a parent, but its rank is higher than
                            // the preferred parent.
                            if !self.rpl.has_parent()
                                || preferred_parent.rank().dag_rank()
                                    < self.rpl.parent_rank.unwrap().dag_rank()
                                || (preferred_parent.rank().dag_rank()
                                    == self.rpl.parent_rank.unwrap().dag_rank()
                                    && preferred_parent.preference()
                                        > self.rpl.parent_preference.unwrap())
                            {
                                self.rpl.parent_address = Some(preferred_parent.ip_addr());
                                self.rpl.parent_rank = Some(preferred_parent.rank());
                                self.rpl.parent_preference = Some(preferred_parent.preference());

                                // Recalculate our rank when updating our parent.
                                let new_rank = ObjectiveFunction0::new_rank(
                                    self.rpl.rank,
                                    // NOTE: we can unwrap, because we just have set it to a value.
                                    self.rpl.parent_rank.unwrap(),
                                );
                                self.rpl.rank = new_rank;

                                // Reset the DIO trickle timer.
                                let InterfaceInner { rand, rpl, now, .. } = self;
                                rpl.dio_timer.hear_inconsistent(*now, rand);
                            }
                        }

                        if self.rpl.parent_address == Some(ip_repr.src_addr) {
                            self.rpl.parent_last_heard = Some(now);
                        }
                    }

                    // We should increment the Trickle timer counter for a valid DIO message,
                    // when we are the root, and the rank that is advertised in the DIO message is
                    // not infinite.
                    // We also increment it when we hear a valid DIO message from our parent (when
                    // we are not the root, obviously).
                    // At this point, the DIO message should be valid.
                    if (self.rpl.is_root && dio_rank != Rank::INFINITE)
                        || self.rpl.parent_rank == Some(dio_rank)
                    {
                        self.rpl.dio_timer.hear_consistent();
                    }
                }

                None
            }
            RplRepr::DestinationAdvertisementObject { .. } => {
                net_trace!("Received DAO message, which we don't support yet");
                None
            }
            RplRepr::DestinationAdvertisementObjectAck { .. } => {
                net_trace!("Received DAO-ACK, which we don't support yet");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::iface::interface::tests::*;
    use crate::iface::interface::*;
    use crate::iface::rpl::*;

    use alloc::{collections::VecDeque, vec::Vec};

    const ROOT_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([1u8; 8]);
    const NODE_1_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([2u8; 8]);
    const NODE_2_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([2u8; 8]);

    fn ip_addr(addr: Ieee802154Address) -> Ipv6Address {
        addr.as_link_local_address().unwrap()
    }

    /// A loopback device.
    #[derive(Debug)]
    pub struct TestDevice {
        pub(crate) rx_queue: VecDeque<Vec<u8>>,
        pub(crate) tx_queue: VecDeque<Vec<u8>>,
        medium: Medium,
    }

    #[allow(clippy::new_without_default)]
    impl TestDevice {
        pub fn new(medium: Medium) -> Self {
            Self {
                rx_queue: VecDeque::new(),
                tx_queue: VecDeque::new(),
                medium,
            }
        }
    }

    impl Device for TestDevice {
        type RxToken<'a> = RxToken;
        type TxToken<'a> = TxToken<'a>;

        fn capabilities(&self) -> DeviceCapabilities {
            DeviceCapabilities {
                max_transmission_unit: 65535,
                medium: self.medium,
                ..DeviceCapabilities::default()
            }
        }

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            self.rx_queue.pop_front().map(move |buffer| {
                let rx = RxToken { buffer };
                let tx = TxToken {
                    queue: &mut self.tx_queue,
                };
                (rx, tx)
            })
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            Some(TxToken {
                queue: &mut self.tx_queue,
            })
        }
    }

    #[doc(hidden)]
    pub struct RxToken {
        buffer: Vec<u8>,
    }

    impl crate::phy::RxToken for RxToken {
        fn consume<R, F>(mut self, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            f(&mut self.buffer)
        }
    }

    #[doc(hidden)]
    #[derive(Debug)]
    pub struct TxToken<'a> {
        queue: &'a mut VecDeque<Vec<u8>>,
    }

    impl<'a> crate::phy::TxToken for TxToken<'a> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut buffer = Vec::new();
            buffer.resize(len, 0);
            let result = f(&mut buffer);
            self.queue.push_back(buffer);
            result
        }
    }

    fn create_rpl_packet(
        ll_src_addr: Ieee802154Address,
        ll_src_pan_id: Ieee802154Pan,
        ll_dst_addr: Ieee802154Address,
        ll_dst_pan_id: Ieee802154Pan,
        dst_addr: Option<Ipv6Address>,
        rpl_repr: RplRepr,
    ) -> Vec<u8> {
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(1),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: Some(ll_dst_pan_id),
            dst_addr: Some(ll_dst_addr),
            src_pan_id: Some(ll_src_pan_id),
            src_addr: Some(ll_src_addr),
        };

        let iphc_repr = SixlowpanIphcRepr {
            src_addr: ll_src_addr.as_link_local_address().unwrap(),
            ll_src_addr: Some(ll_src_addr),
            dst_addr: if let Some(addr) = dst_addr {
                addr
            } else {
                ll_dst_addr.as_link_local_address().unwrap()
            },
            ll_dst_addr: Some(ll_dst_addr),
            next_header: SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
            hop_limit: 64,
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        let icmpv6_repr = Icmpv6Repr::Rpl(rpl_repr);

        let size = ieee_repr.buffer_len() + iphc_repr.buffer_len() + icmpv6_repr.buffer_len();

        let mut data = vec![0; size];
        let mut buffer = &mut data[..];

        let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut buffer[..ieee_repr.buffer_len()]);
        ieee_repr.emit(&mut ieee_packet);
        buffer = &mut buffer[ieee_repr.buffer_len()..];

        let mut iphc_packet =
            SixlowpanIphcPacket::new_unchecked(&mut buffer[..iphc_repr.buffer_len()]);
        iphc_repr.emit(&mut iphc_packet);
        buffer = &mut buffer[iphc_repr.buffer_len()..];

        let mut icmpv6_packet =
            Icmpv6Packet::new_unchecked(&mut buffer[..icmpv6_repr.buffer_len()]);
        icmpv6_repr.emit(
            &ll_src_addr.as_link_local_address().unwrap().into(),
            &if let Some(addr) = dst_addr {
                addr.into()
            } else {
                ll_dst_addr.as_link_local_address().unwrap().into()
            },
            &mut icmpv6_packet,
            &ChecksumCapabilities::default(),
        );

        data
    }

    /// Generate a random IEEE802.15.4 addres.
    fn random_ieee802154_address(rand: &mut Rand) -> Ieee802154Address {
        let mut address = [0u8; 8];

        for i in &mut address {
            *i = rand.rand_u8();
        }

        Ieee802154Address::Extended(address)
    }

    fn rpl_root_node(mop: ModeOfOperation) -> (Interface, SocketSet<'static>, TestDevice) {
        let (mut iface, sockets, _) = create(Medium::Ieee802154);
        iface.context_mut().rpl_mut().mode_of_operation = mop;

        iface.set_hardware_addr(HardwareAddress::Ieee802154(ROOT_ADDRESS));
        iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(ROOT_ADDRESS), 128)));

        let rpl = iface.context_mut().rpl_mut();
        rpl.is_root = true;
        rpl.dodag_id = Some(ip_addr(ROOT_ADDRESS));

        (iface, sockets, TestDevice::new(Medium::Ieee802154))
    }

    fn rpl_connected_node(
        addr: Ieee802154Address,
        mop: ModeOfOperation,
    ) -> (Interface, SocketSet<'static>, TestDevice) {
        let (mut iface, sockets, _) = create(Medium::Ieee802154);
        iface.context_mut().rpl_mut().mode_of_operation = mop;

        iface.set_hardware_addr(HardwareAddress::Ieee802154(addr));
        iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(addr), 128)));

        let rpl = iface.context_mut().rpl_mut();
        rpl.is_root = false;
        rpl.parent_rank = Some(Rank::ROOT);
        rpl.parent_address = Some(ip_addr(ROOT_ADDRESS));
        rpl.parent_preference = Some(0);
        rpl.parent_last_heard = Some(Instant::now());
        rpl.rank = Rank::new(256 * 2, 256);
        rpl.dodag_id = Some(ip_addr(ROOT_ADDRESS));

        (iface, sockets, TestDevice::new(Medium::Ieee802154))
    }

    fn rpl_unconnected_node(
        addr: Ieee802154Address,
        mop: ModeOfOperation,
    ) -> (Interface, SocketSet<'static>, TestDevice) {
        let (mut iface, sockets, _) = create(Medium::Ieee802154);
        iface.context_mut().rpl_mut().mode_of_operation = mop;

        iface.set_hardware_addr(HardwareAddress::Ieee802154(addr));
        iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(addr), 128)));

        let rpl = iface.context_mut().rpl_mut();
        rpl.is_root = false;

        (iface, sockets, TestDevice::new(Medium::Ieee802154))
    }

    #[test]
    fn trickle_timer_intervals() {
        let (mut iface, mut sockets, mut device) =
            rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

        let now = Instant::now();

        iface.poll(now, &mut device, &mut sockets);

        let mut i = iface.context().rpl().dio_timer.get_i();

        // Poll the interface and simulate 2.000 seconds.
        for t in 0..100_000 {
            // We set the counter to 1 to check that when a new interval is selected, the counter
            // is set to 0.
            iface.context_mut().rpl_mut().dio_timer.set_counter(1);

            iface.poll(
                now + Duration::from_millis(t * 10),
                &mut device,
                &mut sockets,
            );

            let trickle = &iface.context().rpl().dio_timer;

            // t should always be in between I/2 and I.
            assert!(trickle.get_i() / 2 < trickle.get_t());
            assert!(trickle.get_i() > trickle.get_t());

            // The new interval I should be double the previous one.
            if i != trickle.get_i() {
                assert_eq!(i * 2, trickle.get_i());
                i = trickle.get_i();
                assert_eq!(trickle.get_counter(), 0);
            }
        }
    }

    #[test]
    fn reset_trickle_timer_on_dis_multicast() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        // Check that the interval of the DIO trickle timer is not equal to the minimum value.
        let rpl = iface.context().rpl();
        assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

        // Create a DIS multicast message.
        let rpl_repr = RplRepr::DodagInformationSolicitation {
            options: Default::default(),
        };
        let packet = create_rpl_packet(
            ROOT_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        // Poll the interface such that the DIS message is processed and thus the trickle timer is
        // reset.
        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();
        assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[test]
    fn ignore_dis_with_solicited_information_option_mismatch() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        // Check that the interval of the DIO trickle timer is not equal to the minimum value.
        let rpl = iface.context().rpl();
        assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

        // Create a DIS multicast message.
        let dis_option = RplOptionRepr::SolicitedInformation {
            instance_id_predicate: true,
            rpl_instance_id: RplInstanceId::from(30),
            dodag_id_predicate: true,
            dodag_id: random_ieee802154_address(&mut Rand::new(1234))
                .as_link_local_address()
                .unwrap(),
            version_predicate: true,
            version_number: 240,
        };
        let mut options = heapless::Vec::new();
        options.push(dis_option).unwrap();
        let rpl_repr = RplRepr::DodagInformationSolicitation { options };
        let packet = create_rpl_packet(
            ROOT_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();
        assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[test]
    fn trickle_timer_is_running_by_default_when_node_is_root() {
        let (mut iface, mut sockets, mut device) =
            rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        // Check that the interval of the DIO trickle timer is not equal to the minimum value.
        let rpl = iface.context().rpl();
        assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[test]
    fn trickle_timer_is_not_running_by_default_when_node_is_not_root() {
        let (mut iface, mut sockets, mut device) =
            rpl_unconnected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        // Check that the interval of the DIO trickle timer is equal to the minimum value.
        let rpl = iface.context().rpl();
        assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[test]
    fn reset_trickle_timer_on_global_repair() {}

    #[test]
    fn reset_trickle_timer_on_local_repair() {}

    #[test]
    fn reset_trickle_timer_on_selecting_parent_and_increment_consistency_counter() {
        let (mut iface, mut sockets, mut device) =
            rpl_unconnected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        let mut options = heapless::Vec::new();
        options.push(iface.context().rpl().dodag_configuration()).unwrap();

        // Create a DIO message from a root node.
        let rpl_repr = RplRepr::DodagInformationObject {
            rpl_instance_id: RplInstanceId::from(30),
            version_number: SequenceCounter::default().value(),
            rank: Rank::ROOT.raw_value(),
            grounded: false,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
            dodag_preference: 0,
            dtsn: SequenceCounter::default().value(),
            dodag_id: ip_addr(ROOT_ADDRESS),
            options,
        };
        let packet = create_rpl_packet(
            ROOT_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        iface.poll(
            Instant::now() + Duration::from_secs(101),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();

        assert_eq!(rpl.parent_address, Some(ip_addr(ROOT_ADDRESS)));
        assert_eq!(rpl.parent_rank, Some(Rank::ROOT));
        assert_eq!(rpl.parent_preference, Some(0));
        assert_eq!(rpl.dodag_id, Some(ip_addr(ROOT_ADDRESS)));
        assert_eq!(rpl.dio_timer.get_counter(), 1);

        let mut options = heapless::Vec::new();
        options.push(iface.context().rpl().dodag_configuration()).unwrap();

        let rpl_repr = RplRepr::DodagInformationObject {
            rpl_instance_id: RplInstanceId::from(30),
            version_number: SequenceCounter::default().value(),
            rank: Rank::ROOT.raw_value(),
            grounded: false,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
            dodag_preference: 0,
            dtsn: SequenceCounter::default().value(),
            dodag_id: ip_addr(ROOT_ADDRESS),
            options,
        };
        let packet = create_rpl_packet(
            NODE_2_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        iface.poll(
            Instant::now() + Duration::from_secs(101),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();
        assert_eq!(rpl.dio_timer.get_counter(), 1);
    }

    #[test]
    fn reset_trickle_timer_on_root_receiving_dio_with_wrong_version_number() {
        let (mut iface, mut sockets, mut device) =
            rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        let rpl = iface.context().rpl();
        assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

        let mut options = heapless::Vec::new();
        options.push(iface.context().rpl().dodag_configuration()).unwrap();

        let mut version_number = SequenceCounter::default();
        version_number.increment();

        // Create a DIO message from a node, with a wrong version number.
        let rpl_repr = RplRepr::DodagInformationObject {
            rpl_instance_id: RplInstanceId::from(30),
            version_number: version_number.value(),
            rank: Rank::ROOT.raw_value(),
            grounded: false,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
            dodag_preference: 0,
            dtsn: SequenceCounter::default().value(),
            dodag_id: ip_addr(ROOT_ADDRESS),
            options,
        };

        let packet = create_rpl_packet(
            NODE_1_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        // Poll the interface such that the DIO message is processed and thus the node selects a
        // parent (and resets the trickle timer).
        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        // Check that the node selected a parent and dodag_id, and that the trickle timer is started.
        let rpl = iface.context().rpl();
        assert_eq!(rpl.dio_timer.get_counter(), 0);
        assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
    }

    #[test]
    fn reset_trickle_timer_on_parent_advertising_() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        let mut options = heapless::Vec::new();
        options.push(iface.context().rpl().dodag_configuration()).unwrap();

        // Create a DIO message from a node, with an infinite Rank.
        let rpl_repr = RplRepr::DodagInformationObject {
            rpl_instance_id: RplInstanceId::from(30),
            version_number: SequenceCounter::default().value(),
            rank: Rank::INFINITE.raw_value(),
            grounded: false,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
            dodag_preference: 0,
            dtsn: SequenceCounter::default().value(),
            dodag_id: ip_addr(ROOT_ADDRESS),
            options,
        };

        let packet = create_rpl_packet(
            ROOT_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            rpl_repr,
        );

        device.rx_queue.push_back(packet);

        // Poll the interface such that the DIO message is processed and thus the node selects a
        // parent (and resets the trickle timer).
        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();
        // TODO(thdveld): local repair
        //assert!(!rpl.has_parent());
        assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[test]
    fn trickle_timer_counter_increment_for_root_dio_from_child_rank_not_infinite() {
        let (mut iface, mut sockets, mut device) =
            rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        let mut options = heapless::Vec::new();
        options.push(iface.context().rpl().dodag_configuration()).unwrap();

        let packet = create_rpl_packet(
            NODE_1_ADDRESS,
            Ieee802154Pan(0xbeef),
            Ieee802154Address::BROADCAST,
            Ieee802154Pan(0xbeef),
            Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
            RplRepr::DodagInformationObject {
                rpl_instance_id: RplInstanceId::from(30),
                version_number: SequenceCounter::default().value(),
                rank: 256 * 2,
                grounded: false,
                mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
                dodag_preference: 0,
                dtsn: SequenceCounter::default().value(),
                dodag_id: ip_addr(ROOT_ADDRESS),
                options,
            },
        );

        device.rx_queue.push_back(packet);

        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();
        assert_eq!(rpl.dio_timer.get_counter(), 1);
    }

    #[test]
    fn remove_parent_when_not_hearing_parent() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        for i in 0..1500 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        let rpl = iface.context_mut().rpl_mut();
        rpl.parent_last_heard = Some(Instant::now() - Duration::from_secs(4_000));

        while let Some(packet) = device.tx_queue.pop_front() {
            println!(
                "{}",
                PrettyPrinter::<Ieee802154Frame<&[u8]>>::new("", &packet)
            );
            println!("");
        }

        for i in 0..10 {
            iface.poll(
                Instant::now() + Duration::from_secs(1505) + Duration::from_millis(i),
                &mut device,
                &mut sockets,
            );
        }

        let result = format!(
            "{}",
            PrettyPrinter::<Ieee802154Frame<&[u8]>>::new("", &device.tx_queue.pop_front().unwrap())
        );
        println!("{result}");

        assert_eq!(
            result,
            "IEEE802.15.4 Frame type=Data pan_id=0x00 src=02:02:02:02:02:02:02:02 dst=ff:ff\n\
             └─ 6LoWPAN_IPHC src=Stateless dst=Stateless nxt_hdr=ICMPv6 hop_limit=64\n\
             └─ IPv6 src=fe80::2:202:202:202 dst=ff02::1a nxt_hdr=ICMPv6 hop_limit=64\n \
             └─ ICMPv6 msg_type=RPL control message msg_code=1\n  \
             └─ DIO IID=Global(30) V=240 R=65535 G=false MOP=NoDownwardRoutesMaintained Pref=0 DTSN=240 DODAGID=fe80::301:101:101:101\n   \
             └─ DODAG CONF IntD=8 IntMin=12 RedCst=10 MaxRankIncr=1792 MinHopRankIncr=256 OCP=0 DefaultLifetime=30 LifeUnit=60"
        );

        let result = format!(
            "{}",
            PrettyPrinter::<Ieee802154Frame<&[u8]>>::new("", &device.tx_queue.pop_front().unwrap())
        );
        println!("{result}");

        assert_eq!(
            result,
            "IEEE802.15.4 Frame type=Data pan_id=0x00 src=02:02:02:02:02:02:02:02 dst=ff:ff\n\
             └─ 6LoWPAN_IPHC src=Stateless dst=Stateless nxt_hdr=ICMPv6 hop_limit=64\n\
             └─ IPv6 src=fe80::2:202:202:202 dst=ff02::1a nxt_hdr=ICMPv6 hop_limit=64\n \
             └─ ICMPv6 msg_type=RPL control message msg_code=0\n  \
             └─ DIS"
        );

        let rpl = iface.context().rpl();
        assert!(!rpl.has_parent());
        assert_eq!(rpl.rank, Rank::INFINITE);
    }

    #[test]
    fn inconsistent_rpl_hop_by_hop_option() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }

        // TODO(thvdveld): rewrite this into a function.
        let packet = {
            let ieee_repr = Ieee802154Repr {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: false,
                sequence_number: Some(7),
                pan_id_compression: true,
                frame_version: Ieee802154FrameVersion::Ieee802154_2003,
                dst_pan_id: Some(Ieee802154Pan(0)),
                dst_addr: Some(NODE_1_ADDRESS),
                src_pan_id: Some(Ieee802154Pan(0)),
                src_addr: Some(NODE_2_ADDRESS),
            };

            let iphc_repr = SixlowpanIphcRepr {
                src_addr: ip_addr(NODE_2_ADDRESS),
                ll_src_addr: Some(NODE_2_ADDRESS),
                dst_addr: ip_addr(ROOT_ADDRESS),
                ll_dst_addr: Some(NODE_1_ADDRESS),
                next_header: SixlowpanNextHeader::Uncompressed(IpProtocol::HopByHop),
                hop_limit: 64,
                ecn: None,
                dscp: None,
                flow_label: None,
            };

            let rpl_hop_by_hop_option = Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                down: false,
                rank_error: false,
                forwarding_error: false,
                instance_id: RplInstanceId::from(30),
                sender_rank: Rank::ROOT.raw_value(),
            });
            let mut rpl_option = vec![0u8; rpl_hop_by_hop_option.buffer_len()];
            rpl_hop_by_hop_option.emit(&mut Ipv6Option::new_unchecked(&mut rpl_option[..]));

            let hop_by_hop = Ipv6HopByHopRepr {
                next_header: None,
                length: 0,
                options: &rpl_option[..],
            };

            let size = ieee_repr.buffer_len() + iphc_repr.buffer_len() + hop_by_hop.buffer_len();

            let mut data = vec![0; size];
            let mut buffer = &mut data[..];

            let mut ieee_packet =
                Ieee802154Frame::new_unchecked(&mut buffer[..ieee_repr.buffer_len()]);
            ieee_repr.emit(&mut ieee_packet);
            buffer = &mut buffer[ieee_repr.buffer_len()..];

            let mut iphc_packet =
                SixlowpanIphcPacket::new_unchecked(&mut buffer[..iphc_repr.buffer_len()]);
            iphc_repr.emit(&mut iphc_packet);
            buffer = &mut buffer[iphc_repr.buffer_len()..];

            hop_by_hop.emit(&mut Ipv6HopByHopHeader::new_unchecked(
                &mut buffer[..hop_by_hop.buffer_len()],
            ));

            data
        };

        device.tx_queue.clear();
        device.rx_queue.push_back(packet);

        iface.context_mut().rpl_mut().dio_timer.set_counter(10);

        iface.poll(
            Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
            &mut device,
            &mut sockets,
        );

        let rpl = iface.context().rpl();

        // There should be a reset of the trickle timer because of the inconsistent hop-by-hop
        // optoin.
        assert_eq!(rpl.dio_timer.get_counter(), 0);
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    #[test]
    fn transmitting_udp_packet() {
        let (mut iface, mut sockets, mut device) =
            rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

        let udp_socket = crate::socket::udp::Socket::new(
            crate::socket::udp::PacketBuffer::new(
                vec![crate::socket::udp::PacketMetadata::EMPTY; 16],
                vec![0; 16 * 16],
            ),
            crate::socket::udp::PacketBuffer::new(
                vec![crate::socket::udp::PacketMetadata::EMPTY; 16],
                vec![0; 16 * 16],
            ),
        );

        let udp_handle = sockets.add(udp_socket);

        iface.context_mut().rpl_mut().neighbor_table.add_neighbor(
            RplNeighbor::new(
                ROOT_ADDRESS.into(),
                ip_addr(ROOT_ADDRESS),
                Some(Rank::ROOT),
                Some(0),
            ),
            Instant::now(),
        );

        // Poll the interface and simulate 100 seconds.
        for i in 0..100 {
            iface.poll(
                Instant::now() + Duration::from_secs(i),
                &mut device,
                &mut sockets,
            );
        }
        device.tx_queue.clear();

        let udp_socket: &mut crate::socket::udp::Socket = sockets.get_mut(udp_handle);
        udp_socket.bind(1234).unwrap();
        udp_socket
            .send_slice(
                b"Lorem ipsum dolor sit amet consectetur adipiscing, \
                elit cubilia integer duis ultrices, \
                montes cum tempor hendrerit tincidunt. R.",
                IpEndpoint::new(ip_addr(ROOT_ADDRESS).into(), 1234),
            )
            .unwrap();

        for i in 0..100 {
            iface.poll(
                Instant::now()
                    + Duration::from_secs(100)
                    + Duration::from_millis(100)
                    + Duration::from_millis(i),
                &mut device,
                &mut sockets,
            );
        }

        assert!(!device.tx_queue.is_empty());
        let first_packet = device.tx_queue.pop_front().unwrap();
        let second_packet = device.tx_queue.pop_front().unwrap();

        // Start parsing the packets and check that they are correct.
        let mut fragments_buffer = FragmentsBuffer {
            #[cfg(feature = "proto-sixlowpan")]
            decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],
            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_fragments: PacketAssemblerSet::new(),
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_fragments: PacketAssemblerSet::new(),
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan_fragments_cache_timeout: Duration::from_secs(60),
        };

        let ieee802154_packet = Ieee802154Frame::new_checked(&first_packet[..]).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_packet).unwrap();

        InterfaceInner::process_sixlowpan_fragment(
            &ieee802154_repr,
            ieee802154_packet.payload().unwrap(),
            &mut fragments_buffer,
            Instant::now(),
            &[],
        );

        let ieee802154_packet = Ieee802154Frame::new_checked(&second_packet[..]).unwrap();
        let ieee802154_repr = Ieee802154Repr::parse(&ieee802154_packet).unwrap();

        let data = InterfaceInner::process_sixlowpan_fragment(
            &ieee802154_repr,
            ieee802154_packet.payload().unwrap(),
            &mut fragments_buffer,
            Instant::now(),
            &[],
        )
        .unwrap();

        let mut buffer = [0u8; 1500];
        let len =
            InterfaceInner::decompress_sixlowpan(&[], &ieee802154_repr, data, None, &mut buffer)
                .unwrap();

        // The buffer should now contain an IPv6 packet.
        let buffer = &buffer[..len];
        let ipv6_packet = Ipv6Packet::new_checked(buffer).unwrap();
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();

        assert_eq!(ipv6_repr.src_addr, ip_addr(NODE_1_ADDRESS),);
        assert_eq!(ipv6_repr.dst_addr, ip_addr(ROOT_ADDRESS));
        assert_eq!(ipv6_repr.next_header, IpProtocol::HopByHop);
        assert_eq!(ipv6_repr.hop_limit, 64);

        // And a hop-by-hop header.
        let hbh = Ipv6HopByHopRepr::parse(
            &Ipv6HopByHopHeader::new_checked(ipv6_packet.payload()).unwrap(),
        )
        .unwrap();

        assert_eq!(hbh.next_header, Some(IpProtocol::Udp));
        assert_eq!(hbh.length, 0);

        for opt in hbh.options() {
            let opt = opt.unwrap();
            match opt {
                Ipv6OptionRepr::Rpl(rpl) => {
                    assert!(!rpl.down);
                    assert!(!rpl.rank_error);
                    assert!(!rpl.forwarding_error);
                    assert_eq!(rpl.instance_id, crate::wire::rpl::InstanceId::from(30));
                    assert_eq!(rpl.sender_rank, 512);
                }
                _ => unreachable!(),
            }
        }

        // And a UDP header.
        let udp_packet =
            UdpPacket::new_checked(&ipv6_packet.payload()[hbh.buffer_len()..]).unwrap();
        let udp = UdpRepr::parse(
            &udp_packet,
            &ipv6_repr.src_addr.into(),
            &ipv6_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();

        assert_eq!(udp.src_port, 1234);
        assert_eq!(udp.dst_port, 1234);
        assert_eq!(
            udp_packet.payload(),
            b"Lorem ipsum dolor sit amet consectetur adipiscing, \
            elit cubilia integer duis ultrices, \
            montes cum tempor hendrerit tincidunt. R.",
        );
    }
}
