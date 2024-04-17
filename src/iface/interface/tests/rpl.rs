use super::*;

use crate::iface::packet::*;

use crate::iface::RplModeOfOperation;

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[cfg(feature = "rpl-mop-0")]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[cfg(feature = "rpl-mop-1")]
#[case::mop2(RplModeOfOperation::StoringMode)]
#[cfg(feature = "rpl-mop-2")]
#[case::mop3(RplModeOfOperation::StoringModeWithMulticast)]
#[cfg(feature = "rpl-mop-3")]
fn unicast_dis(#[case] mop: RplModeOfOperation) {
    use crate::iface::rpl::{Dodag, Rank, RplInstanceId};

    let (mut iface, _, _) = setup(Medium::Ieee802154);
    iface.inner.rpl.is_root = true;
    iface.inner.rpl.mode_of_operation = mop;
    iface.inner.rpl.dodag = Some(Dodag {
        instance_id: RplInstanceId::Local(30),
        id: Default::default(),
        version_number: Default::default(),
        preference: 0,
        rank: Rank::ROOT,
        dio_timer: Default::default(),
        dao_expiration: Instant::now(),
        dao_seq_number: Default::default(),
        dao_acks: Default::default(),
        daos: Default::default(),
        parent: Default::default(),
        without_parent: Default::default(),
        authentication_enabled: Default::default(),
        path_control_size: Default::default(),
        dtsn: Default::default(),
        dtsn_incremented_at: Instant::now(),
        default_lifetime: Default::default(),
        lifetime_unit: Default::default(),
        grounded: false,
        parent_set: Default::default(),
        relations: Default::default(),
    });

    let addr = Ipv6Address::from_parts(&[0xfe80, 0, 0, 0, 0, 0, 0, 2]);

    let response = iface.inner.process_rpl_dis(
        Ipv6Repr {
            src_addr: addr,
            dst_addr: iface.ipv6_addr().unwrap(),
            next_header: IpProtocol::Icmpv6,
            payload_len: 0, // does not matter
            hop_limit: 0,   // does not matter
        },
        RplDis {
            options: Default::default(),
        },
    );

    let mut dio_options = heapless::Vec::new();
    dio_options
        .push(RplOptionRepr::DodagConfiguration(RplDodagConfiguration {
            authentication_enabled: false,
            path_control_size: 0,
            dio_interval_doublings: 8,
            dio_interval_min: 12,
            dio_redundancy_constant: 10,
            max_rank_increase: 0,
            minimum_hop_rank_increase: 256,
            objective_code_point: 0,
            default_lifetime: 0,
            lifetime_unit: 0,
        }))
        .unwrap();

    let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(RplDio {
        rpl_instance_id: RplInstanceId::Local(30),
        version_number: Default::default(),
        rank: Rank::ROOT.raw_value(),
        grounded: false,
        mode_of_operation: mop.into(),
        dodag_preference: 0,
        dtsn: Default::default(),
        dodag_id: Default::default(),
        options: dio_options,
    }));

    let expected = Some(Packet::Ipv6(PacketV6::new(
        Ipv6Repr {
            src_addr: iface.ipv6_addr().unwrap(),
            dst_addr: addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv6(icmp),
    )));

    assert_eq!(response, expected,);
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[cfg(feature = "rpl-mop-0")]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[cfg(feature = "rpl-mop-1")]
#[case::mop2(RplModeOfOperation::StoringMode)]
#[cfg(feature = "rpl-mop-2")]
#[case::mop3(RplModeOfOperation::StoringModeWithMulticast)]
#[cfg(feature = "rpl-mop-3")]
fn dio_without_configuration(#[case] mop: RplModeOfOperation) {
    use crate::iface::rpl::{Rank, RplInstanceId};

    let (mut iface, _, _) = setup(Medium::Ieee802154);
    iface.inner.rpl.mode_of_operation = mop;

    let ll_addr = Ieee802154Address::Extended([0, 0, 0, 0, 0, 0, 0, 2]);
    let addr = ll_addr.as_link_local_address().unwrap();

    let response = iface.inner.process_rpl_dio(
        Ipv6Repr {
            src_addr: addr,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: 0, // does not matter
            hop_limit: 0,   // does not matter
        },
        RplDio {
            rpl_instance_id: RplInstanceId::Local(30),
            version_number: Default::default(),
            rank: Rank::ROOT.raw_value(),
            grounded: false,
            mode_of_operation: mop.into(),
            dodag_preference: 0,
            dtsn: Default::default(),
            dodag_id: Default::default(),
            options: Default::default(),
        },
    );

    let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation(RplDis {
        options: Default::default(),
    }));

    let expected = Some(Packet::Ipv6(PacketV6::new(
        Ipv6Repr {
            src_addr: iface.ipv6_addr().unwrap(),
            dst_addr: addr,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv6(icmp),
    )));

    assert_eq!(response, expected,);
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[cfg(feature = "rpl-mop-0")]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[cfg(feature = "rpl-mop-1")]
#[case::mop2(RplModeOfOperation::StoringMode)]
#[cfg(feature = "rpl-mop-2")]
#[case::mop3(RplModeOfOperation::StoringModeWithMulticast)]
#[cfg(feature = "rpl-mop-3")]
fn dio_with_increased_version_number(#[case] mop: RplModeOfOperation) {
    use crate::iface::rpl::{Dodag, ObjectiveFunction0, Parent, ParentSet, Rank, RplInstanceId};

    let (mut iface, _, _) = setup(Medium::Ieee802154);

    let ll_addr = Ieee802154Address::Extended([0, 0, 0, 0, 0, 0, 0, 1]);
    let addr = ll_addr.as_link_local_address().unwrap();

    let now = Instant::now();
    let mut set = ParentSet::default();
    let _ = set.add(Parent::new(
        addr,
        Rank::ROOT,
        Default::default(),
        RplSequenceCounter::from(240),
        Default::default(),
        now,
    ));

    // Setting a dodag configuration with parent
    iface.inner.rpl.mode_of_operation = mop;
    iface.inner.rpl.of = ObjectiveFunction0::default();
    iface.inner.rpl.is_root = false;
    iface.inner.rpl.dodag = Some(Dodag {
        instance_id: RplInstanceId::Local(30),
        id: Default::default(),
        version_number: Default::default(),
        preference: 0,
        rank: Rank::new(1024, 16),
        dio_timer: Default::default(),
        dao_expiration: Instant::now(),
        dao_seq_number: Default::default(),
        dao_acks: Default::default(),
        daos: Default::default(),
        parent: Some(addr),
        without_parent: Default::default(),
        authentication_enabled: Default::default(),
        path_control_size: Default::default(),
        dtsn: Default::default(),
        dtsn_incremented_at: Instant::now(),
        default_lifetime: Default::default(),
        lifetime_unit: Default::default(),
        grounded: false,
        parent_set: set,
        relations: Default::default(),
    });
    let old_version_number = iface.inner.rpl.dodag.as_ref().unwrap().version_number;

    // Check if the parameters are set correctly
    assert_eq!(old_version_number, RplSequenceCounter::from(240));
    assert!(!iface
        .inner
        .rpl
        .dodag
        .as_ref()
        .unwrap()
        .parent_set
        .is_empty());

    // Receiving DIO with increased version number from node from another dodag
    let response = iface.inner.process_rpl_dio(
        Ipv6Repr {
            src_addr: addr,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: 0, // does not matter
            hop_limit: 0,   // does not matter
        },
        RplDio {
            rpl_instance_id: RplInstanceId::Local(31),
            version_number: RplSequenceCounter::from(242),
            rank: Rank::new(16, 16).raw_value(),
            grounded: false,
            mode_of_operation: mop.into(),
            dodag_preference: 0,
            dtsn: Default::default(),
            dodag_id: Default::default(),
            options: Default::default(),
        },
    );

    // The version number should stay the same
    assert_eq!(
        iface.inner.rpl.dodag.as_ref().unwrap().version_number,
        RplSequenceCounter::from(240)
    );

    // The instance id should stay the same
    assert_eq!(
        iface.inner.rpl.dodag.as_ref().unwrap().instance_id,
        RplInstanceId::Local(30)
    );

    // The parent should remain the same
    assert_eq!(iface.inner.rpl.dodag.as_ref().unwrap().parent, Some(addr));

    // The parent set should remain the same
    assert!(!iface
        .inner
        .rpl
        .dodag
        .as_ref()
        .unwrap()
        .parent_set
        .is_empty());

    // Response should be None
    assert_eq!(response, None);

    // Upon receving a DIO with a lesser DODAG Version Number value the node cannot select the sender as a parent
    let ll_addr2 = Ieee802154Address::Extended([0, 0, 0, 0, 0, 0, 0, 3]);
    let addr2 = ll_addr2.as_link_local_address().unwrap();

    let response = iface.inner.process_rpl_dio(
        Ipv6Repr {
            src_addr: addr2,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: 0, // does not matter
            hop_limit: 0,   // does not matter
        },
        RplDio {
            rpl_instance_id: RplInstanceId::Local(30),
            version_number: RplSequenceCounter::from(239),
            rank: Rank::new(16, 16).raw_value(),
            grounded: false,
            mode_of_operation: mop.into(),
            dodag_preference: 0,
            dtsn: Default::default(),
            dodag_id: Default::default(),
            options: Default::default(),
        },
    );

    // Response should be None
    assert_eq!(response, None);

    // The parent should remain the same
    assert_eq!(iface.inner.rpl.dodag.as_ref().unwrap().parent, Some(addr));

    // Receiving DIO with increased version number from root which is also parent
    let response = iface.inner.process_rpl_dio(
        Ipv6Repr {
            src_addr: addr,
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: 0, // does not matter
            hop_limit: 0,   // does not matter
        },
        RplDio {
            rpl_instance_id: RplInstanceId::Local(30),
            version_number: RplSequenceCounter::from(241),
            rank: Rank::ROOT.raw_value(),
            grounded: false,
            mode_of_operation: mop.into(),
            dodag_preference: 0,
            dtsn: Default::default(),
            dodag_id: Default::default(),
            options: Default::default(),
        },
    );

    // The version number should be increased
    assert_eq!(
        iface.inner.rpl.dodag.as_ref().unwrap().version_number,
        RplSequenceCounter::from(241)
    );

    // The parent should be removed
    assert_eq!(iface.inner.rpl.dodag.as_ref().unwrap().parent, None);

    // The parent set should be empty
    assert!(iface
        .inner
        .rpl
        .dodag
        .as_ref()
        .unwrap()
        .parent_set
        .is_empty());

    let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(RplDio {
        rpl_instance_id: RplInstanceId::Local(30),
        version_number: RplSequenceCounter::from(241),
        rank: Rank::INFINITE.raw_value(),
        grounded: false,
        mode_of_operation: mop.into(),
        dodag_preference: 0,
        dtsn: Default::default(),
        dodag_id: Default::default(),
        options: heapless::Vec::new(),
    }));

    let expected = Some(Packet::Ipv6(PacketV6::new(
        Ipv6Repr {
            src_addr: iface.ipv6_addr().unwrap(),
            dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
            next_header: IpProtocol::Icmpv6,
            payload_len: icmp.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv6(icmp),
    )));

    // DIO with infinite rank is sent with the new version number so the nodes
    // know they have to leave the network
    assert_eq!(response, expected,);
}
