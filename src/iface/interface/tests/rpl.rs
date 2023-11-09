use super::*;

use crate::iface::RplModeOfOperation;

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[cfg(feature = "rpl-mop-0")]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[cfg(feature = "rpl-mop-1")]
#[case::mop2(RplModeOfOperation::StoringMode)]
#[cfg(feature = "rpl-mop-2")]
fn unicast_dis(#[case] mop: RplModeOfOperation) {
    use crate::iface::rpl::{Dodag, Rank, RplInstanceId};

    let (mut iface, mut sockets, _device) = setup(Medium::Ieee802154);
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

    assert_eq!(
        response,
        Some(IpPacket::Ipv6(Ipv6Packet {
            header: Ipv6Repr {
                src_addr: iface.ipv6_addr().unwrap(),
                dst_addr: addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: 44,
                hop_limit: 64
            },
            hop_by_hop: None,
            routing: None,
            payload: IpPayload::Icmpv6(Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(RplDio {
                rpl_instance_id: RplInstanceId::Local(30),
                version_number: Default::default(),
                rank: Rank::ROOT.raw_value(),
                grounded: false,
                mode_of_operation: mop.into(),
                dodag_preference: 0,
                dtsn: Default::default(),
                dodag_id: Default::default(),
                options: dio_options,
            }))),
        }))
    );
}
