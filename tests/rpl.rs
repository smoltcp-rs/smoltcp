use rstest::rstest;

use smoltcp::iface::RplConfig;
use smoltcp::iface::RplModeOfOperation;
use smoltcp::iface::RplRootConfig;
use smoltcp::time::*;
use smoltcp::wire::{Icmpv6Repr, Ipv6Address, RplInstanceId, RplOptionRepr, RplRepr};

mod sim;

const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

/// A RPL root node only. We count the amount of DIO's it transmits. For our Trickle implementation,
/// this should be around 10 for 1 hour. Changing the Trickle parameters will make this test fail.
/// This is valid for all modes of operation.
#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn root_node_only(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::NetworkSim::new();
    sim.create_node(RplConfig::new(mop).add_root_config(RplRootConfig::new(
        RplInstanceId::from(30),
        Ipv6Address::default(),
    )));

    sim.run(Duration::from_millis(500), ONE_HOUR);

    assert!(!sim.msgs().is_empty());

    // In 1 hour, a root node will transmit around 10 messages.
    let dio_count = sim.msgs().iter().filter(|m| m.is_dio()).count();
    assert!(dio_count == 9 || dio_count == 10 || dio_count == 11);

    // There should only be DIO's.
    for msg in sim.msgs() {
        assert!(msg.is_dio());
    }
}

/// A RPL normal node that is out of range of any DODAG. The normal node
/// should transmit DIS messages, soliciting for a DODAG. These messages are transmitted every 60
/// seconds. In hour, 60 DIS messages should be transmitted.
#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn normal_node_without_dodag(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::NetworkSim::new();
    sim.create_node(RplConfig::new(mop));

    sim.run(Duration::from_millis(500), ONE_HOUR);

    assert!(!sim.msgs().is_empty());

    // In 1 hour, around 60 DIS messages are transmitted by 1 node.
    let dis_count = sim.msgs().iter().filter(|m| m.is_dis()).count();
    assert!(dis_count == 59 || dis_count == 60 || dis_count == 61);

    // There should only be DIS messages.
    for msg in sim.msgs() {
        assert!(msg.is_dis());
    }
}

/// A RPL root node and a normal node in range of the root node.
/// In all mode of operations, DIOs should be transmitted.
/// For MOP1, MOP2 and MOP3, DAOs and DAO-ACKs should be transmitted.
/// We run the simulation for 15 minutes. During this period, around 7 DIOs should be transmitted
/// by each node (root and normal node). In MOP1, MOP2 and MOP3, the normal node should transmit 1
/// DAO and the root 1 DAO-ACK. By default, DAOs require an ACK in smoltcp.
#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn root_and_normal_node(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 1);

    sim.run(Duration::from_millis(500), Duration::from_secs(60 * 15));

    assert!(!sim.msgs().is_empty());

    let dio_count = sim.msgs().iter().filter(|m| m.is_dio()).count();

    assert!(dio_count > 12 && dio_count < 17);

    match mop {
        RplModeOfOperation::NonStoringMode
        | RplModeOfOperation::StoringMode
        | RplModeOfOperation::StoringModeWithMulticast => {
            let dao_count = sim.msgs().iter().filter(|m| m.is_dao()).count();
            let dao_ack_count = sim.msgs().iter().filter(|m| m.is_dao_ack()).count();

            assert_eq!(dao_count, 1);
            assert_eq!(dao_ack_count, 1);
        }
        _ => (),
    }

    for msg in sim.msgs() {
        match mop {
            // In MOP0, all messages should be DIOs. A node only transmits its first DIS after 5
            // seconds. The first DIO from the root is transmitted after 2 - 4 seconds after the
            // start. Therefore, there should never be a DIS in the messages.
            RplModeOfOperation::NoDownwardRoutesMaintained => assert!(msg.is_dio()),
            // In MOP1, MOP2, MOP3, DAOs and DAO-ACKs are also transmitted.
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(msg.is_dio() || msg.is_dao() || msg.is_dao_ack())
            }
        }
    }
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn root_and_normal_node_moved_out_of_range(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 1);

    sim.run(Duration::from_millis(100), ONE_HOUR);

    assert!(!sim.msgs().is_empty());

    // We check that a node is connect to the DODAG, meaning there should be no DIS messages.
    for msg in sim.msgs() {
        match mop {
            // In MOP0, all messages should be DIOs. A node only transmits its first DIS after 5
            // seconds. The first DIO from the root is transmitted after 2 - 4 seconds after the
            // start. Therefore, there should never be a DIS in the messages.
            RplModeOfOperation::NoDownwardRoutesMaintained => assert!(msg.is_dio()),
            // In MOP1, MOP2, MOP3, DAOs and DAO-ACKs are also transmitted.
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(msg.is_dio() || msg.is_dao() || msg.is_dao_ack())
            }
        }
    }

    sim.clear_msgs();

    // Move the node far from the root node.
    sim.nodes_mut()[1].set_position(sim::Position((1000., 0.)));

    sim.run(Duration::from_millis(400), ONE_HOUR);

    match mop {
        RplModeOfOperation::NonStoringMode | RplModeOfOperation::StoringMode => {
            let dao_count = sim.msgs().iter().filter(|m| m.is_dao()).count();
            assert!(dao_count < 5);
        }
        _ => {}
    }

    // When a node leaves a DODAG, it multicasts an INFINITE rank DIO.
    let infinite_rank_dio_count = sim
        .msgs()
        .iter()
        .filter(|m| {
            if m.is_dio() {
                let icmp = m.icmp().unwrap();
                let Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(dio)) = icmp else {
                    return false;
                };
                dio.rank == 0xffff
            } else {
                false
            }
        })
        .count();

    assert!(infinite_rank_dio_count == 1);

    for msg in sim.msgs() {
        match mop {
            // There should be no DAO or DAO-ACK, however, it should containt DIS's.
            RplModeOfOperation::NoDownwardRoutesMaintained => {
                assert!(msg.is_dio() || msg.is_dis())
            }
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(msg.is_dio() || msg.is_dis() || msg.is_dao());
            }
        }
    }

    sim.clear_msgs();

    // Move the node back in range of the root node.
    sim.nodes_mut()[1].set_position(sim::Position((100., 0.)));

    sim.run(Duration::from_millis(100), ONE_HOUR);

    // NOTE: in rare cases, I don't know why, 2 DIS messages are transmitted instead of just 1.
    let dis_count = sim.msgs().iter().filter(|m| m.is_dis()).count();
    assert!(dis_count < 3);

    for msg in sim.msgs() {
        match mop {
            // In MOP0, all messages should be DIOs. A node only transmits its first DIS after 5
            // seconds. The first DIO from the root is transmitted after 2 - 4 seconds after the
            // start. Therefore, there should never be a DIS in the messages.
            RplModeOfOperation::NoDownwardRoutesMaintained => {
                assert!(msg.is_dio() || msg.is_dis())
            }
            // In MOP1, MOP2, MOP3, DAOs and DAO-ACKs are also transmitted.
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(msg.is_dis() || msg.is_dio() || msg.is_dao() || msg.is_dao_ack())
            }
        }
    }
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn message_forwarding_to_root(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 2);

    let dst_addr = sim.nodes()[0].ip_address;
    sim::udp_receiver_node(&mut sim.nodes_mut()[0], 1234);
    sim::udp_sender_node(&mut sim.nodes_mut()[2], 1234, dst_addr);

    sim.init();
    sim.run(Duration::from_millis(500), ONE_HOUR);

    assert!(!sim.msgs().is_empty());

    let dio_count = sim.msgs().iter().filter(|m| m.is_dio()).count();
    assert!(dio_count > 27 && dio_count < 33);

    // We transmit a message every 60 seconds. We simulate for 1 hour, so the node will transmit
    // 59 messages. The node is not in range of the destination (which is the root). There is one
    // node inbetween that has to forward it. Thus, it is forwarding 59 messages.
    let udp_count = sim.msgs().iter().filter(|m| m.is_udp()).count();
    assert!(udp_count >= 59 * 2 && udp_count <= 60 * 2);

    for msg in sim.msgs() {
        match mop {
            RplModeOfOperation::NoDownwardRoutesMaintained => {
                assert!(msg.is_dis() || msg.is_dio() || msg.is_udp())
            }
            // In MOP1, MOP2, MOP3, DAOs and DAO-ACKs are also transmitted.
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(
                    msg.is_dis()
                        || msg.is_dio()
                        || msg.is_dao()
                        || msg.is_dao_ack()
                        || msg.is_udp()
                )
            }
        }
    }
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn message_forwarding_up_and_down(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 2, 2);

    let dst_addr = sim.nodes()[3].ip_address;
    sim::udp_receiver_node(&mut sim.nodes_mut()[3], 1234);
    sim::udp_sender_node(&mut sim.nodes_mut()[4], 1234, dst_addr);

    sim.init();
    sim.run(Duration::from_millis(500), Duration::from_secs(60 * 15));

    assert!(!sim.msgs().is_empty());

    let dio_count = sim.msgs().iter().filter(|m| m.is_dio()).count();
    assert!(dio_count >= 30 && dio_count <= 40);

    // We transmit a message every 60 seconds. We simulate for 1 hour, so the node will transmit
    // 59 messages. The node is not in range of the destination (which is the root). There is one
    // node inbetween that has to forward it. Thus, it is forwarding 59 messages.
    let udp_count = sim.msgs().iter().filter(|m| m.is_udp()).count();
    match mop {
        RplModeOfOperation::NoDownwardRoutesMaintained => {
            assert!(udp_count >= 14 * 2 && udp_count <= 15 * 2);
        }
        RplModeOfOperation::NonStoringMode
        | RplModeOfOperation::StoringMode
        | RplModeOfOperation::StoringModeWithMulticast => {
            assert!(udp_count >= 14 * 4 && udp_count <= 15 * 4);
        }
    }

    for msg in sim.msgs() {
        match mop {
            RplModeOfOperation::NoDownwardRoutesMaintained => {
                assert!(msg.is_dis() || msg.is_dio() || msg.is_udp())
            }
            // In MOP1, MOP2, MOP3, DAOs and DAO-ACKs are also transmitted.
            RplModeOfOperation::NonStoringMode
            | RplModeOfOperation::StoringMode
            | RplModeOfOperation::StoringModeWithMulticast => {
                assert!(
                    msg.is_dis()
                        || msg.is_dio()
                        || msg.is_dao()
                        || msg.is_dao_ack()
                        || msg.is_udp()
                )
            }
        }
    }

    // All UDP, DAO, DAO-ACK packets should have a HBH or a source routing header
    sim.msgs()
        .iter()
        .filter(|m| m.is_udp() || m.is_dao() || m.is_dao_ack())
        .for_each(|m| assert!(m.has_hbh() || m.has_routing()));

    let dao_ack_packets_with_routing = sim
        .msgs()
        .iter()
        .filter(|m| m.is_dao_ack() && m.has_routing())
        .count();
    let dao_ack_packets_without_routing = sim
        .msgs()
        .iter()
        .filter(|m| m.is_dao_ack() && !m.has_routing())
        .count();

    match mop {
        RplModeOfOperation::NonStoringMode => {
            assert!(dao_ack_packets_with_routing == 4,);
            assert!(dao_ack_packets_without_routing == 2,);
        }
        RplModeOfOperation::StoringMode | RplModeOfOperation::StoringModeWithMulticast => {
            assert!(dao_ack_packets_with_routing == 0,);
            assert!(dao_ack_packets_without_routing == 6,);
        }
        _ => {
            assert!(dao_ack_packets_with_routing == 0,);
            assert!(dao_ack_packets_without_routing == 0,);
        }
    }
}

#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn normal_node_change_parent(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 2);
    sim.run(Duration::from_millis(100), Duration::from_secs(60 * 5));

    assert!(!sim.messages.is_empty());

    // Move the the second node such that it is also in the range of a node with smaller rank.
    sim.nodes[2].set_position(sim::Position((50., -50.)));

    sim.run(Duration::from_millis(100), Duration::from_secs(60 * 5));

    // Counting number of NO-PATH DAOs sent
    let mut no_path_dao_count = 0;

    for msg in sim.messages {
        if msg.is_dao().unwrap() {
            let icmp = msg.icmp().unwrap().unwrap();
            let Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(dao)) = icmp else {
                break;
            };
            for opt in dao.options {
                if let RplOptionRepr::TransitInformation(o) = opt {
                    if o.path_lifetime == 0 {
                        no_path_dao_count += 1;
                    }
                }
            }
        }
    }
    match mop {
        // In MOP 2 when a nodes leaves it's parent it should send a NO-PATH DAO
        RplModeOfOperation::StoringMode => {
            assert!(no_path_dao_count > 0,);
        }
        // In MOP 1 and MOP 0 there should be no NO-PATH DAOs sent
        RplModeOfOperation::NonStoringMode | RplModeOfOperation::NoDownwardRoutesMaintained => {
            assert!(no_path_dao_count == 0,);
        }
        _ => {}
    }
}
