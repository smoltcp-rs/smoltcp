use rstest::rstest;

use smoltcp::iface::RplConfig;
use smoltcp::iface::RplModeOfOperation;
use smoltcp::iface::RplRootConfig;
use smoltcp::time::*;
use smoltcp::wire::{Icmpv6Repr, Ipv6Address, RplDio, RplInstanceId, RplOptionRepr, RplRepr};

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
    assert!((118..=120).contains(&udp_count));

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
    assert!((30..=40).contains(&dio_count));

    // We transmit a message every 60 seconds. We simulate for 1 hour, so the node will transmit
    // 59 messages. The node is not in range of the destination (which is the root). There is one
    // node inbetween that has to forward it. Thus, it is forwarding 59 messages.
    let udp_count = sim.msgs().iter().filter(|m| m.is_udp()).count();
    match mop {
        RplModeOfOperation::NoDownwardRoutesMaintained => {
            assert!((28..=30).contains(&udp_count));
        }
        RplModeOfOperation::NonStoringMode
        | RplModeOfOperation::StoringMode
        | RplModeOfOperation::StoringModeWithMulticast => {
            assert!((52..=60).contains(&udp_count));
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
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 3);
    sim.run(Duration::from_millis(500), Duration::from_secs(60 * 5));

    assert!(!sim.msgs().is_empty());

    // Move the the second node such that it is also in the range of a node with smaller rank.
    sim.nodes_mut()[3].set_position(sim::Position((150., -50.)));
    sim.clear_msgs();

    sim.run(Duration::from_millis(500), ONE_HOUR);

    // Counter for sent NO-PATH DAOs
    let mut no_path_dao_count = 0;
    // Counter for not acknowledged NO-PATH DAOs
    let mut dao_no_ack_req_count = 0;
    // Counter for DIOs for the node that changed the parent
    // This node should reset its Trickle Timer
    let mut dio_count = 0;

    for msg in sim.msgs() {
        if msg.is_dao() {
            let icmp = msg.icmp().unwrap();
            let Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(dao)) = icmp else {
                break;
            };
            dao_no_ack_req_count += !dao.expect_ack as usize;
            no_path_dao_count += dao
                .options
                .iter()
                .filter(|opt| {
                    if let RplOptionRepr::TransitInformation(o) = opt {
                        o.path_lifetime == 0
                    } else {
                        false
                    }
                })
                .count();
        }
        if msg.is_dio() && msg.from.0 == 3 {
            dio_count += 1;
        }
    }

    match mop {
        // In MOP 2 when a nodes leaves it's parent it should send a NO-PATH DAO
        RplModeOfOperation::StoringMode => {
            // The node sends a NO-PATH DAO to the parent that forwards it to its own parent
            // until it reaches the root, that is why there will be 3 NO-PATH DAOs sent
            assert!(no_path_dao_count == 3);
            // NO-PATH DAO should have the ack request flag set to false only when it is sent
            // to the old parent
            assert!(dao_no_ack_req_count == 1);
            assert!(dio_count > 9 && dio_count < 12);
        }
        // In MOP 1 and MOP 0 there should be no NO-PATH DAOs sent
        RplModeOfOperation::NonStoringMode | RplModeOfOperation::NoDownwardRoutesMaintained => {
            assert!(no_path_dao_count == 0,);
            // By default all DAOs are acknowledged with the exception of the NO-PATH DAO
            // destined to the old parent
            assert!(dao_no_ack_req_count == 0,);
            assert!(dio_count > 9 && dio_count < 12);
        }
        _ => {}
    }
}

// When a parent leaves the network, its children nodes should also leave the DODAG
// if there are no alternate parents they can choose from.
#[rstest]
#[case::mop0(RplModeOfOperation::NoDownwardRoutesMaintained)]
#[case::mop1(RplModeOfOperation::NonStoringMode)]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn parent_leaves_network_no_other_parent(#[case] mop: RplModeOfOperation) {
    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 4, 2);
    sim.run(Duration::from_millis(500), ONE_HOUR);

    // Parent leaves network, child node does not have an alternative parent.
    // The child node should send INFINITE_RANK DIO and after that only send DIS messages
    // since it is unable to connect back to the tree
    sim.nodes_mut()[1].set_position(sim::Position((300., 300.)));

    sim.clear_msgs();

    sim.run(Duration::from_millis(500), ONE_HOUR);

    let no_parent_node_msgs: Vec<_> = sim.msgs().iter().filter(|m| m.from.0 == 5).collect();

    let infinite_dio_msgs = no_parent_node_msgs
        .iter()
        .filter(|m| {
            let icmp = m.icmp().unwrap();
            let Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(dio)) = icmp else {
                return false;
            };
            dio.rank == 65535
        })
        .count();
    let dis_msgs = no_parent_node_msgs.iter().filter(|m| m.is_dis()).count();

    assert_eq!(infinite_dio_msgs, 1);
    assert!(dis_msgs > 0 && dis_msgs < 62);
}

// In MOP 2 the DTSN is incremented when a parent does not hear anymore from one of its children.
#[rstest]
#[case::mop2(RplModeOfOperation::StoringMode)]
fn dtsn_incremented_when_child_leaves_network(#[case] mop: RplModeOfOperation) {
    use std::collections::HashMap;

    let mut sim = sim::topology(sim::NetworkSim::new(), mop, 1, 5);
    sim.nodes_mut()[4].set_position(sim::Position((200., 100.)));
    sim.nodes_mut()[5].set_position(sim::Position((-100., 0.)));

    sim.run(Duration::from_millis(500), ONE_HOUR);

    // One node is moved out of the range of its parent.
    sim.nodes_mut()[4].set_position(sim::Position((500., 500.)));

    sim.clear_msgs();

    sim.run(Duration::from_millis(500), ONE_HOUR);

    // Keep track of when was the first DIO with increased DTSN sent
    let mut dio_at = Instant::ZERO;
    let mut time_set = false;

    // The parent will not hear anymore from the child and will increment DTSN.
    // All the nodes that had the missing child in the relations table will increment DTSN.
    let node_ids_with_dtsn_incremented: Vec<usize> = sim
        .nodes_mut()
        .iter()
        .filter_map(|n| if n.id != 5 { Some(n.id) } else { None })
        .collect();

    let dios: HashMap<usize, RplDio> = sim
        .msgs()
        .iter()
        .filter_map(|msg| {
            if let Some(Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(dio))) = msg.icmp() {
                if msg.from.0 == 2 && dio.dtsn.value() == 241 && !time_set {
                    dio_at = msg.at;
                    time_set = true;
                }
                Some((msg.from.0, dio))
            } else {
                None
            }
        })
        .collect();

    if dios.is_empty() {
        panic!("No DIO messages found");
    }

    dios.iter()
        .filter(|(_, v)| v.dtsn.value() == 241)
        .for_each(|(k, _)| assert!(node_ids_with_dtsn_incremented.contains(k)));

    // The nodes that did not have the missing child in the relations table will not increase
    // the DTSN even if they hear a DIO with increased DTSN from parent.
    dios.iter()
        .filter(|(k, _)| **k == 4 || **k == 5)
        .for_each(|(_, v)| assert_eq!(v.dtsn.value(), 240));

    // The remaining children will send DAOs to renew paths when hearing a DIO
    // with incremented DTSN from their preferred parent
    let dao_at = sim.msgs().iter().find_map(|m| {
        if m.from.0 == 3 && m.is_dao() && m.at.gt(&dio_at) {
            return Some(m.at);
        }
        None
    });

    if dao_at.is_some() {
        println!("dao_at {} and dio_at {dio_at}", dao_at.unwrap());
        assert!(dao_at.unwrap() - dio_at < Duration::from_secs(6));
    }
}
