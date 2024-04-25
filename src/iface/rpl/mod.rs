#![allow(unused)]

mod consts;
mod of0;
mod parents;
mod rank;
mod relations;
mod trickle;

use crate::config::RPL_MAX_OPTIONS;
use crate::rand::Rand;
use crate::time::{Duration, Instant};
use crate::wire::{
    Icmpv6Repr, Ipv6Address, RplDao, RplDio, RplDodagConfiguration, RplOptionRepr, RplRepr,
    RplSequenceCounter, RplTarget, RplTransitInformation,
};

pub(crate) use of0::{ObjectiveFunction, ObjectiveFunction0};
pub(crate) use parents::{Parent, ParentSet};
pub(crate) use rank::Rank;
pub(crate) use relations::Relations;

pub use crate::wire::RplInstanceId;
pub use trickle::TrickleTimer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeOfOperation {
    NoDownwardRoutesMaintained,
    #[cfg(feature = "rpl-mop-1")]
    NonStoringMode,
    #[cfg(feature = "rpl-mop-2")]
    StoringMode,
    #[cfg(feature = "rpl-mop-3")]
    StoringModeWithMulticast,
}

#[cfg(feature = "std")]
impl core::fmt::Display for ModeOfOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ModeOfOperation::NoDownwardRoutesMaintained => write!(f, "mop0"),
            #[cfg(feature = "rpl-mop-1")]
            ModeOfOperation::NonStoringMode => write!(f, "mop1"),
            #[cfg(feature = "rpl-mop-2")]
            ModeOfOperation::StoringMode => write!(f, "mop1"),
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => write!(f, "mop3"),
        }
    }
}

impl From<crate::wire::rpl::ModeOfOperation> for ModeOfOperation {
    fn from(value: crate::wire::rpl::ModeOfOperation) -> Self {
        use crate::wire::rpl::ModeOfOperation as WireMop;
        match value {
            WireMop::NoDownwardRoutesMaintained => Self::NoDownwardRoutesMaintained,
            #[cfg(feature = "rpl-mop-1")]
            WireMop::NonStoringMode => Self::NonStoringMode,
            #[cfg(feature = "rpl-mop-2")]
            WireMop::StoringModeWithoutMulticast => Self::StoringMode,
            #[cfg(feature = "rpl-mop-3")]
            WireMop::StoringModeWithMulticast => Self::StoringModeWithMulticast,

            _ => unreachable!(),
        }
    }
}

impl From<ModeOfOperation> for crate::wire::rpl::ModeOfOperation {
    fn from(value: ModeOfOperation) -> Self {
        use crate::wire::rpl::ModeOfOperation as WireMop;

        match value {
            ModeOfOperation::NoDownwardRoutesMaintained => WireMop::NoDownwardRoutesMaintained,
            #[cfg(feature = "rpl-mop-1")]
            ModeOfOperation::NonStoringMode => WireMop::NonStoringMode,
            #[cfg(feature = "rpl-mop-2")]
            ModeOfOperation::StoringMode => WireMop::StoringModeWithoutMulticast,
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => WireMop::StoringModeWithMulticast,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode_of_operation: ModeOfOperation,
    pub root: Option<RootConfig>,
}

impl Default for Config {
    fn default() -> Self {
        // TODO: Make some kind of leaf mode
        Self {
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained,
            root: None,
        }
    }
}

impl Config {
    /// Create a new RPL configuration.
    pub fn new(mode_of_operation: ModeOfOperation) -> Self {
        Self {
            mode_of_operation,
            root: None,
        }
    }

    /// Add RPL root configuration to this config.
    pub fn add_root_config(mut self, root_config: RootConfig) -> Self {
        self.root = Some(root_config);
        self
    }

    fn is_root(&self) -> bool {
        self.root.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootConfig {
    pub instance_id: RplInstanceId,
    pub dodag_id: Ipv6Address,
    pub preference: u8,
    pub dio_timer: TrickleTimer,
}

impl RootConfig {
    /// Create a new RPL Root configuration.
    pub fn new(instance_id: RplInstanceId, dodag_id: Ipv6Address) -> Self {
        Self {
            instance_id,
            dodag_id,
            preference: 0,
            dio_timer: Default::default(),
        }
    }

    /// Set the administrative preference of the DODAG.
    pub fn with_preference(mut self, preference: u8) -> Self {
        self.preference = preference;
        self
    }

    /// Set the DIO timer to use by the RPL implementation.
    pub fn with_dio_timer(mut self, timer: TrickleTimer) -> Self {
        self.dio_timer = timer;
        self
    }
}

pub struct Rpl {
    pub(crate) is_root: bool,
    pub(crate) mode_of_operation: ModeOfOperation,
    pub(crate) of: ObjectiveFunction0,

    pub(crate) dis_expiration: Instant,

    pub(crate) dodag: Option<Dodag>,
}

pub struct Dodag {
    pub(crate) instance_id: RplInstanceId,
    pub(crate) id: Ipv6Address,
    pub(crate) version_number: RplSequenceCounter,
    pub(crate) preference: u8,

    pub(crate) rank: Rank,

    pub(crate) dio_timer: TrickleTimer,

    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) dao_expiration: Instant,
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) dao_seq_number: RplSequenceCounter,
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) dao_acks: heapless::Vec<(Ipv6Address, RplSequenceCounter), 16>,
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) daos: heapless::Vec<Dao, 16>,

    pub(crate) parent: Option<Ipv6Address>,
    pub(crate) without_parent: Option<Instant>,

    pub(crate) authentication_enabled: bool,
    pub(crate) path_control_size: u8,

    pub(crate) dtsn: RplSequenceCounter,
    pub(crate) dtsn_incremented_at: Instant,
    pub(crate) default_lifetime: u8,
    pub(crate) lifetime_unit: u16,
    pub(crate) grounded: bool,

    pub(crate) parent_set: ParentSet,

    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) relations: Relations,
}

#[derive(Debug)]
pub(crate) struct Dao {
    pub needs_sending: bool,
    pub next_tx: Option<Instant>,
    pub sent_count: u8,
    pub to: Ipv6Address,
    pub targets: heapless::Vec<Ipv6Address, { RPL_MAX_OPTIONS - 1 }>,
    pub parent: Option<Ipv6Address>,
    pub sequence: RplSequenceCounter,
    pub is_no_path: bool,
    pub lifetime: u8,
    pub rank: Rank,

    pub instance_id: RplInstanceId,
    pub dodag_id: Option<Ipv6Address>,
}

impl Dao {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        to: Ipv6Address,
        targets: &[Ipv6Address; RPL_MAX_OPTIONS - 1],
        parent: Option<Ipv6Address>,
        sequence: RplSequenceCounter,
        lifetime: u8,
        instance_id: RplInstanceId,
        dodag_id: Option<Ipv6Address>,
        rank: Rank,
    ) -> Self {
        Dao {
            needs_sending: false,
            next_tx: None,
            sent_count: 0,
            to,
            targets: heapless::Vec::from_slice(targets).unwrap(), // Length check in types
            parent,
            sequence,
            lifetime,
            is_no_path: false,
            instance_id,
            dodag_id,
            rank,
        }
    }

    pub(crate) fn no_path(
        to: Ipv6Address,
        targets: heapless::Vec<Ipv6Address, { RPL_MAX_OPTIONS - 1 }>,
        sequence: RplSequenceCounter,
        instance_id: RplInstanceId,
        dodag_id: Option<Ipv6Address>,
        rank: Rank,
    ) -> Self {
        Dao {
            needs_sending: true,
            next_tx: None,
            sent_count: 0,
            to,
            targets,
            parent: None,
            sequence,
            lifetime: 0,
            is_no_path: true,
            instance_id,
            dodag_id,
            rank,
        }
    }

    pub(crate) fn as_rpl_dao_repr<'dao>(&mut self) -> RplRepr<'dao> {
        let mut options = heapless::Vec::new();
        for target in &self.targets {
            options
                .push(RplOptionRepr::RplTarget(RplTarget {
                    prefix_length: 64, // TODO: get the prefix length from the address.
                    prefix: heapless::Vec::from_slice(target.as_bytes()).unwrap(),
                }))
                .unwrap();
        }
        options
            .push(RplOptionRepr::TransitInformation(RplTransitInformation {
                external: false,
                path_control: 0,
                path_sequence: 0,
                path_lifetime: self.lifetime,
                parent_address: self.parent,
            }))
            .unwrap();

        RplRepr::DestinationAdvertisementObject(RplDao {
            rpl_instance_id: self.instance_id,
            expect_ack: self.lifetime != 0,
            sequence: self.sequence,
            dodag_id: self.dodag_id,
            options,
        })
    }
}

impl Rpl {
    pub fn new(config: Config, now: Instant) -> Self {
        Self {
            is_root: config.is_root(),
            mode_of_operation: config.mode_of_operation,
            of: Default::default(),
            dis_expiration: now + Duration::from_secs(5),
            dodag: if let Some(root) = config.root {
                Some(Dodag {
                    instance_id: root.instance_id,
                    id: root.dodag_id,
                    version_number: RplSequenceCounter::default(),
                    preference: root.preference,
                    rank: Rank::ROOT,
                    dio_timer: root.dio_timer,
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    dao_expiration: now,
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    dao_seq_number: RplSequenceCounter::default(),
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    dao_acks: Default::default(),
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    daos: Default::default(),
                    parent: None,
                    without_parent: None,
                    authentication_enabled: false,
                    path_control_size: 0,
                    dtsn: RplSequenceCounter::default(),
                    dtsn_incremented_at: now,
                    default_lifetime: 30,
                    lifetime_unit: 60,
                    grounded: false,
                    parent_set: Default::default(),
                    #[cfg(any(
                        feature = "rpl-mop-1",
                        feature = "rpl-mop-2",
                        feature = "rpl-mop-3"
                    ))]
                    relations: Default::default(),
                })
            } else {
                None
            },
        }
    }

    pub fn parent(&self) -> Option<&Ipv6Address> {
        if let Some(dodag) = &self.dodag {
            dodag.parent.as_ref()
        } else {
            None
        }
    }

    pub fn is_root(&self) -> bool {
        self.is_root
    }

    pub fn instance(&self) -> Option<&RplInstanceId> {
        if let Some(dodag) = &self.dodag {
            Some(&dodag.instance_id)
        } else {
            None
        }
    }

    pub fn dodag(&self) -> Option<&Dodag> {
        self.dodag.as_ref()
    }

    pub(crate) fn has_parent(&self) -> bool {
        if let Some(dodag) = &self.dodag {
            return dodag.parent.is_some();
        }

        false
    }

    /// ## Panics
    /// This function will panic if the node is not part of a DODAG.
    pub(crate) fn dodag_configuration<'o>(&self) -> RplOptionRepr<'o> {
        let dodag = self.dodag.as_ref().unwrap();

        // FIXME: I think we need to convert from seconds to something else, not sure what.
        let dio_interval_doublings = dodag.dio_timer.i_max as u8 - dodag.dio_timer.i_min as u8;

        RplOptionRepr::DodagConfiguration(RplDodagConfiguration {
            authentication_enabled: dodag.authentication_enabled,
            path_control_size: dodag.path_control_size,
            dio_interval_doublings,
            dio_interval_min: dodag.dio_timer.i_min as u8,
            dio_redundancy_constant: dodag.dio_timer.k as u8,
            max_rank_increase: self.of.max_rank_increase(),
            minimum_hop_rank_increase: self.of.min_hop_rank_increase(),
            objective_code_point: self.of.objective_code_point(),
            default_lifetime: dodag.default_lifetime,
            lifetime_unit: dodag.lifetime_unit,
        })
    }

    /// ## Panics
    /// This function will panic if the node is not part of a DODAG.
    pub(crate) fn dodag_information_object<'o>(
        &self,
        options: heapless::Vec<RplOptionRepr<'o>, 2>,
    ) -> RplRepr<'o> {
        let dodag = self.dodag.as_ref().unwrap();

        RplRepr::DodagInformationObject(RplDio {
            rpl_instance_id: dodag.instance_id,
            version_number: dodag.version_number,
            rank: dodag.rank.raw_value(),
            grounded: dodag.grounded,
            mode_of_operation: self.mode_of_operation.into(),
            dodag_preference: dodag.preference,
            dtsn: dodag.dtsn,
            dodag_id: dodag.id,
            options,
        })
    }
}

impl Dodag {
    pub fn id(&self) -> &Ipv6Address {
        &self.id
    }
    /// ## Panics
    /// This function will panic if the DODAG does not have a parent selected.
    // pub(crate) fn remove_parent<OF: ObjectiveFunction>(
    pub(crate) fn remove_parent(
        &mut self,
        // mop: ModeOfOperation,
        // our_addr: Ipv6Address,
        // of: &OF,
        // now: Instant,
        // rand: &mut Rand,
    ) -> Ipv6Address {
        let old_parent = self.parent.unwrap();

        self.parent = None;
        self.parent_set.remove(&old_parent);

        // FIXME: Probably not a good idea to have a recursive loop in function calls
        // self.find_new_parent(mop, our_addr, of, now, rand);

        old_parent
    }

    /// ## Panics
    /// This function will panic if the DODAG does not have a parent selected.
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) fn remove_parent_with_no_path<OF: ObjectiveFunction>(
        &mut self,
        mop: ModeOfOperation,
        // our_addr: Ipv6Address,
        targets: &[Ipv6Address],
        targets_multicast: &[Ipv6Address],
        of: &OF,
        now: Instant,
        rand: &mut Rand,
    ) {
        // let old_parent = self.remove_parent(mop, our_addr, of, now, rand);
        let old_parent = self.remove_parent();

        #[cfg(any(feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        {
            for targets in targets.chunks(RPL_MAX_OPTIONS - 1) {
                self.daos
                    .push(Dao::no_path(
                        old_parent,
                        heapless::Vec::from_slice(targets).unwrap(),
                        self.dao_seq_number,
                        self.instance_id,
                        Some(self.id),
                        self.rank,
                    ))
                    .unwrap();
                self.dao_seq_number.increment();
            }

            #[cfg(feature = "rpl-mop-3")]
            for targets in targets_multicast.chunks(RPL_MAX_OPTIONS - 1) {
                self.daos
                    .push(Dao::no_path(
                        old_parent,
                        heapless::Vec::from_slice(targets).unwrap(),
                        self.dao_seq_number,
                        self.instance_id,
                        Some(self.id),
                        self.rank,
                    ))
                    .unwrap();
                self.dao_seq_number.increment();
            }
        }
    }

    pub(crate) fn find_new_parent<OF: ObjectiveFunction>(
        &mut self,
        mop: ModeOfOperation,
        targets: &[Ipv6Address],
        targets_multicast: &[Ipv6Address],
        of: &OF,
        now: Instant,
        rand: &mut Rand,
    ) {
        // Remove expired parents from the parent set.
        self.parent_set
            .purge(now, self.dio_timer.max_expiration() * 2);

        let old_parent = self.parent;

        if let Some(parent) = of.preferred_parent(&self.parent_set) {
            // Send a NO-PATH DAO in MOP 2 when we already had a parent.
            #[cfg(any(feature = "rpl-mop-2", feature = "rpl-mop-3"))]
            if let Some(old_parent) = old_parent {
                let is_mop2 = {
                    #[cfg(feature = "rpl-mop-2")]
                    {
                        matches!(mop, ModeOfOperation::StoringMode)
                    }
                    #[cfg(not(feature = "rpl-mop-2"))]
                    false
                };
                let is_mop3 = {
                    #[cfg(feature = "rpl-mop-3")]
                    {
                        matches!(mop, ModeOfOperation::StoringModeWithMulticast)
                    }
                    #[cfg(not(feature = "rpl-mop-3"))]
                    false
                };
                if (is_mop2 || is_mop3) && old_parent != parent {
                    net_trace!(
                        "scheduling NO-PATH DAO for {:?} and {:?} to {}",
                        targets,
                        targets_multicast,
                        old_parent
                    );
                    self.remove_parent_with_no_path(
                        mop,
                        // our_addr,
                        targets,
                        targets_multicast,
                        of,
                        now,
                        rand,
                    )
                }
            }

            // Schedule a DAO when we didn't have a parent yet, or when the new parent is different
            // from our old parent.
            if old_parent.is_none() || old_parent != Some(parent) {
                self.dio_timer.hear_inconsistency(now, rand);
                self.parent = Some(parent);
                self.without_parent = None;
                self.rank = of.rank(self.rank, self.parent_set.find(&parent).unwrap().rank);

                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                if !matches!(mop, ModeOfOperation::NoDownwardRoutesMaintained) {
                    self.schedule_dao(mop, targets, targets_multicast, parent, now, false);
                }
            }
        } else {
            self.without_parent = Some(now);
            self.rank = Rank::INFINITE;
        }
    }

    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) fn schedule_dao(
        &mut self,
        mop: ModeOfOperation,
        targets: &[Ipv6Address],
        targets_multicast: &[Ipv6Address],
        parent: Ipv6Address,
        now: Instant,
        is_no_path: bool,
    ) -> Result<(), DodagTransmissionError> {
        use heapless::LinearMap;

        #[cfg(feature = "rpl-mop-1")]
        if matches!(mop, ModeOfOperation::NonStoringMode) {
            net_trace!("scheduling DAO: {} is parent of {:?}", parent, targets);
            for targets in targets.chunks(RPL_MAX_OPTIONS - 1) {
                self.daos
                    .push(if is_no_path {
                        Dao::no_path(
                            self.id,
                            targets.try_into().unwrap(), // Checks in the types
                            self.dao_seq_number,
                            self.instance_id,
                            Some(self.id),
                            self.rank,
                        )
                    } else {
                        Dao::new(
                            self.id,
                            targets.try_into().unwrap(), // Checks in the types
                            Some(parent),
                            self.dao_seq_number,
                            self.default_lifetime,
                            self.instance_id,
                            Some(self.id),
                            self.rank,
                        )
                    })
                    .map_err(|_err| DodagTransmissionError::DaoExhausted);
                self.dao_seq_number.increment();
            }
        }

        #[cfg(all(feature = "rpl-mop-2", feature = "rpl-mop-3"))]
        if matches!(
            mop,
            ModeOfOperation::StoringMode | ModeOfOperation::StoringModeWithMulticast
        ) {
            net_trace!("scheduling DAO: {} is parent of {:?}", parent, targets);
            for targets in targets.chunks(RPL_MAX_OPTIONS - 1) {
                self.daos
                    .push(if is_no_path {
                        Dao::no_path(
                            parent,
                            targets.try_into().unwrap(), // Checks in the types
                            self.dao_seq_number,
                            self.instance_id,
                            Some(self.id),
                            self.rank,
                        )
                    } else {
                        Dao::new(
                            parent,
                            targets.try_into().unwrap(), // Checks in the types
                            None,
                            self.dao_seq_number,
                            self.default_lifetime,
                            self.instance_id,
                            Some(self.id),
                            self.rank,
                        )
                    })
                    .unwrap();
            }

            // If we are in MOP3, we also send a DOA with our subscribed multicast addresses.
            #[cfg(feature = "rpl-mop-3")]
            {
                net_trace!("scheduling multicast DAO");
                for targets in targets_multicast.chunks(RPL_MAX_OPTIONS - 1) {
                    self.daos
                        .push(if is_no_path {
                            Dao::no_path(
                                parent,
                                targets.try_into().unwrap(), // Checks in the types
                                self.dao_seq_number,
                                self.instance_id,
                                Some(self.id),
                                self.rank,
                            )
                        } else {
                            Dao::new(
                                parent,
                                targets.try_into().unwrap(), // Checks in the types
                                None,
                                self.dao_seq_number,
                                self.default_lifetime,
                                self.instance_id,
                                Some(self.id),
                                self.rank,
                            )
                        })
                        .unwrap();
                }
            }

            self.dao_seq_number.increment();
        }

        let exp = (self.lifetime_unit as u64 * self.default_lifetime as u64)
            .checked_sub(2 * 60)
            .unwrap_or(2 * 60);
        self.dao_expiration = now + Duration::from_secs(exp);

        Ok(())
    }

    /// ## Panics
    /// This function will panic if the node is not part of a DODAG.
    #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
    pub(crate) fn destination_advertisement_object<'o>(
        &mut self,
        options: heapless::Vec<RplOptionRepr<'o>, 2>,
    ) -> RplRepr<'o> {
        let sequence = self.dao_seq_number;
        self.dao_seq_number.increment();
        RplRepr::DestinationAdvertisementObject(RplDao {
            rpl_instance_id: self.instance_id,
            expect_ack: true,
            sequence,
            dodag_id: Some(self.id),
            options,
        })
    }
}

#[derive(Debug, Clone)]
pub enum DodagTransmissionError {
    DaoExhausted,
}

impl core::fmt::Display for DodagTransmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DaoExhausted => write!(f, "DAO buffer is exhausted"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for DodagTransmissionError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::DaoExhausted => defmt::write!(f, "DAO buffer is exhausted"),
        }
    }
}
