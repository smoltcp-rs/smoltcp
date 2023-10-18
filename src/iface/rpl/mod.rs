#![allow(unused)]

mod consts;
mod lollipop;
mod of0;
mod parents;
mod rank;
mod relations;
mod trickle;

use crate::time::{Duration, Instant};
use crate::wire::{
    Icmpv6Repr, Ipv6Address, RplDao, RplDio, RplDodagConfiguration, RplOptionRepr, RplRepr,
    RplTarget, RplTransitInformation,
};

pub(crate) use lollipop::SequenceCounter;
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

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub mode_of_operation: ModeOfOperation,
    pub root: Option<RootConfig>,
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

#[derive(Debug, PartialEq, Eq)]
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
    pub(crate) version_number: SequenceCounter,
    pub(crate) preference: u8,

    pub(crate) rank: Rank,

    pub(crate) dio_timer: TrickleTimer,
    pub(crate) dao_expiration: Instant,

    pub(crate) parent: Option<Ipv6Address>,
    pub(crate) without_parent: Option<Instant>,

    pub(crate) authentication_enabled: bool,
    pub(crate) path_control_size: u8,

    pub(crate) dtsn: SequenceCounter,
    pub(crate) dtsn_incremented_at: Instant,
    pub(crate) default_lifetime: u8,
    pub(crate) lifetime_unit: u16,
    pub(crate) grounded: bool,

    pub(crate) dao_seq_number: SequenceCounter,

    pub(crate) dao_acks: heapless::Vec<(Ipv6Address, SequenceCounter), 16>,
    pub(crate) daos: heapless::Vec<Dao, 16>,

    pub(crate) parent_set: ParentSet,
    #[cfg(feature = "rpl-mop-1")]
    pub(crate) relations: Relations,
}

#[derive(Debug)]
pub(crate) struct Dao {
    pub needs_sending: bool,
    pub next_tx: Option<Instant>,
    pub sent_count: u8,
    pub to: Ipv6Address,
    pub child: Ipv6Address,
    pub parent: Option<Ipv6Address>,
    pub sequence: SequenceCounter,
    pub is_no_path: bool,
    pub lifetime: u8,

    pub instance_id: RplInstanceId,
    pub dodag_id: Option<Ipv6Address>,
}

impl Dao {
    pub(crate) fn new(
        to: Ipv6Address,
        child: Ipv6Address,
        parent: Option<Ipv6Address>,
        sequence: SequenceCounter,
        lifetime: u8,
        instance_id: RplInstanceId,
        dodag_id: Option<Ipv6Address>,
    ) -> Self {
        Dao {
            needs_sending: false,
            next_tx: None,
            sent_count: 0,
            to,
            child,
            parent,
            sequence,
            lifetime,
            is_no_path: false,
            instance_id,
            dodag_id,
        }
    }

    pub(crate) fn no_path(
        to: Ipv6Address,
        child: Ipv6Address,
        sequence: SequenceCounter,
        instance_id: RplInstanceId,
        dodag_id: Option<Ipv6Address>,
    ) -> Self {
        Dao {
            needs_sending: true,
            next_tx: None,
            sent_count: 0,
            to,
            child,
            parent: None,
            sequence,
            lifetime: 0,
            is_no_path: true,
            instance_id,
            dodag_id,
        }
    }

    pub(crate) fn as_rpl_dao_repr<'dao>(&mut self) -> RplRepr<'dao> {
        let mut options = heapless::Vec::new();
        options
            .push(RplOptionRepr::RplTarget(RplTarget {
                prefix_length: 64,
                prefix: self.child,
            }))
            .unwrap();
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
            expect_ack: true,
            sequence: self.sequence.value(),
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
                    version_number: SequenceCounter::default(),
                    preference: root.preference,
                    rank: Rank::ROOT,
                    dio_timer: root.dio_timer,
                    dao_expiration: now,
                    parent: None,
                    without_parent: None,
                    authentication_enabled: false,
                    path_control_size: 0,
                    dtsn: SequenceCounter::default(),
                    dtsn_incremented_at: now,
                    default_lifetime: 30,
                    lifetime_unit: 60,
                    grounded: false,
                    dao_seq_number: SequenceCounter::default(),
                    dao_acks: Default::default(),
                    daos: Default::default(),
                    parent_set: Default::default(),
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
            version_number: dodag.version_number.value(),
            rank: dodag.rank.raw_value(),
            grounded: dodag.grounded,
            mode_of_operation: self.mode_of_operation.into(),
            dodag_preference: dodag.preference,
            dtsn: dodag.dtsn.value(),
            dodag_id: dodag.id,
            options,
        })
    }

    /// ## Panics
    /// This function will panic if the node is not part of a DODAG.
    pub(crate) fn destination_advertisement_object<'o>(
        &self,
        sequence: SequenceCounter,
        options: heapless::Vec<RplOptionRepr<'o>, 2>,
    ) -> RplRepr<'o> {
        let dodag = self.dodag.as_ref().unwrap();
        RplRepr::DestinationAdvertisementObject(RplDao {
            rpl_instance_id: dodag.instance_id,
            expect_ack: true,
            sequence: sequence.value(),
            dodag_id: Some(dodag.id),
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
    pub(crate) fn remove_parent<OF: ObjectiveFunction>(
        &mut self,
        mop: ModeOfOperation,
        our_addr: Ipv6Address,
        of: &OF,
        now: Instant,
    ) -> Ipv6Address {
        let old_parent = self.parent.unwrap();

        self.parent = None;
        self.parent_set.remove(&old_parent);

        self.find_new_parent(mop, our_addr, of, now);

        old_parent
    }

    /// ## Panics
    /// This function will panic if the DODAG does not have a parent selected.
    pub(crate) fn remove_parent_with_no_path<OF: ObjectiveFunction>(
        &mut self,
        mop: ModeOfOperation,
        our_addr: Ipv6Address,
        child: Ipv6Address,
        of: &OF,
        now: Instant,
    ) {
        let old_parent = self.remove_parent(mop, our_addr, of, now);

        #[cfg(feature = "rpl-mop-2")]
        self.daos
            .push(Dao::no_path(
                old_parent,
                child,
                self.dao_seq_number,
                self.instance_id,
                Some(self.id),
            ))
            .unwrap();
        self.dao_seq_number.increment();
    }

    pub(crate) fn find_new_parent<OF: ObjectiveFunction>(
        &mut self,
        mop: ModeOfOperation,
        child: Ipv6Address,
        of: &OF,
        now: Instant,
    ) {
        // Remove expired parents from the parent set.
        self.parent_set.purge(now, self.dio_timer.max_expiration());

        let old_parent = self.parent;

        if let Some(parent) = of.preferred_parent(&self.parent_set) {
            // Send a NO-PATH DAO in MOP 2 when we already had a parent.
            #[cfg(feature = "rpl-mop-2")]
            if let Some(old_parent) = old_parent {
                if matches!(mop, ModeOfOperation::StoringMode) && old_parent != parent {
                    net_trace!("scheduling NO-PATH DAO for {} to {}", child, old_parent);
                    match self.daos.push(Dao::no_path(
                        old_parent,
                        child,
                        self.dao_seq_number,
                        self.instance_id,
                        Some(self.id),
                    )) {
                        Ok(_) => self.dao_seq_number.increment(),
                        Err(_) => net_trace!("could not schedule DAO"),
                    }
                }
            }

            // Schedule a DAO when we didn't have a parent yet, or when the new parent is different
            // from our old parent.
            if old_parent.is_none() || old_parent != Some(parent) {
                self.parent = Some(parent);
                self.without_parent = None;
                self.rank = of.rank(self.rank, self.parent_set.find(&parent).unwrap().rank);

                #[cfg(any(feature = "rpl-mop-1", feature = "rpl-mop-2", feature = "rpl-mop-3"))]
                if !matches!(mop, ModeOfOperation::NoDownwardRoutesMaintained) {
                    self.schedule_dao(mop, child, parent, now);
                }
            }
        } else {
            self.without_parent = Some(now);
            self.rank = Rank::INFINITE;
        }
    }

    pub(crate) fn schedule_dao(
        &mut self,
        mop: ModeOfOperation,
        child: Ipv6Address,
        parent: Ipv6Address,
        now: Instant,
    ) {
        net_trace!("scheduling DAO: {} is parent of {}", parent, child);

        #[cfg(feature = "rpl-mop-1")]
        if matches!(mop, ModeOfOperation::NonStoringMode) {
            self.daos
                .push(Dao::new(
                    self.id,
                    child,
                    Some(parent),
                    self.dao_seq_number,
                    self.default_lifetime,
                    self.instance_id,
                    Some(self.id),
                ))
                .unwrap();
            self.dao_seq_number.increment();
        }

        #[cfg(feature = "rpl-mop-2")]
        if matches!(mop, ModeOfOperation::StoringMode) {
            self.daos
                .push(Dao::new(
                    parent,
                    child,
                    None,
                    self.dao_seq_number,
                    self.default_lifetime,
                    self.instance_id,
                    Some(self.id),
                ))
                .unwrap();
            self.dao_seq_number.increment();
        }

        let exp = (self.lifetime_unit as u64 * self.default_lifetime as u64)
            .checked_sub(2 * 60)
            .unwrap_or(2 * 60);
        self.dao_expiration = now + Duration::from_secs(exp);
    }
}
