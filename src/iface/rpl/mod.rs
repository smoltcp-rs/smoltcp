#![allow(unused)]

mod consts;
mod lollipop;
mod of0;
mod parents;
mod rank;
mod relations;
mod trickle;

use crate::time::{Duration, Instant};
use crate::wire::{Ipv6Address, RplOptionRepr, RplRepr};

use parents::ParentSet;
use relations::Relations;

pub(crate) use lollipop::SequenceCounter;
pub(crate) use of0::{ObjectiveFunction, ObjectiveFunction0};
pub(crate) use rank::Rank;

pub use crate::wire::RplInstanceId;
pub use trickle::TrickleTimer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeOfOperation {
    #[cfg(feature = "rpl-mop-0")]
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

            _ => Self::NoDownwardRoutesMaintained,
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
    mode_of_operation: ModeOfOperation,
    root: Option<RootConfig>,
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
    instance_id: RplInstanceId,
    preference: u8,
    dio_timer: TrickleTimer,
}

impl RootConfig {
    /// Create a new RPL Root configuration.
    pub fn new(instance_id: RplInstanceId) -> Self {
        Self {
            instance_id,
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

pub(crate) struct Rpl {
    pub is_root: bool,
    pub mode_of_operation: ModeOfOperation,
    pub of: ObjectiveFunction0,

    pub dis_expiration: Instant,

    pub instance: Option<Instance>,
    pub dodag: Option<Dodag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Instance {
    pub id: RplInstanceId,
}

pub(crate) struct Dodag {
    pub id: Ipv6Address,
    pub version_number: SequenceCounter,
    pub preference: u8,

    pub rank: Rank,

    pub dio_timer: TrickleTimer,
    pub dao_expiration: Instant,

    pub parent: Option<Ipv6Address>,
    pub without_parent: Option<Instant>,

    pub authentication_enabled: bool,
    pub path_control_size: u8,

    pub default_lifetime: u8,
    pub lifetime_unit: u16,
    pub grounded: bool,

    pub dao_seq_number: SequenceCounter,

    pub dao_acks: heapless::Vec<(Ipv6Address, SequenceCounter), 16>,
    pub daos: heapless::Vec<Dao, 16>,

    pub parent_set: ParentSet,
    #[cfg(feature = "rpl-mop-1")]
    pub relations: Relations,
}

#[derive(Debug)]
pub(crate) struct Dao {
    pub needs_sending: bool,
    pub sent_at: Option<Instant>,
    pub sent_count: u8,
    pub to: Ipv6Address,
    pub child: Ipv6Address,
    pub parent: Option<Ipv6Address>,
    pub sequence: Option<SequenceCounter>,
}

impl Dao {
    pub(crate) fn new() -> Self {
        todo!();
    }

    pub(crate) fn no_path() -> Self {
        todo!();
    }
}

impl Rpl {
    pub fn new(config: Config, now: Instant) -> Self {
        Self {
            is_root: config.is_root(),
            mode_of_operation: config.mode_of_operation,
            of: Default::default(),
            dis_expiration: now + Duration::from_secs(5),
            instance: None,
            dodag: None,
        }
    }

    pub(crate) fn has_parent(&self) -> bool {
        if let Some(dodag) = &self.dodag {
            return dodag.parent.is_some();
        }

        false
    }

    pub(crate) fn dodag_configuration<'o>(&self) -> RplOptionRepr<'o> {
        todo!()
    }

    pub(crate) fn dodag_information_object<'o>(
        &self,
        options: heapless::Vec<RplOptionRepr<'o>, 2>,
    ) -> RplRepr<'o> {
        todo!()
    }

    pub(crate) fn destination_advertisement_object<'o>(
        &self,
        sequence: SequenceCounter,
        options: heapless::Vec<RplOptionRepr<'o>, 2>,
    ) -> RplRepr<'o> {
        todo!()
    }
}

impl Dodag {
    /// ## Panics
    /// This function will panic if the DODAG does not have a parent selected.
    pub(crate) fn remove_parent<OF: ObjectiveFunction>(&mut self, of: &OF, now: Instant) {
        let old_parent = self.parent.unwrap();

        self.parent = None;
        self.parent_set.remove(&old_parent);

        #[cfg(feature = "rpl-mop-2")]
        self.daos.push(Dao::no_path()).unwrap();

        self.parent = of.preferred_parent(&self.parent_set);

        if let Some(parent) = self.parent {
            #[cfg(feature = "rpl-mop-1")]
            self.daos.push(Dao::new()).unwrap();
        } else {
            self.without_parent = Some(now);
            self.rank = Rank::INFINITE;
        }
    }
}
