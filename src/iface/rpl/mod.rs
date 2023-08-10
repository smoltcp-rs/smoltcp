#![allow(unused)]

mod consts;
mod lollipop;
mod of0;
mod parents;
mod rank;
mod relations;
mod trickle;

use crate::wire::Ipv6Address;

pub(crate) use crate::wire::RplInstanceId;
pub(crate) use lollipop::SequenceCounter;
pub(crate) use rank::Rank;
pub(crate) use trickle::TrickleTimer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeOfOperation {
    #[cfg(feature = "rpl-mop-0")]
    NoDownwardRoutesMaintained,
    #[cfg(feature = "rpl-mop-1")]
    NonStoringMode,
    #[cfg(feature = "rpl-mop-2")]
    StoringModeWithoutMulticast,
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
            WireMop::StoringModeWithoutMulticast => Self::StoringModeWithoutMulticast,
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
            ModeOfOperation::StoringModeWithoutMulticast => WireMop::StoringModeWithoutMulticast,
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => WireMop::StoringModeWithMulticast,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    root: Option<RootConfig>,
    dio_timer: TrickleTimer,
    instance_id: RplInstanceId,
    version_number: SequenceCounter,
    mode_of_operation: ModeOfOperation,
    dtsn: SequenceCounter,
    rank: rank::Rank,
}

impl Default for Config {
    fn default() -> Self {
        #![allow(unused_variables)]

        #[cfg(feature = "rpl-mop-0")]
        let mode_of_operation = ModeOfOperation::NoDownwardRoutesMaintained;
        #[cfg(feature = "rpl-mop-1")]
        let mode_of_operation = ModeOfOperation::NonStoringMode;
        #[cfg(feature = "rpl-mop-2")]
        let mode_of_operation = ModeOfOperation::StoringModeWithoutMulticast;
        #[cfg(feature = "rpl-mop-3")]
        let mode_of_operation = ModeOfOperation::StoringModeWithMulticast;

        Self {
            root: None,
            dio_timer: TrickleTimer::default(),
            instance_id: RplInstanceId::from(consts::DEFAULT_RPL_INSTANCE_ID),
            version_number: lollipop::SequenceCounter::default(),
            rank: rank::Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
            mode_of_operation,
        }
    }
}

impl Config {
    /// Add RPL root configuration to this config.
    pub fn add_root_config(mut self, root_config: RootConfig) -> Self {
        self.root = Some(root_config);
        self.rank = rank::Rank::ROOT;
        self
    }

    /// Set the RPL Instance ID.
    pub fn with_instance_id(mut self, instance_id: RplInstanceId) -> Self {
        self.instance_id = instance_id;
        self
    }

    /// Set the RPL Version number.
    pub fn with_version_number(mut self, version_number: SequenceCounter) -> Self {
        self.version_number = version_number;
        self
    }

    /// Set the RPL Mode of Operation.
    pub fn with_mode_of_operation(mut self, mode_of_operation: ModeOfOperation) -> Self {
        self.mode_of_operation = mode_of_operation;
        self
    }

    /// Set the DIO timer to use by the RPL implementation.
    pub fn with_dio_timer(mut self, timer: TrickleTimer) -> Self {
        self.dio_timer = timer;
        self
    }

    fn is_root(&self) -> bool {
        self.root.is_some()
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct RootConfig {
    pub preference: u8,
}


impl RootConfig {
    /// Set the administrative preference of the DODAG.
    pub fn with_preference(mut self, preference: u8) -> Self {
        self.preference = preference;
        self
    }
}
