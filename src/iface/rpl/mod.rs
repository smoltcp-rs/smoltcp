pub(crate) mod consts;
mod lollipop;
mod neighbor_table;
mod obj_function;
mod of_zero;
mod rank;
mod routing;
mod trickle;

pub(crate) use self::rank::Rank;
use crate::time::{Duration, Instant};
use crate::wire::ipv6::Address;
use crate::wire::*;
pub(crate) use lollipop::SequenceCounter;
pub(crate) use neighbor_table::{RplNeighbor, RplNeighborEntry, RplNeighborTable};
pub(crate) use of_zero::ObjectiveFunction0;
pub(crate) use routing::RplNodeRelations;

#[derive(Debug, Clone, Copy, PartialEq)]
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

            _ => Self::NoDownwardRoutesMaintained, // FIXME: is this the correct thing to do?
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

pub struct Config {
    pub is_root: bool,
    pub preference: u8,
    pub dio_timer: trickle::TrickleTimer,
    pub instance_id: RplInstanceId,
    pub version_number: lollipop::SequenceCounter,
    pub dodag_id: Option<Address>,
    pub rank: rank::Rank,
    pub dtsn: lollipop::SequenceCounter,
    pub mode_of_operation: ModeOfOperation,
}

impl Default for Config {
    fn default() -> Self {
        #[cfg(feature = "rpl-mop-0")]
        let mode_of_operation = ModeOfOperation::NoDownwardRoutesMaintained;
        #[cfg(feature = "rpl-mop-1")]
        let mode_of_operation = ModeOfOperation::NonStoringMode;
        #[cfg(feature = "rpl-mop-2")]
        let mode_of_operation = ModeOfOperation::StoringModeWithoutMulticast;
        #[cfg(feature = "rpl-mop-3")]
        let mode_of_operation = ModeOfOperation::StoringModeWithMulticast;

        Self {
            is_root: false,
            preference: 0,
            dio_timer: trickle::TrickleTimer::default(),
            instance_id: RplInstanceId::from(consts::RPL_DEFAULT_INSTANCE),
            version_number: lollipop::SequenceCounter::default(),
            dodag_id: None,
            rank: Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
            mode_of_operation,
        }
    }
}

impl Config {
    pub fn new(instance_id: RplInstanceId, mode_of_operation: ModeOfOperation) -> Self {
        Self {
            is_root: false,
            preference: 0,
            dio_timer: trickle::TrickleTimer::default(),
            instance_id,
            version_number: lollipop::SequenceCounter::default(),
            dodag_id: None,
            rank: Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
            mode_of_operation,
        }
    }

    pub fn new_root(
        instance_id: RplInstanceId,
        mode_of_operation: ModeOfOperation,
        dodag_id: Ipv6Address,
    ) -> Self {
        let mut config = Self::new(instance_id, mode_of_operation);
        config.is_root = true;
        config.rank = Rank::ROOT;
        config.dodag_id = Some(dodag_id);
        config
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DodagConfiguration {
    pub authentication_enabled: bool,
    pub path_control_size: u8,
    pub dio_interval_doublings: u8,
    pub dio_interval_min: u8,
    pub dio_redundancy_constant: u8,
    pub max_rank_increase: u16,
    pub minimum_hop_rank_increase: u16,
    pub objective_code_point: u16,
    pub default_lifetime: u8,
    pub lifetime_unit: u16,
}

impl Default for DodagConfiguration {
    fn default() -> Self {
        Self {
            authentication_enabled: false,
            path_control_size: 0,
            dio_interval_doublings: consts::DEFAULT_DIO_INTERVAL_DOUBLINGS,
            dio_interval_min: consts::DEFAULT_DIO_INTERVAL_MIN,
            dio_redundancy_constant: consts::DEFAULT_DIO_REDUNDANCY_CONSTANT,
            // FIXME: check where this value comes from:
            max_rank_increase: 7 * consts::DEFAULT_MIN_HOP_RANK_INCREASE,
            minimum_hop_rank_increase: consts::DEFAULT_MIN_HOP_RANK_INCREASE,
            objective_code_point: ObjectiveFunction0::OCP,
            default_lifetime: 30,
            lifetime_unit: 60,
        }
    }
}

#[derive(Debug)]
pub struct Rpl {
    pub is_root: bool,
    pub instance_id: RplInstanceId,
    pub version_number: lollipop::SequenceCounter,
    pub dodag_id: Option<Address>,
    pub rank: rank::Rank,
    pub dtsn: lollipop::SequenceCounter,
    pub mode_of_operation: ModeOfOperation,
    pub dodag_preference: u8,

    pub dio_timer: trickle::TrickleTimer,
    pub dis_expiration: Instant,

    pub neighbor_table: RplNeighborTable,
    pub node_relations: RplNodeRelations,

    pub parent_address: Option<Address>,
    pub parent_rank: Option<Rank>,
    pub parent_preference: Option<u8>,
    pub parent_last_heard: Option<Instant>,

    pub dodag_configuration: DodagConfiguration,
    pub grounded: bool,
    pub ocp: u16,
}


impl Rpl {
    pub fn new(config: Config, now: Instant) -> Self {
        Self {
            is_root: config.is_root,
            instance_id: config.instance_id,
            version_number: config.version_number,
            dodag_id: config.dodag_id,
            rank: config.rank,
            dtsn: config.dtsn,
            mode_of_operation: config.mode_of_operation,
            dodag_preference: config.preference,

            dio_timer: config.dio_timer,
            dis_expiration: now + Duration::from_secs(5),

            neighbor_table: Default::default(),
            node_relations: Default::default(),

            parent_address: None,
            parent_rank: None,
            parent_preference: None,
            parent_last_heard: None,

            dodag_configuration: Default::default(),
            grounded: false,
            ocp: 0,
        }
    }

    pub fn has_parent(&self) -> bool {
        self.parent_address.is_some()
    }

    pub fn should_send_dis(&self, now: Instant) -> bool {
        !self.has_parent() && !self.is_root && now >= self.dis_expiration
    }

    pub fn set_dis_expiration(&mut self, expiration: Instant) {
        self.dis_expiration = expiration;
    }

    pub fn dodag_information_object<'p>(&self) -> RplRepr<'p> {
        RplRepr::DodagInformationObject {
            rpl_instance_id: self.instance_id,
            version_number: self.version_number.value(),
            rank: self.rank.value,
            grounded: false,
            mode_of_operation: self.mode_of_operation.into(),
            dodag_preference: self.dodag_preference,
            dtsn: self.dtsn.value(),
            dodag_id: self.dodag_id.unwrap(),
            options: &[],
        }
    }

    pub fn dodag_configuration(&self) -> RplOptionRepr<'static> {
        RplOptionRepr::DodagConfiguration {
            authentication_enabled: self.dodag_configuration.authentication_enabled,
            path_control_size: self.dodag_configuration.path_control_size,
            dio_interval_doublings: self.dodag_configuration.dio_interval_doublings,
            dio_interval_min: self.dodag_configuration.dio_interval_min,
            dio_redundancy_constant: self.dodag_configuration.dio_redundancy_constant,
            max_rank_increase: self.dodag_configuration.max_rank_increase,
            minimum_hop_rank_increase: self.dodag_configuration.minimum_hop_rank_increase,
            objective_code_point: self.dodag_configuration.objective_code_point,
            default_lifetime: self.dodag_configuration.default_lifetime,
            lifetime_unit: self.dodag_configuration.lifetime_unit,
        }
    }

    pub fn update_dodag_conf(&mut self, dodag_conf: &RplOptionRepr) {
        match dodag_conf {
            RplOptionRepr::DodagConfiguration {
                authentication_enabled,
                path_control_size,
                dio_interval_doublings,
                dio_interval_min,
                dio_redundancy_constant,
                max_rank_increase,
                minimum_hop_rank_increase,
                objective_code_point,
                default_lifetime,
                lifetime_unit,
            } => {
                self.dodag_configuration.authentication_enabled = *authentication_enabled;
                self.dodag_configuration.path_control_size = *path_control_size;
                self.dodag_configuration.dio_interval_doublings = *dio_interval_doublings;
                self.dodag_configuration.dio_interval_min = *dio_interval_min;
                self.dodag_configuration.dio_redundancy_constant = *dio_redundancy_constant;
                self.dodag_configuration.max_rank_increase = *max_rank_increase;
                self.dodag_configuration.minimum_hop_rank_increase = *minimum_hop_rank_increase;
                self.dodag_configuration.objective_code_point = *objective_code_point;
                self.dodag_configuration.default_lifetime = *default_lifetime;
                self.dodag_configuration.lifetime_unit = *lifetime_unit;
            }
            _ => unreachable!(),
        }
    }
}
