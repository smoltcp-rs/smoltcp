mod builder;
pub(crate) mod consts;
mod lollipop;
mod neighbor_table;
mod obj_function;
mod of_zero;
mod rank;
mod routing;
mod trickle;

pub(crate) use self::rank::Rank;
use crate::time::Instant;
use crate::wire::ipv6::Address;
use crate::wire::rpl::ModeOfOperation;
use crate::wire::*;
pub use builder::RplBuilder;
pub(crate) use lollipop::SequenceCounter;
pub(crate) use neighbor_table::{RplNeighbor, RplNeighborEntry, RplNeighborTable};
pub(crate) use of_zero::ObjectiveFunction0;
pub(crate) use routing::RplNodeRelations;

//#[derive(Debug)]
//pub enum RplMode {
//Mesh = 0,
//Feather = 1,
//Leaf = 2,
//}

#[derive(Debug)]
pub struct Rpl {
    pub is_root: bool,
    pub dis_expiration: Instant,
    pub dio_timer: trickle::TrickleTimer,
    pub neighbor_table: RplNeighborTable,
    pub node_relations: RplNodeRelations,
    pub instance_id: RplInstanceId,
    pub version_number: lollipop::SequenceCounter,
    pub dodag_id: Option<Address>,
    pub rank: rank::Rank,
    pub dtsn: lollipop::SequenceCounter,
    pub parent_address: Option<Address>,
    pub parent_rank: Option<Rank>,
    pub parent_preference: Option<u8>,
    pub parent_last_heard: Option<Instant>,
    pub mode_of_operation: ModeOfOperation,
    pub dodag_configuration: DodagConfiguration,
    pub grounded: bool,
    pub dodag_preference: u8,
    pub ocp: u16,
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

impl Rpl {
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
            mode_of_operation: rpl::ModeOfOperation::NoDownwardRoutesMaintained,
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
