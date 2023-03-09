use crate::{
    time::{Duration, Instant},
    wire::{
        ipv6::Address,
        rpl::{InstanceId, ModeOfOperation},
    },
};

use super::{consts, lollipop, rank, trickle, Rpl};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RplBuilder {
    is_root: bool,
    dodag_preference: u8,
    dio_timer: trickle::TrickleTimer,
    instance_id: InstanceId,
    version_number: lollipop::SequenceCounter,
    dodag_id: Option<Address>,
    rank: rank::Rank,
    dtsn: lollipop::SequenceCounter,
}

impl RplBuilder {
    #[inline]
    pub fn set_root(mut self) -> Self {
        self.is_root = true;
        self.rank = rank::Rank::ROOT;
        self
    }

    #[inline]
    pub fn set_preference(mut self, preference: u8) -> Self {
        self.dodag_preference = preference;
        self
    }

    /// Set the trickle timer.
    #[inline]
    pub fn set_dio_timer(mut self, dio_timer: trickle::TrickleTimer) -> Self {
        self.dio_timer = dio_timer;
        self
    }

    /// Set the Instance ID.
    #[inline]
    pub fn set_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = instance_id;
        self
    }

    /// Set the Version number.
    #[inline]
    pub fn set_version_number(mut self, version_number: lollipop::SequenceCounter) -> Self {
        self.version_number = version_number;
        self
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dodag_id(mut self, dodag_id: Address) -> Self {
        self.dodag_id = Some(dodag_id);
        self
    }

    /// Set the Rank.
    #[inline]
    pub fn set_rank(mut self, rank: rank::Rank) -> Self {
        self.rank = rank;
        self
    }

    /// Set the DTSN.
    #[inline]
    pub fn set_dtsn(mut self, dtsn: lollipop::SequenceCounter) -> Self {
        self.dtsn = dtsn;
        self
    }

    /// Build the RPL configuration.
    #[inline]
    pub fn finalize(self, now: Instant) -> Rpl {
        Rpl {
            is_root: self.is_root,
            dis_expiration: now + Duration::from_secs(5),
            dio_timer: self.dio_timer,
            neighbor_table: Default::default(),
            node_relations: Default::default(),
            instance_id: self.instance_id,
            version_number: self.version_number,
            dodag_id: self.dodag_id,
            rank: self.rank,
            dtsn: self.dtsn,
            parent_address: None,
            parent_rank: None,
            parent_preference: None,
            parent_last_heard: None,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained,
            dodag_configuration: Default::default(),
            grounded: false,
            dodag_preference: self.dodag_preference,
            ocp: 0,
        }
    }
}

impl Default for RplBuilder {
    fn default() -> Self {
        Self {
            is_root: false,
            dodag_preference: 0,
            dio_timer: trickle::TrickleTimer::new(
                consts::DEFAULT_DIO_INTERVAL_MIN as u32,
                consts::DEFAULT_DIO_INTERVAL_MIN as u32
                    + consts::DEFAULT_DIO_INTERVAL_DOUBLINGS as u32,
                consts::DEFAULT_DIO_REDUNDANCY_CONSTANT as usize,
            ),
            instance_id: InstanceId::from(consts::RPL_DEFAULT_INSTANCE), // NOTE: this is the value that contiki uses.
            version_number: lollipop::SequenceCounter::default(),
            dodag_id: None,
            // address of the Device is known.
            rank: rank::Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use lollipop::SequenceCounter;
    use rank::Rank;

    use crate::iface::rpl::trickle::TrickleTimer;

    use super::*;

    #[test]
    fn builder() {
        let now = Instant::now();
        let rpl = RplBuilder::default()
            .set_root()
            .set_rank(Rank::INFINITE)
            .set_dtsn(SequenceCounter::new(241))
            .set_dodag_id(crate::wire::Ipv6Address::default())
            .set_dio_timer(TrickleTimer::new(2, 18, 2))
            .set_preference(1)
            .set_instance_id(InstanceId::Local(10))
            .set_version_number(SequenceCounter::new(242))
            .finalize(now);

        assert!(rpl.is_root);
        assert_eq!(rpl.dis_expiration, now + Duration::from_secs(5));
        assert_eq!(rpl.dio_timer, TrickleTimer::new(2, 18, 2));
        assert_eq!(rpl.instance_id, InstanceId::Local(10));
        assert_eq!(rpl.version_number, SequenceCounter::new(242));
        assert_eq!(rpl.dodag_id, Some(crate::wire::Ipv6Address::default()));
        assert_eq!(rpl.rank, Rank::INFINITE);
        assert_eq!(rpl.dtsn, SequenceCounter::new(241));
        assert_eq!(rpl.parent_address, None);
        assert_eq!(rpl.parent_rank, None);
        assert_eq!(rpl.parent_preference, None);
        assert_eq!(rpl.parent_last_heard, None);
        assert_eq!(
            rpl.mode_of_operation,
            ModeOfOperation::NoDownwardRoutesMaintained
        );
        assert!(!rpl.grounded);
        assert_eq!(rpl.dodag_preference, 1);
        assert_eq!(rpl.ocp, 0);
    }
}
