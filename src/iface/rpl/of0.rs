use super::parents::*;
use super::rank::Rank;

use crate::wire::Ipv6Address;

pub(crate) trait ObjectiveFunction: Default {
    const OCP: u16;

    /// Return the new calculated Rank, based on information from the parent.
    fn rank(&self, current_rank: Rank, parent_rank: Rank) -> Rank;

    /// Return the preferred parent from a given parent set.
    fn preferred_parent(&self, parent_set: &ParentSet) -> Option<Ipv6Address>;

    fn objective_code_point(&self) -> u16;

    /// Return the MaxRankIncrease value of an Objective Function.
    fn max_rank_increase(&self) -> u16;
    /// Set the MaxRankIncrease value of an Objective Function.
    fn set_max_rank_increase(&mut self, max_rank_increase: u16);

    /// Return the MinHopRankIncrease value of an Objective Function.
    fn min_hop_rank_increase(&self) -> u16;
    /// Set the MinHopRankIncrease value of an Objective Function.
    fn set_min_hop_rank_increase(&mut self, min_hop_rank_increase: u16);
}

pub struct ObjectiveFunction0 {
    max_rank_increase: u16,
    min_hop_rank_increase: u16,
}

impl Default for ObjectiveFunction0 {
    fn default() -> Self {
        Self::new(Self::MIN_HOP_RANK_INCREASE, Self::MAX_RANK_INCREASE)
    }
}

impl ObjectiveFunction0 {
    const OCP: u16 = 0;

    const RANK_STRETCH: u16 = 0;
    const RANK_FACTOR: u16 = 1;
    const RANK_STEP: u16 = 3;

    const MIN_HOP_RANK_INCREASE: u16 = 256;

    // We use a value of 0 for the maximum rank increase, since the OF0 RFC does not define one.
    // This value is application specific and limits how deep a RPL DODAG network will be.
    // 0 means that the depth of the tree is not limited.
    // Contiki-NG uses a value of 7.
    const MAX_RANK_INCREASE: u16 = 0;

    pub(crate) fn new(min_hop_rank_increase: u16, max_rank_increase: u16) -> Self {
        Self {
            min_hop_rank_increase,
            max_rank_increase,
        }
    }

    fn rank_increase(&self, parent_rank: Rank) -> u16 {
        (Self::RANK_FACTOR * Self::RANK_STEP + Self::RANK_STRETCH) * self.min_hop_rank_increase
    }
}

impl ObjectiveFunction for ObjectiveFunction0 {
    const OCP: u16 = 0;

    fn rank(&self, _: Rank, parent_rank: Rank) -> Rank {
        assert_ne!(parent_rank, Rank::INFINITE);

        Rank::new(
            parent_rank.value + self.rank_increase(parent_rank),
            parent_rank.min_hop_rank_increase,
        )
    }

    fn preferred_parent(&self, parent_set: &ParentSet) -> Option<Ipv6Address> {
        let mut pref_addr = None;
        let mut pref_parent: Option<&Parent> = None;

        for parent in parent_set.parents() {
            if pref_parent.is_none() || parent.rank < pref_parent.unwrap().rank {
                pref_parent = Some(parent);
                pref_addr = Some(parent.address);
            }
        }

        pref_addr
    }

    fn objective_code_point(&self) -> u16 {
        Self::OCP
    }

    fn max_rank_increase(&self) -> u16 {
        self.max_rank_increase
    }

    fn min_hop_rank_increase(&self) -> u16 {
        self.min_hop_rank_increase
    }

    fn set_max_rank_increase(&mut self, max_rank_increase: u16) {
        self.max_rank_increase = max_rank_increase;
    }

    fn set_min_hop_rank_increase(&mut self, min_hop_rank_increase: u16) {
        self.min_hop_rank_increase = min_hop_rank_increase;
    }
}

#[cfg(test)]
mod tests {
    use crate::iface::rpl::consts::DEFAULT_MIN_HOP_RANK_INCREASE;
    use crate::time::Instant;

    use super::*;

    #[test]
    fn rank_increase() {
        let of = ObjectiveFunction0::default();
        // 256 (root) + 3 * 256
        assert_eq!(
            of.rank(Rank::INFINITE, Rank::ROOT),
            Rank::new(256 + 3 * 256, DEFAULT_MIN_HOP_RANK_INCREASE)
        );

        // 1024 + 3 * 256
        assert_eq!(
            of.rank(
                Rank::INFINITE,
                Rank::new(1024, DEFAULT_MIN_HOP_RANK_INCREASE)
            ),
            Rank::new(1024 + 3 * 256, DEFAULT_MIN_HOP_RANK_INCREASE)
        );
    }

    #[test]
    #[should_panic]
    fn rank_increase_infinite() {
        let of = ObjectiveFunction0::default();
        assert_eq!(of.rank(Rank::INFINITE, Rank::INFINITE), Rank::INFINITE);
    }

    #[test]
    fn empty_set() {
        let of = ObjectiveFunction0::default();
        assert_eq!(of.preferred_parent(&ParentSet::default()), None);
    }

    #[test]
    fn non_empty_set() {
        use crate::wire::Ipv6Address;

        let mut parents = ParentSet::default();

        parents.add(Parent::new(
            Default::default(),
            Rank::ROOT,
            Default::default(),
            Default::default(),
            Default::default(),
            Instant::now(),
        ));

        let mut address = Ipv6Address::default();
        address.0[15] = 1;

        parents.add(Parent::new(
            address,
            Rank::new(1024, DEFAULT_MIN_HOP_RANK_INCREASE),
            Default::default(),
            Default::default(),
            Default::default(),
            Instant::now(),
        ));

        let of = ObjectiveFunction0::default();
        assert_eq!(of.preferred_parent(&parents), Some(Ipv6Address::default()));
    }
}
