use crate::wire::Ipv6Address;

use super::{lollipop::SequenceCounter, rank::Rank};
use crate::config::RPL_PARENTS_BUFFER_COUNT;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Parent {
    rank: Rank,
    address: Ipv6Address,
    preference: u8,
    version_number: SequenceCounter,
    dodag_id: Ipv6Address,
}

impl Parent {
    /// Create a new parent.
    pub(crate) fn new(
        address: Ipv6Address,
        preference: u8,
        rank: Rank,
        version_number: SequenceCounter,
        dodag_id: Ipv6Address,
    ) -> Self {
        Self {
            rank,
            address,
            preference,
            version_number,
            dodag_id,
        }
    }

    /// Return the Rank of the parent.
    pub(crate) fn rank(&self) -> &Rank {
        &self.rank
    }
}

#[derive(Debug, Default)]
pub(crate) struct ParentSet {
    parents: heapless::Vec<Parent, { RPL_PARENTS_BUFFER_COUNT }>,
}

impl ParentSet {
    /// Add a new parent to the parent set. The Rank of the new parent should be lower than the
    /// Rank of the node that holds this parent set.
    pub(crate) fn add(&mut self, parent: Parent) {
        if let Some(p) = self.find_mut(parent.address) {
            // Update information
            *p = parent;
        } else if let Err(p) = self.parents.push(parent) {
            // Look for the worst parent
            if let Some(worst) = self.worst_parent() {
                if worst.rank().dag_rank() > parent.rank().dag_rank() {
                    *worst = parent;
                } else {
                    net_debug!("could not add parent");
                }
            } else {
                // WARNING: there should be a worst parent, since the list of parents is not empty
                unreachable!();
            }
        }
    }

    /// Find a parent based on its address.
    pub(crate) fn find(&self, address: Ipv6Address) -> Option<&Parent> {
        self.parents.iter().find(|p| p.address == address)
    }

    /// Find a mutable parent based on its address.
    pub(crate) fn find_mut(&mut self, address: Ipv6Address) -> Option<&mut Parent> {
        self.parents.iter_mut().find(|p| p.address == address)
    }

    /// Return a slice to the parent set.
    pub(crate) fn parents(&self) -> &[Parent] {
        &self.parents
    }

    /// Find the worst parent that is currently in the parent set.
    fn worst_parent(&mut self) -> Option<&mut Parent> {
        let mut worst: Option<&mut Parent> = None;

        for p in self.parents.iter_mut() {
            if worst.is_none() || worst.as_mut().unwrap().rank.dag_rank() < p.rank.dag_rank() {
                worst = Some(p);
            }
        }

        worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parent() {
        let mut set = ParentSet::default();
        set.add(Parent::new(
            Default::default(),
            0,
            Rank::ROOT,
            Default::default(),
            Default::default(),
        ));

        assert_eq!(
            set.find(Default::default()),
            Some(&Parent::new(
                Default::default(),
                0,
                Rank::ROOT,
                Default::default(),
                Default::default()
            ))
        );
    }

    #[test]
    fn add_more_parents() {
        use super::super::consts::DEFAULT_MIN_HOP_RANK_INCREASE;
        let mut set = ParentSet::default();

        let mut last_address = Default::default();
        for i in 0..RPL_PARENTS_BUFFER_COUNT {
            let i = i as u16;
            let mut address = Ipv6Address::default();
            address.0[15] = i as u8;
            last_address = address;

            set.add(Parent::new(
                address,
                0,
                Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                address,
            ));

            assert_eq!(
                set.find(address),
                Some(&Parent::new(
                    address,
                    0,
                    Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                    Default::default(),
                    address,
                ))
            );
        }

        // This one is not added to the set, because its Rank is worse than any other parent in the
        // set.
        let mut address = Ipv6Address::default();
        address.0[15] = 8;
        set.add(Parent::new(
            address,
            0,
            Rank::new(256 * 8, DEFAULT_MIN_HOP_RANK_INCREASE),
            Default::default(),
            address,
        ));
        assert_eq!(set.find(address), None);

        /// This Parent has a better rank than the last one in the set.
        let mut address = Ipv6Address::default();
        address.0[15] = 9;
        set.add(Parent::new(
            address,
            0,
            Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
            Default::default(),
            address,
        ));
        assert_eq!(
            set.find(address),
            Some(&Parent::new(
                address,
                0,
                Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                address
            ))
        );
        assert_eq!(set.find(last_address), None);
    }
}
