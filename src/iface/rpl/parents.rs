use crate::time::{Duration, Instant};
use crate::wire::{Ipv6Address, RplSequenceCounter};

use super::rank::Rank;
use crate::config::RPL_PARENTS_BUFFER_COUNT;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Parent {
    pub address: Ipv6Address,
    pub dodag_id: Ipv6Address,
    pub rank: Rank,
    pub version_number: RplSequenceCounter,
    pub dtsn: RplSequenceCounter,
    pub last_heard: Instant,
}

impl Parent {
    /// Create a new parent.
    pub(crate) fn new(
        address: Ipv6Address,
        rank: Rank,
        version_number: RplSequenceCounter,
        dtsn: RplSequenceCounter,
        dodag_id: Ipv6Address,
        last_heard: Instant,
    ) -> Self {
        Self {
            address,
            rank,
            version_number,
            dtsn,
            dodag_id,
            last_heard,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ParentSet {
    parents: heapless::Vec<Parent, { RPL_PARENTS_BUFFER_COUNT }>,
}

impl ParentSet {
    /// Add a new parent to the parent set. The Rank of the new parent should be lower than the
    /// Rank of the node that holds this parent set.
    pub(crate) fn add(&mut self, parent: Parent) -> Result<(), Parent> {
        if let Some(p) = self.find_mut(&parent.address) {
            *p = parent;
        } else {
            match self.parents.push(parent) {
                Ok(_) => net_trace!("added {} to parent set", parent.address),
                Err(e) => {
                    if let Some(worst_parent) = self.worst_parent() {
                        if worst_parent.rank.dag_rank() > parent.rank.dag_rank() {
                            *worst_parent = parent;
                            net_trace!("added {} to parent set", parent.address);
                        } else {
                            return Err(parent);
                        }
                    } else {
                        unreachable!()
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn remove(&mut self, address: &Ipv6Address) {
        if let Some(i) = self.parents.iter().enumerate().find_map(|(i, p)| {
            if p.address == *address {
                Some(i)
            } else {
                None
            }
        }) {
            self.parents.remove(i);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.parents.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.parents.clear();
    }

    /// Find a parent based on its address.
    pub(crate) fn find(&self, address: &Ipv6Address) -> Option<&Parent> {
        self.parents.iter().find(|p| p.address == *address)
    }

    /// Find a mutable parent based on its address.
    pub(crate) fn find_mut(&mut self, address: &Ipv6Address) -> Option<&mut Parent> {
        self.parents.iter_mut().find(|p| p.address == *address)
    }

    /// Return a slice to the parent set.
    pub(crate) fn parents(&self) -> impl Iterator<Item = &Parent> {
        self.parents.iter()
    }

    /// Find the worst parent that is currently in the parent set.
    fn worst_parent(&mut self) -> Option<&mut Parent> {
        self.parents.iter_mut().max_by_key(|p| p.rank.dag_rank())
    }

    pub(crate) fn purge(&mut self, now: Instant, expiration: Duration) {
        let mut keys = heapless::Vec::<usize, RPL_PARENTS_BUFFER_COUNT>::new();
        for (i, p) in self.parents.iter().enumerate() {
            if p.last_heard + expiration < now {
                keys.push(i);
            }
        }

        for k in keys {
            self.parents.remove(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parent() {
        let now = Instant::now();
        let mut set = ParentSet::default();
        set.add(
            Default::default(),
            Parent::new(
                Rank::ROOT,
                Default::default(),
                Default::default(),
                Default::default(),
                now,
            ),
        );

        assert_eq!(
            set.find(&Default::default()),
            Some(&Parent::new(
                Rank::ROOT,
                Default::default(),
                Default::default(),
                Default::default(),
                now,
            ))
        );
    }

    #[test]
    fn add_more_parents() {
        let now = Instant::now();
        use super::super::consts::DEFAULT_MIN_HOP_RANK_INCREASE;
        let mut set = ParentSet::default();

        let mut last_address = Default::default();
        for i in 0..RPL_PARENTS_BUFFER_COUNT {
            let i = i as u16;
            let mut address = Ipv6Address::default();
            address.0[15] = i as u8;
            last_address = address;

            set.add(
                address,
                Parent::new(
                    Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                    Default::default(),
                    Default::default(),
                    address,
                    now,
                ),
            );

            assert_eq!(
                set.find(&address),
                Some(&Parent::new(
                    Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                    Default::default(),
                    Default::default(),
                    address,
                    now,
                ))
            );
        }

        // This one is not added to the set, because its Rank is worse than any other parent in the
        // set.
        let mut address = Ipv6Address::default();
        address.0[15] = 8;
        set.add(
            address,
            Parent::new(
                Rank::new(256 * 8, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ),
        );
        assert_eq!(set.find(&address), None);

        /// This Parent has a better rank than the last one in the set.
        let mut address = Ipv6Address::default();
        address.0[15] = 9;
        set.add(
            address,
            Parent::new(
                Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ),
        );
        assert_eq!(
            set.find(&address),
            Some(&Parent::new(
                Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ))
        );
        assert_eq!(set.find(&last_address), None);
    }
}
