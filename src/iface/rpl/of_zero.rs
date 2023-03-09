use super::{
    obj_function::ObjectiveFunction, rank::Rank, RplNeighbor, RplNeighborEntry, RplNeighborTable,
};

pub struct ObjectiveFunction0 {}

impl ObjectiveFunction for ObjectiveFunction0 {}

impl ObjectiveFunction0 {
    pub const OCP: u16 = 0;

    const RANK_STRETCH: u16 = 0;
    const RANK_FACTOR: u16 = 1;
    const RANK_STEP: u16 = 3;

    // const MIN_STEP_OF_RANK: u16 = 1;
    // const MAX_STEP_OF_RANK: u16 = 9;
    // const MAX_RANK_STRETCH: u16 = 5;
    // const MIN_RANK_FACTOR: u16 = 1;
    // const MAX_RANK_FACTOR: u16 = 4;

    pub(crate) fn new_rank(_rank: Rank, parent_rank: Rank) -> Rank {
        Rank::new(
            parent_rank.value + Self::rank_increase(parent_rank),
            parent_rank.min_hop_rank_increase,
        )
    }

    pub(crate) fn rank_increase(parent_rank: Rank) -> u16 {
        (Self::RANK_FACTOR * Self::RANK_STEP + Self::RANK_STRETCH)
            * parent_rank.min_hop_rank_increase
    }

    /// Return the most preferred neighbor from the table.
    pub(crate) fn preferred_parent(neighbors: &RplNeighborTable) -> Option<&RplNeighbor> {
        let mut preferred_parent = None;
        for n in &neighbors.neighbors {
            if let RplNeighborEntry::Neighbor((n, _)) = n {
                if preferred_parent.is_none() {
                    preferred_parent = Some(n);
                } else {
                    let parent1 = preferred_parent.as_ref().unwrap();

                    if parent1.rank().dag_rank() > n.rank().dag_rank() {
                        preferred_parent = Some(n);
                    }
                }
            }
        }

        preferred_parent
    }
}
