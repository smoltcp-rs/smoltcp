use super::Rank;
use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, Ipv6Address};

#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RplNeighborTable {
    pub(crate) neighbors: [RplNeighborEntry; super::consts::RPL_NEIGHBOR_TABLE_SIZE],
}

#[cfg(feature = "std")]
impl ToString for RplNeighborTable {
    fn to_string(&self) -> String {
        let mut s = String::new();

        for n in self.neighbors.iter() {
            if let RplNeighborEntry::Neighbor((
                RplNeighbor {
                    ll_addr,
                    rank,
                    ip_addr,
                    ..
                },
                last_heard,
            )) = n
            {
                s.push_str(&format!(
                    "IEEE={ll_addr} IPv6={ip_addr} {rank} LH={last_heard}\n"
                ));
            }
        }

        s
    }
}

impl RplNeighborTable {
    /// Get the first free entry in the neighbor table.
    fn get_first_free_entry(&mut self) -> Option<&mut RplNeighborEntry> {
        self.neighbors
            .iter_mut()
            .find(|neighbor| matches!(neighbor, RplNeighborEntry::Empty))
    }

    /// Return a mutable reference to a neighbor matching the link-layer address.
    pub(crate) fn get_neighbor_from_ll_addr(
        &mut self,
        addr: &HardwareAddress,
    ) -> Option<&mut (RplNeighbor, Instant)> {
        self.neighbors
            .iter_mut()
            .find(|neighbor| match neighbor {
                RplNeighborEntry::Neighbor((RplNeighbor { ll_addr, .. }, _)) if ll_addr == addr => {
                    true
                }
                _ => false,
            })
            .map(|n| match n {
                RplNeighborEntry::Neighbor(n) => n,
                RplNeighborEntry::Empty => unreachable!(),
            })
    }

    /// Return a mutable reference to a neighbor matching the IPv6 address.
    pub(crate) fn get_neighbor_from_ip_addr(
        &mut self,
        addr: &Ipv6Address,
    ) -> Option<&mut (RplNeighbor, Instant)> {
        self.neighbors
            .iter_mut()
            .find(|neighbor| match neighbor {
                RplNeighborEntry::Neighbor((RplNeighbor { ip_addr, .. }, _)) if ip_addr == addr => {
                    true
                }
                _ => false,
            })
            .map(|n| match n {
                RplNeighborEntry::Neighbor(n) => n,
                RplNeighborEntry::Empty => unreachable!(),
            })
    }

    fn find_worst_neighbor(&mut self) -> Option<&mut RplNeighbor> {
        let mut worst_neighbor = None;

        for n in &mut self.neighbors {
            if let RplNeighborEntry::Neighbor((neighbor, _)) = n {
                if worst_neighbor.is_none() {
                    worst_neighbor = Some(neighbor);
                } else if worst_neighbor.as_ref().unwrap().rank.dag_rank()
                    < neighbor.rank.dag_rank()
                {
                    worst_neighbor = Some(neighbor)
                }
            } else {
                continue;
            }
        }

        worst_neighbor
    }

    /// Add a neighbor to the neighbor table.
    pub(crate) fn add_neighbor(&mut self, neighbor: RplNeighbor, instant: Instant) {
        if let Some((n, last_heard)) = self.get_neighbor_from_ll_addr(&neighbor.ll_addr) {
            n.update_info(
                neighbor.ip_addr.into(),
                neighbor.rank.into(),
                neighbor.preference.into(),
            );

            *last_heard = instant;

            return;
        }

        if let Some(free_entry) = self.get_first_free_entry() {
            *free_entry = RplNeighborEntry::Neighbor((neighbor, instant));
            return;
        }

        // We didn't find the neighbor and there was no free space in the table.
        // We remove the neighbor with the highest rank.
        let worst_neighbor = self.find_worst_neighbor().unwrap();
        if neighbor.rank.dag_rank() < worst_neighbor.rank.dag_rank() {
            *worst_neighbor = neighbor;
        }
    }

    pub(crate) fn purge(&mut self, now: Instant, expiration: Duration) {
        for n in self.neighbors.iter_mut() {
            if let RplNeighborEntry::Neighbor((_, last_heard)) = n {
                if *last_heard < now - expiration {
                    *n = RplNeighborEntry::Empty;
                }
            }
        }
    }

    pub fn count(&self) -> usize {
        self.neighbors
            .iter()
            .filter(|n| matches!(n, RplNeighborEntry::Neighbor(_)))
            .count()
    }
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum RplNeighborEntry {
    #[default]
    Empty,
    Neighbor((RplNeighbor, Instant)),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RplNeighbor {
    ll_addr: HardwareAddress,
    rank: Rank,
    ip_addr: Ipv6Address,
    preference: u8,
}

impl RplNeighbor {
    pub fn new(
        addr: HardwareAddress,
        ip_addr: Ipv6Address,
        rank: Option<Rank>,
        preference: Option<u8>,
    ) -> Self {
        Self {
            ll_addr: addr,
            ip_addr,
            rank: rank.unwrap_or(Rank::INFINITE),
            preference: preference.unwrap_or(0),
        }
    }

    pub fn update_info(
        &mut self,
        ip_addr: Option<Ipv6Address>,
        rank: Option<Rank>,
        preference: Option<u8>,
    ) {
        if let Some(ip_addr) = ip_addr {
            self.ip_addr = ip_addr;
        }

        if let Some(rank) = rank {
            self.rank = rank;
        }

        if let Some(preference) = preference {
            self.preference = preference;
        }
    }

    pub fn link_layer_addr(&self) -> HardwareAddress {
        self.ll_addr
    }

    pub fn ip_addr(&self) -> Ipv6Address {
        self.ip_addr
    }

    pub fn rank(&self) -> Rank {
        self.rank
    }

    pub fn preference(&self) -> u8 {
        self.preference
    }
}
