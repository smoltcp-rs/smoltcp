use crate::time::{Duration, Instant};
use crate::wire::Ipv6Address;

use crate::config::RPL_RELATIONS_BUFFER_COUNT;

#[derive(Debug)]
pub struct Relation {
    destination: Ipv6Address,
    next_hop: Ipv6Address,
    added: Instant,
    lifetime: Duration,
}

impl core::fmt::Display for Relation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via {} (expires at {})",
            self.destination,
            self.next_hop,
            self.added + self.lifetime
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Relation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "{} via {} (expires at {})",
            self.destination,
            self.next_hop,
            self.added + self.lifetime
        );
    }
}

#[derive(Default, Debug)]
pub struct Relations {
    relations: heapless::Vec<Relation, { RPL_RELATIONS_BUFFER_COUNT }>,
}

impl Relations {
    /// Add a new relation to the buffer. If there was already a relation in the buffer, then
    /// update it.
    pub fn add_relation(
        &mut self,
        destination: Ipv6Address,
        next_hop: Ipv6Address,
        now: Instant,
        lifetime: Duration,
    ) {
        if let Some(r) = self
            .relations
            .iter_mut()
            .find(|r| r.destination == destination)
        {
            net_trace!("Updating old relation information");
            r.next_hop = next_hop;
            r.added = now;
            r.lifetime = lifetime;
        } else {
            let relation = Relation {
                destination,
                next_hop,
                added: now,
                lifetime,
            };

            if let Err(e) = self.relations.push(relation) {
                net_trace!("unable to add relation, buffer is full");
            }
        }
    }

    /// Remove all relation entries for a specific destination.
    pub fn remove_relation(&mut self, destination: Ipv6Address) {
        self.relations.retain(|r| r.destination != destination)
    }

    /// Return the next hop for a specific IPv6 address, if there is one.
    pub fn find_next_hop(&self, destination: Ipv6Address) -> Option<Ipv6Address> {
        self.relations.iter().find_map(|r| {
            if r.destination == destination {
                Some(r.next_hop)
            } else {
                None
            }
        })
    }

    /// Purge expired relations.
    ///
    /// Returns `true` when a relation was actually removed.
    pub fn purge(&mut self, now: Instant) -> bool {
        let len = self.relations.len();
        for r in &self.relations {
            if r.added + r.lifetime <= now {
                net_trace!("removing {} relation (expired)", r.destination);
            }
        }
        self.relations.retain(|r| r.added + r.lifetime > now);
        self.relations.len() != len
    }

    pub fn iter(&self) -> impl Iterator<Item = &Relation> {
        self.relations.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Duration;

    fn addresses(count: usize) -> Vec<Ipv6Address> {
        (0..count)
            .map(|i| {
                let mut ip = Ipv6Address::default();
                ip.0[0] = i as u8;
                ip
            })
            .collect()
    }

    #[test]
    fn add_relation() {
        let addrs = addresses(2);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            addrs[1],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
    }

    #[test]
    fn add_relations_full_buffer() {
        let addrs = addresses(crate::config::RPL_RELATIONS_BUFFER_COUNT + 1);

        // Try to add RPL_RELATIONS_BUFFER_COUNT + 1 to the buffer.
        // The size of the buffer should still be RPL_RELATIONS_BUFFER_COUNT.
        let mut relations = Relations::default();
        for a in addrs {
            relations.add_relation(a, a, Instant::now(), Duration::from_secs(60 * 30));
        }

        assert_eq!(relations.relations.len(), RPL_RELATIONS_BUFFER_COUNT);
    }

    #[test]
    fn update_relation() {
        let addrs = addresses(3);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            addrs[1],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);

        relations.add_relation(
            addrs[0],
            addrs[2],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);

        assert_eq!(relations.find_next_hop(addrs[0]), Some(addrs[2]));
    }

    #[test]
    fn find_next_hop() {
        let addrs = addresses(3);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            addrs[1],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.find_next_hop(addrs[0]), Some(addrs[1]));

        relations.add_relation(
            addrs[0],
            addrs[2],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.find_next_hop(addrs[0]), Some(addrs[2]));

        // Find the next hop of a destination not in the buffer.
        assert_eq!(relations.find_next_hop(addrs[1]), None);
    }

    #[test]
    fn remove_relation() {
        let addrs = addresses(2);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            addrs[1],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);

        relations.remove_relation(addrs[0]);
        assert!(relations.relations.is_empty());
    }

    #[test]
    fn purge_relation() {
        let addrs = addresses(2);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            addrs[1],
            Instant::now() - Duration::from_secs(60 * 30 + 1),
            Duration::from_secs(60 * 30),
        );

        assert_eq!(relations.relations.len(), 1);

        relations.purge(Instant::now());
        assert!(relations.relations.is_empty());
    }
}
