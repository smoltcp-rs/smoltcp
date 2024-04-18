use crate::time::{Duration, Instant};
use crate::wire::Ipv6Address;

use crate::config::{RPL_MAX_NEXT_HOP_PER_DESTINATION, RPL_RELATIONS_BUFFER_COUNT};

#[derive(Debug)]
pub enum RelationError {
    NextHopExhausted,
    ToFewNextHops,
}

#[cfg(feature = "std")]
impl std::error::Error for RelationError {}

impl core::fmt::Display for RelationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RelationError::NextHopExhausted => write!(f, "Next hop exhausted"),
            RelationError::ToFewNextHops => write!(f, "Expected at least 1 next hop"),
        }
    }
}

#[derive(Debug)]
pub struct UnicastRelation {
    destination: Ipv6Address,
    next_hops: [Ipv6Address; 1],
    added: Instant,
    lifetime: Duration,
}

impl core::fmt::Display for UnicastRelation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via {} (expires at {})",
            self.destination,
            self.next_hops[0],
            self.added + self.lifetime
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for UnicastRelation {
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

#[cfg(feature = "rpl-mop-3")]
#[derive(Debug)]
pub struct MulticastRelation {
    destination: Ipv6Address,
    next_hops: heapless::Vec<Ipv6Address, { RPL_MAX_NEXT_HOP_PER_DESTINATION }>,
    added: Instant,
    lifetime: Duration,
}

impl MulticastRelation {
    /// Insert a next hop for this relation. If the next hop already exists, if
    /// will return Ok(true) otherwise Ok(false)
    fn insert_next_hop(&mut self, ip: Ipv6Address) -> Result<bool, RelationError> {
        if !self.next_hops.contains(&ip) {
            self.next_hops
                .push(ip)
                .map_err(|_err| RelationError::NextHopExhausted)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Removes the next_hop from this relation
    pub fn remove_next_hop(&mut self, ip: Ipv6Address) {
        self.next_hops.retain(|next_hop| next_hop == &ip);
    }
}

#[cfg(feature = "rpl-mop-3")]
impl core::fmt::Display for MulticastRelation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via {:?} (expires at {})",
            self.destination,
            self.next_hops,
            self.added + self.lifetime
        )
    }
}

#[cfg(all(feature = "defmt", feature = "rpl-mop-3"))]
impl defmt::Format for MulticastRelation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "{} via {:?} (expires at {})",
            self.destination,
            self.next_hop,
            self.added + self.lifetime
        );
    }
}

#[derive(Debug)]
pub enum Relation {
    Unicast(UnicastRelation),
    #[cfg(feature = "rpl-mop-3")]
    Multicast(MulticastRelation),
}

impl Relation {
    pub fn new(
        destination: Ipv6Address,
        next_hops: &[Ipv6Address],
        now: Instant,
        lifetime: Duration,
    ) -> Result<Self, RelationError> {
        if destination.is_multicast() {
            Ok(Self::Multicast(MulticastRelation {
                destination,
                next_hops: heapless::Vec::from_slice(next_hops)
                    .map_err(|_err| RelationError::NextHopExhausted)?,
                added: now,
                lifetime,
            }))
        } else {
            if next_hops.len() > 1 {
                return Err(RelationError::NextHopExhausted);
            }
            Ok(Self::Unicast(UnicastRelation {
                destination,
                next_hops: next_hops.try_into().unwrap(),
                added: now,
                lifetime,
            }))
        }
    }

    pub fn destination(&self) -> Ipv6Address {
        match self {
            Self::Unicast(rel) => rel.destination,
            Self::Multicast(rel) => rel.destination,
        }
    }

    pub fn insert_next_hop(&mut self, ip: Ipv6Address) -> Result<bool, RelationError> {
        match self {
            Self::Unicast(rel) => {
                rel.next_hops[0] = ip;
                Ok(true)
            }
            Self::Multicast(rel) => rel.insert_next_hop(ip),
        }
    }

    pub fn next_hop_unicast(&self) -> Option<&Ipv6Address> {
        if let Self::Unicast(rel) = self {
            Some(&rel.next_hops[0])
        } else {
            None
        }
    }

    pub fn next_hop_multicast(&self) -> Option<&[Ipv6Address]> {
        if let Self::Multicast(rel) = self {
            Some(&rel.next_hops)
        } else {
            None
        }
    }

    pub fn next_hop(&self) -> &[Ipv6Address] {
        match self {
            Self::Unicast(rel) => &rel.next_hops,
            Self::Multicast(rel) => &rel.next_hops,
        }
    }

    pub fn added_mut(&mut self) -> &mut Instant {
        match self {
            Self::Unicast(rel) => &mut rel.added,
            Self::Multicast(rel) => &mut rel.added,
        }
    }

    pub fn added(&self) -> Instant {
        match self {
            Self::Unicast(rel) => rel.added,
            Self::Multicast(rel) => rel.added,
        }
    }

    pub fn lifetime_mut(&mut self) -> &mut Duration {
        match self {
            Self::Unicast(rel) => &mut rel.lifetime,
            Self::Multicast(rel) => &mut rel.lifetime,
        }
    }

    pub fn lifetime(&self) -> Duration {
        match self {
            Self::Unicast(rel) => rel.lifetime,
            Self::Multicast(rel) => rel.lifetime,
        }
    }
}

impl core::fmt::Display for Relation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unicast(rel) => rel.fmt(f),
            Self::Multicast(rel) => rel.fmt(f),
        }
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
        next_hops: &[Ipv6Address],
        now: Instant,
        lifetime: Duration,
    ) -> Result<(), RelationError> {
        if let Some(r) = self
            .relations
            .iter_mut()
            .find(|r| r.destination() == destination)
        {
            net_trace!("Updating old relation information");
            for next_hop in next_hops {
                r.insert_next_hop(*next_hop)?;
            }
            *r.added_mut() = now;
            *r.lifetime_mut() = lifetime; // FIXME: How should this be handled for multicast?
        } else {
            let relation = Relation::new(destination, next_hops, now, lifetime)?;

            if let Err(e) = self.relations.push(relation) {
                net_trace!("unable to add relation, buffer is full");
            }
        }

        Ok(())
    }

    /// Remove all relation entries for a specific destination.
    pub fn remove_relation(&mut self, destination: Ipv6Address) {
        self.relations.retain(|r| r.destination() != destination)
    }

    /// Return the next hop for a specific IPv6 address, if there is one.
    pub fn find_next_hop(&self, destination: Ipv6Address) -> Option<&[Ipv6Address]> {
        self.relations.iter().find_map(|r| {
            if r.destination() == destination {
                match r {
                    Relation::Unicast(r) => Some(&r.next_hops[..]),
                    Relation::Multicast(r) => Some(&r.next_hops),
                }
            } else {
                None
            }
        })
    }

    /// Purge expired relations.
    ///
    /// Returns `true` when a relation was actually removed.
    pub fn flush(&mut self, now: Instant) -> bool {
        let len = self.relations.len();
        for r in &self.relations {
            if r.added() + r.lifetime() <= now {
                net_trace!("removing {} relation (expired)", r.destination());
            }
        }
        self.relations.retain(|r| r.added() + r.lifetime() > now);
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
            &[addrs[1]],
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
            relations.add_relation(a, &[a], Instant::now(), Duration::from_secs(60 * 30));
        }

        assert_eq!(relations.relations.len(), RPL_RELATIONS_BUFFER_COUNT);
    }

    #[test]
    fn update_relation() {
        let addrs = addresses(3);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            &[addrs[1]],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);

        relations.add_relation(
            addrs[0],
            &[addrs[2]],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);

        assert_eq!(relations.find_next_hop(addrs[0]), Some(&[addrs[2]][..]));
    }

    #[test]
    fn find_next_hop() {
        let addrs = addresses(3);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            &[addrs[1]],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.find_next_hop(addrs[0]), Some(&[addrs[1]][..]));

        relations.add_relation(
            addrs[0],
            &[addrs[2]],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.find_next_hop(addrs[0]), Some(&[addrs[2]][..]));

        // Find the next hop of a destination not in the buffer.
        assert_eq!(relations.find_next_hop(addrs[1]), None);
    }

    #[test]
    fn remove_relation() {
        let addrs = addresses(2);

        let mut relations = Relations::default();
        relations.add_relation(
            addrs[0],
            &[addrs[1]],
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
            &[addrs[1]],
            Instant::now() - Duration::from_secs(60 * 30 + 1),
            Duration::from_secs(60 * 30),
        );

        assert_eq!(relations.relations.len(), 1);

        relations.flush(Instant::now());
        assert!(relations.relations.is_empty());
    }
}
