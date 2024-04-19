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
    next_hop: [RelationHop; 1],
}

impl core::fmt::Display for UnicastRelation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} via [{}] (expires at {})",
            self.destination,
            self.next_hop[0],
            self.next_hop[0].added + self.next_hop[0].lifetime
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for UnicastRelation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "{} via [{}] (expires at {})",
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
    next_hops: heapless::Vec<RelationHop, { RPL_MAX_NEXT_HOP_PER_DESTINATION }>,
}

#[derive(Debug)]
pub struct RelationHop {
    pub ip: Ipv6Address,
    pub added: Instant,
    pub lifetime: Duration,
}

impl RelationHop {
    pub fn expires_at(&self) -> Instant {
        self.added + self.lifetime
    }

    pub fn has_expired(&self, now: Instant) -> bool {
        self.expires_at() <= now
    }
}

impl core::fmt::Display for RelationHop {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (expires at {})", self.ip, self.added + self.lifetime)
    }
}

#[cfg(all(feature = "defmt", feature = "rpl-mop-3"))]
impl defmt::Format for RelationHop {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(f, "{} (expires at {})", self.ip, self.added + self.lifetime)
    }
}

#[cfg(feature = "rpl-mop-3")]
impl MulticastRelation {
    /// Insert a next hop for this relation. If the next hop already exists, if
    /// will return Ok(true) otherwise Ok(false)
    fn insert_next_hop(
        &mut self,
        ip: Ipv6Address,
        added: Instant,
        lifetime: Duration,
    ) -> Result<bool, RelationError> {
        if let Some(next_hop) = self.next_hops.iter_mut().find(|hop| hop.ip == ip) {
            next_hop.added = added;
            next_hop.lifetime = lifetime;

            Ok(true)
        } else {
            self.next_hops
                .push(RelationHop {
                    ip,
                    added,
                    lifetime,
                })
                .map_err(|_err| RelationError::NextHopExhausted)?;
            Ok(false)
        }
    }

    /// Removes the next_hop from this relation
    pub fn remove_next_hop(&mut self, ip: Ipv6Address) {
        self.next_hops.retain(|next_hop| next_hop.ip == ip);
    }
}

#[cfg(feature = "rpl-mop-3")]
impl core::fmt::Display for MulticastRelation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via [", self.destination)?;

        for hop in &self.next_hops {
            write!(f, "{},", hop)?;
        }

        write!(f, "]")?;

        Ok(())
    }
}

#[cfg(all(feature = "defmt", feature = "rpl-mop-3"))]
impl defmt::Format for MulticastRelation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(f, "{} via [", self.destination)?;

        for hop in self.next_hops {
            defmt::write!(f, "{},", hop)?;
        }

        defmt::write!(f, "]")?;

        Ok(())
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
                next_hops: heapless::Vec::from_iter(next_hops.iter().map(|hop| RelationHop {
                    ip: *hop,
                    added: now,
                    lifetime,
                })),
            }))
        } else {
            if next_hops.len() > 1 {
                return Err(RelationError::NextHopExhausted);
            }
            Ok(Self::Unicast(UnicastRelation {
                destination,
                next_hop: [RelationHop {
                    ip: next_hops[0],
                    added: now,
                    lifetime,
                }],
            }))
        }
    }

    pub fn destination(&self) -> Ipv6Address {
        match self {
            Self::Unicast(rel) => rel.destination,
            Self::Multicast(rel) => rel.destination,
        }
    }

    /// Insert a next hop for the given relation. If this is a unicast relation,
    /// the previous will be overwritten and if it is a multicast relation it
    /// will add an extra hop if the hop does not already exist. If there already
    /// exists a hop in the multicast relation, the lifetime related metadata
    /// will be updated.
    pub fn insert_next_hop(
        &mut self,
        ip: Ipv6Address,
        added: Instant,
        lifetime: Duration,
    ) -> Result<bool, RelationError> {
        match self {
            Self::Unicast(rel) => {
                let next_hop = &mut rel.next_hop[0];
                next_hop.ip = ip;
                next_hop.added = added;
                next_hop.lifetime = lifetime;
                Ok(true)
            }
            Self::Multicast(rel) => rel.insert_next_hop(ip, added, lifetime),
        }
    }

    pub fn next_hop(&self) -> &[RelationHop] {
        match self {
            Self::Unicast(rel) => &rel.next_hop,
            Self::Multicast(rel) => &rel.next_hops,
        }
    }

    /// A relation has expired if all its possible hops have expired
    pub fn has_expired(&self, now: Instant) -> bool {
        match self {
            Self::Unicast(rel) => rel.next_hop.iter().all(|hop| hop.has_expired(now)),
            Self::Multicast(rel) => rel.next_hops.iter().all(|hop| hop.has_expired(now)),
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
                r.insert_next_hop(*next_hop, now, lifetime)?;
            }
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
    pub fn find_next_hop(&self, destination: Ipv6Address) -> Option<&[RelationHop]> {
        self.relations.iter().find_map(|r| {
            if r.destination() == destination {
                match r {
                    Relation::Unicast(r) => Some(&r.next_hop[..]),
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
        self.relations.retain_mut(|r| {
            // First flush all relations if it is a multicast relation
            let has_expired = match r {
                Relation::Unicast(rel) => rel.next_hop[0].has_expired(now),
                Relation::Multicast(rel) => {
                    rel.next_hops.retain(|hop| {
                        if hop.has_expired(now) {
                            net_trace!("Removing {} hop (expired)", hop);
                            false
                        } else {
                            true
                        }
                    });
                    rel.next_hops.is_empty()
                }
            };

            if has_expired {
                net_trace!("Removing {} (destination)", r.destination());
            }

            !has_expired
        });
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

        assert_eq!(
            relations.find_next_hop(addrs[0]).map(|hop| hop[0].ip),
            Some(addrs[2])
        );
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
        assert_eq!(
            relations.find_next_hop(addrs[0]).map(|hop| hop[0].ip),
            Some(addrs[1])
        );

        relations.add_relation(
            addrs[0],
            &[addrs[2]],
            Instant::now(),
            Duration::from_secs(60 * 30),
        );
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(
            relations.find_next_hop(addrs[0]).map(|hop| hop[0].ip),
            Some(addrs[2])
        );

        // Find the next hop of a destination not in the buffer.
        assert_eq!(relations.find_next_hop(addrs[1]).map(|hop| hop[0].ip), None);
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
