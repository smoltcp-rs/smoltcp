use crate::time::Instant;
use crate::wire::Ipv6Address;

extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RplNode {
    ip_addr: Ipv6Address,
    expires_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RplNodeRelation {
    child: RplNode,
    parent: RplNode,
}

#[derive(Debug, Default)]
pub struct RplNodeRelations {
    relations: Vec<RplNodeRelation>,
}

impl RplNodeRelations {
    /// Adds a new relation if it does not exist
    pub fn add_relation_checked(&mut self, child: RplNode, parent: RplNode) {
        if !self
            .relations
            .iter()
            .any(|r| r.child.ip_addr == child.ip_addr)
        {
            self.relations.push(RplNodeRelation { child, parent })
        }
    }

    /// Updates the parent of a found child
    pub fn update_parent(&mut self, child: RplNode, new_parent: RplNode) {
        if let Some(rel) = self.relations.iter_mut().find(|rel| rel.child == child) {
            rel.parent = new_parent;
        }
    }

    /// Removes an existing relation
    pub fn remove_relation(&mut self, child_addr: &Ipv6Address, parent_addr: &Ipv6Address) {
        if let Some(i) = self
            .relations
            .iter()
            .enumerate()
            .find(|(_, rel)| rel.child.ip_addr == *child_addr && rel.parent.ip_addr == *parent_addr)
            .map(|(i, _)| i)
        {
            self.relations.remove(i);
        }
    }

    /// Returns the parent of a given child
    pub fn find_parent<'p>(&'p self, child_addr: &'p Ipv6Address) -> Option<&'p RplNode> {
        self.relations
            .iter()
            .find(|r| r.child.ip_addr == *child_addr)
            .map(|r| &r.parent)
    }

    /// Returns an iterator over the children of a given parent
    pub fn find_children<'p>(&'p self, parent_addr: &'p Ipv6Address) -> RplNodeRelationsIter<'p> {
        RplNodeRelationsIter {
            relations: &self.relations,
            index: 0,
            addr: parent_addr,
        }
    }

    /// Remove relations where either the child or parent are stale    
    pub fn purge(&mut self, now: Instant) {
        while let Some(i) = self
            .relations
            .iter()
            .enumerate()
            .find(|(_, rel)| rel.child.expires_at <= now || rel.parent.expires_at <= now)
            .map(|(i, _)| i)
        {
            self.relations.remove(i);
        }
    }
}

pub struct RplNodeRelationsIter<'r> {
    relations: &'r [RplNodeRelation],
    index: usize,
    addr: &'r Ipv6Address,
}

impl<'r> Iterator for RplNodeRelationsIter<'r> {
    type Item = &'r RplNode;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.relations.len() {
            let i = self.index;
            self.index += 1;

            if self.relations[i].parent.ip_addr == *self.addr {
                return Some(&self.relations[i].child);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::{RplNode, RplNodeRelation, RplNodeRelations};

    fn nodes(count: usize) -> Vec<RplNode> {
        let mut nodes = vec![];

        for i in 0..count {
            let mut ip_addr = crate::wire::ipv6::Address::default();
            ip_addr.0[0] = i as u8;
            nodes.push(RplNode {
                ip_addr,
                expires_at: crate::time::Instant::now(),
            });
        }

        nodes
    }

    #[test]
    fn add_relation() {
        let nodes = nodes(2);

        let mut relations = RplNodeRelations::default();

        relations.add_relation_checked(nodes[0], nodes[1]);
        assert_eq!(
            relations.relations[0],
            RplNodeRelation {
                child: nodes[0],
                parent: nodes[1]
            }
        );

        // Tries to add the same relation again, should not be possible
        relations.add_relation_checked(nodes[0], nodes[1]);
        assert_eq!(relations.relations.len(), 1);
    }

    #[test]
    fn update_parent() {
        let nodes = nodes(3);

        let mut relations = RplNodeRelations::default();

        relations.add_relation_checked(nodes[0], nodes[1]);

        // Tries to update the parent of an non-exitsing child, should not change anything
        relations.update_parent(nodes[2], nodes[2]);
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(
            relations.relations[0],
            RplNodeRelation {
                child: nodes[0],
                parent: nodes[1]
            }
        );

        relations.update_parent(nodes[0], nodes[2]);
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.relations[0].child, nodes[0]);
        assert_eq!(relations.relations[0].parent, nodes[2]);
    }

    #[test]
    fn remove_relation() {
        let nodes = nodes(4);

        let mut relations = RplNodeRelations::default();

        relations.add_relation_checked(nodes[0], nodes[1]);

        // Tries to remove a non-existing relation, should not do anything
        relations.remove_relation(&nodes[2].ip_addr, &nodes[3].ip_addr);
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(
            relations.relations[0],
            RplNodeRelation {
                child: nodes[0],
                parent: nodes[1]
            }
        );

        relations.remove_relation(&nodes[0].ip_addr, &nodes[1].ip_addr);
        assert_eq!(relations.relations.len(), 0);
    }

    #[test]
    fn find_parent() {
        let nodes = nodes(5);

        let mut relations = RplNodeRelations::default();

        relations.add_relation_checked(nodes[0], nodes[1]);
        relations.add_relation_checked(nodes[2], nodes[3]);

        assert_eq!(relations.find_parent(&nodes[2].ip_addr), Some(&nodes[3]));
        assert_eq!(relations.find_parent(&nodes[0].ip_addr), Some(&nodes[1]));
        assert_eq!(relations.find_parent(&nodes[4].ip_addr), None);
    }

    #[test]
    fn find_children() {
        let nodes = nodes(10);

        let mut relations = RplNodeRelations::default();

        relations.add_relation_checked(nodes[0], nodes[1]);
        relations.add_relation_checked(nodes[2], nodes[1]);
        relations.add_relation_checked(nodes[3], nodes[1]);
        relations.add_relation_checked(nodes[4], nodes[1]);

        relations.add_relation_checked(nodes[6], nodes[2]);

        // The following adds a loop in the network:
        relations.add_relation_checked(nodes[1], nodes[6]);

        assert_eq!(
            &relations
                .find_children(&nodes[1].ip_addr)
                .collect::<Vec<&RplNode>>(),
            &[&nodes[0], &nodes[2], &nodes[3], &nodes[4]]
        );

        assert_eq!(
            &relations
                .find_children(&nodes[2].ip_addr)
                .collect::<Vec<&RplNode>>(),
            &[&nodes[6]]
        );
    }

    #[test]
    fn purge() {
        let mut nodes = nodes(9);

        let mut relations = RplNodeRelations::default();

        nodes[4].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
        nodes[5].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
        nodes[6].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
        nodes[7].expires_at = crate::time::Instant::now() - crate::time::Duration::from_secs(100);
        nodes[8].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);

        relations.add_relation_checked(nodes[0], nodes[1]);
        relations.add_relation_checked(nodes[2], nodes[4]);
        relations.add_relation_checked(nodes[4], nodes[5]);
        relations.add_relation_checked(nodes[5], nodes[3]);
        relations.add_relation_checked(nodes[6], nodes[7]);
        relations.add_relation_checked(nodes[8], nodes[4]);

        relations.purge(crate::time::Instant::now());

        assert_eq!(relations.relations.len(), 2);
    }
}
