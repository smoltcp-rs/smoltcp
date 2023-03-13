use crate::time::Instant;
use crate::wire::Ipv6Address;

use super::lollipop;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct RelationInfo {
    parent: Ipv6Address,
    expires_at: Instant,
    dao_sequence: lollipop::SequenceCounter,
}

#[derive(Debug, Default)]
pub struct RplNodeRelations {
    relations: heapless::FnvIndexMap<Ipv6Address, RelationInfo, 128>,
}

impl RplNodeRelations {
    /// Adds a new relation if it does not exist
    pub fn add_relation_checked(&mut self, child: &Ipv6Address, rel: RelationInfo) {
        if !self.relations.contains_key(child) {
            self.relations.insert(*child, rel).unwrap();
        }
    }

    /// Removes an existing relation.
    pub fn remove_relation(&mut self, child: &Ipv6Address) {
        self.relations.remove(child).unwrap();
    }

    /// Returns the parent of a given child
    pub fn find_parent(&self, child: &Ipv6Address) -> Option<Ipv6Address> {
        self.relations.get(child).map(|r| r.parent)
    }

    /// Remove relations that expired.    
    pub fn purge(&mut self, now: Instant) {
        self.relations.retain(|_, r| r.expires_at > now)
    }
}

//#[cfg(test)]
//mod tests {
//use super::{RplNode, RplNodeRelation, RplNodeRelations};

//fn nodes(count: usize) -> Vec<RplNode> {
//let mut nodes = vec![];

//for i in 0..count {
//let mut ip_addr = crate::wire::ipv6::Address::default();
//ip_addr.0[0] = i as u8;
//nodes.push(RplNode {
//ip_addr,
//expires_at: crate::time::Instant::now(),
//});
//}

//nodes
//}

//#[test]
//fn add_relation() {
//let nodes = nodes(2);

//let mut relations = RplNodeRelations::default();

//relations.add_relation_checked(nodes[0], nodes[1]);
//assert_eq!(
//relations.relations[0],
//RplNodeRelation {
//child: nodes[0],
//parent: nodes[1]
//}
//);

//// Tries to add the same relation again, should not be possible
//relations.add_relation_checked(nodes[0], nodes[1]);
//assert_eq!(relations.relations.len(), 1);
//}

//#[test]
//fn update_parent() {
//let nodes = nodes(3);

//let mut relations = RplNodeRelations::default();

//relations.add_relation_checked(nodes[0], nodes[1]);

//// Tries to update the parent of an non-exitsing child, should not change anything
//relations.update_parent(nodes[2], nodes[2]);
//assert_eq!(relations.relations.len(), 1);
//assert_eq!(
//relations.relations[0],
//RplNodeRelation {
//child: nodes[0],
//parent: nodes[1]
//}
//);

//relations.update_parent(nodes[0], nodes[2]);
//assert_eq!(relations.relations.len(), 1);
//assert_eq!(relations.relations[0].child, nodes[0]);
//assert_eq!(relations.relations[0].parent, nodes[2]);
//}

//#[test]
//fn remove_relation() {
//let nodes = nodes(4);

//let mut relations = RplNodeRelations::default();

//relations.add_relation_checked(nodes[0], nodes[1]);

//// Tries to remove a non-existing relation, should not do anything
//relations.remove_relation(&nodes[2].ip_addr, &nodes[3].ip_addr);
//assert_eq!(relations.relations.len(), 1);
//assert_eq!(
//relations.relations[0],
//RplNodeRelation {
//child: nodes[0],
//parent: nodes[1]
//}
//);

//relations.remove_relation(&nodes[0].ip_addr, &nodes[1].ip_addr);
//assert_eq!(relations.relations.len(), 0);
//}

//#[test]
//fn find_parent() {
//let nodes = nodes(5);

//let mut relations = RplNodeRelations::default();

//relations.add_relation_checked(nodes[0], nodes[1]);
//relations.add_relation_checked(nodes[2], nodes[3]);

//assert_eq!(relations.find_parent(&nodes[2].ip_addr), Some(&nodes[3]));
//assert_eq!(relations.find_parent(&nodes[0].ip_addr), Some(&nodes[1]));
//assert_eq!(relations.find_parent(&nodes[4].ip_addr), None);
//}

//#[test]
//fn find_children() {
//let nodes = nodes(10);

//let mut relations = RplNodeRelations::default();

//relations.add_relation_checked(nodes[0], nodes[1]);
//relations.add_relation_checked(nodes[2], nodes[1]);
//relations.add_relation_checked(nodes[3], nodes[1]);
//relations.add_relation_checked(nodes[4], nodes[1]);

//relations.add_relation_checked(nodes[6], nodes[2]);

//// The following adds a loop in the network:
//relations.add_relation_checked(nodes[1], nodes[6]);

//assert_eq!(
//&relations
//.find_children(&nodes[1].ip_addr)
//.collect::<Vec<&RplNode>>(),
//&[&nodes[0], &nodes[2], &nodes[3], &nodes[4]]
//);

//assert_eq!(
//&relations
//.find_children(&nodes[2].ip_addr)
//.collect::<Vec<&RplNode>>(),
//&[&nodes[6]]
//);
//}

//#[test]
//fn purge() {
//let mut nodes = nodes(9);

//let mut relations = RplNodeRelations::default();

//nodes[4].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
//nodes[5].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
//nodes[6].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);
//nodes[7].expires_at = crate::time::Instant::now() - crate::time::Duration::from_secs(100);
//nodes[8].expires_at = crate::time::Instant::now() + crate::time::Duration::from_secs(100);

//relations.add_relation_checked(nodes[0], nodes[1]);
//relations.add_relation_checked(nodes[2], nodes[4]);
//relations.add_relation_checked(nodes[4], nodes[5]);
//relations.add_relation_checked(nodes[5], nodes[3]);
//relations.add_relation_checked(nodes[6], nodes[7]);
//relations.add_relation_checked(nodes[8], nodes[4]);

//relations.purge(crate::time::Instant::now());

//assert_eq!(relations.relations.len(), 2);
//}
//}
