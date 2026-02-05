/*! Filter duplicate shows of credentials and open invitations by id
(which will typically be a Scalar).

This implementation just keeps the table of seen ids in memory, but a
production one would of course use a disk-backed database. */

use std::collections::HashSet;
use std::hash::Hash;

use serde::{Deserialize, Serialize};

/// Each instance of DupFilter maintains its own independent table of
/// seen ids. IdType will typically be Scalar.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DupFilter<IdType: Hash + Eq + Copy + Serialize> {
    seen_table: HashSet<IdType>,
}

/// A return type indicating whether the item was fresh (not previously
/// seen) or previously seen
#[derive(PartialEq, Eq, Debug)]
pub enum SeenType {
    Fresh,
    Seen,
}

impl<IdType: Hash + Eq + Copy + Serialize> DupFilter<IdType> {
    /// Check to see if the id is in the seen table, but do not add it
    /// to the seen table.  Return Seen if it is already in the table,
    /// Fresh if not.
    pub fn check(&self, id: &IdType) -> SeenType {
        if self.seen_table.contains(id) {
            SeenType::Seen
        } else {
            SeenType::Fresh
        }
    }

    /// As atomically as possible, check to see if the id is in the seen
    /// table, and add it if not.  Return Fresh if it was not already
    /// in the table, and Seen if it was.
    pub fn filter(&mut self, id: &IdType) -> SeenType {
        match self.seen_table.insert(*id) {
            true => SeenType::Fresh,
            false => SeenType::Seen,
        }
    }
}
