//! Defins the Diff type.

use std::collections::HashMap;

use crate::{
    StateMap,
    statemap::{StateMapKey, StateMapValue},
};

/// A `Diff` defines how to update the values in a [`crate::StateMap`]
/// [`Diff<K, T>::get_diff()`] returns a `&Vec<(K, T)>`. This defines how
/// different keys `K` values should be set in the `StateMap`.
#[derive(Debug, Clone)]
pub struct Diff<K, T> {
    diff: Vec<(K, T)>,
    is_full: bool,
    from_update_id: u64,
    upto_update_id: u64,
}

impl<K, T> Diff<K, T> {
    /// Create a new `Diff` based on a owned iterable over the Key and Values. The iterable items should be `(K, T)`.
    /// representing the type variables for [`crate::StateMap<K, T>`]. Also provides additional metadata about weather
    /// its a full state update, what updates are included in the diff and what update id does it come up to.
    pub fn new<I>(diff: I, is_full: bool, from_update_id: u64, upto_update_id: u64) -> Self
    where
        I: IntoIterator<Item = (K, T)>,
    {
        Self {
            diff: diff.into_iter().collect(),
            is_full,
            from_update_id,
            upto_update_id,
        }
    }

    /// Creates an empty diff, calling [`Diff::is_empty`] returns true on this.
    pub fn empty() -> Diff<K, T> {
        Self {
            diff: Vec::new(),
            is_full: false,
            from_update_id: 0,
            upto_update_id: 0,
        }
    }

    /// Returns a reference to the internal vector containing the actual diff
    pub fn get_diff(&self) -> &Vec<(K, T)> {
        &self.diff
    }

    /// Returns weather the thing is a full state update or not
    pub fn is_full_update(&self) -> bool {
        self.is_full
    }

    /// The initial update id of the diff
    pub fn from_update_id(&self) -> u64 {
        self.from_update_id
    }

    /// The final update id of the diff, this is supposed to be set as the new update id when the diff is applied
    /// to [`crate::StateMap`]
    pub fn upto_update_id(&self) -> u64 {
        self.upto_update_id
    }

    /// Returns weather the diff is empty or not
    pub fn is_empty(&self) -> bool {
        self.diff.is_empty()
    }
}

impl<K: StateMapKey, T: StateMapValue> Diff<K, T> {
    /// Compresses a diff by eliminating entries that modify the same key
    /// in succession. Requires the Key to be hashable for this to work
    pub fn compress(self) -> Self {
        let mut new_diff = Self {
            diff: Vec::new(),
            is_full: self.is_full,
            from_update_id: self.from_update_id,
            upto_update_id: self.upto_update_id,
        };

        let mut diff_hashmap = HashMap::new();

        for (k, v) in self.diff {
            diff_hashmap.insert(k, v);
        }

        new_diff.diff.reserve_exact(diff_hashmap.len());
        for (k, v) in diff_hashmap {
            new_diff.diff.push((k, v));
        }

        new_diff
    }

    /// Consumes an iterator of Diffs and gives out a compressed Diff
    pub fn merge<I>(iterator: I) -> Diff<K, T>
    where
        I: IntoIterator<Item = Diff<K, T>>,
    {
        let mut total_diff = HashMap::new();

        let mut min_update_id = u64::MAX;
        let mut max_update_id = u64::MIN;

        iterator.into_iter().for_each(|x| {
            min_update_id = min_update_id.min(x.from_update_id);
            max_update_id = max_update_id.max(x.upto_update_id);

            x.diff.into_iter().for_each(|x| {
                total_diff.insert(x.0, x.1);
            });
        });

        Diff::new(total_diff, false, min_update_id, max_update_id)
    }

    /// Generates a full diff from a given reference to [`StateMap`].
    pub fn full_diff(statemap: &StateMap<K, T>) -> Self {
        Diff::new(
            statemap
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned())),
            true,
            0,
            statemap.get_update_id(),
        )
    }
}
