//! A trait that describes what a remote should be able to do.
//!
//! A remote is defined as something that can fetch updates
//! based on update_id. or be able to fetch entire state at any given moment

use crate::{Diff, StateMap};
use std::error::Error;

/// A Remote provides the ability to fetch diffs from a location such as a server. The implementation of this
/// trait is left to the user to decide.
pub trait Remote<K, T>: Sync + Send {
    /// Given a [`crate::StateMap`]'s hash value, it can fetch the updates from the remote that it is configured
    /// to fetch from. This trait shall return a diff to identify what values have changed and by how much.
    /// The values themselves are considered atomic and need to be transmitted with every change in state.
    fn fetch_updates(
        &self,
        update_id_current: u64,
        update_id_new: u64,
        hash: &[u8; 32],
    ) -> Result<Diff<K, T>, Box<dyn Error>>;

    /// This function ensures that the Remote holds or hosts an instance of the [`StateMap`] that we
    /// identify with
    fn init(&self, statemap: &StateMap<K, T>) -> Result<(), Box<dyn Error>>;
}

/// This trait is usually implemented by remotes that support sending or broadcasting events
/// back to the server
pub trait EventBroadcaster: Sync + Send {
    /// This function allows for streaming events to the master state map.
    fn send_event(&self, encoded_event: Vec<u8>, hash: &[u8; 32]) -> Result<(), Box<dyn Error>>;
}

/// A DummyRemote is a placeholder for cases where updates are not fetched.
/// This is usually helpful for master state maps that are updated manually by
/// the central authority.
pub struct DummyRemote;

impl<K, T> Remote<K, T> for DummyRemote {
    /// Returns a Diff with zero changes, and `from_update_id` & `upto_update_id` set to 0.
    fn fetch_updates(
        &self,
        _update_id_current: u64,
        _update_id_new: u64,
        _hash: &[u8; 32],
    ) -> Result<crate::remote::Diff<K, T>, Box<dyn std::error::Error>> {
        Ok(Diff::new([], false, 0, 0))
    }

    /// Returns `Ok(())` always without doing anything
    fn init(&self, _statemap: &StateMap<K, T>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

impl EventBroadcaster for DummyRemote {
    /// Returns `Ok(())` always without doing anything
    fn send_event(&self, _encoded_event: Vec<u8>, _hash: &[u8; 32]) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
