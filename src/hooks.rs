//! Trait for user defined hooks

use crate::{
    Event, StateMap,
    event::EventType,
    statemap::{StateMapKey, StateMapValue},
};
use std::{error::Error, sync::Mutex};

/// Hooks are user defined functions that recieve a [`Mutex`] over the centralized
/// [`StateMap`]. Events are of different types are called by different sorts
/// of state servers. Hooks are the only way a statemap can be modified, It is recommended
/// that the StateMap be locked at once during the start of the function if it relies
/// on changing the values based on the old value or some other value inside the statemap.
///
/// The `process_event` is the actual function tha should be implemented by a hook function.
pub trait Hook<K: StateMapKey, T: StateMapValue, E: EventType>: Send + Sync {
    fn process_event(
        &self,
        state: &Mutex<StateMap<K, T>>,
        event: &Event<E>,
    ) -> Result<(), Box<dyn Error>>;
}
