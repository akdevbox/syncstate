//! Defines a statemap along with all the trait bounds needed for the keys
//! and values associated.
//!
//! For an effective [`StateMap`], the key should implement the marker trait
//! [`StateMapKey`] and the value should implement the marker trait [`StateMapValue`].

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt::Debug,
    hash::Hash,
    sync::Arc,
};

use crate::{Diff, remote::Remote};

/// A marker trait that defines what `K` for [`StateMap<K, T>`] should be
pub trait StateMapKey:
    Hash + Eq + Clone + AsRef<[u8]> + Ord + Send + 'static + Serialize + DeserializeOwned
{
}
impl<T: Hash + Eq + Clone + AsRef<[u8]> + Ord + Send + 'static + Serialize + DeserializeOwned>
    StateMapKey for T
{
}

/// A marker trait that defines what `T` for [`StateMap<K, T>`] should be
pub trait StateMapValue:
    Clone + AsRef<[u8]> + Send + 'static + Serialize + DeserializeOwned
{
}
impl<T: Clone + AsRef<[u8]> + Send + 'static + Serialize + DeserializeOwned> StateMapValue for T {}

/// `StateMapError` can describe certain situations that might arise upon doing illegal operations
/// pushing new items to the [`StateMap`] after its frozen will trigger in [`StateMapError::Frozen`].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum StateMapError {
    #[error(
        "The StateMap is frozen, modifications to keys is not possible, only the data can be mutated using updates"
    )]
    Frozen,
    #[error(
        "The StateMap is not frozen, Please freeze the StateMap before doing any post init operations."
    )]
    Unfrozen,
    #[error("Error while trying to fetch updates: {0}")]
    FetchUpdateError(String),
    #[error("Key not found in the statemap")]
    KeyNotFound,
    #[error("Empty diff, no items in diff")]
    EmptyDiff,
    #[error("Unkown error")]
    UnknownError(String),
}

// Ability to convert dynamic error objects to our custom error type under the Unknown Category
impl From<Box<dyn Error>> for StateMapError {
    fn from(value: Box<dyn Error>) -> Self {
        Self::UnknownError(value.to_string())
    }
}

/// `StateMap` is a HashMap but it preserves order and can only take in new items
/// but not remove them. Once frozen, the `StateMap` does not allow changes and is ready to be used,
/// freezing it calculates a SHA-256 digest of the initial key values, in the process assigning
/// a unique id to the `StateMap`. Then updates can be fetched to the `StateMap` using [`StateMap::set_update_id`].
/// If the update_id is determined to be more than remote's update capacity, the remote returns a
/// full state update to bring the `StateMap` to the latest updates.
///
/// The initial state of the map is set to update index 0.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use syncstate::*;
///
/// let mut map = StateMap::new(Arc::new(DummyRemote));
/// map.push(String::from("0"), String::from("Message 0"));
/// map.push(String::from("1"), String::from("Message 1"));
/// map.push(String::from("2"), String::from("Message 2"));
///
/// // Freeze the StateMap to start streaming updates from the remote.
/// map.freeze();
///
/// // Pushing on a frozen map returns an error
/// assert_eq!(map.push(String::from("3"), String::from("Message 3")), Err(StateMapError::Frozen));
///
/// // Fetch updates upto a update id like 100, but since the diff only provides updates upto 0 (that's how DummyRemote works).
/// assert_eq!(map.set_update_id(100), Err(StateMapError::EmptyDiff), "should raise emptydiff error since dummy rmeote doesn't provide a real diff");
///
/// assert_eq!(map.get_update_id(), 0);
///
/// // Get values from the StateMap (since it maintains a copy of what the remote has)
/// assert_eq!(map.get(&String::from("0")), Some(&String::from("Message 0")));
/// assert_eq!(map.get(&String::from("3")), None);
/// ```
pub struct StateMap<K, T> {
    data: HashMap<K, T>,
    order: Vec<K>,
    update_id: u64,
    hash: Option<[u8; 32]>,
    remote: Arc<dyn Remote<K, T>>,
    is_master: bool,
    diffs: VecDeque<Diff<K, T>>, // Applied diffs
}

impl<K, T> StateMap<K, T> {
    /// Creates a new `StateMap` object given a remote.
    /// The remote should be able to fetch updates given hash and `update_id`.
    pub fn new(remote: Arc<dyn Remote<K, T>>) -> Self {
        Self {
            data: HashMap::new(),
            order: Vec::new(),
            update_id: 0,
            hash: None,
            remote,
            is_master: false,
            diffs: VecDeque::new(),
        }
    }

    /// Returns the current `update_id` of the `StateMap`, this id identifies what
    /// version or reference of the state it has stored.
    ///
    /// This is incremented as new updates are streamed. [`StateMap::set_update_id`]
    /// function lets you set the new update id (with some catch).
    pub fn get_update_id(&self) -> u64 {
        self.update_id
    }

    /// Returns weather the `StateMap` is frozen or not, indicating weather new initial values
    /// can be pushed or not.
    pub fn is_frozen(&self) -> bool {
        self.hash.is_some()
    }

    /// Sets the master flag on the state map, this can only be done when the state map is not frozen.
    ///
    /// # Errors
    /// * Returns [`StateMapError::Frozen`] if this method is called after freezing the state map.
    pub fn set_master(&mut self, is_master: bool) -> Result<(), StateMapError> {
        if self.is_frozen() {
            Err(StateMapError::Frozen)
        } else {
            self.is_master = is_master;
            Ok(())
        }
    }

    /// Returns the initial hash of the `StateMap`, call this only after having frozen the `StateMap`
    pub fn hash(&self) -> Option<&[u8; 32]> {
        self.hash.as_ref()
    }
}

impl<K: StateMapKey, T: StateMapValue> StateMap<K, T> {
    /// Add a new key-value initial state to the `StateMap`
    ///
    /// This function can only be called on a `StateMap` that is being actively built (not frozen)
    /// StateMap. ie, pre hash.
    ///
    /// # Errors
    /// * Returns [`StateMapError::Frozen`] if the `StateMap` is already frozen.
    pub fn push(&mut self, key: K, value: T) -> Result<(), StateMapError> {
        if self.hash.is_some() {
            return Err(StateMapError::Frozen);
        }

        self.data.insert(key.clone(), value);
        self.order.push(key);

        Ok(())
    }

    /// Returns a SHA-256 digest of the current data. (current implies that even if the data has been changed
    /// after freezing, the new hash is returned, to get the initial hash which is used for communication
    /// and identification, please use [`StateMap::hash()`])
    ///
    /// It is implemented as follows.
    /// * For each key, value pair in data:
    ///   * add 8 big-endian bytes based on the u64 length of key
    ///   * add the binary representation of the key
    ///   * add 8 big-endian bytes based on the u64 length of value
    ///   * add the binary representation of the value
    ///
    /// and finally, the SHA-256 hash of the above is returned as a `[u8; u32]`.
    ///
    /// The order of data in which it is added to the hasher is based on asscending order of the keys.
    /// The key is supposed to support the comparision operators hence why it can be sorted into
    /// an asscending order array.
    fn calculate_hash(&mut self) -> [u8; 32] {
        self.order.sort();
        let mut hasher = Sha256::new();
        for x in &self.order {
            let v = self
                .data
                .get(x)
                .expect("No value found for a Key, this should never happen");

            let bytelen_key = (x.as_ref().len() as u64).to_be_bytes();
            let bytelen_data = (v.as_ref().len() as u64).to_be_bytes();

            hasher.update(&bytelen_key);
            hasher.update(x);
            hasher.update(&bytelen_data);
            hasher.update(v);
        }

        hasher.finalize().into()
    }

    /// Freeze the Initial State of the `StateMap`, this also calculates a SHA-256
    /// digest of the Initial State which is guarenteed to be consistent across servers.
    ///
    /// The `StateMap` is marked as Frozen after this, implying no new keys can be added
    /// or removed. Each Init state has a unique hash which helps identify which group
    /// this `StateMap` will sync with. Calling this method initiates [`Remote::init`] method
    /// so it might make network calls.
    pub fn freeze(&mut self) -> Result<(), StateMapError> {
        if !self.hash.is_some() {
            self.hash = Some(self.calculate_hash());
            self.diffs.push_back(Diff::full_diff(self));
            self.remote.init(self)?;
        };

        Ok(())
    }

    /// Tries to set the `update_id` based on the given `update_id`, this does not allow the state
    /// to move backwards.
    ///
    /// `update_id` that is provided as an argument in itself just a suggestion. The actual update
    /// is decided by the remote that was passed on during the [`StateMap::new`] call. It internally
    /// calls [`Remote::fetch_updates`] which then returns a [`crate::Diff`], the new
    /// `update_id` is based on that.
    ///
    /// # Errors
    /// * When the `StateMap` is not frozen, returns [`StateMapError::Unfrozen`]
    /// * When there is an error fetching the updates from remote, returns [`StateMapError::FetchUpdateError`], this also contains
    ///   the appropriate context for the same.
    pub fn set_update_id(&mut self, update_id: u64) -> Result<(), StateMapError> {
        // Check if the target update id is older than our current update id
        if update_id > self.update_id {
            // Ensure that we are frozen
            if let Some(hash) = &self.hash {
                let diff = self
                    .remote
                    .fetch_updates(self.update_id, update_id, hash)
                    .map_err(|e| StateMapError::FetchUpdateError(e.to_string()))?;

                if diff.is_empty() {
                    return Err(StateMapError::EmptyDiff);
                }

                // In the rare case where we do not recieve some update ids that we need.
                if diff.from_update_id() > self.update_id {
                    return Err(StateMapError::FetchUpdateError(format!(
                        "The from update id is not consistent, diff from_update_id: {}, self update_id: {}",
                        diff.from_update_id(),
                        self.update_id
                    )));
                }

                // Set the update id and commit the diffs to state.
                self.update_id = diff.upto_update_id();
                for (k, v) in diff.get_diff() {
                    self.data.insert(k.clone(), v.clone());
                }
            } else {
                // In the case where the state map hasn't yet been frozen.
                return Err(StateMapError::Unfrozen);
            }
        }
        // Returns just Ok(()) in the case the data is updated or even in the case where update id is changed.

        Ok(())
    }

    /// A simple wrapper over [`HashMap::get`], direct access to the field is not given to protect against
    /// logical errors.
    pub fn get(&self, key: &K) -> Option<&T> {
        self.data.get(key)
    }

    /// Sets a given key to a value, but only if the key already exists.
    ///
    /// To push new keys, use [`StateMap::push`], which can be used before freezing.
    /// This method can only be used if the `StateMap` is a master map, ie, it is controlled
    /// by a central authority like a server. No client state maps should be master maps.
    /// Each call to this function increments the `update_id` and creates a diff in the history.
    /// To modify the `StateMap` in batch, see [`StateMap::begin_modification()`]
    ///
    /// # Errors
    /// * Returns [`StateMapError::Frozen`] if the map is frozen. this behaviour is overridden
    ///   if the map is master, in which case the write happens either way.
    /// * Returns [`StateMapError::KeyNotFound`] if the key is not already in the state map.
    pub fn set(&mut self, key: K, value: T) -> Result<(), StateMapError> {
        if self.data.contains_key(&key) {
            if !self.is_frozen() || self.is_master {
                assert!(
                    self.data.insert(key.clone(), value.clone()).is_some(),
                    "Set added a new key which it shouldn't have"
                );

                // Creates a new diff and update id for this
                self.update_id += 1;

                self.diffs.push_back(Diff::new(
                    [(key, value)],
                    false,
                    self.update_id - 1,
                    self.update_id,
                ));
                Ok(())
            } else {
                Err(StateMapError::Frozen)
            }
        } else {
            Err(StateMapError::KeyNotFound)
        }
    }

    /// Returns a [`StateMapModifier`] struct that holds a mutable reference to the `StateMap`
    /// that is passed into this. This is useful for batch committing changes without spamming
    /// changes to update_id. This also ensures atomic diffs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use syncstate::{StateMap, DummyRemote};
    /// use std::sync::Arc;
    ///
    /// let mut map = StateMap::new(Arc::new(DummyRemote));
    /// map.push(String::from("0"), String::from("Message 0"));
    /// map.push(String::from("1"), String::from("Message 1"));
    /// map.push(String::from("2"), String::from("Message 2"));
    ///
    /// map.set_master(true);
    /// map.freeze();
    ///
    /// let mut mods = map.begin_modification().unwrap();
    ///
    /// mods.set(String::from("1"), String::from("Modified Message 1")).unwrap()
    ///     .set(String::from("0"), String::from("Modified Message 0")).unwrap();
    /// mods.commit();
    ///
    /// ```
    ///
    /// # Errors
    /// * Returns [`StateMapError::Frozen`] if the map is frozen. this behaviour is overridden
    ///   if the map is master, in which case the write happens either way.
    /// * Underlying [`StateMapModifier::set`] might return errors for [`StateMapError::KeyNotFound`]
    pub fn begin_modification(&mut self) -> Result<StateMapModifier<'_, K, T>, StateMapError> {
        if !self.is_frozen() || self.is_master {
            Ok(StateMapModifier::new(self))
        } else {
            Err(StateMapError::Frozen)
        }
    }

    /// Generates the diff from a given update id upto the requested update id.
    ///
    /// Returns a full diff if the diffs are not available
    pub fn get_diff(&self, from_update_id: u64, upto_update_id: u64) -> Diff<K, T> {
        let mut start = 0;
        let mut end = self.diffs.len();

        // Tries to find the exact match of an from update id, if not it will return a full diff
        for (idx, x) in self.diffs.iter().enumerate() {
            if x.from_update_id() == from_update_id {
                start = idx;
                break;
            }
            if x.from_update_id() > from_update_id {
                return Diff::full_diff(self);
            }
        }

        if self
            .diffs
            .back()
            .expect("there should atleast be one diff")
            .from_update_id()
            < from_update_id
        {
            // This case shouldn't happen and indicates an error in the request, but handle it gracefully
            return Diff::full_diff(self);
        }

        // Tries to find the exact match of upto update id, if not, it will either return the diff to apply
        // updates to the latest point, or return an empty Diff for requests wanting to update backwards.
        for (idx, x) in self.diffs.iter().enumerate().rev() {
            if x.upto_update_id() == upto_update_id {
                end = idx;
                break;
            }
            if x.upto_update_id() < upto_update_id {
                return Diff::merge(self.diffs.range(start..=idx).cloned());
            }
        }

        if self
            .diffs
            .front()
            .expect("there should atleast be one diff")
            .upto_update_id()
            > upto_update_id
        {
            // Requested update expects us to update into the past which we don't have
            return Diff::empty();
        }

        // This returns an empty diff when start and end are same, ie no updates
        Diff::merge(self.diffs.range(start..=end).cloned())
    }
}

impl<'a, K, T> IntoIterator for &'a StateMap<K, T> {
    type Item = (&'a K, &'a T);
    type IntoIter = std::collections::hash_map::Iter<'a, K, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<K, T> IntoIterator for StateMap<K, T> {
    type Item = (K, T);
    type IntoIter = std::collections::hash_map::IntoIter<K, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<K, T> Debug for StateMap<K, T>
where
    K: Debug,
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateMap")
            .field("data", &self.data)
            .field("update_id", &self.update_id)
            .field("hash", &self.hash.as_ref().map(|x| hex::encode(x)))
            .field("is_master", &self.is_master)
            .field("diffs", &self.diffs)
            .finish()
    }
}

/// Wraps the [`StateMap`] in a temporary structure that doesn't commit
/// changes to the [`StateMap`]
pub struct StateMapModifier<'a, K, T> {
    statemap: &'a mut StateMap<K, T>,
    diff: HashMap<K, T>,
}

impl<'a, K: StateMapKey, T: StateMapValue> StateMapModifier<'a, K, T> {
    /// This method is hidden from the user so that to ensure that this struct is only constructed
    /// for master StateMaps.
    fn new(statemap: &'a mut StateMap<K, T>) -> Self {
        // When a mutable reference to the StateMap is acquired, it is expected that no other thread
        // has such a reference, due to rust's ownership model, we can safely assume that only one batch
        // is being created at the same time, this lets us set the update id in advance.
        Self {
            statemap,
            diff: HashMap::new(),
        }
    }

    /// Calls the underlying `HashMap`'s get method. First checks
    /// if the active `StateMapModifier` has the updated value, if not, gets the value
    /// from the `StateMap`.
    pub fn get(&self, key: &K) -> Option<&T> {
        self.diff.get(key).or_else(|| self.statemap.get(key))
    }

    /// Sets a value in the given `StateMapModifier`, this also implies that this struct is actually
    /// derived/created from a master [`StateMap`], this is ensured because there is no other way
    /// to create this struct except from [`StateMap::begin_modification()`] which ensures the condition.
    pub fn set(&mut self, key: K, value: T) -> Result<&mut Self, StateMapError> {
        if self.statemap.data.contains_key(&key) {
            self.diff.insert(key, value);
            Ok(self)
        } else {
            Err(StateMapError::KeyNotFound)
        }
    }

    /// Commits the diff to the [`StateMap`] and increments its `update_id`.
    pub fn commit(self) {
        self.statemap.update_id += 1;

        for (k, v) in &self.diff {
            assert!(
                self.statemap.data.insert(k.clone(), v.clone()).is_some(),
                "Ensure no new keys are added"
            );
        }

        self.statemap.diffs.push_back(Diff::new(
            self.diff,
            false,
            self.statemap.update_id - 1,
            self.statemap.update_id,
        ));
    }
}
