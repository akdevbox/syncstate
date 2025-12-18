//! A TCP implementation of the master-slave model of [`crate::StateMap`]
mod remote;
mod server;

#[doc(inline)]
pub use server::{TcpStateServer, TcpStateServerError};

#[doc(inline)]
pub use remote::TcpStateRemote;

/// `TcpStateServerRequest` defines the serializable events that are sent over
/// the network to the [`TcpStateServer`]. (Note: The actual struct being
/// sent is [`TcpStateServerRequestWrapper`])
///
/// All fields tagged as hash are not actual data hash but instead the hash
/// that identifies a [`crate::StateMap`], these hash values can be obtained
/// from the state map after its frozen using [`crate::StateMap::hash()`]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum TcpStateServerRequest {
    /// Requests the server for the current update id
    GetUpdateId { hash: [u8; 32] },

    /// Contains the serialized form of an event
    Event { hash: [u8; 32], evt_data: Vec<u8> },

    /// Requests the server to create a StateMap Diff
    GetDiff {
        hash: [u8; 32],
        from_update_id: u64,
        upto_update_id: u64,
    },

    /// Contains bincode serialized data of `HashMap<K, T>` for a `StateMap<K, T>`
    Init { hash: [u8; 32], init_data: Vec<u8> },
}

/// Wraps [`TcpStateServerRequest`] with other important things specific to security.
///
/// * password (This is a `Vec<u8>` sequence of bytes that is then verified by the server, its a pre-shared key)
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TcpStateServerRequestWrapper {
    password: Vec<u8>,
    event: TcpStateServerRequest,
}

/// All the different responses that the Tcp Server can return
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum TcpStateServerResponse {
    IncorrectPassword,
    UpdateId {
        update_id: u64,
    },
    HashNotFound,
    EventInProcess,
    InitSuccess,
    HashMismatch,
    Diff {
        from_update_id: u64,
        upto_update_id: u64,
        is_full: bool,
        /// The encoded diff is serialized form of Vec<(K, T)>
        encoded_diff: Vec<u8>,
    },
    InitFailure {
        error_message: String,
    },
}
