use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle, sleep},
    time::Duration,
};
use tracing::{error, info};

use crate::{
    DummyRemote, Event, Hook, InitHook, StateMap, StateMapError,
    event::EventType,
    statemap::{StateMapKey, StateMapValue},
    tcp::TcpStateServerResponse,
};

use super::{TcpStateServerRequest, TcpStateServerRequestWrapper};

/// All errors associated with TcpStateServer
#[derive(thiserror::Error, Debug)]
pub enum TcpStateServerError {
    #[error("IO Error")]
    IoError(#[from] io::Error),
    #[error("RustLs Error")]
    RustlsError(#[from] rustls::Error),
    #[error("Decode Error")]
    DecodeError(#[from] bincode::error::DecodeError),
    #[error("Encode Error")]
    EncodeError(#[from] bincode::error::EncodeError),
    #[error("Mutex Poisoned Error: {0}")]
    MutexPoisonError(String),
    #[error("Unknown Error: {0}")]
    UnknownError(String),
    #[error("StateMapError Error: {0}")]
    StateMapError(#[from] StateMapError),
}

///  A small helper function to convert errors to MutexPoisonError
fn to_mutex_poison_err<T: ToString>(v: T) -> TcpStateServerError {
    TcpStateServerError::MutexPoisonError(v.to_string())
}

///  A small helper function to convert errors to UnknownError
fn to_unknown_err<T: ToString>(v: T) -> TcpStateServerError {
    TcpStateServerError::UnknownError(v.to_string())
}

pub type HooksVec<K, T, E> = Arc<Vec<Box<dyn Hook<K, T, E>>>>;
pub type InitHooksVec<K, T> = Arc<Vec<Box<dyn InitHook<K, T>>>>;

/// A TCP protocol based state server.
/// TLS is mandatory and provided by rustls.
///
/// It is assumed that the statemaps are being handled by trusted entities
/// ie, they can create as many statemaps as they want using different hashes.
/// This server implementation is not public facing and does not disallow creation
/// of new statemaps.
///
/// You can modify the `serv` field to change hot-swap the tcp listener socket
///
/// # Example
///
/// ```rust
/// use syncstate::tcp::TcpStateServer;
/// use std::net::TcpListener;
/// use std::sync::Arc;
///
/// #[derive(serde::Serialize, serde::Deserialize, Debug)]
/// enum EventType {
///     Hello,
///     Echo(String)
/// }
///
/// let listner = TcpListener::bind("127.0.0.1:1234").unwrap();
///
/// // WARNING: DO NOT USE THESE, THEY ARE PART OF THE PUBLIC LIBRARY, THIS SHOULD NOT BE USED IN ANY CASE
/// let (certs, private_key) = syncstate::test_data::load_certs_and_key().unwrap();
///
/// // Build the server tls config
/// let tls_config = rustls::ServerConfig::builder()
///     .with_no_client_auth()
///     .with_single_cert(certs, private_key)
///     .unwrap();
///
/// let tls_config = Arc::new(tls_config);
/// let password = b"HelloWorld".to_vec();
///     
/// // Hooks can only be set once
/// let hooks = Arc::new(Vec::new());
///
/// let state_server: TcpStateServer<String, String, EventType> = TcpStateServer::from_tcp_listner(listner, tls_config, hooks, password);
/// ```
pub struct TcpStateServer<K, T, E> {
    /// Hot swappable, you can change the socket whenever you'd like
    pub serv: TcpListener,

    statemaps: HashMap<[u8; 32], Arc<Mutex<StateMap<K, T>>>>,
    hooks: HooksVec<K, T, E>,
    init_hooks: InitHooksVec<K, T>,
    tls_config: Arc<rustls::ServerConfig>,
    password: Vec<u8>,
    processed_hashes: HashSet<[u8; 32]>, // any hashes that are in between init phase are also added here
}

impl<K, T, E> TcpStateServer<K, T, E>
where
    K: StateMapKey,
    T: StateMapValue,
    E: EventType,
{
    /// Create a new `TcpStateServer` from an existing [`std::net::TcpListener`] and TLS config ([`rustls::ServerConfig`])
    ///
    /// Look at the example provided to figure out a minimal configuration
    pub fn from_tcp_listner(
        listner: TcpListener,
        tls_config: Arc<ServerConfig>,
        hooks: HooksVec<K, T, E>,
        password: Vec<u8>,
    ) -> Self {
        Self {
            serv: listner,
            statemaps: HashMap::new(),
            hooks,
            init_hooks: Arc::new(Vec::new()),
            tls_config,
            password,
            processed_hashes: HashSet::new(),
        }
    }

    /// By default no init hooks are present, use this function to set a vector of init hooks that will
    /// be run on any initialization of new state maps that are created after calling this.
    pub fn set_init_hooks(&mut self, init_hooks: InitHooksVec<K, T>) {
        self.init_hooks = init_hooks;
    }

    /// Helper function to create a buffer
    fn new_buffer() -> Vec<u8> {
        vec![0u8; 100_000]
    }

    /// Takes an owned TcpStateServer and starts a multi threaded server on it, this function
    /// keeps accepting requests and processes them in individual threads. if you want to do
    /// custom behaviours and custom error handling, you can look at [`TcpStateServer::handle_stream`]
    /// (it contains the logic to handle a `TcpStream` and returns a `std::thread::JoinHandle`)
    pub fn start_server(self) -> Result<(), TcpStateServerError> {
        let sock = self.serv.try_clone()?;
        let server = Arc::new(Mutex::new(self));
        loop {
            let (stream, addr) = match sock.accept() {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Error encountered when accepting a connection on socket: {sock:?}, error: {e}"
                    );
                    continue;
                }
            };

            info!("Accepted connection from {addr}");

            Self::handle_stream(server.clone(), stream);
        }
    }

    /// Handles an existing freshly accepted TcpStream and negotiates a TLS handshake on,
    /// and then finally streams the Event from the socket, after which all the Hooks
    /// are run.
    ///
    /// Returns a `JoinHandle<Result<TcpStateServerResponse, TcpStateServerError>>` which
    /// is a handle on the thread spawned by this method. The handle might never return
    /// if its a request to stream updates, so it is generally advised to use this handle
    /// to kill ongoing requests rather than to check up on the response.
    ///
    /// This can accept a multitude of requests based on [`TcpStateServerRequestWrapper`].
    /// Writes back the response by first encoding the length using u32be and then
    /// bincode serialized [`TcpStateServerResponse`]
    ///
    /// # Errors
    /// * returns [`TcpStateServerError::IoError`] for any IO related errors including TLS errors.
    /// * returns [`TcpStateServerError::DecodeError`] if unable to deserialize the request using bincode
    /// * returns [`TcpStateServerError::EncodeError`] in cases where it is unable to serialize the response,
    ///   this case should never really happen so if it does, please report this as a bug.
    /// * any [`rustls::Error`] is returned as [`TcpStateServerError::RustlsError`]
    /// * if there are errors pertaining to `Mutex`, [`TcpStateServerError::MutexPoisonError`] is returned
    pub fn handle_stream(
        server: Arc<Mutex<Self>>,
        stream: TcpStream,
    ) -> JoinHandle<Result<TcpStateServerResponse, TcpStateServerError>> {
        // Form the stream and TLS wrapper around it

        thread::spawn(move || {
            let server_lock = server.lock().map_err(to_mutex_poison_err)?;

            let tls_config_arc = server_lock.tls_config.clone();
            let server_password_clone = server_lock.password.clone();

            drop(server_lock); // Drop the lock after copying essential values.

            let mut stream = StreamOwned::new(ServerConnection::new(tls_config_arc)?, stream);

            // We send and recieve data in a length-prefixed manner, get the length of
            // te payload as a big-endian u32.
            let mut len_buffer = [0u8; 4];
            stream.read_exact(&mut len_buffer)?;
            let len = u32::from_be_bytes(len_buffer) as usize;

            // Resize the buffer for anticipated length and read into it
            let mut buffer = Self::new_buffer();

            buffer.resize(len, 0);
            stream.read_exact(&mut buffer)?;

            let req: TcpStateServerRequestWrapper =
                bincode::serde::decode_from_slice(&buffer, bincode::config::standard())?.0;

            // Password checking
            if server_password_clone != req.password {
                sleep(Duration::from_micros(rand::random_range(100..100000)));

                let resp_buffer = bincode::serde::encode_to_vec(
                    TcpStateServerResponse::IncorrectPassword,
                    bincode::config::standard(),
                )?;

                let _ = stream.write(&(resp_buffer.len() as u32).to_be_bytes())?;
                let _ = stream.write(&resp_buffer)?;
                drop(stream); // This line is redundant but added for the sake of it. We absolutely do not want to proceed when the verification fails
                return Ok(TcpStateServerResponse::IncorrectPassword);
            }

            // Process the request appropriately from this point forward
            let resp = Self::process_request(server, req.event)?;
            let resp_buffer = bincode::serde::encode_to_vec(&resp, bincode::config::standard())?;

            let _ = stream.write(&(resp_buffer.len() as u32).to_be_bytes())?;
            let _ = stream.write(&resp_buffer)?;

            Ok(resp)
        })
    }

    /// Usually not called directly, this function processes a [`TcpStateServerRequest`] and returns appropriately to
    /// work alongside [`TcpStateServer::accept`]. Please use the afformentioned function instead.
    ///
    /// This function runs a match statement and processes all sorts of events that it can proces
    fn process_request(
        server: Arc<Mutex<Self>>,
        request: TcpStateServerRequest,
    ) -> Result<TcpStateServerResponse, TcpStateServerError> {
        let mut server_lock = server.lock().map_err(to_mutex_poison_err)?;

        match request {
            TcpStateServerRequest::GetUpdateId { hash } => {
                if let Some(v) = server_lock.statemaps.get(&hash) {
                    Ok(TcpStateServerResponse::UpdateId {
                        update_id: v.lock().map_err(to_mutex_poison_err)?.get_update_id(),
                    })
                } else {
                    Ok(TcpStateServerResponse::HashNotFound)
                }
            }
            TcpStateServerRequest::Event { hash, evt_data } => {
                if let Some(v) = server_lock.statemaps.get(&hash) {
                    let event: Event<E> = Event::deserialize(&evt_data).map_err(to_unknown_err)?;
                    // This point forward we run the hooks in threads
                    let hooks_arc = server_lock.hooks.clone();
                    let statemap_arc = v.clone();

                    thread::spawn(move || {
                        let statemap_arc = statemap_arc;

                        info!("Processing event: {:?}", event);
                        for x in hooks_arc.iter() {
                            if let Err(e) = x.process_event(&statemap_arc, &event) {
                                error!("Error processing hook: {e}");
                            }
                        }
                    });

                    Ok(TcpStateServerResponse::EventInProcess)
                } else {
                    Ok(TcpStateServerResponse::HashNotFound)
                }
            }
            TcpStateServerRequest::GetDiff {
                hash,
                from_update_id,
                upto_update_id,
            } => {
                if let Some(v) = server_lock.statemaps.get(&hash) {
                    let diff = v
                        .lock()
                        .map_err(to_mutex_poison_err)?
                        .get_diff(from_update_id, upto_update_id);

                    Ok(TcpStateServerResponse::Diff {
                        from_update_id: diff.from_update_id(),
                        upto_update_id: diff.upto_update_id(),
                        is_full: diff.is_full_update(),
                        encoded_diff: bincode::serde::encode_to_vec(
                            diff.get_diff(),
                            bincode::config::standard(),
                        )?,
                    })
                } else {
                    Ok(TcpStateServerResponse::HashNotFound)
                }
            }
            TcpStateServerRequest::Init { hash, init_data } => {
                if server_lock.statemaps.contains_key(&hash) {
                    Ok(TcpStateServerResponse::InitSuccess)
                } else {
                    let init_hooks = server_lock.init_hooks.clone();
                    if !server_lock.processed_hashes.insert(hash) {
                        // Server already processed this hash
                        return Ok(TcpStateServerResponse::InitSuccess);
                    }

                    drop(server_lock);

                    let mut stmap = StateMap::new(Arc::new(DummyRemote));
                    let raw_map: HashMap<K, T> =
                        bincode::serde::decode_from_slice(&init_data, bincode::config::standard())
                            .inspect_err(|_| {
                                // This ugly looking function is simply to ensure that the server removes the specific hash from processed hashes
                                // before erroring out.
                                if let Ok(mut server_lock) = server.lock() {
                                    server_lock.processed_hashes.remove(&hash);
                                }
                            })?
                            .0;

                    for (k, v) in raw_map {
                        stmap
                            .push(k, v)
                            .expect("state map should not be frozen at this point");
                    }

                    stmap
                        .set_master(true)
                        .expect("state map should not yet be frozen when setting master to true");

                    stmap.freeze().inspect_err(|_| {
                        // This ugly looking function is simply to ensure that the server removes the specific hash from processed hashes
                        // before erroring out.
                        if let Ok(mut server_lock) = server.lock() {
                            server_lock.processed_hashes.remove(&hash);
                        }
                    })?;

                    if stmap.hash().unwrap() != &hash {
                        Ok(TcpStateServerResponse::HashMismatch)
                    } else {
                        let stmap_arc = Arc::new(Mutex::new(stmap));

                        // Run init hooks
                        for hook in init_hooks.iter() {
                            if let Err(e) = hook.process_init(stmap_arc.clone()) {
                                error!("Init hook errored out: {e}");

                                // Also ensure that the hash is removed from processing
                                if let Ok(mut server_lock) = server.lock() {
                                    server_lock.processed_hashes.remove(&hash);
                                }

                                return Ok(TcpStateServerResponse::InitFailure {
                                    error_message: e.to_string(),
                                });
                            }
                        }

                        // If all init hooks go successfully
                        let mut server_lock = server.lock().map_err(to_mutex_poison_err)?;
                        server_lock.statemaps.insert(hash, stmap_arc.clone());
                        server_lock.processed_hashes.remove(&hash);

                        Ok(TcpStateServerResponse::InitSuccess)
                    }
                }
            }
        }
    }
}
