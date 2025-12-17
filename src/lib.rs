//! A global synchronization system to synchronize states across multiple locations
//! regardless of how far they are placed.
//!
//! First, a [`StateMap`] is constructed with the initial keys and their initial data.
//! This initial state should be constant for all entities that want to synchronize.
//! A hash using SHA-256 over the initial state is calculated when the `StateMap` is frozen.
//! This allows for unique identification of different `StateMap` on the server.
//!
//! One important thing to keep in mind is that the `StateMap` type used by the server
//! must have same generic paramters, essentially, the data model between the server
//! and the client should be uniform. A server can only host one concrete kind of
//! state maps. The [`Event`] type should also be uniform to ensure that the serialization
//! and deserialization of it remains consistent.
//!
//! # Concepts
//!
//! The following concepts need to be understood to be able to use this library
//!
//! * **StateMap** - This is an immutable entity with master-slave model, there is only
//!   one place that can modify its own statemap and streams updates to all slave state maps.
//!   Any requests ie events, should be sent to the server, and only the server can instruct
//!   changes to the local state map uding diffs.
//!
//!   The master state map maintains a list of diffs and update id, in a way similar to
//!   linear history in git, the slave state maps can query the master map using remotes
//!   for these diffs and updates
//! * **Diff** - This tracks all the changes across two different update ids, update ids being
//!   the counter for changes.
//!
//!   A diff contains the following fields
//!   * A vector of changes made to the state map
//!   * The update id on which the changes are to be applied to
//!   * The new update id after the changes are applied
//!   * a boolean indicating weather the diff contains the entire statemap in cases where diffs can
//!     not be recovered for old history
//! * **Remote** - Remotes take their naming inspiration from git remotes, they track a certain
//!   source for updates and changes. These remotes are also used for sending events to the main server
//!   the events are managed manually.
//! * **Hook** - A hook is provided a mutable instance of the state map along with the event
//!   that was recieved by the master state map. these hooks run only on the master state map
//!   and are the only source of modifications made to the state map. They allow for generating diffs
//!   over the state map for streaming the changes to the clients.
//!
//! # Actual Implementation
//!
//! Most of the library is agnostic of how the transport layer handles things, this library provides
//! a secure implementation over the TCP protocol, along with TLS provided by [`rustls`]. You are free
//! to implement your own transport layer, be it UnixSockets, UDP, or some other method. The core
//! functionality of the library remains consistent.
//!
//! Infact, this flexibility allows for multimodal transport layers, proxies, and other things. One thing
//! to note is that higher latency can periodically render the slave state maps out of sync for a fraction
//! of a second. There is no reliable way to have the update be recieved at the exact same time.
//!
//! The implementation present within this library is based on the idea of polling and doesn't scale well
//! and hence is mainly meant for internal use, like microservices.
//!
//! # Getting Started
//!
//! In the below example, we will show a detailed example as to how you could implement your own
//! concrete state map and event system. The below implements two threads, one running the server and one
//! running the client.
//!
//! For the sake of this example, we will use the TCP implementation provided by this library.
//!
//! ```rust
//! use syncstate::*;
//! use serde::{Serialize, Deserialize};
//!
//! use std::{sync::{Mutex, Arc}, error::Error, net::TcpListener, fmt::{self, Debug, Display}, time::Duration, thread::sleep};
//!
//! type MyMapKey = String;  // For this example, we will use String for key and value, it implements all the traits that we need
//! type MyMapValue = String;
//!
//! #[derive(Serialize, Deserialize, Debug)]
//! enum MyEvent {
//!     ChangeValue(MyMapKey, MyMapValue)
//! }
//!
//! // Due to lifetime constraints on the &Mutex inside the Hook definition, PoisonErrors can't really
//! // be returned that easily, hence we need to implement a very basic Error kind that owns the String
//! // it holds.
//! #[derive(Debug)]
//! struct MyErr(String);
//! impl Error for MyErr {}
//! impl Display for MyErr {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         write!(f, "MyErr: {}", self.0)
//!     }
//! }
//! fn conv_err<T: Debug>(err: T) -> MyErr { MyErr(format!("MyErr: {:#?}", err)) }
//!
//! struct MyHook;
//! impl Hook<MyMapKey, MyMapValue, MyEvent> for MyHook {
//!     fn process_event(&self, state: &Mutex<StateMap<MyMapKey, MyMapValue>>, event: &Event<MyEvent>) -> Result<(), Box<dyn Error>> {
//!         let mut state_lock = state.lock().map_err(conv_err)?;
//!
//!         #[allow(irrefutable_let_patterns)]
//!         if let MyEvent::ChangeValue(k, v) = &event.content {
//!             state_lock.set(k.to_owned(), v.to_owned())?;
//!         }
//!         
//!         Ok(())
//!     }
//! }
//!
//! fn server() {
//!     let listner = TcpListener::bind("127.0.0.1:12345").unwrap();
//!
//!     // WARNING: DO NOT USE THESE, THEY ARE PART OF THE PUBLIC LIBRARY, THIS SHOULD NOT BE USED IN ANY CASE
//!     let (certs, private_key) = syncstate::test_data::load_certs_and_key().unwrap();
//!
//!     // Build the server tls config
//!     let tls_config = rustls::ServerConfig::builder()
//!         .with_no_client_auth()
//!         .with_single_cert(certs, private_key)
//!         .unwrap();
//!
//!     let tls_config = Arc::new(tls_config);
//!     let password = b"HelloWorld".to_vec();
//!     
//!     // Hooks can only be set once
//!     let hooks: Arc<Vec<Box<dyn Hook<MyMapKey, MyMapValue, MyEvent>>>> = Arc::new(vec![Box::new(MyHook)]);
//!
//!     let mut state_server: tcp::TcpStateServer<MyMapKey, MyMapValue, MyEvent> = tcp::TcpStateServer::from_tcp_listner(listner, tls_config, hooks, password);
//!     
//!     // Loop
//!     loop {
//!         match state_server.accept() {
//!             Ok(response) => println!("Response sent: {response:#?}"),
//!             Err(e) => eprintln!("Error encountered: {e}"),
//!         }
//!     }
//! }
//!
//! fn client() {
//!     // WARNING: DO NOT USE THESE, THEY ARE PART OF THE PUBLIC LIBRARY, THIS SHOULD NOT BE USED IN ANY CASE
//!     let (certs, _) = syncstate::test_data::load_certs_and_key().unwrap();
//!     
//!     let mut root_store = rustls::RootCertStore::empty();
//!     for cert in &certs {
//!         root_store.add(cert.clone()).expect("Failed to add test certificates to root store");
//!     }
//!     
//!     let config = Arc::new(rustls::ClientConfig::builder()
//!         .with_root_certificates(root_store)
//!         .with_no_client_auth());
//!     let password = b"HelloWorld".to_vec();
//!
//!     let remote = Arc::new(tcp::TcpStateRemote::new("127.0.0.1:12345".parse().unwrap(), config, password));
//!     let mut map = StateMap::new(remote.clone());
//!     map.push(String::from("0"), String::from("Message 0"));
//!     map.push(String::from("1"), String::from("Message 1"));
//!     map.push(String::from("2"), String::from("Message 2"));
//!
//!     // Freeze the StateMap to initialize the state on the remote and to start the event streaming process.
//!     map.freeze();
//!
//!     // Now create an event and send it
//!     let evt = Event::new(MyEvent::ChangeValue(String::from("1"), String::from("Updated Message 1")));
//!     remote.send_event(evt.serialize().unwrap(), map.hash().expect("hash should be there after freeze")).unwrap();
//!
//!     sleep(Duration::from_millis(200));  // Ensure that the event has been processed upstream
//!
//!     map.set_update_id(10000).unwrap();  // This should fetch any updates from upstream
//!     
//!     assert_eq!(map.get(&String::from("1")), Some(&String::from("Updated Message 1")), "Message should be updated");
//!
//!     println!("client_map: {map:#?}");
//! }
//!
//! fn main() {
//!     rustls::crypto::aws_lc_rs::default_provider()
//!         .install_default()
//!         .expect("Failed to install crypto provider");
//!     std::thread::spawn(server);
//!
//!     sleep(Duration::from_millis(200));  // Ensure the server initialized itself
//!     
//!     client();  // Run the client code in main thread
//! }
//! ```

pub mod diff;
pub mod event;
pub mod hooks;
pub mod remote;
pub mod statemap;
pub mod tcp;

#[cfg(feature = "tests")]
pub mod test_data;

#[doc(inline)]
pub use statemap::{StateMap, StateMapError};

#[doc(inline)]
pub use event::Event;

#[doc(inline)]
pub use remote::{DummyRemote, EventBroadcaster, Remote};

#[doc(inline)]
pub use diff::Diff;

#[doc(inline)]
pub use hooks::Hook;
