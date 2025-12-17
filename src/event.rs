//! Event types are generics that can be transferred between the remote and
//! server. The Event type should be compatible with serde.
//!
//! Both the server and the client application should use the same [`Event<T>`]
//! for it to work without any errors

use bincode;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::fmt::Debug;

/// Any type that can be enclosed inside an Event is considered an EventType.
/// ie, any event that can be serialized and deserialized by serde.
pub trait EventType: Serialize + DeserializeOwned + Debug + Send + 'static {}
impl<T: Serialize + DeserializeOwned + Debug + Send + 'static> EventType for T {}

/// `Event` type can be transferred between different instances of applications
/// by serializing and deserializing it.
///
/// ```rust
/// use syncstate::Event;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize, Debug)]
/// enum MyEvent {
///     Ping,
///     Echo(String)
/// }
///
/// let event: Event<MyEvent> = Event::new(
///     MyEvent::Echo(String::from("Hello Event"))
/// );
///
/// // Now this can be forwarded or transported by some other layer
/// let encoded: Vec<u8> = event.serialize().unwrap();
/// ```
#[derive(Debug)]
pub struct Event<T>
where
    T: EventType,
{
    pub content: T,
}

impl<T> Event<T>
where
    T: EventType,
{
    /// Creates a new event from owned content
    pub fn new(content: T) -> Self {
        Event { content }
    }

    /// Serializes an event for it to be transported over a transport layer
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        bincode::serde::encode_to_vec(&self.content, bincode::config::standard())
            .map_err(|e| e.to_string())
    }

    /// Deserializes an event from its serialized state
    pub fn deserialize(evt: &[u8]) -> Result<Self, String> {
        Ok(Self::new(
            bincode::serde::decode_from_slice::<T, _>(evt, bincode::config::standard())
                .map_err(|e| e.to_string())?
                .0,
        ))
    }
}
