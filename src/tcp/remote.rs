use crate::{
    Diff, EventBroadcaster, Remote,
    statemap::{StateMapKey, StateMapValue},
    tcp::{TcpStateServerRequest, TcpStateServerRequestWrapper, TcpStateServerResponse},
};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

/// This error type is used for custom Errors that need to be fit inside
/// `Box<dyn Error>`.
///
/// Usually returned when the response from the TcpStateServer is unexpected
#[derive(thiserror::Error, Debug)]
pub enum BasicError {
    #[error("Err: ")]
    Unknown(String),
}

/// A Remote that can be used with [`crate::StateMap`], allows fetching of updates
/// from a central [`crate::tcp::TcpStateServer`].
///
/// This requries an address to the server as well as [`rustls::ClientConfig`] to setup
/// TLS, the password is part of the `TcpStateServer`'s authentication mechanism and is
/// transferred over the TLS wrapped socket.
pub struct TcpStateRemote {
    pub address: SocketAddr,
    tls_config: Arc<rustls::ClientConfig>,
    password: Vec<u8>,
}

impl TcpStateRemote {
    /// Create a new remote connection to the specified address
    ///
    /// Requires you to provide a [`rustls::ClientConfig`] and `password` for authentication.
    /// No connection or network request is sent out unless either of the methods are called first.
    pub fn new(address: SocketAddr, tls_config: Arc<ClientConfig>, password: Vec<u8>) -> Self {
        Self {
            address,
            tls_config,
            password,
        }
    }

    fn establish_stream(
        &self,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(self.address)?;

        Ok(StreamOwned::new(
            ClientConnection::new(self.tls_config.clone(), self.address.ip().into())?,
            stream,
        ))
    }

    fn send_request(
        &self,
        request: TcpStateServerRequest,
    ) -> Result<TcpStateServerResponse, Box<dyn std::error::Error>> {
        let mut stream = self.establish_stream()?;

        let wrapper = TcpStateServerRequestWrapper {
            password: self.password.to_owned(),
            event: request,
        };

        let req_buffer = bincode::serde::encode_to_vec(wrapper, bincode::config::standard())?;
        stream.write(&(req_buffer.len() as u32).to_be_bytes())?;
        stream.write(&req_buffer)?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = (u32::from_be_bytes(len_buf)) as usize;

        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer)?;

        let resp: TcpStateServerResponse =
            bincode::serde::decode_from_slice(&buffer, bincode::config::standard())?.0;

        Ok(resp)
    }
}

impl<K: StateMapKey, T: StateMapValue> Remote<K, T> for TcpStateRemote {
    fn fetch_updates(
        &self,
        update_id_current: u64,
        update_id_new: u64,
        hash: &[u8; 32],
    ) -> Result<crate::Diff<K, T>, Box<dyn std::error::Error>> {
        let req = TcpStateServerRequest::GetDiff {
            hash: hash.to_owned(),
            from_update_id: update_id_current,
            upto_update_id: update_id_new,
        };

        let resp = self.send_request(req)?;
        if let TcpStateServerResponse::Diff {
            from_update_id,
            upto_update_id,
            is_full,
            encoded_diff,
        } = resp
        {
            let diff: Vec<(K, T)> =
                bincode::serde::decode_from_slice(&encoded_diff, bincode::config::standard())?.0;
            Ok(Diff::new(diff, is_full, from_update_id, upto_update_id))
        } else {
            // In the case the response was not a diff
            Err(Box::new(BasicError::Unknown(format!(
                "Expected Diff as response, recieved: {:#?}",
                resp
            ))))
        }
    }

    fn init(&self, statemap: &crate::StateMap<K, T>) -> Result<(), Box<dyn std::error::Error>> {
        let hash = statemap
            .hash()
            .expect("Expected the statemap to be frozen before init was called on remote")
            .to_owned();

        let resp = self.send_request(TcpStateServerRequest::GetUpdateId { hash: hash.clone() })?;

        if let TcpStateServerResponse::HashNotFound = &resp {
            let init_resp = self.send_request(TcpStateServerRequest::Init {
                hash: hash.clone(),
                init_data: bincode::serde::encode_to_vec(
                    statemap
                        .into_iter()
                        .map(|x| (x.0.clone(), x.1.clone()))
                        .collect::<HashMap<K, T>>(),
                    bincode::config::standard(),
                )?,
            })?;

            if let TcpStateServerResponse::InitSuccess = init_resp {
                // Init succeeded
            } else {
                return Err(Box::new(BasicError::Unknown(format!(
                    "Initialization response is not success: {:#?}",
                    init_resp
                ))));
            }
        }

        Ok(())
    }
}

impl EventBroadcaster for TcpStateRemote {
    fn send_event(
        &self,
        encoded_event: Vec<u8>,
        hash: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self.send_request(TcpStateServerRequest::Event {
            hash: hash.to_owned(),
            evt_data: encoded_event,
        })?;

        if let TcpStateServerResponse::EventInProcess = resp {
            Ok(())
        } else {
            Err(Box::new(BasicError::Unknown(format!(
                "Unknown error: {:#?}",
                resp
            ))))
        }
    }
}
