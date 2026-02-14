//! Chained multi-server measurements that detect violations of causal ordering.

use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::protocol_ver::ProtocolVersion;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::{Response, ResponseDraft08};
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::{FromFrame, ToFrame};

use crate::measurement::Measurement;
use crate::{Client, ClientError};

/// A chained multi-server sequential measurement that detects violations of causal ordering.
///
/// The first request in the sequence uses a randomly generated nonce. The second query uses
/// `H(prior_response || chaining_rand)` where `chaining_rand` is a random 32-byte value and
/// `prior_response` is the response to the first probe. Each subsequent query uses
/// `H(prior_response || chaining_rand)` for the previous response and a new 32-byte random
/// value.
///
/// For each pair of responses `(i, j)`, where `i` was received before `j`, `MIDP_i-RADI_i` is
/// confirmed to be less than or equal to `MIDP_j+RADI_j`. If all checks pass, the times are
/// consistent with causal ordering.
///
/// See also [`validate_causality`](crate::validation::ResponseValidator::validate_causality).
pub struct MeasurementSequence {
    clients: Vec<Client>,
}

impl MeasurementSequence {
    /// RFC section 10: "query at least three servers"
    pub const MIN_SERVERS: usize = 3;

    /// RFC section 8.2: "the whole sequence of servers is repeated twice"
    pub const DEFAULT_ROUNDS: usize = 2;

    /// Create a new measurement sequence with the given clients.
    ///
    /// Returns an error if fewer than [`MIN_SERVERS`](Self::MIN_SERVERS) clients are provided,
    /// as required by RFC section 10.
    pub fn new(clients: Vec<Client>) -> Result<Self, ClientError> {
        if clients.len() < Self::MIN_SERVERS {
            return Err(ClientError::InvalidConfiguration(format!(
                "measurement sequence requires at least {} servers (RFC section 10), got {}",
                Self::MIN_SERVERS,
                clients.len()
            )));
        }
        Ok(Self { clients })
    }

    /// Run chained measurements across all servers for the specified number of rounds, returning
    /// all measurements collected during the run.
    ///
    /// The returned [`Measurement`]s can be validated using [`validate_causality`](crate::validation::ResponseValidator::validate_causality).
    pub fn run(&mut self, rounds: usize) -> Result<Vec<Measurement>, ClientError> {
        for client in &self.clients {
            if client.public_key.is_none() {
                return Err(ClientError::InvalidConfiguration(format!(
                    "measurement sequence requires all servers to have public keys ('{}' missing public key)",
                    client.hostname
                )));
            }
        }

        let mut measurements = Vec::new();
        let mut prior_response: Option<Response> = None;

        for _round in 0..rounds {
            for client in &self.clients {
                let measurement = self.query(client, prior_response)?;
                prior_response = Some(measurement.response().clone());
                measurements.push(measurement);
            }
        }

        Ok(measurements)
    }

    fn query(
        &self,
        client: &Client,
        prior_response: Option<Response>,
    ) -> Result<Measurement, ClientError> {
        let (nonce, rand_value) = Self::generate_nonce(&prior_response)?;

        // Create request based on protocol version
        let request = match client.protocol_version {
            ProtocolVersion::RfcDraft08 => Request::new_draft08(&nonce),
            ProtocolVersion::RfcDraft14 => {
                let srv_commit = client.srv_commit.clone().unwrap();
                Request::new_draft14_with_server_commitment(&nonce, &srv_commit)
            }
        };

        let request_bytes = request.as_frame_bytes()?;
        let _request_bytes_count = client.transport.send(&request_bytes, client.server)?;

        let mut buf = [0u8; 1024];
        let (response_bytes_count, _addr) = client.transport.recv(&mut buf)?;
        let response_bytes = buf[..response_bytes_count].to_vec();
        let mut cursor = ParseCursor::new(&mut buf[..response_bytes_count]);

        // Parse and validate response based on protocol version
        let response = match client.protocol_version {
            ProtocolVersion::RfcDraft08 => {
                let response = ResponseDraft08::from_frame(&mut cursor)?;
                client
                    .validator
                    .validate_draft08(&request_bytes, &response, &response_bytes)?;
                Response::from(response)
            }
            ProtocolVersion::RfcDraft14 => {
                let response = Response::from_frame(&mut cursor)?;
                client
                    .validator
                    .validate_draft14(&request_bytes, &response, &response_bytes)?;
                response
            }
        };

        Measurement::builder()
            .server(client.server)
            .hostname(client.hostname.clone())
            .public_key(client.public_key)
            .request(request)
            .response(response)
            .rand_value(rand_value)
            .prior_response(prior_response.clone())
            .build()
    }

    /// If we have a prior response, then generate `H(prior_response || chaining_rand)`. Otherwise
    /// generate a random nonce.
    fn generate_nonce(
        prior_response: &Option<Response>,
    ) -> Result<(Nonce, Option<[u8; 32]>), ClientError> {
        let (nonce, rand) = if let Some(prior_response) = &prior_response {
            let rand = random_bytes::<32>();
            let nonce = calculate_chained_nonce(prior_response, &rand);

            (nonce, Some(rand))
        } else {
            let nonce = Nonce::from(random_bytes::<32>());
            (nonce, None)
        };

        Ok((nonce, rand))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn test_client(id: u8) -> Client {
        let addr: SocketAddr = format!("127.0.0.1:{}", 2000 + id as u16).parse().unwrap();
        Client::builder(addr).build()
    }

    #[test]
    fn min_servers_constant_is_three() {
        assert_eq!(MeasurementSequence::MIN_SERVERS, 3);
    }

    #[test]
    fn default_rounds_constant_is_two() {
        assert_eq!(MeasurementSequence::DEFAULT_ROUNDS, 2);
    }

    #[test]
    fn new_rejects_zero_clients() {
        let result = MeasurementSequence::new(vec![]);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("at least 3 servers"));
        assert!(err.to_string().contains("got 0"));
    }

    #[test]
    fn new_rejects_one_client() {
        let result = MeasurementSequence::new(vec![test_client(1)]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("got 1"));
    }

    #[test]
    fn new_rejects_two_clients() {
        let result = MeasurementSequence::new(vec![test_client(1), test_client(2)]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("got 2"));
    }

    #[test]
    fn new_accepts_three_clients() {
        let clients = vec![test_client(1), test_client(2), test_client(3)];
        let result = MeasurementSequence::new(clients);
        assert!(result.is_ok());
    }

    #[test]
    fn new_accepts_more_than_three_clients() {
        let clients = vec![
            test_client(1),
            test_client(2),
            test_client(3),
            test_client(4),
        ];
        let result = MeasurementSequence::new(clients);
        assert!(result.is_ok());
    }
}
