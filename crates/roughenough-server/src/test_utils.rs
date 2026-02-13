//!
//! Provides "glue" needed for complex testing scenarios
//!

use std::net::SocketAddr;
use std::time::Duration;

use roughenough_keys::seed::MemoryBackend;
use roughenough_merkle::{MerklePath, MerkleTree};
use roughenough_protocol::FromFrame;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{Request, RequestDraft08};
use roughenough_protocol::response::{Response, ResponseDraft08};
use roughenough_protocol::tags::{MerkleRoot, Nonce, ProtocolVersion};
use roughenough_protocol::util::ClockSource;
use roughenough_protocol::wire::ToFrame;

use crate::keysource::KeySource;
use crate::responses::ResponseHandler;

#[allow(dead_code)]
pub struct TestContext {
    pub batch_size: u8,
    pub clock: ClockSource,
    pub response_handler: ResponseHandler,
    pub key_source: KeySource,
}

/// Creates a test ResponseHandler from a fixed seed and configuration
pub fn new_response_handler() -> ResponseHandler {
    TestContext::new(64).response_handler
}

/// Creates a TestContext so the midpoints of responses can be set to arbitrary values.
impl TestContext {
    pub fn new(batch_size: u8) -> Self {
        let approx_90_days = Duration::from_secs(8_000_000);
        Self::with_key_validity(batch_size, approx_90_days)
    }

    /// Create a TestContext with a custom key validity duration.
    /// Use short durations (e.g., 60 seconds) to test key rotation scenarios.
    pub fn with_key_validity(batch_size: u8, key_validity: Duration) -> Self {
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
        let key_source = KeySource::new(
            ProtocolVersion::RfcDraft14,
            seed,
            clock.clone(),
            key_validity,
        );
        let response_handler =
            ResponseHandler::new(batch_size, key_source.clone(), ProtocolVersion::RfcDraft14);

        TestContext {
            batch_size,
            clock,
            response_handler,
            key_source,
        }
    }

    /// Force the online key to rotate. Call this after advancing the clock
    /// past the key validity period to simulate server key rotation.
    #[allow(dead_code)]
    pub fn rotate_key(&mut self) {
        self.response_handler.replace_online_key();
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair(&mut self, midpoint: u64) -> (Request, Response) {
        let (request, response, _bytes) = self.create_interaction_pair_with_bytes(midpoint);
        (request, response)
    }

    /// Create a request/response pair and return the raw response bytes.
    /// The response bytes are needed for signature verification.
    #[allow(dead_code)]
    pub fn create_interaction_pair_with_bytes(
        &mut self,
        midpoint: u64,
    ) -> (Request, Response, Vec<u8>) {
        let mut val = [0u8; 32];
        aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
        let nonce = Nonce::from(val);

        self.create_interaction_pair_with_nonce_and_bytes(midpoint, &nonce)
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair_with_nonce(
        &mut self,
        midpoint: u64,
        nonce: &Nonce,
    ) -> (Request, Response) {
        let (request, response, _bytes) =
            self.create_interaction_pair_with_nonce_and_bytes(midpoint, nonce);
        (request, response)
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair_with_nonce_and_bytes(
        &mut self,
        midpoint: u64,
        nonce: &Nonce,
    ) -> (Request, Response, Vec<u8>) {
        self.clock.set_time(midpoint);

        let request = Request::new_draft14(nonce);
        let request_bytes = request.as_frame_bytes().unwrap();
        let sock_addr = "127.0.0.1:8080".parse().unwrap();

        self.response_handler
            .add_request(&request_bytes, request.clone(), sock_addr);

        let mut responses = Vec::new();

        self.response_handler
            .process_responses(|_addr, response_bytes| {
                let bytes_copy = response_bytes.to_vec();
                let mut parse_bytes = bytes_copy.clone();
                let mut cursor = ParseCursor::new(&mut parse_bytes);
                let response = Response::from_frame(&mut cursor).unwrap();
                responses.push((response, bytes_copy));
            });
        assert_eq!(responses.len(), 1, "one response was generated");

        // Clear for next use
        self.response_handler.clear();

        let (response, response_bytes) = responses.pop().unwrap();
        (request, response, response_bytes)
    }
}

/// Draft-08 test context for generating draft-08 format responses.
///
/// Draft-08 differs from draft-14 in several ways:
/// - Merkle tree leaves are computed from just the 32-byte nonce (not the full framed request)
/// - SREP has only 3 tags: RADI, MIDP, ROOT (no VER, no VERS)
/// - Response has 6 tags: SIG, VER, PATH, SREP, CERT, INDX (no NONC, no TYPE)
#[allow(dead_code)]
pub struct Draft08TestContext {
    pub batch_size: u8,
    pub clock: ClockSource,
    pub key_source: KeySource,
    merkle_tree: MerkleTree,
    merkle_path: MerklePath,
    requests: Vec<(RequestDraft08, SocketAddr)>,
    response_buf: [u8; 1024],
}

impl Draft08TestContext {
    #[allow(dead_code)]
    pub fn new(batch_size: u8) -> Self {
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
        let approx_90_days = Duration::from_secs(8_000_000);
        let key_source = KeySource::new(
            ProtocolVersion::RfcDraft08,
            seed,
            clock.clone(),
            approx_90_days,
        );

        let mut merkle_tree = MerkleTree::new();
        merkle_tree.reserve(batch_size as usize);

        Draft08TestContext {
            batch_size,
            clock,
            key_source,
            merkle_tree,
            merkle_path: MerklePath::default(),
            requests: Vec::with_capacity(batch_size as usize),
            response_buf: [0u8; 1024],
        }
    }

    /// Add a draft-08 request to be processed.
    /// Note: Draft-08 Merkle tree uses only the nonce bytes as leaf input.
    #[allow(dead_code)]
    pub fn add_request(&mut self, request: RequestDraft08, src_addr: SocketAddr) {
        // Draft-08: Merkle leaf is just the 32-byte nonce
        self.merkle_tree.push_leaf(request.nonc().as_ref());
        self.requests.push((request, src_addr));
    }

    /// Process all requests and generate draft-08 responses.
    #[allow(dead_code)]
    pub fn process_responses<F>(&mut self, mut callback: F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        if self.requests.is_empty() {
            return;
        }

        let root_hash: [u8; 32] = self.merkle_tree.compute_root();
        let merkle_root = MerkleRoot::from(root_hash);

        let mut online_key = self.key_source.make_online_key_draft08();
        let cert = online_key.cert().clone();
        let (srep, sig) = online_key.make_srep(&merkle_root);

        let mut response_common = ResponseDraft08::default();
        response_common.set_cert(cert);
        response_common.set_srep(srep);
        response_common.set_sig(sig);

        for (index, (_request, src_addr)) in self.requests.iter().enumerate() {
            self.merkle_path.clear();
            self.merkle_tree.get_paths_to(index, &mut self.merkle_path);

            let mut response = response_common.clone();
            response.copy_path(&self.merkle_path);
            response.set_indx(index as u32);

            let mut cursor = ParseCursor::new(&mut self.response_buf);
            response
                .to_frame(&mut cursor)
                .expect("to_frame should be infallible");

            let frame_size = response.frame_size();
            callback(*src_addr, &self.response_buf[..frame_size]);
        }
    }

    /// Create a request/response pair for testing.
    #[allow(dead_code)]
    pub fn create_interaction_pair(&mut self, midpoint: u64) -> (RequestDraft08, ResponseDraft08) {
        let mut val = [0u8; 32];
        aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
        let nonce = Nonce::from(val);
        self.create_interaction_pair_with_nonce(midpoint, &nonce)
    }

    /// Create a request/response pair with a specific nonce.
    #[allow(dead_code)]
    pub fn create_interaction_pair_with_nonce(
        &mut self,
        midpoint: u64,
        nonce: &Nonce,
    ) -> (RequestDraft08, ResponseDraft08) {
        self.clock.set_time(midpoint);

        let request = RequestDraft08::new(nonce);
        let sock_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        self.add_request(request.clone(), sock_addr);

        let mut responses = Vec::new();
        self.process_responses(|_addr, response_bytes| {
            let mut bytes_copy = response_bytes.to_vec();
            let mut cursor = ParseCursor::new(&mut bytes_copy);
            let response = ResponseDraft08::from_frame(&mut cursor).unwrap();
            responses.push(response);
        });
        assert_eq!(responses.len(), 1, "one response was generated");

        // Clear for next use
        self.merkle_tree.clear();
        self.requests.clear();

        let response = responses.pop().unwrap();
        (request, response)
    }
}
