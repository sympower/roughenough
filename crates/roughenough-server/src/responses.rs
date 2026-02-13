use std::net::SocketAddr;

use roughenough_keys::online::onlinekey::{OnlineKeyDraft08, OnlineKeyDraft14};
use roughenough_merkle::{MerklePath, MerkleTree};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::protocol_ver::ProtocolVersion;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::{Response, ResponseDraft08};
use roughenough_protocol::tags::{MerkleRoot, PublicKey};
use roughenough_protocol::wire::ToFrame;

use crate::keysource::KeySource;
use crate::metrics::types::ResponseMetrics;

#[derive(Debug)]
pub struct PendingRequest {
    request: Request,
    src_addr: SocketAddr,
}

enum OnlineKey {
    Draft14(OnlineKeyDraft14),
    Draft08(OnlineKeyDraft08),
}

pub struct ResponseHandler {
    batch_size: usize,
    merkle_tree: MerkleTree,
    merkle_path: MerklePath,
    key_source: KeySource,
    online_key: OnlineKey,
    response_metrics: ResponseMetrics,
    requests: Vec<PendingRequest>,
    response_buf: [u8; 1024],
    protocol_version: ProtocolVersion,
}

impl ResponseHandler {
    pub fn new(batch_size: u8, key_source: KeySource, protocol_version: ProtocolVersion) -> Self {
        let batch_size = batch_size as usize;
        let online_key = match protocol_version {
            ProtocolVersion::RfcDraft08 => OnlineKey::Draft08(key_source.make_online_key_draft08()),
            ProtocolVersion::RfcDraft14 => OnlineKey::Draft14(key_source.make_online_key_draft14()),
        };
        let mut merkle_tree = MerkleTree::new();

        merkle_tree.reserve(batch_size);

        Self {
            batch_size,
            merkle_tree,
            key_source,
            online_key,
            merkle_path: MerklePath::default(),
            response_metrics: ResponseMetrics::default(),
            requests: Vec::with_capacity(batch_size),
            response_buf: [0u8; 1024],
            protocol_version,
        }
    }

    pub fn add_request(&mut self, request_bytes: &[u8], request: Request, src_addr: SocketAddr) {
        debug_assert!(self.requests.len() < self.batch_size, "Batch size exceeded");

        // Draft-08 uses only the 32-byte nonce as the merkle leaf, while draft-14 uses
        // the full framed request. See RFC section 5.3 for details.
        match self.protocol_version {
            ProtocolVersion::RfcDraft08 => {
                self.merkle_tree.push_leaf(request.nonc().as_ref());
            }
            ProtocolVersion::RfcDraft14 => {
                self.merkle_tree.push_leaf(request_bytes);
            }
        }
        self.requests.push(PendingRequest { request, src_addr })
    }

    pub fn replace_online_key(&mut self) {
        self.online_key = match self.protocol_version {
            ProtocolVersion::RfcDraft08 => {
                OnlineKey::Draft08(self.key_source.make_online_key_draft08())
            }
            ProtocolVersion::RfcDraft14 => {
                OnlineKey::Draft14(self.key_source.make_online_key_draft14())
            }
        };
    }

    /// Process all responses. `callback` receives each response as a borrowed slice that's
    /// valid only during the callback.
    pub fn process_responses<F>(&mut self, mut callback: F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        if self.requests.is_empty() {
            return;
        }

        self.response_metrics
            .add_batch_size(self.requests.len() as u8);

        let root_hash: [u8; 32] = self.merkle_tree.compute_root();
        let merkle_root = MerkleRoot::from(root_hash);

        match self.protocol_version {
            ProtocolVersion::RfcDraft08 => {
                self.process_responses_draft08(&merkle_root, &mut callback)
            }
            ProtocolVersion::RfcDraft14 => {
                self.process_responses_draft14(&merkle_root, &mut callback)
            }
        }
    }

    fn process_responses_draft14<F>(&mut self, merkle_root: &MerkleRoot, callback: &mut F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        let OnlineKey::Draft14(ref mut key) = self.online_key else {
            panic!("process_responses_draft14 called with non-draft14 key");
        };

        // Tags that are common to all responses in this batch
        let cert = key.cert().clone();
        let (srep, sig) = key.make_srep(merkle_root);
        let mut response_common = Response::default();
        response_common.set_cert(cert);
        response_common.set_srep(srep);
        response_common.set_sig(sig);

        for (index, pending_req) in self.requests.iter().enumerate() {
            self.merkle_path.clear();
            self.merkle_tree.get_paths_to(index, &mut self.merkle_path);

            let mut response = response_common.clone();
            response.copy_path(&self.merkle_path);
            response.set_nonc(*pending_req.request.nonc());
            response.set_indx(index as u32);

            let mut cursor = ParseCursor::new(&mut self.response_buf);
            response
                .to_frame(&mut cursor)
                .expect("to_frame(ParseCursor) should be infallible");

            let frame_size = response.frame_size();
            self.response_metrics.add_bytes_sent(frame_size);

            callback(pending_req.src_addr, &self.response_buf[..frame_size]);
        }
    }

    fn process_responses_draft08<F>(&mut self, merkle_root: &MerkleRoot, callback: &mut F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        let OnlineKey::Draft08(ref mut key) = self.online_key else {
            panic!("process_responses_draft08 called with non-draft08 key");
        };

        // Tags that are common to all responses in this batch
        let cert = key.cert().clone();
        let (srep, sig) = key.make_srep(merkle_root);
        let mut response_common = ResponseDraft08::default();
        response_common.set_cert(cert);
        response_common.set_srep(srep);
        response_common.set_sig(sig);

        for (index, pending_req) in self.requests.iter().enumerate() {
            self.merkle_path.clear();
            self.merkle_tree.get_paths_to(index, &mut self.merkle_path);

            let mut response = response_common.clone();
            response.copy_path(&self.merkle_path);
            response.set_indx(index as u32);

            let mut cursor = ParseCursor::new(&mut self.response_buf);
            response
                .to_frame(&mut cursor)
                .expect("to_frame(ParseCursor) should be infallible");

            let frame_size = response.frame_size();
            self.response_metrics.add_bytes_sent(frame_size);

            callback(pending_req.src_addr, &self.response_buf[..frame_size]);
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match &self.online_key {
            OnlineKey::Draft14(key) => key.public_key(),
            OnlineKey::Draft08(key) => key.public_key(),
        }
    }

    pub fn clear(&mut self) {
        self.merkle_tree.clear();
        self.requests.clear();
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn metrics(&self) -> ResponseMetrics {
        self.response_metrics.clone()
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn reset_metrics(&mut self) {
        self.response_metrics.reset_metrics();
    }

    #[cfg(test)]
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    #[cfg(test)]
    pub fn num_pending(&self) -> usize {
        self.requests.len()
    }
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::cursor::ParseCursor;
    use roughenough_protocol::request::Request;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::{FromWire, ToWire};

    use super::*;
    use crate::test_utils::new_response_handler;

    fn create_test_request(nonce_value: u8) -> Request {
        let nonce = Nonce::from([nonce_value; 32]);
        Request::new_draft14(&nonce)
    }

    #[test]
    fn clear_state() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Add a request
        let request = create_test_request(42);
        responder.add_request(&request.as_bytes().unwrap(), request, addr);

        assert_eq!(responder.num_pending(), 1);
        assert!(!responder.merkle_tree().is_empty());

        responder.clear();

        assert_eq!(responder.num_pending(), 0);
        assert!(responder.merkle_tree().is_empty());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn batch_size_limit_exceeded_panics() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Add requests up to batch size
        for i in 0..64 {
            let request = create_test_request(i as u8);
            responder.add_request(&request.as_bytes().unwrap(), request, addr);
        }

        assert_eq!(responder.num_pending(), 64);

        // This should trigger the batch size limit debug assertion in add_request
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let request = create_test_request(100);
            responder.add_request(&request.as_bytes().unwrap(), request, addr);
        }));

        assert!(result.is_err(), "Should panic when batch size is exceeded");
    }

    #[test]
    fn single_request_response_roundtrips() {
        let mut responder = new_response_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request(42);
        let expected_nonce = *request.nonc();
        responder.add_request(&request.as_bytes().unwrap(), request, addr);

        let mut responses = Vec::new();
        responder.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert!(response_bytes.starts_with(b"ROUGHTIM"));

        let mut response_data = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut response_data);
        let resp = Response::from_wire(&mut cursor).unwrap();
        assert_eq!(resp.nonc(), &expected_nonce);
    }

    #[test]
    fn multiple_requests_responses_roundtrip() {
        let mut responder = new_response_handler();

        let num_requests = 5;
        let mut expected_addrs = Vec::new();
        let mut expected_nonces = Vec::new();

        // Add multiple requests
        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8080 + i).parse().unwrap();
            let request = create_test_request(i as u8);

            expected_addrs.push(addr);
            expected_nonces.push(*request.nonc());
            responder.add_request(&request.as_bytes().unwrap(), request, addr);
        }

        let mut responses = Vec::new();
        responder.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
            assert_eq!(*response_addr, expected_addrs[idx]);
            assert!(response_bytes.starts_with(b"ROUGHTIM"));

            // Parse and verify the response
            let mut response_data = response_bytes[12..].to_vec();
            let mut cursor = ParseCursor::new(&mut response_data);
            let resp = Response::from_wire(&mut cursor).unwrap();
            assert_eq!(resp.nonc(), &expected_nonces[idx]);
            assert_eq!(resp.indx(), idx as u32);
        }
    }

    #[test]
    fn responder_does_nothing_with_no_requests() {
        let mut responder = new_response_handler();

        let mut call_count = 0;
        responder.process_responses(|_addr, _bytes| {
            call_count += 1;
        });

        assert_eq!(call_count, 0);
    }
}
