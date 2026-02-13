use std::net::SocketAddr;

use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{REQUEST_SIZE, Request};
use roughenough_protocol::tags::PublicKey;
use roughenough_protocol::wire::FromFrame;

use crate::metrics::types::RequestMetrics;
use crate::responses::ResponseHandler;

pub struct RequestHandler {
    responder: ResponseHandler,
    metrics: RequestMetrics,
}

impl RequestHandler {
    pub fn new(handler: ResponseHandler) -> Self {
        Self {
            responder: handler,
            metrics: RequestMetrics::default(),
        }
    }

    pub fn collect_request(&mut self, request_bytes: &mut [u8], src_addr: SocketAddr) {
        // Reject requests != 1024 bytes
        if request_bytes.len() < REQUEST_SIZE {
            self.metrics.num_runt_requests += 1;
            return;
        } else if request_bytes.len() > REQUEST_SIZE {
            self.metrics.num_jumbo_requests += 1;
            return;
        }

        let mut cursor = ParseCursor::new(request_bytes);
        match Request::from_frame(&mut cursor) {
            Ok(request) => {
                self.responder.add_request(request_bytes, request, src_addr);
                self.metrics.num_ok_requests += 1;
            }
            Err(_) => {
                self.metrics.num_bad_requests += 1;
            }
        }
    }

    pub fn generate_responses<F>(&mut self, callback: F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        self.responder.process_responses(callback);
        self.responder.clear();
    }

    pub fn replace_online_key(&mut self) {
        self.responder.replace_online_key();
    }

    pub fn public_key(&self) -> PublicKey {
        self.responder.public_key()
    }

    #[allow(dead_code)] // used in tests, but compiler can't see that
    pub fn metrics(&self) -> RequestMetrics {
        self.metrics
    }

    #[allow(dead_code)] // used in tests, but compiler can't see that
    pub fn reset_metrics(&mut self) {
        self.metrics = RequestMetrics::default();
        self.responder.reset_metrics();
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn response_metrics(&self) -> crate::metrics::types::ResponseMetrics {
        self.responder.metrics()
    }
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::{FRAME_MAGIC, ToFrame};

    use super::*;
    use crate::test_utils::new_response_handler;

    fn create_request_handler() -> RequestHandler {
        let responder = new_response_handler();
        RequestHandler::new(responder)
    }

    fn create_test_request_bytes(nonce_value: u8) -> Vec<u8> {
        let nonce = Nonce::from([nonce_value; 32]);
        let request = Request::new_draft14(&nonce);

        let bytes = request.as_frame_bytes().unwrap();
        assert_eq!(bytes.len(), REQUEST_SIZE);
        bytes
    }

    #[test]
    fn test_process_valid_request() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_bad_requests, 0);
        assert_eq!(metrics.num_runt_requests, 0);
        assert_eq!(metrics.num_jumbo_requests, 0);
    }

    #[test]
    fn test_process_runt_requests() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Test various undersized requests
        let sizes = [0, 1, 15, 100, 512, REQUEST_SIZE - 1];

        for size in sizes {
            let mut runt = vec![0u8; size];
            // Add valid magic to make it look somewhat legitimate
            if size >= 8 {
                runt[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
            }
            handler.collect_request(&mut runt, addr);
        }

        let metrics = handler.metrics();
        assert_eq!(
            metrics.num_runt_requests,
            sizes.len(),
            "All undersized requests should be counted as runt"
        );
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_process_jumbo_requests() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Test various oversized requests
        let sizes = [REQUEST_SIZE + 1, REQUEST_SIZE + 100, 2048, 4096];

        for size in sizes {
            let mut jumbo = vec![0u8; size];
            jumbo[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
            handler.collect_request(&mut jumbo, addr);
        }

        let metrics = handler.metrics();
        assert_eq!(
            metrics.num_jumbo_requests,
            sizes.len(),
            "All oversized requests should be counted as jumbo"
        );
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_generate_responses() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);

        let mut responses = Vec::new();
        handler.generate_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
    }

    #[test]
    fn test_metrics_reset() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);
        assert_eq!(handler.metrics().num_ok_requests, 1);

        handler.reset_metrics();
        assert_eq!(handler.metrics().num_ok_requests, 0);
    }

    // =========================================================================
    // Malformed Wire Data Tests
    // =========================================================================
    //
    // These tests verify that RequestHandler gracefully handles truncated,
    // malformed, and adversarial wire data without crashing.

    #[test]
    fn test_bad_magic_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Correct size but wrong magic
        let mut bad_magic = vec![0u8; REQUEST_SIZE];
        bad_magic[..8].copy_from_slice(b"BADMAGIC");
        handler.collect_request(&mut bad_magic, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_bad_frame_length_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Valid magic but frame length claims to need more data than available
        let mut bad_len = vec![0u8; REQUEST_SIZE];
        bad_len[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        // Claim the frame is larger than what we have
        bad_len[8..12].copy_from_slice(&(REQUEST_SIZE as u32 + 100).to_le_bytes());

        handler.collect_request(&mut bad_len, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_zero_frame_length_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut zero_len = vec![0u8; REQUEST_SIZE];
        zero_len[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        zero_len[8..12].copy_from_slice(&0u32.to_le_bytes());

        handler.collect_request(&mut zero_len, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_tag_count_overflow_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut overflow = vec![0u8; REQUEST_SIZE];
        overflow[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        // Correct frame length (REQUEST_SIZE - 12 for framing)
        overflow[8..12].copy_from_slice(&1012u32.to_le_bytes());
        // Malicious tag count that would overflow offset calculations
        overflow[12..16].copy_from_slice(&u32::MAX.to_le_bytes());

        handler.collect_request(&mut overflow, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_all_zeros_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut zeros = vec![0u8; REQUEST_SIZE];
        handler.collect_request(&mut zeros, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_random_garbage_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Create several garbage packets
        for seed in 0..10u8 {
            let mut garbage = vec![seed.wrapping_mul(37); REQUEST_SIZE];
            handler.collect_request(&mut garbage, addr);
        }

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 10);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_mixed_valid_and_invalid_requests() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Valid request
        let nonce = Nonce::from([1u8; 32]);
        let valid_request = Request::new_draft14(&nonce);
        let mut valid_bytes = valid_request.as_frame_bytes().unwrap();
        handler.collect_request(&mut valid_bytes, addr);

        // Malformed request (bad magic)
        let mut bad = vec![0u8; REQUEST_SIZE];
        bad[..8].copy_from_slice(b"NOTVALID");
        handler.collect_request(&mut bad, addr);

        // Another valid request
        let nonce2 = Nonce::from([2u8; 32]);
        let valid_request2 = Request::new_draft14(&nonce2);
        let mut valid_bytes2 = valid_request2.as_frame_bytes().unwrap();
        handler.collect_request(&mut valid_bytes2, addr);

        // Runt request
        let mut runt = vec![0u8; 100];
        handler.collect_request(&mut runt, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 2, "Should have 2 valid requests");
        assert_eq!(
            metrics.num_bad_requests, 1,
            "Should have 1 bad (malformed) request"
        );
        assert_eq!(metrics.num_runt_requests, 1, "Should have 1 runt request");
    }

    #[test]
    fn test_malformed_requests_generate_no_responses() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Send only malformed requests
        let mut bad_magic = vec![0u8; REQUEST_SIZE];
        bad_magic[..8].copy_from_slice(b"BADMAGIC");
        handler.collect_request(&mut bad_magic, addr);

        let mut runt = vec![0u8; 100];
        handler.collect_request(&mut runt, addr);

        // Try to generate responses
        let mut responses = Vec::new();
        handler.generate_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert!(
            responses.is_empty(),
            "Malformed requests should not generate responses"
        );
    }

    #[test]
    fn test_non_monotonic_offsets_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut bad = vec![0u8; REQUEST_SIZE];
        bad[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        bad[8..12].copy_from_slice(&1012u32.to_le_bytes());
        // 4 tags
        bad[12..16].copy_from_slice(&4u32.to_le_bytes());
        // Non-monotonic offsets (second offset goes backwards)
        bad[16..20].copy_from_slice(&100u32.to_le_bytes());
        bad[20..24].copy_from_slice(&50u32.to_le_bytes()); // Goes backwards

        handler.collect_request(&mut bad, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }

    #[test]
    fn test_out_of_bounds_offset_is_rejected() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut bad = vec![0u8; REQUEST_SIZE];
        bad[..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        bad[8..12].copy_from_slice(&1012u32.to_le_bytes());
        // 4 tags
        bad[12..16].copy_from_slice(&4u32.to_le_bytes());
        // Offset pointing beyond the buffer
        bad[16..20].copy_from_slice(&((REQUEST_SIZE + 1000) as u32).to_le_bytes());

        handler.collect_request(&mut bad, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_bad_requests, 1);
        assert_eq!(metrics.num_ok_requests, 0);
    }
}
