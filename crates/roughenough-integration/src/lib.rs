#![forbid(unsafe_code)]

mod load_gen;

#[cfg(test)]
mod integration_tests {
    //! These tests verify that the server's request processing and response generation
    //! paths are compatible with the client. They test the complete end-to-end flow
    //! from request processing through response generation and client-side validation.
    //!
    //! These tests are not exhaustive and do not cover all possible edge cases.
    //! They are intended to catch regressions and verify that the server's behavior
    //! matches the client's expectations.

    use std::net::SocketAddr;

    use roughenough_client::validation::ResponseValidator;
    use roughenough_protocol::cursor::ParseCursor;
    use roughenough_protocol::request::{Request, RequestDraft08};
    use roughenough_protocol::response::{Response, ResponseDraft08};
    use roughenough_protocol::tags::{Nonce, PublicKey};
    use roughenough_protocol::wire::{FromFrame, FromWire, ToFrame, ToWire};
    use roughenough_server::test_utils::{Draft08TestContext, TestContext};

    /// Validates a draft-14 response against its originating request.
    fn validate_response_draft14(
        request_bytes: &[u8],
        response_bytes: &[u8],
        pub_key: PublicKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
        // Skip framing: 8-byte "ROUGHTIM" + 4-byte length
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let response = Response::from_wire(&mut cursor)?;

        let validator = ResponseValidator::new_with_key(pub_key);
        validator.validate_draft14(request_bytes, &response, response_bytes)?;
        Ok(())
    }

    /// Creates a draft-14 test request with a Nonce based on a repeated single byte.
    fn create_test_request_draft14(nonce_byte: u8) -> Request {
        let nonce = Nonce::from([nonce_byte; 32]);
        Request::new_draft14(&nonce)
    }

    /// Tests that a single request generates a valid response.
    /// For single-element trees, the Merkle path is empty since there are no siblings, and the
    /// client will verify that the request nonce hashes to the signed root.
    #[test]
    fn single_request_validation() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);

        let pub_key = test_context.key_source.public_key();

        validate_response_draft14(&request_bytes, response_bytes, pub_key).unwrap();
    }

    /// Stress tests the responder with a batch of 64 requests. This is an expected (but maximum)
    /// batch size that the server supports.
    #[test]
    fn large_batch_validation() {
        let num_requests = 64;

        let mut test_context = TestContext::new(num_requests as u8);

        let mut request_data = Vec::new();

        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
            let request = create_test_request_draft14((i * 37) as u8);
            let request_bytes = request.as_bytes().unwrap();

            request_data.push((request_bytes.clone(), addr));
            test_context
                .response_handler
                .add_request(&request_bytes, request, addr);
        }

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
            let expected_addr = format!("127.0.0.1:{}", 8000 + idx)
                .parse::<SocketAddr>()
                .unwrap();
            assert_eq!(*response_addr, expected_addr);

            let (request_bytes, _) = &request_data[idx];
            let public_key = test_context.key_source.public_key();

            match validate_response_draft14(request_bytes, response_bytes, public_key) {
                Ok(_) => {} // Success
                Err(e) => {
                    println!("Response {idx} validation failed: {e}");

                    let mut buf = response_bytes[12..].to_vec();
                    let mut cursor = ParseCursor::new(&mut buf);
                    let response = Response::from_wire(&mut cursor).unwrap();

                    println!("Debug info for failed validation:");
                    println!("  Request bytes length: {}", request_bytes.len());
                    println!("  Response index: {}", response.indx());
                    println!("  Response path length: {}", response.path().as_ref().len());
                    println!(
                        "  Server root: {}",
                        data_encoding::HEXLOWER.encode(response.srep().root().as_ref())
                    );

                    // Compare with what the client computes to identify mismatch source
                    let tree = roughenough_merkle::MerkleTree::new();
                    let computed_root = tree.root_from_paths(
                        response.indx() as usize,
                        request_bytes,
                        response.path(),
                    );
                    println!(
                        "  Client computed: {}",
                        data_encoding::HEXLOWER.encode(&computed_root)
                    );

                    panic!("Validation failed for response {idx}: {e}");
                }
            }
        }
    }

    // ============================================================================
    // Draft-08 Integration Tests
    // ============================================================================

    /// Validates a draft-08 response against its originating request.
    fn validate_response_draft08(
        request_bytes: &[u8],
        response_bytes: &[u8],
        pub_key: PublicKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
        let mut buf = response_bytes.to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let response = ResponseDraft08::from_frame(&mut cursor)?;

        let validator = ResponseValidator::new_with_key(pub_key);
        validator.validate_draft08(request_bytes, &response, response_bytes)?;
        Ok(())
    }

    /// Creates a draft-08 test request with a Nonce based on a repeated single byte.
    fn create_test_request_draft08(nonce_byte: u8) -> RequestDraft08 {
        let nonce = Nonce::from([nonce_byte; 32]);
        RequestDraft08::new(&nonce)
    }

    /// Tests that a single draft-08 request generates a valid response.
    #[test]
    fn draft08_single_request_validation() {
        let mut test_context = Draft08TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft08(42);
        let request_bytes = request.as_frame_bytes().unwrap();

        test_context.add_request(request, addr);

        let mut responses = Vec::new();
        test_context.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);

        let pub_key = test_context.key_source.public_key();
        validate_response_draft08(&request_bytes, response_bytes, pub_key).unwrap();
    }

    /// Stress tests the draft-08 responder with a batch of 64 requests.
    #[test]
    fn draft08_large_batch_validation() {
        let num_requests = 64;
        let mut test_context = Draft08TestContext::new(num_requests as u8);

        let mut request_data = Vec::new();

        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
            let request = create_test_request_draft08((i * 37) as u8);
            let request_bytes = request.as_frame_bytes().unwrap();

            request_data.push((request_bytes.clone(), addr));
            test_context.add_request(request, addr);
        }

        let mut responses = Vec::new();
        test_context.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
            let expected_addr = format!("127.0.0.1:{}", 8000 + idx)
                .parse::<SocketAddr>()
                .unwrap();
            assert_eq!(*response_addr, expected_addr);

            let (request_bytes, _) = &request_data[idx];
            let public_key = test_context.key_source.public_key();

            match validate_response_draft08(request_bytes, response_bytes, public_key) {
                Ok(_) => {}
                Err(e) => {
                    println!("Draft-08 Response {idx} validation failed: {e}");

                    let mut buf = response_bytes[12..].to_vec();
                    let mut cursor = ParseCursor::new(&mut buf);
                    let response = ResponseDraft08::from_wire(&mut cursor).unwrap();

                    println!("Debug info for failed validation:");
                    println!("  Request bytes length: {}", request_bytes.len());
                    println!("  Response index: {}", response.indx());
                    println!("  Response path length: {}", response.path().as_ref().len());
                    println!(
                        "  Server root: {}",
                        data_encoding::HEXLOWER.encode(response.srep().root().as_ref())
                    );

                    panic!("Validation failed for draft-08 response {idx}: {e}");
                }
            }
        }
    }

    /// Tests draft-08 response wire roundtrip (serialization/deserialization).
    #[test]
    fn draft08_response_wire_roundtrip() {
        let mut test_context = Draft08TestContext::new(1);

        let nonce = Nonce::from([0x42u8; 32]);
        let (_request, response) =
            test_context.create_interaction_pair_with_nonce(1234567890, &nonce);

        // Serialize the response
        let mut buf = vec![0u8; response.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            response.to_wire(&mut cursor).unwrap();
        }

        // Deserialize and compare
        let mut cursor = ParseCursor::new(&mut buf);
        let response2 = ResponseDraft08::from_wire(&mut cursor).unwrap();

        assert_eq!(response.indx(), response2.indx());
        assert_eq!(response.srep().midp(), response2.srep().midp());
        assert_eq!(response.srep().radi(), response2.srep().radi());
        assert_eq!(response.srep().root(), response2.srep().root());
    }

    // ============================================================================
    // Error Handling Integration Tests
    // ============================================================================

    /// Tests that validation fails when using the wrong public key.
    /// This simulates a scenario where a client has a stale or incorrect key.
    #[test]
    fn wrong_public_key_is_rejected() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];

        // Use a completely wrong public key (all zeros)
        let wrong_key = PublicKey::from([0u8; 32].as_slice());

        let result = validate_response_draft14(&request_bytes, response_bytes, wrong_key);
        assert!(
            result.is_err(),
            "Validation should fail with wrong public key"
        );
    }

    /// Tests that validation fails when the response is for a different nonce.
    /// This catches nonce substitution attacks or server bugs.
    #[test]
    fn response_for_wrong_nonce_is_rejected() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Create and process request with nonce=42
        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Try to validate with a DIFFERENT request (nonce=99)
        let different_request = create_test_request_draft14(99);
        let different_request_bytes = different_request.as_bytes().unwrap();

        let result = validate_response_draft14(&different_request_bytes, response_bytes, pub_key);
        assert!(
            result.is_err(),
            "Validation should fail when response doesn't match request nonce"
        );
    }

    /// Tests that a response with tampered SREP (midpoint) is rejected.
    #[test]
    fn tampered_srep_is_rejected() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Parse the response, tamper with SREP, and re-serialize
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let mut response = Response::from_wire(&mut cursor).unwrap();

        // Tamper with the midpoint
        let mut srep = response.srep().clone();
        srep.set_midp(srep.midp() + 1000);
        response.set_srep(srep);

        // Re-serialize the tampered response
        let mut tampered_buf = vec![0u8; response.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut tampered_buf);
            response.to_wire(&mut cursor).unwrap();
        }

        // Add framing back
        let mut framed_tampered = b"ROUGHTIM".to_vec();
        framed_tampered.extend_from_slice(&(tampered_buf.len() as u32).to_le_bytes());
        framed_tampered.extend_from_slice(&tampered_buf);

        let result = validate_response_draft14(&request_bytes, &framed_tampered, pub_key);
        assert!(result.is_err(), "Validation should fail with tampered SREP");
    }

    /// Tests that a response with tampered DELE (validity period) is rejected.
    #[test]
    fn tampered_dele_is_rejected() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Parse the response, tamper with DELE, and re-serialize
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let mut response = Response::from_wire(&mut cursor).unwrap();

        // Tamper with the certificate's DELE
        let mut cert = response.cert().clone();
        let mut dele = cert.dele().clone();
        dele.set_mint(dele.mint() + 1000);
        cert.set_dele(dele);
        response.set_cert(cert);

        // Re-serialize the tampered response
        let mut tampered_buf = vec![0u8; response.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut tampered_buf);
            response.to_wire(&mut cursor).unwrap();
        }

        // Add framing back
        let mut framed_tampered = b"ROUGHTIM".to_vec();
        framed_tampered.extend_from_slice(&(tampered_buf.len() as u32).to_le_bytes());
        framed_tampered.extend_from_slice(&tampered_buf);

        let result = validate_response_draft14(&request_bytes, &framed_tampered, pub_key);
        assert!(result.is_err(), "Validation should fail with tampered DELE");
    }

    /// Tests that draft-08 validation fails with wrong public key.
    #[test]
    fn draft08_wrong_public_key_is_rejected() {
        let mut test_context = Draft08TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft08(42);
        let request_bytes = request.as_frame_bytes().unwrap();
        test_context.add_request(request, addr);

        let mut responses = Vec::new();
        test_context.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        let (_, response_bytes) = &responses[0];

        // Use wrong public key
        let wrong_key = PublicKey::from([0u8; 32].as_slice());

        let result = validate_response_draft08(&request_bytes, response_bytes, wrong_key);
        assert!(
            result.is_err(),
            "Draft-08 validation should fail with wrong public key"
        );
    }

    /// Tests that validation fails when CERT is expired (MAXT in the past).
    #[test]
    fn expired_cert_is_rejected() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request_draft14(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Parse response and set MAXT to a time in the past
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let mut response = Response::from_wire(&mut cursor).unwrap();

        // Set MAXT to be before the midpoint (expired cert)
        let mut cert = response.cert().clone();
        let mut dele = cert.dele().clone();
        dele.set_maxt(response.srep().midp() - 1000); // 1 second before midpoint
        cert.set_dele(dele);
        response.set_cert(cert);

        // Re-serialize
        let mut tampered_buf = vec![0u8; response.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut tampered_buf);
            response.to_wire(&mut cursor).unwrap();
        }

        let mut framed = b"ROUGHTIM".to_vec();
        framed.extend_from_slice(&(tampered_buf.len() as u32).to_le_bytes());
        framed.extend_from_slice(&tampered_buf);

        let result = validate_response_draft14(&request_bytes, &framed, pub_key);
        assert!(
            result.is_err(),
            "Validation should fail with expired CERT (MAXT in past)"
        );
    }

    /// Tests that validation fails when merkle path index is corrupted.
    #[test]
    fn corrupted_merkle_index_is_rejected() {
        let mut test_context = TestContext::new(64);

        // Add multiple requests to create a non-trivial merkle tree
        for i in 0..4u8 {
            let request = create_test_request_draft14(i);
            let request_bytes = request.as_bytes().unwrap();
            let req_addr: SocketAddr = format!("127.0.0.1:{}", 8080 + i as u16).parse().unwrap();
            test_context
                .response_handler
                .add_request(&request_bytes, request, req_addr);
        }

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        // Get the first response (index 0)
        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Parse response and corrupt the index
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let mut response = Response::from_wire(&mut cursor).unwrap();

        // Change index from 0 to 1 - the merkle path won't match
        response.set_indx(1);

        // Re-serialize
        let mut tampered_buf = vec![0u8; response.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut tampered_buf);
            response.to_wire(&mut cursor).unwrap();
        }

        let mut framed = b"ROUGHTIM".to_vec();
        framed.extend_from_slice(&(tampered_buf.len() as u32).to_le_bytes());
        framed.extend_from_slice(&tampered_buf);

        let request = create_test_request_draft14(0);
        let request_bytes = request.as_bytes().unwrap();

        let result = validate_response_draft14(&request_bytes, &framed, pub_key);
        assert!(
            result.is_err(),
            "Validation should fail with corrupted merkle index"
        );
    }

    /// Tests that draft-08 validation fails when response is for different nonce.
    #[test]
    fn draft08_response_for_wrong_nonce_is_rejected() {
        let mut test_context = Draft08TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Create and process request with nonce=42
        let request = create_test_request_draft08(42);
        test_context.add_request(request, addr);

        let mut responses = Vec::new();
        test_context.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Try to validate with a DIFFERENT request (nonce=99)
        let different_request = create_test_request_draft08(99);
        let different_request_bytes = different_request.as_frame_bytes().unwrap();

        let result = validate_response_draft08(&different_request_bytes, response_bytes, pub_key);
        assert!(
            result.is_err(),
            "Draft-08 validation should fail when response doesn't match request nonce"
        );
    }

    // ============================================================================
    // Protocol Version Mismatch Tests
    // ============================================================================

    /// Tests that validation fails when client expects draft-14 but gets draft-08 response.
    #[test]
    fn draft14_client_rejects_draft08_response() {
        let mut test_context = Draft08TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Server processes draft-08 request and generates draft-08 response
        let request_draft08 = create_test_request_draft08(42);
        test_context.add_request(request_draft08, addr);

        let mut responses = Vec::new();
        test_context.process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Create a draft-14 request (different format)
        let request_draft14 = create_test_request_draft14(42);
        let request_bytes_draft14 = request_draft14.as_bytes().unwrap();

        // Try to validate draft-08 response as if it were draft-14
        // This should fail because the response format differs
        let result = validate_response_draft14(&request_bytes_draft14, response_bytes, pub_key);
        assert!(
            result.is_err(),
            "Draft-14 validation should fail on draft-08 response"
        );
    }

    /// Tests that validation fails when client expects draft-08 but gets draft-14 response.
    #[test]
    fn draft08_client_rejects_draft14_response() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Server processes draft-14 request and generates draft-14 response
        let request_draft14 = create_test_request_draft14(42);
        let request_bytes = request_draft14.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request_draft14, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        let (_, response_bytes) = &responses[0];
        let pub_key = test_context.key_source.public_key();

        // Create a draft-08 request
        let request_draft08 = create_test_request_draft08(42);
        let request_bytes_draft08 = request_draft08.as_frame_bytes().unwrap();

        // Try to validate draft-14 response as if it were draft-08
        let result = validate_response_draft08(&request_bytes_draft08, response_bytes, pub_key);
        assert!(
            result.is_err(),
            "Draft-08 validation should fail on draft-14 response"
        );
    }

    // ============================================================================
    // Timeout Handling Tests
    // ============================================================================

    /// Tests that the client properly times out when server is unavailable.
    #[test]
    fn client_times_out_when_server_unavailable() {
        use std::time::{Duration, Instant};

        use roughenough_client::Client;

        // Connect to a port where nothing is listening
        let addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let timeout = Duration::from_secs(1);

        let client = Client::builder(addr).timeout(timeout).build();

        let start = Instant::now();
        let result = client.query();
        let elapsed = start.elapsed();

        // Should fail with timeout
        assert!(
            result.is_err(),
            "Query should fail when no server is running"
        );

        // Should take approximately the timeout duration (with some margin)
        assert!(
            elapsed >= Duration::from_millis(900),
            "Should wait at least ~1 second before timing out, but only waited {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "Should not wait much longer than timeout, but waited {:?}",
            elapsed
        );
    }
}
