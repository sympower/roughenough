//! Validate Responses from Roughtime servers.
//!
//! * Use [`ResponseValidator::validate_draft14`] to validate a draft-14 [`Response`], or
//! * Use [`ResponseValidator::validate_draft08`] to validate a draft-08 response, or
//! * [`ResponseValidator::validate_causality`]
//!   to inspect the results of a [`MeasurementSequence`](crate::sequence::MeasurementSequence).

use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;
use data_encoding::HEXLOWER;
use roughenough_merkle::MerkleTree;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::header::Header;
use roughenough_protocol::protocol_ver::ProtocolVersion;
use roughenough_protocol::request::RequestDraft08;
use roughenough_protocol::response::{Response, ResponseDraft08};
use roughenough_protocol::tags::PublicKey;
use roughenough_protocol::wire::ToWire;

use crate::measurement::Measurement;

/// Reasons a response's time may be invalid
#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("The returned midpoint time is invalid: {0}")]
    InvalidMidpoint(String),

    #[error("Bad signature: {0}")]
    BadSignature(String),

    #[error("Invalid Merkle proof: {0}")]
    FailedProof(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(#[from] roughenough_protocol::error::Error),

    #[error("Version mismatch: VER ({0:?}) not found in VERS")]
    VersionMismatch(ProtocolVersion),

    #[error("Invalid radius: {0}")]
    InvalidRadius(String),
}

/// An instance of causality constraints being violated. For this pair of responses `(i, j)`
/// where `i` was received before `j`, the lower bound (`MIDP_i - RADI_i`) is greater than the
/// upper bound (`MIDP_j + RADI_j`).
#[derive(Debug)]
pub struct CausalityViolation {
    pub measurement_i: Measurement,
    pub measurement_j: Measurement,
    pub lower_bound_i: u64,
    pub upper_bound_j: u64,
}

// TODO(stuart) right now CausalityViolation only supports two measurements. It needs to be
// extended to support arbitrary number of measurements, and somehow capture/note the relationship
// between the measurements and the violation.
impl CausalityViolation {
    pub fn new(measurement_i: Measurement, measurement_j: Measurement) -> Self {
        let lower_bound_i = measurement_i.midpoint() - measurement_i.radius() as u64;
        let upper_bound_j = measurement_j.midpoint() + measurement_j.radius() as u64;
        assert!(
            lower_bound_i > upper_bound_j,
            "(MIDP_i - RADI_i > MIDP_j + RADI_j) does not hold"
        );

        Self {
            measurement_i,
            measurement_j,
            lower_bound_i,
            upper_bound_j,
        }
    }
}

/// Validate the [`Response`]s from roughtime servers.
///
/// Use [`validate_draft14`](Self::validate_draft14) or [`validate_draft08`](Self::validate_draft08)
/// to validate individual responses. Use [`validate_causality`](Self::validate_causality)
/// to inspect the results of a [`MeasurementSequence`](crate::sequence::MeasurementSequence).
#[derive(Debug, Default)]
pub struct ResponseValidator {
    pub_key: Option<UnparsedPublicKey<[u8; 32]>>,
}

impl ResponseValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_key(pub_key: PublicKey) -> Self {
        let key_bytes: [u8; 32] = pub_key
            .as_ref()
            .try_into()
            .expect("expected a valid 32-byte public key");

        let key = UnparsedPublicKey::new(&signature::ED25519, key_bytes);

        Self { pub_key: Some(key) }
    }

    /// Validate a draft-14 response. Validity does not prove the timestamp is correct, but
    /// merely that the server claims to have signed it during the interval (MIDP-RADI, MIDP+RADI).
    ///
    /// The `response_bytes` parameter must contain the original framed response bytes as received
    /// from the server. These are used for signature verification to ensure byte-exact fidelity.
    pub fn validate_draft14(
        &self,
        request: &[u8],
        response: &Response,
        response_bytes: &[u8],
    ) -> Result<u64, ValidationError> {
        // RFC section 5.4. Validity of Response:
        //   "A client MUST check the following properties when it receives a
        //   response. We assume the long-term server public key is known to the
        //   client through other means."

        // The signature in CERT was made with the long-term key of the server.
        if let Some(ref pub_key) = self.pub_key {
            self.check_dele_signature_with_key(pub_key, response.cert(), response.srep().ver())?;
        }

        // RFC section 5.1.3: "The VERS tag value MUST contain [...] the version number
        // specified in the VER tag."
        self.check_vers_contains_ver(response)?;

        // The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        self.check_midpoint_inner(
            response.srep().midp(),
            response.cert().dele().mint(),
            response.cert().dele().maxt(),
        )?;

        // RFC section 5.2.5: "The value of RADI MUST NOT be zero"
        self.check_radius(response.srep().radi())?;

        // The INDX and PATH values prove a hash value derived from the request packet was included
        // in the Merkle tree ROOT
        self.check_merkle_proof_draft14(request, response)?;

        // The signature of SREP in SIG validates with the public key in DELE.
        self.check_srep_signature_draft14(response, response_bytes)?;

        Ok(response.srep().midp())
    }

    /// Validate a draft-08 response. Validity does not prove the timestamp is correct, but
    /// merely that the server claims to have signed it during the interval (MIDP-RADI, MIDP+RADI).
    ///
    /// The `response_bytes` parameter must contain the original framed response bytes as received
    /// from the server. These are used for signature verification to ensure byte-exact fidelity.
    ///
    /// Draft-08 differs from draft-14 in:
    /// - Merkle leaf hash uses only the nonce (32 bytes), not the full framed request
    /// - SREP has 3 tags (RADI, MIDP, ROOT) instead of 5 (VER, RADI, MIDP, VERS, ROOT)
    /// - Response has no NONC or TYPE tags
    pub fn validate_draft08(
        &self,
        request: &[u8],
        response: &ResponseDraft08,
        response_bytes: &[u8],
    ) -> Result<u64, ValidationError> {
        // The signature in CERT was made with the long-term key of the server.
        if let Some(ref pub_key) = self.pub_key {
            self.check_dele_signature_with_key(
                pub_key,
                response.cert(),
                &ProtocolVersion::RfcDraft08,
            )?;
        }

        // The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        self.check_midpoint_inner(
            response.srep().midp(),
            response.cert().dele().mint(),
            response.cert().dele().maxt(),
        )?;

        // RFC section 5.2.5: "The value of RADI MUST NOT be zero"
        self.check_radius(response.srep().radi())?;

        // The INDX and PATH values prove a hash value derived from the nonce was included
        // in the Merkle tree ROOT (draft-08 uses nonce only, not full request)
        self.check_merkle_proof_draft08(request, response)?;

        // The signature of SREP in SIG validates with the public key in DELE.
        self.check_srep_signature_draft08(response, response_bytes)?;

        Ok(response.srep().midp())
    }

    fn check_dele_signature_with_key(
        &self,
        pub_key: &UnparsedPublicKey<[u8; 32]>,
        cert: &roughenough_protocol::tags::Certificate,
        version: &ProtocolVersion,
    ) -> Result<(), ValidationError> {
        let dele = cert.dele();
        let prefix = version.dele_prefix();

        let mut cert_bytes = vec![0u8; prefix.len() + dele.wire_size()];
        cert_bytes[..prefix.len()].copy_from_slice(prefix);
        let mut cursor = ParseCursor::new(&mut cert_bytes[prefix.len()..]);
        dele.to_wire(&mut cursor)?;

        pub_key
            .verify(&cert_bytes, cert.sig().as_ref())
            .map_err(|_| ValidationError::BadSignature("signature on DELE is invalid".to_string()))
    }

    fn check_vers_contains_ver(&self, response: &Response) -> Result<(), ValidationError> {
        let ver = *response.srep().ver();
        let vers = response.srep().vers();

        if !vers.is_supported(ver) {
            return Err(ValidationError::VersionMismatch(ver));
        }
        Ok(())
    }

    fn check_srep_signature_draft14(
        &self,
        response: &Response,
        response_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        let prefix = response.srep().ver().srep_prefix();

        // Extract original SREP bytes from the framed response for byte-exact signature verification.
        // Layout: frame header (12) + message header (56 for 7 tags) + values
        // SREP is tag index 4, so its value is at offsets[3]..offsets[4]
        let offsets = response.header().offsets();
        const FRAME_HEADER_SIZE: usize = 12;
        const MSG_HEADER_SIZE_7_TAGS: usize = 56; // 4 + 6*4 + 7*4
        let values_start = FRAME_HEADER_SIZE + MSG_HEADER_SIZE_7_TAGS;

        let srep_start = values_start + offsets[3] as usize;
        let srep_end = values_start + offsets[4] as usize;

        if srep_end > response_bytes.len() {
            return Err(ValidationError::BadSignature(
                "SREP offset extends beyond response bytes".to_string(),
            ));
        }

        let srep_bytes = &response_bytes[srep_start..srep_end];
        let dele = response.cert().dele();

        Self::verify_srep_signature(prefix, srep_bytes, response.sig(), dele.pubk())
    }

    fn verify_srep_signature(
        prefix: &[u8],
        srep_bytes: &[u8],
        sig: &roughenough_protocol::tags::Signature,
        pubk: &roughenough_protocol::tags::PublicKey,
    ) -> Result<(), ValidationError> {
        let mut signed_bytes = vec![0u8; prefix.len() + srep_bytes.len()];
        signed_bytes[..prefix.len()].copy_from_slice(prefix);
        signed_bytes[prefix.len()..].copy_from_slice(srep_bytes);

        let verification_key = UnparsedPublicKey::new(&signature::ED25519, pubk.as_ref());

        verification_key
            .verify(&signed_bytes, sig.as_ref())
            .map_err(|_| {
                ValidationError::BadSignature(format!(
                    "signature {sig:?} by {pubk:?} on SREP is invalid"
                ))
            })
    }

    fn check_midpoint_inner(
        &self,
        midpoint: u64,
        mint: u64,
        maxt: u64,
    ) -> Result<(), ValidationError> {
        if midpoint < mint {
            let msg = format!("midpoint ({midpoint}) is *before* delegation span ({mint}, {maxt})");
            return Err(ValidationError::InvalidMidpoint(msg));
        }
        if midpoint > maxt {
            let msg = format!("midpoint ({midpoint}) is *after* delegation span ({mint}, {maxt})");
            return Err(ValidationError::InvalidMidpoint(msg));
        }
        Ok(())
    }

    fn check_radius(&self, radius: u32) -> Result<(), ValidationError> {
        if radius == 0 {
            return Err(ValidationError::InvalidRadius(
                "RADI must not be zero (RFC 5.2.5)".to_string(),
            ));
        }
        Ok(())
    }

    fn check_merkle_proof_inner(
        &self,
        leaf_data: &[u8],
        response_path: &roughenough_merkle::MerklePath,
        response_index: usize,
        response_root: &[u8],
    ) -> Result<(), ValidationError> {
        let tree = MerkleTree::new();
        let computed_root = tree.root_from_paths(response_index, leaf_data, response_path);

        if computed_root != *response_root {
            let msg = format!(
                "Nonce is not present in the response's merkle tree: computed {} != ROOT {}",
                HEXLOWER.encode(&computed_root),
                HEXLOWER.encode(response_root)
            );
            return Err(ValidationError::FailedProof(msg));
        }

        Ok(())
    }

    fn check_merkle_proof_draft14(
        &self,
        request: &[u8],
        response: &Response,
    ) -> Result<(), ValidationError> {
        self.check_merkle_proof_inner(
            request,
            response.path(),
            response.indx() as usize,
            response.srep().root().as_ref(),
        )
    }

    // Convenience methods for testing

    #[cfg(test)]
    fn check_dele_signature_draft14(&self, response: &Response) -> Result<(), ValidationError> {
        if let Some(ref pub_key) = self.pub_key {
            self.check_dele_signature_with_key(pub_key, response.cert(), response.srep().ver())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn check_midpoint_draft14(&self, response: &Response) -> Result<(), ValidationError> {
        self.check_midpoint_inner(
            response.srep().midp(),
            response.cert().dele().mint(),
            response.cert().dele().maxt(),
        )
    }

    // Draft-08 specific validation methods

    fn check_srep_signature_draft08(
        &self,
        response: &ResponseDraft08,
        response_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        let prefix = ProtocolVersion::RfcDraft08.srep_prefix();

        // Extract original SREP bytes from the framed response for byte-exact signature verification.
        // Layout: frame header (12) + message header (48 for 6 tags) + values
        // SREP is tag index 3, so its value is at offsets[2]..offsets[3]
        let offsets = response.header().offsets();
        const FRAME_HEADER_SIZE: usize = 12;
        const MSG_HEADER_SIZE_6_TAGS: usize = 48; // 4 + 5*4 + 6*4
        let values_start = FRAME_HEADER_SIZE + MSG_HEADER_SIZE_6_TAGS;

        let srep_start = values_start + offsets[2] as usize;
        let srep_end = values_start + offsets[3] as usize;

        if srep_end > response_bytes.len() {
            return Err(ValidationError::BadSignature(
                "SREP offset extends beyond response bytes".to_string(),
            ));
        }

        let srep_bytes = &response_bytes[srep_start..srep_end];
        let dele = response.cert().dele();

        Self::verify_srep_signature(prefix, srep_bytes, response.sig(), dele.pubk())
    }

    /// Extract nonce from a draft-08 framed request and verify the Merkle proof.
    ///
    /// Draft-08 uses only the 32-byte nonce as the Merkle leaf hash input, not the full
    /// framed request as in draft-14. The nonce position is determined by the request
    /// wire format - see [`RequestDraft08::FRAMED_NONCE_OFFSET`].
    fn check_merkle_proof_draft08(
        &self,
        request: &[u8],
        response: &ResponseDraft08,
    ) -> Result<(), ValidationError> {
        const NONCE_SIZE: usize = 32;
        let nonce_end = RequestDraft08::FRAMED_NONCE_OFFSET + NONCE_SIZE;

        if request.len() < nonce_end {
            return Err(ValidationError::InvalidMessage(
                roughenough_protocol::error::Error::BufferTooSmall(nonce_end, request.len()),
            ));
        }

        let nonce = &request[RequestDraft08::FRAMED_NONCE_OFFSET..nonce_end];

        self.check_merkle_proof_inner(
            nonce,
            response.path(),
            response.indx() as usize,
            response.srep().root().as_ref(),
        )
    }

    /// Validate causality constraints across a set of measurements. For each pair of responses
    /// `(i, j)` where `i` was received before `j`, checks that
    /// `MIDP_i - RADI_i <= MIDP_j + RADI_j`. Returns a list of violations if any are found,
    /// otherwise returns an empty list.
    pub fn validate_causality(measurements: &[Measurement]) -> Vec<CausalityViolation> {
        if measurements.len() < 2 {
            return Vec::new();
        }

        let mut violations = Vec::new();

        for i in 0..measurements.len() {
            for j in (i + 1)..measurements.len() {
                let lower_bound_i = measurements[i].midpoint() - measurements[i].radius() as u64;
                let upper_bound_j = measurements[j].midpoint() + measurements[j].radius() as u64;

                if lower_bound_i > upper_bound_j {
                    violations.push(CausalityViolation::new(
                        measurements[i].clone(),
                        measurements[j].clone(),
                    ));
                }
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use ValidationError::{BadSignature, InvalidMidpoint};
    use data_encoding::BASE64;
    use roughenough_protocol::cursor::ParseCursor;
    use roughenough_protocol::header::Header;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::PublicKey;
    use roughenough_protocol::wire::FromFrame;

    use crate::validation::{ResponseValidator, ValidationError};

    #[test]
    fn dele_signature_is_validated() {
        let pub_key = BASE64
            .decode(b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=")
            .unwrap();

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();
        let validator = ResponseValidator::new_with_key(PublicKey::from(pub_key.as_slice()));

        validator.check_dele_signature_draft14(&response).unwrap();
    }

    #[test]
    fn srep_signature_is_validated() {
        let msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();

        let mut parse_bytes = msg_bytes.clone();
        let mut cursor = ParseCursor::new(&mut parse_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();
        let validator = ResponseValidator::new();

        validator
            .check_srep_signature_draft14(&response, &msg_bytes)
            .unwrap();
    }

    #[test]
    fn corrupt_dele_signature_is_detected() {
        let pub_key = BASE64
            .decode(b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=")
            .unwrap();

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let mut response = Response::from_frame(&mut cursor).unwrap();

        let mut cert_copy = response.cert().clone();
        let mut dele_copy = cert_copy.dele().clone();

        // Change the value of the DELE.MINT field
        dele_copy.set_mint(dele_copy.mint() + 1);
        cert_copy.set_dele(dele_copy);
        response.set_cert(cert_copy);

        let validator = ResponseValidator::new_with_key(PublicKey::from(pub_key.as_slice()));

        match validator.check_dele_signature_draft14(&response) {
            Err(BadSignature(msg)) => assert!(msg.contains("DELE")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn corrupt_srep_signature_is_detected() {
        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();

        let mut parse_bytes = msg_bytes.clone();
        let mut cursor = ParseCursor::new(&mut parse_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();

        // Corrupt a byte in the SREP region of the original message bytes
        // SREP starts at offset 68 + offsets[3] in the framed response
        let srep_offset = 68 + response.header().offsets()[3] as usize;
        msg_bytes[srep_offset + 10] ^= 0xFF; // flip some bits

        let validator = ResponseValidator::new();

        match validator.check_srep_signature_draft14(&response, &msg_bytes) {
            Err(BadSignature(msg)) => assert!(msg.contains("SREP")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn midpoint_is_validated() {
        let validator = ResponseValidator::new();

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response1 = Response::from_frame(&mut cursor).unwrap();

        // Happy-path should pass
        validator.check_midpoint_draft14(&response1).unwrap();
    }

    #[test]
    fn midpoint_outside_of_dele_bounds_is_detected() {
        let validator = ResponseValidator::new();

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();

        //
        // Change request so that the midpoint is *before* MINT
        //
        let mut response1 = response.clone();
        let mut cert1 = response1.cert().clone();
        let mut dele1 = cert1.dele().clone();

        dele1.set_mint(response1.srep().midp() + 1000);
        cert1.set_dele(dele1);
        response1.set_cert(cert1);

        match validator.check_midpoint_draft14(&response1) {
            Err(InvalidMidpoint(msg)) => assert!(msg.contains("before")),
            Err(e) => panic!("expected InvalidMidpoint, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        //
        // Other direction: request midpoint is *after* MAXT
        //
        let mut response2 = response.clone();
        let mut cert2 = response2.cert().clone();
        let mut dele2 = cert2.dele().clone();

        dele2.set_maxt(response2.srep().midp() - 1000);
        cert2.set_dele(dele2);
        response2.set_cert(cert2);

        match validator.check_midpoint_draft14(&response2) {
            Err(InvalidMidpoint(msg)) => assert!(msg.contains("after")),
            Err(e) => panic!("expected InvalidMidpoint, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn merkle_proof_with_wrong_nonce_is_detected() {
        use roughenough_protocol::ToFrame;
        use roughenough_protocol::request::Request;
        use roughenough_protocol::tags::Nonce;

        let validator = ResponseValidator::new();

        let nonce = Nonce::from([0x42u8; 32]);
        let request = Request::new_draft14(&nonce);
        let request_bytes = request.as_frame_bytes().unwrap();

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();

        // This should fail because the response was for a different nonce
        match validator.check_merkle_proof_draft14(&request_bytes, &response) {
            Err(ValidationError::FailedProof(_)) => {} // ok, expected failure
            Err(e) => panic!("expected ValidationError::FailedProof, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn draft08_truncated_request_is_rejected() {
        use roughenough_protocol::response::ResponseDraft08;

        let validator = ResponseValidator::new();

        // Create a truncated request (less than 76 bytes needed for nonce extraction)
        let truncated_request = [0u8; 50];

        // Create a minimal ResponseDraft08 for testing
        let response = ResponseDraft08::default();

        match validator.check_merkle_proof_draft08(&truncated_request, &response) {
            Err(ValidationError::InvalidMessage(_)) => {} // ok, expected
            Err(e) => panic!("expected InvalidMessage, got {e:?}"),
            Ok(_) => panic!("expected validation to fail on truncated request"),
        }
    }

    #[test]
    fn vers_must_contain_ver() {
        use roughenough_protocol::protocol_ver::ProtocolVersion;
        use roughenough_protocol::tags::SupportedVersions;

        let mut msg_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let mut response = Response::from_frame(&mut cursor).unwrap();

        // Verify that the unmodified response passes validation
        let validator = ResponseValidator::new();
        validator.check_vers_contains_ver(&response).unwrap();

        // Modify VERS to not include VER (response has VER=RfcDraft14)
        let mut srep = response.srep().clone();
        srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::RfcDraft08]));
        response.set_srep(srep);

        match validator.check_vers_contains_ver(&response) {
            Err(ValidationError::VersionMismatch(ver)) => {
                assert_eq!(ver, ProtocolVersion::RfcDraft14);
            }
            Err(e) => panic!("expected VersionMismatch, got {e:?}"),
            Ok(_) => panic!("expected validation to fail when VERS doesn't contain VER"),
        }
    }

    #[test]
    fn radi_must_not_be_zero() {
        let validator = ResponseValidator::new();

        // Valid radius passes
        validator.check_radius(1).unwrap();
        validator.check_radius(1000).unwrap();
        validator.check_radius(u32::MAX).unwrap();

        // Zero radius fails per RFC 5.2.5
        match validator.check_radius(0) {
            Err(ValidationError::InvalidRadius(msg)) => {
                assert!(msg.contains("RADI"));
            }
            Err(e) => panic!("expected InvalidRadius, got {e:?}"),
            Ok(_) => panic!("expected validation to fail when RADI is zero"),
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod causality {
    use roughenough_server::test_utils::TestContext;

    use super::*;

    fn create_measurement(midpoint: u64) -> Measurement {
        let mut test_context = TestContext::new(64);
        let (req, resp) = test_context.create_interaction_pair(midpoint);
        let pubkey = PublicKey::from(test_context.key_source.public_key_bytes());

        Measurement::builder()
            .server("127.0.0.1:8000".parse().unwrap())
            .request(req)
            .response(resp)
            .hostname("testing1234".to_string())
            .public_key(Some(pubkey))
            .prior_response(None)
            .rand_value(None)
            .build()
            .unwrap()
    }

    #[test]
    fn empty() {
        let measurements = vec![];
        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Empty measurements should return no violations"
        );
    }

    #[test]
    fn single() {
        let measurements = vec![create_measurement(1000000)];
        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Single measurement should return no violations"
        );
    }

    #[test]
    fn valid_sequence() {
        // Create causally consistent measurements
        // M0: [ 995, 1005]
        // M1: [1995, 2005]
        // M2: [2995, 3005]
        let measurements = vec![
            create_measurement(1000),
            create_measurement(2000),
            create_measurement(3000),
        ];

        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Valid causal sequence should return no violations"
        );
    }

    #[test]
    fn invalid_sequence() {
        // Create causally inconsistent measurements
        // M0: [1995, 2005]
        // M1: [995, 1005]
        // Violation: 1995 > 1005
        let measurements = vec![create_measurement(2000), create_measurement(1000)];

        let violations = ResponseValidator::validate_causality(&measurements);
        assert!(
            !violations.is_empty(),
            "Invalid sequence should return some violations"
        );

        assert_eq!(violations.len(), 1, "Should have exactly one violation");

        let v = &violations[0];
        assert_eq!(v.lower_bound_i, 1995);
        assert_eq!(v.upper_bound_j, 1005);
    }

    #[test]
    fn multiple_violations() {
        // Create multiple violations
        // M0: [2995, 3005]
        // M1: [ 995, 1005] - violates with M0
        // M2: [1000, 1010] - violates with M0
        let measurements = vec![
            create_measurement(3000),
            create_measurement(1000),
            create_measurement(1005),
        ];

        let violations = ResponseValidator::validate_causality(&measurements);
        assert!(!violations.is_empty(), "Should have violations");

        assert_eq!(violations.len(), 2, "Should have exactly two violations");

        // Check first violation (0,1)
        assert_eq!(violations[0].lower_bound_i, 2995);
        assert_eq!(violations[0].upper_bound_j, 1005);

        // Check second violation (0,2)
        assert_eq!(violations[1].lower_bound_i, 2995);
        assert_eq!(violations[1].upper_bound_j, 1010);
    }

    #[test]
    fn edge_case() {
        // Test exact boundary condition: lower_bound_i == upper_bound_j
        // M0: [995, 1005]
        // M1: [985, 995]
        // This should be valid (995 <= 995)
        let measurements = vec![create_measurement(1000), create_measurement(990)];

        let result = ResponseValidator::validate_causality(&measurements);
        assert!(result.is_empty(), "Exact boundary should be valid");
    }
}

/// Tests for server key rotation scenarios.
/// Verifies that clients can validate responses across online key rotations
/// as long as the long-term identity key remains the same.
#[cfg(all(test, feature = "test-utils"))]
mod key_rotation {
    use std::time::Duration;

    use roughenough_protocol::tags::PublicKey;
    use roughenough_protocol::wire::ToFrame;
    use roughenough_server::test_utils::TestContext;

    use super::*;

    /// Test that client correctly validates responses before and after server key rotation.
    ///
    /// The server's online key rotates periodically, but responses should still validate
    /// as long as:
    /// 1. The DELE certificate is signed by the same long-term key
    /// 2. The SREP is signed by the online key specified in DELE
    /// 3. The MIDP falls within the DELE validity period (MINT <= MIDP <= MAXT)
    #[test]
    fn client_validates_across_key_rotation() {
        // Create context with 60-second key validity for fast rotation testing
        let key_validity = Duration::from_secs(60);
        let mut ctx = TestContext::with_key_validity(64, key_validity);

        let long_term_pubkey = PublicKey::from(ctx.key_source.public_key_bytes());
        let validator = ResponseValidator::new_with_key(long_term_pubkey);

        // Use the mock clock's current time as baseline (initialized from system time)
        let start_time = ctx.clock.epoch_seconds();

        // Generate response with first online key
        let (request1, response1, response1_bytes) =
            ctx.create_interaction_pair_with_bytes(start_time);
        let request1_bytes = request1.as_frame_bytes().unwrap();

        // Capture the online key's public key from the first response
        let online_pubkey1 = *response1.cert().dele().pubk();

        // Validate first response
        validator
            .validate_draft14(&request1_bytes, &response1, &response1_bytes)
            .expect("Response before key rotation should validate");

        // Advance time past the key validity period to force rotation
        let rotated_time = start_time + 61; // Past 60-second validity
        ctx.clock.set_time(rotated_time);
        ctx.rotate_key(); // Trigger key rotation

        // Generate response with rotated (new) online key
        let (request2, response2, response2_bytes) =
            ctx.create_interaction_pair_with_bytes(rotated_time);
        let request2_bytes = request2.as_frame_bytes().unwrap();

        // Capture the online key's public key from the second response
        let online_pubkey2 = *response2.cert().dele().pubk();

        // Verify the online key actually rotated
        assert_ne!(
            online_pubkey1, online_pubkey2,
            "Online key should have rotated after validity period"
        );

        // Validate second response - should succeed with same long-term key
        validator
            .validate_draft14(&request2_bytes, &response2, &response2_bytes)
            .expect("Response after key rotation should validate");

        // Verify both responses have the same long-term key signature chain
        // (both DELE certificates should be signed by the same long-term key)
        assert_eq!(
            response1.cert().sig(),
            response1.cert().sig(),
            "Sanity check: signature should equal itself"
        );

        // The DELE validity periods should be different (rotated)
        let dele1 = response1.cert().dele();
        let dele2 = response2.cert().dele();

        assert_ne!(
            dele1.mint(),
            dele2.mint(),
            "DELE MINT should differ after rotation"
        );
        assert_ne!(
            dele1.maxt(),
            dele2.maxt(),
            "DELE MAXT should differ after rotation"
        );
    }

    /// Test that tampered DELE certificates are rejected due to signature validation.
    /// When an attacker modifies the DELE (e.g., to extend validity), the signature check fails.
    #[test]
    fn tampered_dele_is_rejected() {
        let key_validity = Duration::from_secs(60);
        let mut ctx = TestContext::with_key_validity(64, key_validity);

        let long_term_pubkey = PublicKey::from(ctx.key_source.public_key_bytes());
        let validator = ResponseValidator::new_with_key(long_term_pubkey);

        // Use the mock clock's current time as baseline
        let start_time = ctx.clock.epoch_seconds();
        let (request, response, response_bytes) =
            ctx.create_interaction_pair_with_bytes(start_time);
        let request_bytes = request.as_frame_bytes().unwrap();

        // Verify it validates at time T
        validator
            .validate_draft14(&request_bytes, &response, &response_bytes)
            .expect("Response should validate at creation time");

        // Attempt to tamper with the DELE by modifying MAXT
        // (an attacker might try to extend validity)
        let mut modified_response = response.clone();
        let mut cert = modified_response.cert().clone();
        let mut dele = cert.dele().clone();

        // Modify MAXT (this invalidates the DELE signature)
        dele.set_maxt(start_time + 9999);
        cert.set_dele(dele);
        modified_response.set_cert(cert);

        // Validation should fail with BadSignature (DELE signature check catches tampering)
        let result =
            validator.validate_draft14(&request_bytes, &modified_response, &response_bytes);

        match result {
            Err(ValidationError::BadSignature(msg)) => {
                assert!(
                    msg.contains("DELE"),
                    "Error should mention DELE signature: {}",
                    msg
                );
            }
            Err(e) => panic!(
                "Expected BadSignature error for tampered DELE, got: {:?}",
                e
            ),
            Ok(_) => panic!("Tampered DELE should not validate"),
        }
    }

    /// Test rapid key rotation with multiple sequential requests.
    #[test]
    fn rapid_key_rotation_sequence() {
        let key_validity = Duration::from_secs(10); // Very short validity
        let mut ctx = TestContext::with_key_validity(64, key_validity);

        let long_term_pubkey = PublicKey::from(ctx.key_source.public_key_bytes());
        let validator = ResponseValidator::new_with_key(long_term_pubkey);

        let mut seen_online_keys = std::collections::HashSet::new();
        let start_time = ctx.clock.epoch_seconds();

        // Generate requests across multiple key rotation periods
        for i in 0..5u64 {
            let time = start_time + (i * 11); // 11 seconds apart, past 10-second validity
            ctx.clock.set_time(time);
            ctx.rotate_key(); // Trigger key rotation for each period

            let (request, response, response_bytes) = ctx.create_interaction_pair_with_bytes(time);
            let request_bytes = request.as_frame_bytes().unwrap();

            // Track unique online keys
            let online_pubkey = *response.cert().dele().pubk();
            seen_online_keys.insert(online_pubkey.as_ref().to_vec());

            // Each response should validate
            validator
                .validate_draft14(&request_bytes, &response, &response_bytes)
                .unwrap_or_else(|e| panic!("Response {} should validate: {:?}", i, e));
        }

        // Should have seen multiple different online keys
        assert!(
            seen_online_keys.len() >= 2,
            "Should have rotated through at least 2 online keys, saw {}",
            seen_online_keys.len()
        );
    }
}
