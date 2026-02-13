use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use roughenough_protocol::ToWire;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::tags::{
    Certificate, MerkleRoot, ProtocolVersion, PublicKey, Signature, SignedResponse,
    SignedResponseDraft08, SupportedVersions,
};
use roughenough_protocol::util::ClockSource;

// An online key is a randomly generated Ed25519 key pair with a time-bounded validity period.
// The long-term identity signs a delegation (DELE) containing the online key's public key,
// authorizing it to sign responses on behalf of the server. Online keys sign SREP (signed
// response) messages that authenticate the server's timestamps to clients.
//
// Create an online key by calling `LongTermIdentity::make_online_key_draft14()` or
// `LongTermIdentity::make_online_key_draft08()`.

/// Online key for RFC draft-14 protocol.
///
/// Creates signed responses with 5 tags: VER, RADI, MIDP, VERS, ROOT.
pub struct OnlineKeyDraft14 {
    signer: OnlineSigner,
    cert: Certificate,
    clock_source: ClockSource,
    template_srep: SignedResponse,
    signing_buf: Vec<u8>,
}

impl OnlineKeyDraft14 {
    pub fn new(version: ProtocolVersion, clock_source: ClockSource) -> Self {
        let mut template = SignedResponse::default();
        template.set_radi(SignedResponse::DEFAULT_RADI_SECONDS);
        template.set_vers(&SupportedVersions::from([version].as_ref()));
        template.set_ver(version);

        let prefix = ProtocolVersion::RfcDraft14.srep_prefix();
        let mut buf = Vec::with_capacity(prefix.len() + template.wire_size());
        buf.extend_from_slice(prefix);
        buf.resize(buf.capacity(), 0);

        Self {
            signer: OnlineSigner::from_random(),
            cert: Certificate::default(),
            clock_source,
            template_srep: template,
            signing_buf: buf,
        }
    }

    pub(crate) fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
    }

    /// Retrieves the delegation certificate (CERT) associated with this online key.
    pub fn cert(&self) -> &Certificate {
        debug_assert!(
            self.cert != Certificate::default(),
            "logic error to use an online key without setting a delegation certificate"
        );
        &self.cert
    }

    /// Retrieves the public key associated with this online key.
    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// Retrieves the raw public key bytes associated with this online key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.public_key_bytes()
    }

    /// Signs the provided data using the private key associated with this online key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signer.sign(data)
    }

    /// Creates a signed response (SREP) and corresponding cryptographic signature.
    ///
    /// This method generates a `SignedResponse` containing the current timestamp, server radius,
    /// protocol version information, and the provided Merkle root. The SREP is then signed with
    /// this online key.
    ///
    /// # Arguments
    ///
    /// * `root` - The Merkle tree root hash that commits to the batch of client requests being
    ///   processed. This root allows clients to verify their request was included in the batch.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `SignedResponse` - The complete SREP structure with timestamp, radius, versions, and root
    /// - `Signature` - Ed25519 signature over the SREP
    pub fn make_srep(&mut self, root: &MerkleRoot) -> (SignedResponse, Signature) {
        let mut srep = self.template_srep.clone();
        srep.set_root(root);
        srep.set_midp(self.clock_source.epoch_seconds());

        let prefix_len = ProtocolVersion::RfcDraft14.srep_prefix().len();
        let total_len = prefix_len + srep.wire_size();

        let mut cursor = ParseCursor::new(&mut self.signing_buf[prefix_len..total_len]);
        srep.to_wire(&mut cursor)
            .expect("SREP serialization should not fail");

        let sig_bytes: [u8; 64] = self.sign(&self.signing_buf[..total_len]);
        let sig = Signature::from(sig_bytes);

        (srep, sig)
    }
}

/// Online key for RFC draft-08 protocol.
///
/// Creates signed responses with 3 tags: RADI, MIDP, ROOT.
pub struct OnlineKeyDraft08 {
    signer: OnlineSigner,
    cert: Certificate,
    clock_source: ClockSource,
    template_srep: SignedResponseDraft08,
    signing_buf: Vec<u8>,
}

impl OnlineKeyDraft08 {
    pub fn new(clock_source: ClockSource) -> Self {
        let mut template = SignedResponseDraft08::default();
        template.set_radi(SignedResponseDraft08::DEFAULT_RADI_SECONDS);

        let prefix = ProtocolVersion::RfcDraft08.srep_prefix();
        let mut buf = Vec::with_capacity(prefix.len() + template.wire_size());
        buf.extend_from_slice(prefix);
        buf.resize(buf.capacity(), 0);

        Self {
            signer: OnlineSigner::from_random(),
            cert: Certificate::default(),
            clock_source,
            template_srep: template,
            signing_buf: buf,
        }
    }

    pub(crate) fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
    }

    /// Retrieves the delegation certificate (CERT) associated with this online key.
    pub fn cert(&self) -> &Certificate {
        debug_assert!(
            self.cert != Certificate::default(),
            "logic error to use an online key without setting a delegation certificate"
        );
        &self.cert
    }

    /// Retrieves the public key associated with this online key.
    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// Retrieves the raw public key bytes associated with this online key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.public_key_bytes()
    }

    /// Signs the provided data using the private key associated with this online key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signer.sign(data)
    }

    /// Creates a signed response (SREP) and corresponding cryptographic signature.
    ///
    /// This method generates a `SignedResponseDraft08` containing the current timestamp, server
    /// radius, and the provided Merkle root. The SREP is then signed with this online key.
    ///
    /// # Arguments
    ///
    /// * `root` - The Merkle tree root hash that commits to the batch of client requests being
    ///   processed. This root allows clients to verify their request was included in the batch.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `SignedResponseDraft08` - The complete SREP structure with timestamp, radius, and root
    /// - `Signature` - Ed25519 signature over the SREP
    pub fn make_srep(&mut self, root: &MerkleRoot) -> (SignedResponseDraft08, Signature) {
        let mut srep = self.template_srep.clone();
        srep.set_root(root);
        srep.set_midp(self.clock_source.epoch_seconds());

        let prefix_len = ProtocolVersion::RfcDraft08.srep_prefix().len();
        let total_len = prefix_len + srep.wire_size();

        let mut cursor = ParseCursor::new(&mut self.signing_buf[prefix_len..total_len]);
        srep.to_wire(&mut cursor)
            .expect("SREP serialization should not fail");

        let sig_bytes: [u8; 64] = self.sign(&self.signing_buf[..total_len]);
        let sig = Signature::from(sig_bytes);

        (srep, sig)
    }
}

pub(crate) struct OnlineSigner {
    key_pair: Ed25519KeyPair,
}

impl OnlineSigner {
    pub(crate) fn from_random() -> OnlineSigner {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        OnlineSigner { key_pair }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key_bytes())
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("infallible")
    }

    pub(crate) fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.key_pair
            .sign(data)
            .as_ref()
            .try_into()
            .expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_random_produces_different_keys() {
        let signers: Vec<_> = (0..10).map(|_| OnlineSigner::from_random()).collect();
        let pubkeys: Vec<_> = signers.iter().map(|s| s.public_key_bytes()).collect();

        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j], "Generated keys should be different");
            }
        }
    }

    #[test]
    fn public_key_methods_are_consistent() {
        let signer = OnlineSigner::from_random();

        let pubkey = signer.public_key();
        let pubkey_bytes = signer.public_key_bytes();

        assert_eq!(pubkey.as_ref(), &pubkey_bytes);

        let pubkey_from_bytes = PublicKey::from(pubkey_bytes);
        assert_eq!(pubkey, pubkey_from_bytes);
    }
}
