use std::time::Duration;

use roughenough_protocol::ToWire;
use roughenough_protocol::tags::{Certificate, Delegation, ProtocolVersion, PublicKey, Signature};
use roughenough_protocol::util::ClockSource;

use crate::online::onlinekey::{OnlineKeyDraft08, OnlineKeyDraft14};
use crate::seed::SeedBackend;

/// The server's long-term Ed25519 identity.
pub struct LongTermIdentity {
    seed: Box<dyn SeedBackend>,
    version: ProtocolVersion,
}

impl LongTermIdentity {
    pub fn new(version: ProtocolVersion, seed: Box<dyn SeedBackend>) -> LongTermIdentity {
        assert_eq!(seed.seed_len(), 32, "seed must be 32 bytes long");

        LongTermIdentity { seed, version }
    }

    /// Retrieves the raw public key bytes associated with this LongTermIdentity.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.seed.public_key_bytes()
    }

    /// Retrieves the public key associated with this LongTermIdentity.
    pub fn public_key(&self) -> PublicKey {
        self.seed.public_key()
    }

    /// Creates a new draft-14 online key and delegation certificate (CERT) signed by the
    /// long-term key. The new online key shares the [`ClockSource`] provided. The delegation
    /// is valid from the current `now` time to `now + validity_length` in the future.
    ///
    /// # Arguments
    ///
    /// * `clock` - Clock source for determining certificate validity timestamps. The returned
    ///   online key will use this clock source.
    /// * `validity_length` - Length of time the generated online key will be valid.
    ///
    /// # Returns
    ///
    /// A valid [`OnlineKeyDraft14`] where its delegation certificate (CERT) proves the online
    /// key is authorized by this long-term identity.
    pub fn make_online_key_draft14(
        &mut self,
        clock: &ClockSource,
        validity_length: Duration,
    ) -> OnlineKeyDraft14 {
        let now = clock.epoch_seconds();
        let mut olk = OnlineKeyDraft14::new(self.version, clock.clone());
        let pubkey = PublicKey::from(olk.public_key_bytes());
        let dele = Delegation::new(pubkey, now, validity_length);

        let mut to_sign = self.version.dele_prefix().to_vec();
        to_sign.extend_from_slice(&dele.as_bytes().expect("DELE serialization should not fail"));

        let dele_sig: [u8; 64] = self
            .seed
            .sign(&to_sign)
            .expect("should not fail; can't continue if it does");
        let sig = Signature::from(dele_sig);
        let cert = Certificate::new(sig, dele);
        olk.set_cert(cert);

        olk
    }

    /// Creates a new draft-08 online key and delegation certificate (CERT) signed by the
    /// long-term key. The new online key shares the [`ClockSource`] provided. The delegation
    /// is valid from the current `now` time to `now + validity_length` in the future.
    ///
    /// # Arguments
    ///
    /// * `clock` - Clock source for determining certificate validity timestamps. The returned
    ///   online key will use this clock source.
    /// * `validity_length` - Length of time the generated online key will be valid.
    ///
    /// # Returns
    ///
    /// A valid [`OnlineKeyDraft08`] where its delegation certificate (CERT) proves the online
    /// key is authorized by this long-term identity.
    pub fn make_online_key_draft08(
        &mut self,
        clock: &ClockSource,
        validity_length: Duration,
    ) -> OnlineKeyDraft08 {
        let now = clock.epoch_seconds();
        let mut olk = OnlineKeyDraft08::new(clock.clone());
        let pubkey = PublicKey::from(olk.public_key_bytes());
        let dele = Delegation::new(pubkey, now, validity_length);

        let mut to_sign = ProtocolVersion::RfcDraft08.dele_prefix().to_vec();
        to_sign.extend_from_slice(&dele.as_bytes().expect("DELE serialization should not fail"));

        let dele_sig: [u8; 64] = self
            .seed
            .sign(&to_sign)
            .expect("should not fail; can't continue if it does");
        let sig = Signature::from(dele_sig);
        let cert = Certificate::new(sig, dele);
        olk.set_cert(cert);

        olk
    }
}
