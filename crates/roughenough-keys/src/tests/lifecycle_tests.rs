#[cfg(test)]
mod tests {
    use std::time::Duration;

    use roughenough_protocol::tags::ProtocolVersion;
    use roughenough_protocol::util::ClockSource;

    use crate::longterm::LongTermIdentity;
    use crate::online::{OnlineKeyDraft08, OnlineKeyDraft14};
    use crate::seed::MemoryBackend;

    // Helper function to check if a draft-14 key is expired based on current time
    fn is_key_expired_draft14(key: &OnlineKeyDraft14, clock: &ClockSource) -> bool {
        let now = clock.epoch_seconds();
        let maxt = key.cert().dele().maxt();
        now >= maxt
    }

    // Helper function to check if a draft-08 key is expired based on current time
    fn is_key_expired_draft08(key: &OnlineKeyDraft08, clock: &ClockSource) -> bool {
        let now = clock.epoch_seconds();
        let maxt = key.cert().dele().maxt();
        now >= maxt
    }

    // Helper function to verify draft-14 key validity window
    fn verify_validity_window_draft14(
        key: &OnlineKeyDraft14,
        expected_mint: u64,
        expected_duration: u64,
    ) {
        let dele = key.cert().dele();
        assert_eq!(dele.mint(), expected_mint);
        assert_eq!(dele.maxt(), expected_mint + expected_duration);
    }

    // Helper function to verify draft-08 key validity window
    fn verify_validity_window_draft08(
        key: &OnlineKeyDraft08,
        expected_mint: u64,
        expected_duration: u64,
    ) {
        let dele = key.cert().dele();
        assert_eq!(dele.mint(), expected_mint);
        assert_eq!(dele.maxt(), expected_mint + expected_duration);
    }

    // ==================== Draft-14 Tests ====================

    #[test]
    fn online_key_has_correct_validity_period_draft14() {
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);

        let online_key = identity.make_online_key_draft14(&clock, validity_duration);

        verify_validity_window_draft14(&online_key, start_time, validity_duration.as_secs());
    }

    #[test]
    fn detect_expired_online_key_draft14() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);
        let online_key = identity.make_online_key_draft14(&clock, validity_duration);

        assert!(!is_key_expired_draft14(&online_key, &clock));

        clock.set_time(start_time + 3599);
        assert!(!is_key_expired_draft14(&online_key, &clock));

        clock.set_time(start_time + 3600);
        assert!(is_key_expired_draft14(&online_key, &clock));

        clock.set_time(start_time + 7200);
        assert!(is_key_expired_draft14(&online_key, &clock));
    }

    #[test]
    fn multiple_key_rotations_over_time_draft14() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(100);
        let rotation_interval = 50u64;

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);

        let mut keys = Vec::new();
        let mut current_time = start_time;

        for i in 0..5 {
            let key = identity.make_online_key_draft14(&clock, validity_duration);
            verify_validity_window_draft14(&key, current_time, validity_duration.as_secs());
            keys.push(key);

            if i < 4 {
                current_time += rotation_interval;
                clock.set_time(current_time);
            }
        }

        assert_eq!(keys.len(), 5);

        let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key_bytes()).collect();
        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j]);
            }
        }

        for i in 0..keys.len() - 1 {
            let current_maxt = keys[i].cert().dele().maxt();
            let next_mint = keys[i + 1].cert().dele().mint();
            assert!(next_mint < current_maxt);
        }
    }

    #[test]
    fn handle_request_at_validity_boundary_draft14() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);
        let mut online_key = identity.make_online_key_draft14(&clock, validity_duration);

        clock.set_time(start_time + 3599);

        let merkle_root = roughenough_protocol::tags::MerkleRoot::from([0x42; 32]);
        let (srep, sig) = online_key.make_srep(&merkle_root);

        assert_eq!(srep.root(), &merkle_root);
        assert_eq!(srep.midp(), start_time + 3599);
        assert_ne!(sig.as_ref(), vec![0u8; 64]);
    }

    #[test]
    fn ensure_key_validity_overlap_draft14() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);
        let rotation_interval = 1800u64;

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);

        let first_key = identity.make_online_key_draft14(&clock, validity_duration);

        clock.set_time(start_time + rotation_interval);
        let second_key = identity.make_online_key_draft14(&clock, validity_duration);

        let first_maxt = first_key.cert().dele().maxt();
        let second_mint = second_key.cert().dele().mint();

        assert!(second_mint < first_maxt);

        let overlap_duration = first_maxt - second_mint;
        assert_eq!(overlap_duration, 1800);

        clock.set_time(start_time + rotation_interval + 900);
        assert!(!is_key_expired_draft14(&first_key, &clock));
        assert!(!is_key_expired_draft14(&second_key, &clock));
    }

    #[test]
    fn key_properties_remain_consistent_draft14() {
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft14, backend);
        let mut online_key = identity.make_online_key_draft14(&clock, validity_duration);

        let merkle_root = roughenough_protocol::tags::MerkleRoot::from([0x77; 32]);
        let (srep, _) = online_key.make_srep(&merkle_root);

        assert_eq!(srep.midp(), start_time);
        assert_eq!(*srep.ver(), ProtocolVersion::RfcDraft14);
        assert_eq!(srep.root(), &merkle_root);
    }

    // ==================== Draft-08 Tests ====================

    #[test]
    fn online_key_has_correct_validity_period_draft08() {
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);

        let online_key = identity.make_online_key_draft08(&clock, validity_duration);

        verify_validity_window_draft08(&online_key, start_time, validity_duration.as_secs());
    }

    #[test]
    fn detect_expired_online_key_draft08() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);
        let online_key = identity.make_online_key_draft08(&clock, validity_duration);

        assert!(!is_key_expired_draft08(&online_key, &clock));

        clock.set_time(start_time + 3599);
        assert!(!is_key_expired_draft08(&online_key, &clock));

        clock.set_time(start_time + 3600);
        assert!(is_key_expired_draft08(&online_key, &clock));

        clock.set_time(start_time + 7200);
        assert!(is_key_expired_draft08(&online_key, &clock));
    }

    #[test]
    fn multiple_key_rotations_over_time_draft08() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(100);
        let rotation_interval = 50u64;

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);

        let mut keys = Vec::new();
        let mut current_time = start_time;

        for i in 0..5 {
            let key = identity.make_online_key_draft08(&clock, validity_duration);
            verify_validity_window_draft08(&key, current_time, validity_duration.as_secs());
            keys.push(key);

            if i < 4 {
                current_time += rotation_interval;
                clock.set_time(current_time);
            }
        }

        assert_eq!(keys.len(), 5);

        let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key_bytes()).collect();
        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j]);
            }
        }

        for i in 0..keys.len() - 1 {
            let current_maxt = keys[i].cert().dele().maxt();
            let next_mint = keys[i + 1].cert().dele().mint();
            assert!(next_mint < current_maxt);
        }
    }

    #[test]
    fn handle_request_at_validity_boundary_draft08() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);
        let mut online_key = identity.make_online_key_draft08(&clock, validity_duration);

        clock.set_time(start_time + 3599);

        let merkle_root = roughenough_protocol::tags::MerkleRoot::from([0x42; 32]);
        let (srep, sig) = online_key.make_srep(&merkle_root);

        assert_eq!(srep.root(), &merkle_root);
        assert_eq!(srep.midp(), start_time + 3599);
        assert_ne!(sig.as_ref(), vec![0u8; 64]);
    }

    #[test]
    fn ensure_key_validity_overlap_draft08() {
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);
        let rotation_interval = 1800u64;

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);

        let first_key = identity.make_online_key_draft08(&clock, validity_duration);

        clock.set_time(start_time + rotation_interval);
        let second_key = identity.make_online_key_draft08(&clock, validity_duration);

        let first_maxt = first_key.cert().dele().maxt();
        let second_mint = second_key.cert().dele().mint();

        assert!(second_mint < first_maxt);

        let overlap_duration = first_maxt - second_mint;
        assert_eq!(overlap_duration, 1800);

        clock.set_time(start_time + rotation_interval + 900);
        assert!(!is_key_expired_draft08(&first_key, &clock));
        assert!(!is_key_expired_draft08(&second_key, &clock));
    }

    #[test]
    fn key_properties_remain_consistent_draft08() {
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(ProtocolVersion::RfcDraft08, backend);
        let mut online_key = identity.make_online_key_draft08(&clock, validity_duration);

        let merkle_root = roughenough_protocol::tags::MerkleRoot::from([0x77; 32]);
        let (srep, _) = online_key.make_srep(&merkle_root);

        // Draft-08 SREP has only 3 tags: RADI, MIDP, ROOT (no VER, no VERS)
        assert_eq!(srep.midp(), start_time);
        assert_eq!(srep.root(), &merkle_root);
    }
}
