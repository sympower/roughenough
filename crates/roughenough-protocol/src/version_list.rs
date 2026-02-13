use std::fmt::Debug;

use Error::UnorderedVersion;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::protocol_ver::ProtocolVersion;
use crate::wire::{FromWire, FromWireN, ToWire};

/// An ordered list of supported protocol versions. Used by clients in VER, and servers in VERS:
///
/// ```text
/// 5.1.1.  VER
/// In a request, the VER tag contains a list of uint32 version numbers.
/// The VER tag MUST include at least one Roughtime version supported by
/// the client and MUST NOT contain more than 32 version numbers.  The
/// client MUST ensure that the version numbers and tags included in the
/// request are not incompatible with each other or the packet contents.
///
/// The version numbers MUST NOT repeat and MUST be sorted in ascending
/// numerical order.
/// ```
///
/// ```text
/// 5.2.5.  SREP
/// ...
/// The VERS tag value MUST contain a list of uint32 version numbers
/// supported by the server, sorted in ascending numerical order.  It
/// MUST contain the version number specified in the VER tag.  It MUST
/// NOT contain more than 32 version numbers.
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct VersionList {
    versions: Vec<ProtocolVersion>,
}

impl VersionList {
    /// Maximum # of versions to hold. Excess versions (if present) will be discarded.
    pub const MAX_VERSIONS: usize = 32;
}

impl Debug for VersionList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionList")
            .field("num_versions", &self.versions.len())
            .field("versions", &self.versions)
            .finish()
    }
}

impl VersionList {
    pub fn new(versions: &[ProtocolVersion]) -> Self {
        let count = std::cmp::min(versions.len(), Self::MAX_VERSIONS);
        Self {
            versions: versions[..count].to_vec(),
        }
    }

    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions
    }

    pub fn is_supported(&self, version: ProtocolVersion) -> bool {
        self.versions.contains(&version)
    }
}

impl ToWire for VersionList {
    fn wire_size(&self) -> usize {
        self.versions.len() * size_of::<ProtocolVersion>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        for version in &self.versions {
            version.to_wire(cursor)?;
        }
        Ok(())
    }
}

impl FromWire for VersionList {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        VersionList::from_wire_n(cursor, cursor.remaining())
    }
}

impl FromWireN for VersionList {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        let mut remaining = n;
        let mut versions = Vec::new();
        let mut prior_version: Option<ProtocolVersion> = None;

        while remaining > 0 && versions.len() < Self::MAX_VERSIONS {
            let version = ProtocolVersion::from_wire(cursor)?;

            // This implementation verifies that the versions are in ascending order,
            // but does not consider duplicates an error. That might change in the future.
            if let Some(prior) = prior_version
                && version < prior
            {
                return Err(UnorderedVersion(versions.len() as u32, version as u32));
            }

            prior_version = Some(version);
            remaining -= version.wire_size();
            versions.push(version);
        }

        Ok(Self { versions })
    }
}

impl From<&[ProtocolVersion]> for VersionList {
    fn from(versions: &[ProtocolVersion]) -> Self {
        VersionList::new(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let versions =
            VersionList::new(&[ProtocolVersion::RfcDraft08, ProtocolVersion::RfcDraft14]);

        let wire_size = versions.wire_size();
        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            versions.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let versions2 = VersionList::from_wire(&mut cursor).unwrap();

        assert_eq!(versions, versions2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn default() {
        let versions = VersionList::default();
        assert!(versions.versions().is_empty());
    }

    #[test]
    fn new() {
        let versions = VersionList::new(&[ProtocolVersion::RfcDraft08]);
        assert_eq!(versions.versions(), &[ProtocolVersion::RfcDraft08]);
        assert!(versions.is_supported(ProtocolVersion::RfcDraft08));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }

    #[test]
    fn zero_versions() {
        let versions = VersionList::new(&[]);
        assert!(versions.versions().is_empty());
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft08));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }

    #[test]
    fn max_versions() {
        let tmp = (0..VersionList::MAX_VERSIONS * 2)
            .map(|_| ProtocolVersion::RfcDraft14)
            .collect::<Vec<_>>();

        let versions = VersionList::new(&tmp);

        // overly long input list is truncated to MAX_VERSIONS
        assert_eq!(versions.versions().len(), VersionList::MAX_VERSIONS);
    }

    #[test]
    fn versions_out_of_order() {
        // Create a VersionList with versions in descending order (RfcDraft14 > RfcDraft08)
        let versions =
            VersionList::new(&[ProtocolVersion::RfcDraft14, ProtocolVersion::RfcDraft08]);

        // Serialize to wire format
        let mut buf = vec![0u8; versions.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            versions.to_wire(&mut cursor).unwrap();
        }

        // Attempt to deserialize - should fail because versions are not in ascending order
        let mut cursor = ParseCursor::new(&mut buf);
        let result = VersionList::from_wire(&mut cursor);
        assert!(result.is_err(), "out-of-order versions should be rejected");

        match result.unwrap_err() {
            UnorderedVersion(1, _) => (), // ok, expected at index 1
            e => panic!("unexpected error: {e:?}"),
        }
    }
}
