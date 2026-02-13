use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{NoSupportedVersions, UnexpectedOffsets, UnexpectedTags};
use crate::header::{Header, Header3, Header5};
use crate::tag::Tag;
use crate::tags::{MerkleRoot, ProtocolVersion, SupportedVersions};
use crate::wire::{FromWire, FromWireN, ToWire};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedResponse {
    header: Header5,
    version: ProtocolVersion,
    radius: u32,
    midpoint: u64,
    supported_versions: SupportedVersions,
    merkle_root: MerkleRoot,
}

impl SignedResponse {
    /// Default server accuracy radius in seconds.
    ///
    /// The RADI tag represents the server's estimate of the accuracy of its MIDP (timestamp)
    /// in seconds. Protocol compliant servers must ensure that the true time lies within the
    /// interval (MIDP-RADI, MIDP+RADI) at the moment of processing.
    ///
    /// The RFC states that servers without leap second information should set RADI to
    /// at least 3 seconds. This implementation uses 5 seconds as a conservative default
    /// to account for potential system latency and clock uncertainty. Also leap seconds suck.
    pub const DEFAULT_RADI_SECONDS: u32 = 5;

    const RADI_OFFSET: u32 = size_of::<ProtocolVersion>() as u32;
    const MIDP_OFFSET: u32 = Self::RADI_OFFSET + (size_of::<u32>() as u32);
    const VERS_OFFSET: u32 = Self::MIDP_OFFSET + (size_of::<u64>() as u32);

    // The size of VERS varies, thus the fourth offset (for ROOT) needs to be computed at runtime
    // (in the `set_vers()` method).
    const OFFSETS: [u32; 4] = [Self::RADI_OFFSET, Self::MIDP_OFFSET, Self::VERS_OFFSET, 0];
    const TAGS: [Tag; 5] = [Tag::VER, Tag::RADI, Tag::MIDP, Tag::VERS, Tag::ROOT];

    pub fn header(&self) -> &impl Header {
        &self.header
    }

    pub fn ver(&self) -> &ProtocolVersion {
        &self.version
    }

    pub fn radi(&self) -> u32 {
        self.radius
    }

    pub fn midp(&self) -> u64 {
        self.midpoint
    }

    pub fn vers(&self) -> &SupportedVersions {
        &self.supported_versions
    }

    pub fn root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    pub fn set_ver(&mut self, version: ProtocolVersion) {
        self.version = version;
    }

    pub fn set_radi(&mut self, radius: u32) {
        self.radius = radius;
    }

    pub fn set_midp(&mut self, midpoint: u64) {
        self.midpoint = midpoint;
    }

    pub fn set_vers(&mut self, versions: &SupportedVersions) {
        self.supported_versions = versions.clone();

        // fix up the offset now that the length of SupportedVersions is known
        self.header.offsets[3] = Self::VERS_OFFSET + (self.supported_versions.wire_size() as u32);
    }

    pub fn set_root(&mut self, root: &MerkleRoot) {
        self.merkle_root = *root;
    }
}

impl Default for SignedResponse {
    fn default() -> Self {
        let mut srep = Self {
            header: Header5::default(),
            version: ProtocolVersion::RfcDraft14,
            radius: 0,
            midpoint: 0,
            supported_versions: SupportedVersions::default(),
            merkle_root: MerkleRoot::default(),
        };

        // The fourth offset will be set once the length of SupportedVersions is known.
        // See `SignedResponse::set_vers()`
        srep.header.offsets = Self::OFFSETS;
        srep.header.tags = Self::TAGS;
        srep
    }
}

impl ToWire for SignedResponse {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + size_of::<u32>()
            + size_of::<u64>()
            + self.supported_versions.wire_size()
            + self.merkle_root.wire_size()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        cursor.put_u32_le(self.radius);
        cursor.put_u64_le(self.midpoint);
        self.supported_versions.to_wire(cursor)?;
        self.merkle_root.to_wire(cursor)?;
        Ok(())
    }
}

impl FromWire for SignedResponse {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header5::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut srep = SignedResponse {
            header,
            ..Default::default()
        };

        let offsets = srep.header.offsets();

        if offsets[..3] != Self::OFFSETS[..3] {
            return Err(UnexpectedOffsets);
        }

        // The VERS value is zero-length, no supported versions
        if offsets[2] == offsets[3] {
            return Err(NoSupportedVersions);
        }

        srep.version = ProtocolVersion::from_wire(cursor)?;
        srep.radius = cursor.try_get_u32_le()?;
        srep.midpoint = cursor.try_get_u64_le()?;

        let vers_size = (offsets[3] - offsets[2]) as usize;
        srep.supported_versions = SupportedVersions::from_wire_n(cursor, vers_size)?;

        // cursor holds remainder of message
        srep.merkle_root = MerkleRoot::from_wire(cursor)?;

        Ok(srep)
    }
}

/// Draft-08 compatible signed response (SREP) format.
///
/// This is the inner signed response from servers implementing IETF draft-ietf-ntp-roughtime-08.
/// The server signs this structure with its online key.
///
/// # Wire Format
///
/// Draft-08 SREP has 3 tags: RADI, MIDP, ROOT (no VER, no VERS).
///
/// ```text
/// +------+------+------+
/// | RADI | MIDP | ROOT |
/// +------+------+------+
/// ```
///
/// # Differences from Draft-14
///
/// - No VER tag (draft-14 includes the negotiated protocol version)
/// - No VERS tag (draft-14 includes all versions the server supports)
/// - Signature prefix is "RoughTime v1 response signature\0" (vs. draft-14's context string)
///
/// # Conversion
///
/// Can be converted to `SignedResponse` (draft-14 format) using `From`:
///
/// ```ignore
/// let draft08_srep: SignedResponseDraft08 = /* ... */;
/// let srep: SignedResponse = SignedResponse::from(draft08_srep);
/// ```
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedResponseDraft08 {
    header: Header3,
    radius: u32,
    midpoint: u64,
    merkle_root: MerkleRoot,
}

impl SignedResponseDraft08 {
    /// Default server accuracy radius in seconds.
    pub const DEFAULT_RADI_SECONDS: u32 = 5;

    const RADI_OFFSET: u32 = size_of::<u32>() as u32;
    const MIDP_OFFSET: u32 = Self::RADI_OFFSET + (size_of::<u64>() as u32);

    const OFFSETS: [u32; 2] = [Self::RADI_OFFSET, Self::MIDP_OFFSET];
    const TAGS: [Tag; 3] = [Tag::RADI, Tag::MIDP, Tag::ROOT];

    pub fn radi(&self) -> u32 {
        self.radius
    }

    pub fn midp(&self) -> u64 {
        self.midpoint
    }

    pub fn root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    pub fn set_radi(&mut self, radius: u32) {
        self.radius = radius;
    }

    pub fn set_midp(&mut self, midpoint: u64) {
        self.midpoint = midpoint;
    }

    pub fn set_root(&mut self, root: &MerkleRoot) {
        self.merkle_root = *root;
    }
}

impl Default for SignedResponseDraft08 {
    fn default() -> Self {
        let mut srep = Self {
            header: Header3::default(),
            radius: 0,
            midpoint: 0,
            merkle_root: MerkleRoot::default(),
        };

        srep.header.offsets = Self::OFFSETS;
        srep.header.tags = Self::TAGS;
        srep
    }
}

impl FromWire for SignedResponseDraft08 {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header3::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut srep = SignedResponseDraft08 {
            header,
            ..Default::default()
        };

        srep.radius = cursor.try_get_u32_le()?;
        srep.midpoint = cursor.try_get_u64_le()?;
        srep.merkle_root = MerkleRoot::from_wire(cursor)?;

        Ok(srep)
    }
}

impl ToWire for SignedResponseDraft08 {
    fn wire_size(&self) -> usize {
        self.header.wire_size() + size_of::<u32>() + size_of::<u64>() + self.merkle_root.wire_size()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        cursor.put_u32_le(self.radius);
        cursor.put_u64_le(self.midpoint);
        self.merkle_root.to_wire(cursor)?;
        Ok(())
    }
}

impl From<SignedResponseDraft08> for SignedResponse {
    /// Convert draft-08 SREP to standard format for downstream compatibility.
    fn from(draft08: SignedResponseDraft08) -> Self {
        let mut srep = SignedResponse::default();
        srep.set_ver(ProtocolVersion::RfcDraft08);
        srep.set_radi(draft08.radius);
        srep.set_midp(draft08.midpoint);
        srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::RfcDraft08]));
        srep.set_root(&draft08.merkle_root);
        srep
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{MerkleRoot, ProtocolVersion, SupportedVersions};

    fn create_valid_signed_response() -> SignedResponse {
        let mut srep = SignedResponse::default();
        srep.set_ver(ProtocolVersion::RfcDraft14);
        srep.set_radi(5);
        srep.set_midp(1234567);
        srep.set_vers(&SupportedVersions::new(&[
            ProtocolVersion::RfcDraft08,
            ProtocolVersion::RfcDraft14,
        ]));
        srep.set_root(&MerkleRoot::from([0x2e; 32]));

        srep
    }

    #[test]
    fn default_value() {
        let srep = SignedResponse::default();
        assert_eq!(srep.ver(), &ProtocolVersion::RfcDraft14);
        assert_eq!(srep.radi(), 0);
        assert_eq!(srep.midp(), 0);
        assert_eq!(srep.vers(), &SupportedVersions::default());
        assert_eq!(srep.root(), &MerkleRoot::default());
    }

    #[test]
    fn wire_roundtrip() {
        let srep1 = create_valid_signed_response();
        let mut buf = vec![0u8; srep1.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            srep1.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        let srep2 = SignedResponse::from_wire(&mut cursor).unwrap();

        assert_eq!(srep1, srep2);
    }

    #[test]
    fn invalid_tags_are_detected() {
        let mut srep = create_valid_signed_response();
        let mut buf = vec![0u8; srep.wire_size()];

        srep.header.tags[4] = Tag::INDX;
        {
            let mut cursor = ParseCursor::new(&mut buf);
            srep.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);

        let result = SignedResponse::from_wire(&mut cursor);
        assert!(result.is_err(), "the tags were modified to be invalid");

        match result {
            Err(UnexpectedTags) => (), // ok, expected
            _ => panic!("unexpected error: {result:?}"),
        }
    }

    // Tests for SignedResponseDraft08

    fn create_valid_signed_response_draft08() -> SignedResponseDraft08 {
        SignedResponseDraft08 {
            radius: 5,
            midpoint: 1234567890,
            merkle_root: MerkleRoot::from([0x3f; 32]),
            ..Default::default()
        }
    }

    #[test]
    fn draft08_default_value() {
        let srep = SignedResponseDraft08::default();
        assert_eq!(srep.radi(), 0);
        assert_eq!(srep.midp(), 0);
        assert_eq!(srep.root(), &MerkleRoot::default());

        // Verify tags (no VER, no VERS)
        assert_eq!(srep.header.tags, [Tag::RADI, Tag::MIDP, Tag::ROOT]);
    }

    #[test]
    fn draft08_wire_roundtrip() {
        let srep1 = create_valid_signed_response_draft08();
        let mut buf = vec![0u8; srep1.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            srep1.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        let srep2 = SignedResponseDraft08::from_wire(&mut cursor).unwrap();

        assert_eq!(srep1, srep2);
    }

    #[test]
    fn draft08_conversion_to_signed_response() {
        let draft08 = create_valid_signed_response_draft08();
        let srep = SignedResponse::from(draft08.clone());

        // Verify conversion preserves values
        assert_eq!(srep.ver(), &ProtocolVersion::RfcDraft08);
        assert_eq!(srep.radi(), draft08.radi());
        assert_eq!(srep.midp(), draft08.midp());
        assert_eq!(srep.root(), draft08.root());

        // Verify VERS contains only draft-08
        assert_eq!(
            srep.vers(),
            &SupportedVersions::new(&[ProtocolVersion::RfcDraft08])
        );
    }

    #[test]
    fn draft08_wire_size() {
        let srep = SignedResponseDraft08::default();

        // header: 4 (num_tags) + 8 (2 offsets) + 12 (3 tags) = 24
        // RADI: 4 bytes
        // MIDP: 8 bytes
        // ROOT: 32 bytes
        // Total: 24 + 4 + 8 + 32 = 68
        assert_eq!(srep.wire_size(), 68);
    }
}
