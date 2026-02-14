use std::fmt::Debug;

use Error::{BadRequestSize, BufferTooSmall, InvalidMessageType, UnexpectedTags};
use Request::{Draft08, Draft14, Draft14Srv};

use crate::FromWireN;
use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::header::{Header, Header3, Header4, Header5};
use crate::protocol_ver::ProtocolVersion;
use crate::tag::Tag;
use crate::tags::ver::RequestedVersions;
use crate::tags::{MessageType, Nonce, SrvCommitment};
use crate::util::as_hex;
use crate::wire::{FromFrame, FromWire, ToFrame, ToWire};

/// RFC 5.1: The size of the request message SHOULD be at least 1024 bytes when
/// the UDP transport mode is used.
///
/// In Roughenough, a Request must be exactly 1024 bytes inclusive of framing
pub const REQUEST_SIZE: usize = 1024;

#[derive(Clone, Eq, PartialEq)]
pub enum Request {
    /// A `Draft08` request has VER, NONC, and ZZZZ tags (no TYPE tag, for draft-08 compatibility)
    Draft08(RequestDraft08),
    /// A `Draft14` request has VER, NONC, TYPE, and ZZZZ tags (no SRV tag)
    Draft14(RequestDraft14),
    /// A `Draft14Srv` request has VER, SRV, NONC, TYPE, and ZZZZ tags
    Draft14Srv(RequestDraft14Srv),
}

impl Request {
    /// Create a draft-14 compatible request (VER, NONC, TYPE, ZZZZ)
    pub fn new_draft14(nonce: &Nonce) -> Self {
        Draft14(RequestDraft14::new(nonce))
    }

    /// Create a draft-08 compatible request (VER, NONC, ZZZZ - no TYPE tag)
    pub fn new_draft08(nonce: &Nonce) -> Self {
        Draft08(RequestDraft08::new(nonce))
    }

    /// Create a draft-14 compatible request with server commitment (VER, SRV, NONC, TYPE, ZZZZ)
    pub fn new_draft14_with_server_commitment(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Draft14Srv(RequestDraft14Srv::new(nonce, server))
    }

    pub fn ver(&self) -> &RequestedVersions {
        match self {
            Draft08(req) => req.ver(),
            Draft14(req) => req.ver(),
            Draft14Srv(req) => req.ver(),
        }
    }

    pub fn nonc(&self) -> &Nonce {
        match self {
            Draft08(req) => req.nonc(),
            Draft14(req) => req.nonc(),
            Draft14Srv(req) => req.nonc(),
        }
    }

    pub fn msg_type(&self) -> MessageType {
        match self {
            Draft08(_) => MessageType::Request,
            Draft14(req) => req.msg_type(),
            Draft14Srv(req) => req.msg_type(),
        }
    }

    pub fn srv(&self) -> Option<&SrvCommitment> {
        match self {
            Draft08(_) => None,
            Draft14(_) => None,
            Draft14Srv(req) => Some(req.srv()),
        }
    }
}

impl ToWire for Request {
    fn wire_size(&self) -> usize {
        match self {
            Draft08(req) => req.wire_size(),
            Draft14(req) => req.wire_size(),
            Draft14Srv(req) => req.wire_size(),
        }
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        match self {
            Draft08(req) => req.to_wire(cursor),
            Draft14(req) => req.to_wire(cursor),
            Draft14Srv(req) => req.to_wire(cursor),
        }
    }
}

impl ToFrame for Request {}

impl FromWire for Request {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        if cursor.remaining() != 1012 {
            return Err(BadRequestSize(cursor.remaining()));
        }

        // Distinguish the variant by peeking at the number of tags.
        // RequestDraft08 has 3 tags, RequestDraft14 has 4 tags, RequestDraft14Srv has 5 tags
        let saved_pos = cursor.position();
        let num_tags = cursor.try_get_u32_le()?;
        cursor.set_position(saved_pos);

        match num_tags {
            3 => Ok(Draft08(RequestDraft08::from_wire(cursor)?)),
            4 => Ok(Draft14(RequestDraft14::from_wire(cursor)?)),
            5 => Ok(Draft14Srv(RequestDraft14Srv::from_wire(cursor)?)),
            _ => Err(Error::InvalidRequestNumTags {
                actual: num_tags,
                expected: "3, 4, or 5",
            }),
        }
    }
}

impl FromFrame for Request {}

impl Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Draft08(req) => req.fmt(f),
            Draft14(req) => req.fmt(f),
            Draft14Srv(req) => req.fmt(f),
        }
    }
}

/// RFC 5.1: A request MUST contain the tags VER, NONC, and TYPE. It SHOULD
/// include the tag SRV.
#[repr(C)]
#[derive(Clone, Eq, PartialEq)]
pub struct RequestDraft14 {
    header: Header4,
    version: RequestedVersions,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; 940],
}

impl RequestDraft14 {
    const TAGS: [Tag; 4] = [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    pub fn new(nonce: &Nonce) -> Self {
        Self {
            nonce: *nonce,
            ..Self::default()
        }
    }

    pub fn ver(&self) -> &RequestedVersions {
        &self.version
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
}

impl FromWire for RequestDraft14 {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header4::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut req = RequestDraft14 {
            header,
            ..Self::default()
        };

        // Offsets are positive, monotonic, and 4-byte aligned. Verified by
        // Header::from_wire() and Header::check_offset_bounds()
        let ver_len = req.header.offsets[0] as usize;
        req.version = RequestedVersions::from_wire_n(cursor, ver_len)?;

        req.nonce = Nonce::from_wire(cursor)?;
        req.msg_type = MessageType::from_wire(cursor)?;

        if req.msg_type != MessageType::Request {
            return Err(InvalidMessageType(req.msg_type as u32));
        }

        Ok(req)
    }
}

impl ToWire for RequestDraft14 {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.padding.len()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        cursor.put_slice(&self.padding);

        Ok(())
    }
}

impl Default for RequestDraft14 {
    fn default() -> Self {
        let mut request = Self {
            header: Header4::default(),
            version: RequestedVersions::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; 940],
        };

        request.header.tags = Self::TAGS;

        request.header.offsets[0] = request.version.wire_size() as u32;
        request.header.offsets[1] = request.header.offsets[0] + request.nonce.wire_size() as u32;
        request.header.offsets[2] = request.header.offsets[1] + request.msg_type.wire_size() as u32;

        request
    }
}

impl Debug for RequestDraft14 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestDraft14")
            .field("VER", &self.version)
            .field("NONC", &self.nonce)
            .field("TYPE", &self.msg_type)
            .field("ZZZZ", &as_hex(&self.padding))
            .finish()
    }
}

/// Draft-08 compatible request format.
///
/// This request format is used for compatibility with servers implementing IETF draft-ietf-ntp-roughtime-08
/// (e.g., Cloudflare's roughtime.cloudflare.com:2003).
///
/// # Wire Format
///
/// Draft-08 requests have 3 tags: VER, NONC, ZZZZ (no TYPE tag).
///
/// ```text
/// +--------+--------+--------+
/// |  VER   |  NONC  |  ZZZZ  |
/// +--------+--------+--------+
/// ```
///
/// # Differences from Draft-14
///
/// - No TYPE tag (draft-14 includes TYPE to distinguish request/response)
/// - VER advertises RfcDraft08 (0x80000008)
///
/// # Usage
///
/// ```no_run
/// use roughenough_protocol::request::Request;
/// use roughenough_protocol::tags::Nonce;
///
/// let nonce = Nonce::from([0x42u8; 32]);
/// let request = Request::new_draft08(&nonce);
/// ```
#[repr(C)]
#[derive(Clone, Eq, PartialEq)]
pub struct RequestDraft08 {
    header: Header3,
    version: RequestedVersions,
    nonce: Nonce,
    padding: [u8; 952],
}

impl RequestDraft08 {
    const TAGS: [Tag; 3] = [Tag::VER, Tag::NONC, Tag::ZZZZ];

    /// Byte offset where the NONC value begins in a framed draft-08 request.
    ///
    /// This constant is valid for the default RequestDraft08 configuration which advertises
    /// exactly 1 protocol version (RfcDraft08). The layout is:
    /// - Frame header: 12 bytes (8 magic + 4 length)
    /// - Header3: 24 bytes (4 num_tags + 8 offsets + 12 tags)
    /// - VER value: 4 bytes (1 version * 4 bytes)
    /// - NONC starts at: 12 + 24 + 4 = 40
    ///
    /// A test verifies this constant matches the actual wire format.
    pub const FRAMED_NONCE_OFFSET: usize = 40;

    pub fn new(nonce: &Nonce) -> Self {
        Self {
            nonce: *nonce,
            ..Self::default()
        }
    }

    pub fn ver(&self) -> &RequestedVersions {
        &self.version
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }
}

impl FromWire for RequestDraft08 {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header3::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut req = RequestDraft08 {
            header,
            ..Self::default()
        };

        let ver_len = req.header.offsets[0] as usize;
        req.version = RequestedVersions::from_wire_n(cursor, ver_len)?;
        req.nonce = Nonce::from_wire(cursor)?;

        Ok(req)
    }
}

impl ToWire for RequestDraft08 {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + self.nonce.wire_size()
            + self.padding.len()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        cursor.put_slice(&self.padding);

        Ok(())
    }
}

impl ToFrame for RequestDraft08 {}

impl Default for RequestDraft08 {
    fn default() -> Self {
        // Advertise draft-08 version only
        let version = RequestedVersions::new(&[ProtocolVersion::RfcDraft08]);

        let mut request = Self {
            header: Header3::default(),
            version,
            nonce: Nonce::default(),
            padding: [0; 952],
        };

        request.header.tags = Self::TAGS;

        request.header.offsets[0] = request.version.wire_size() as u32;
        request.header.offsets[1] = request.header.offsets[0] + request.nonce.wire_size() as u32;

        request
    }
}

impl Debug for RequestDraft08 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestDraft08")
            .field("VER", &self.version)
            .field("NONC", &self.nonce)
            .field("ZZZZ", &as_hex(&self.padding))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RequestDraft14Srv {
    header: Header5,
    version: RequestedVersions,
    server: SrvCommitment,
    nonce: Nonce,
    msg_type: MessageType,
    padding: [u8; 900],
}

impl RequestDraft14Srv {
    const TAGS: [Tag; 5] = [Tag::VER, Tag::SRV, Tag::NONC, Tag::TYPE, Tag::ZZZZ];

    pub fn new(nonce: &Nonce, server: &SrvCommitment) -> Self {
        Self {
            server: server.clone(),
            nonce: *nonce,
            ..Self::default()
        }
    }

    pub fn ver(&self) -> &RequestedVersions {
        &self.version
    }

    pub fn srv(&self) -> &SrvCommitment {
        &self.server
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }
}

impl Default for RequestDraft14Srv {
    fn default() -> Self {
        let mut request = Self {
            header: Header5::default(),
            version: RequestedVersions::default(),
            server: SrvCommitment::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Request,
            padding: [0; 900],
        };

        request.header.tags = Self::TAGS;

        request.header.offsets[0] = request.version.wire_size() as u32;
        request.header.offsets[1] = request.header.offsets[0] + request.server.wire_size() as u32;
        request.header.offsets[2] = request.header.offsets[1] + request.nonce.wire_size() as u32;
        request.header.offsets[3] = request.header.offsets[2] + request.msg_type.wire_size() as u32;

        request
    }
}

impl FromWire for RequestDraft14Srv {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header5::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut req = RequestDraft14Srv {
            header,
            ..Self::default()
        };

        // Offsets are positive, monotonic, and 4-byte aligned. Verified by
        // Header::from_wire() and Header::check_offset_bounds()
        let ver_len = req.header.offsets[0] as usize;
        req.version = RequestedVersions::from_wire_n(cursor, ver_len)?;

        req.server = SrvCommitment::from_wire(cursor)?;
        req.nonce = Nonce::from_wire(cursor)?;
        req.msg_type = MessageType::from_wire(cursor)?;

        if req.msg_type != MessageType::Request {
            return Err(InvalidMessageType(req.msg_type as u32));
        }

        Ok(req)
    }
}

impl ToWire for RequestDraft14Srv {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + self.server.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.padding.len()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.server.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        cursor.put_slice(&self.padding);

        Ok(())
    }
}

impl Debug for RequestDraft14Srv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestDraft14Srv")
            .field("VER", &self.version)
            .field("SRV", &self.server)
            .field("NONC", &self.nonce)
            .field("TYPE", &self.msg_type)
            .field("ZZZZ", &as_hex(&self.padding))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::protocol_ver::ProtocolVersion;

    #[test]
    fn request_draft14_wire_roundtrip() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestDraft14::new(&nonce);

        let mut buf = vec![0u8; size_of::<RequestDraft14>()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            req.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let decoded = RequestDraft14::from_wire(&mut cursor).unwrap();

        assert_eq!(decoded.ver(), req.ver());
        assert_eq!(decoded.nonc(), req.nonc());
        assert_eq!(decoded.msg_type(), req.msg_type());
        assert_eq!(decoded.padding, req.padding);
        assert_eq!(decoded.header, req.header);
    }

    #[test]
    fn request_draft14_wire_error() {
        let req = RequestDraft14::default();
        let mut small_buf = [0u8; 10];
        let mut cursor = ParseCursor::new(&mut small_buf);
        let result = req.to_wire(&mut cursor);

        assert!(result.is_err());
    }

    #[test]
    fn request_draft14_defaults() {
        let req = RequestDraft14::default();
        assert_eq!(req.version, RequestedVersions::default());
        assert_eq!(req.msg_type, MessageType::Request);
        assert_eq!(req.nonce, Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; 940]);

        // Verify offsets and tags
        assert_eq!(req.header.offsets[0], size_of::<ProtocolVersion>() as u32);
        assert_eq!(
            req.header.offsets[1],
            size_of::<ProtocolVersion>() as u32 + size_of::<Nonce>() as u32
        );
        assert_eq!(req.header.tags, [Tag::VER, Tag::NONC, Tag::TYPE, Tag::ZZZZ]);
    }

    #[test]
    fn request_draft14_wire() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestDraft14::new(&nonce);

        let mut buf = vec![0u8; req.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.wire_size());
        assert_eq!(&buf[36..68], nonce.as_ref());
    }

    #[test]
    fn request_draft14_srv_defaults() {
        let req = RequestDraft14Srv::default();
        assert_eq!(req.ver(), &RequestedVersions::default());
        assert_eq!(req.msg_type(), MessageType::Request);
        assert_eq!(req.srv(), &SrvCommitment::from([0u8; 32]));
        assert_eq!(req.nonc(), &Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; 900]);

        assert_eq!(req.header.offsets[0], req.ver().wire_size() as u32);
        assert_eq!(
            req.header.offsets[1],
            req.ver().wire_size() as u32 + req.srv().wire_size() as u32
        );
        assert_eq!(
            req.header.tags,
            [Tag::VER, Tag::SRV, Tag::NONC, Tag::TYPE, Tag::ZZZZ]
        );
    }

    #[test]
    fn request_draft14_srv_wire() {
        let nonce = Nonce::from([0x42; 32]);
        let server = SrvCommitment::from([0xbb; 32]);
        let req = RequestDraft14Srv::new(&nonce, &server);

        let mut buf = vec![0u8; req.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        req.to_wire(&mut cursor).unwrap();
        assert_eq!(cursor.position(), req.wire_size());
        assert_eq!(&buf[44..76], server.as_ref());
        assert_eq!(&buf[76..108], nonce.as_ref());
    }

    #[test]
    fn from_wire_known_bytes() {
        // Request = RtMessage|4|{
        //   VER(4) = 0c000080
        //   NONC(32) = 071039e5723323191eaa7449e64e0b839b7a11028cbd943c31b28bfb93fadb32
        //   TYPE(4) = 00000000
        //   ZZZZ(940) = 0000000...
        // }
        let raw = include_bytes!("../testdata/rfc-request.071039e5");

        // skip 12 framing bytes as we're constructing a concrete RequestDraft14
        let mut data = raw[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        let request = RequestDraft14::from_wire(&mut cursor).unwrap();

        assert_eq!(request.version, RequestedVersions::default());
        assert_eq!(
            request.nonce.as_ref()[..8],
            [0x07, 0x10, 0x39, 0xe5, 0x72, 0x33, 0x23, 0x19]
        );
        assert_eq!(request.msg_type, MessageType::Request);
        assert_eq!(request.padding, [0u8; 940]);
    }

    #[test]
    fn request_from_wire_selects_correct_impl() {
        let raw = include_bytes!("../testdata/rfc-request.SRV.417aa962");
        let mut data = raw.to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        match Request::from_frame(&mut cursor) {
            Ok(Draft14Srv(req)) => {
                assert_eq!(
                    req.nonc().as_ref()[..8],
                    [0x41, 0x7a, 0xa9, 0x62, 0xcd, 0x46, 0xe1, 0xe5]
                );
                assert_eq!(
                    req.server.as_ref()[..8],
                    [0xee, 0xf0, 0x88, 0xf0, 0x68, 0x4d, 0xe2, 0x1f]
                );
            }
            Ok(Draft14(_)) => panic!("Expected Draft14Srv variant"),
            Ok(Draft08(_)) => panic!("Expected Draft14Srv variant"),
            Err(e) => panic!("No error should have been returned: {e:?}"),
        }
    }

    #[test]
    fn wrong_msg_type_is_detected() {
        let mut raw = include_bytes!("../testdata/rfc-request.071039e5").to_vec();
        // 12 bytes framing + 32 bytes nonce = 44 = offset to message_type; set it to an invalid value
        raw[80] = 0xaa;

        let result = Request::from_frame(&mut ParseCursor::new(&mut raw));
        match result {
            Err(InvalidMessageType(actual)) => assert_eq!(actual, 0xaa),
            Err(e) => panic!("Expected InvalidMessageType error, got: {e:?}"),
            Ok(r) => panic!("Expected InvalidMessageType error, got: Ok {r:?}"),
        }
    }

    #[test]
    fn request_draft08_wire_roundtrip() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestDraft08::new(&nonce);

        let mut buf = vec![0u8; req.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            req.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let decoded = RequestDraft08::from_wire(&mut cursor).unwrap();

        assert_eq!(decoded.ver(), req.ver());
        assert_eq!(decoded.nonc(), req.nonc());
        assert_eq!(decoded.padding, req.padding);
        assert_eq!(decoded.header, req.header);
    }

    #[test]
    fn request_draft08_defaults() {
        let req = RequestDraft08::default();

        // Draft-08 advertises only draft-08 version
        let expected_versions = RequestedVersions::new(&[ProtocolVersion::RfcDraft08]);
        assert_eq!(*req.ver(), expected_versions);
        assert_eq!(req.nonc(), &Nonce::from([0u8; 32]));
        assert_eq!(req.padding, [0u8; 952]);

        // Verify tags (no TYPE tag)
        assert_eq!(req.header.tags, [Tag::VER, Tag::NONC, Tag::ZZZZ]);
    }

    #[test]
    fn request_draft08_from_wire_known_bytes() {
        // Request captured from Cloudflare roughtime.cloudflare.com:2002 (draft-08)
        // Request = RtMessage|3|{
        //   VER(4) = 08000080
        //   NONC(32) = ec05ed444c1c840f3875e6ac4ee2a74e08b228893 11ea4f2253cdecd320d6d7d
        //   ZZZZ(952) = 0000000...
        // }
        let raw = include_bytes!("../testdata/draft08-request.ec05ed44");

        // skip 12 framing bytes as we're constructing a concrete RequestDraft08
        let mut data = raw[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        let request = RequestDraft08::from_wire(&mut cursor).unwrap();

        // Draft-08 version
        let expected_versions = RequestedVersions::new(&[ProtocolVersion::RfcDraft08]);
        assert_eq!(*request.ver(), expected_versions);
        assert_eq!(
            request.nonce.as_ref()[..8],
            [0xec, 0x05, 0xed, 0x44, 0x4c, 0x1c, 0x84, 0x0f]
        );
        assert_eq!(request.padding, [0u8; 952]);
    }

    #[test]
    fn request_draft08_from_frame_selects_correct_impl() {
        let raw = include_bytes!("../testdata/draft08-request.ec05ed44");
        let mut data = raw.to_vec();
        let mut cursor = ParseCursor::new(&mut data);

        match Request::from_frame(&mut cursor) {
            Ok(Draft08(req)) => {
                assert_eq!(
                    req.nonc().as_ref()[..8],
                    [0xec, 0x05, 0xed, 0x44, 0x4c, 0x1c, 0x84, 0x0f]
                );
            }
            Ok(Draft14(_)) => panic!("Expected Draft08 variant"),
            Ok(Draft14Srv(_)) => panic!("Expected Draft08 variant"),
            Err(e) => panic!("No error should have been returned: {e:?}"),
        }
    }

    #[test]
    fn request_draft08_wire_size() {
        let nonce = Nonce::from([0x42; 32]);
        let req = RequestDraft08::new(&nonce);

        // Draft-08 request is 1012 bytes (1024 - 12 framing)
        // header: 4 (num_tags) + 8 (2 offsets) + 12 (3 tags) = 24
        // VER: 4 bytes (1 version)
        // NONC: 32 bytes
        // ZZZZ: 952 bytes padding
        // Total: 24 + 4 + 32 + 952 = 1012
        assert_eq!(req.wire_size(), 1012);
    }

    #[test]
    fn request_draft08_via_request_enum() {
        let nonce = Nonce::from([0x42; 32]);
        let req = Request::new_draft08(&nonce);

        assert_eq!(req.nonc(), &nonce);
        assert_eq!(req.msg_type(), MessageType::Request);
        assert!(req.srv().is_none());

        // Verify it creates a Draft08 variant
        match req {
            Draft08(_) => {} // expected
            _ => panic!("Expected Draft08 variant"),
        }
    }

    #[test]
    fn request_draft08_wire_error() {
        let req = RequestDraft08::default();
        let mut small_buf = [0u8; 10];
        let mut cursor = ParseCursor::new(&mut small_buf);
        let result = req.to_wire(&mut cursor);

        assert!(result.is_err());
    }

    #[test]
    fn request_draft08_framed_nonce_offset_is_correct() {
        use crate::wire::ToFrame;

        let nonce_bytes = [0x42u8; 32];
        let nonce = Nonce::from(nonce_bytes);
        let req = Request::new_draft08(&nonce);

        let framed_bytes = req.as_frame_bytes().unwrap();

        // Verify the nonce appears at the expected offset
        let actual_nonce =
            &framed_bytes[RequestDraft08::FRAMED_NONCE_OFFSET..][..nonce_bytes.len()];
        assert_eq!(
            actual_nonce,
            &nonce_bytes,
            "FRAMED_NONCE_OFFSET ({}) does not point to the nonce in the framed request",
            RequestDraft08::FRAMED_NONCE_OFFSET
        );
    }
}
