use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{BufferTooSmall, UnexpectedTags};
use crate::header::{Header, Header6, Header7};
use crate::protocol_ver::ProtocolVersion;
use crate::tag::Tag;
use crate::tags::srep::{SignedResponse, SignedResponseDraft08};
use crate::tags::{Certificate, MerklePath, MessageType, Nonce, Signature};
use crate::wire::{FromFrame, FromWire, FromWireN, ToFrame, ToWire};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    header: Header7,
    signature: Signature,
    nonce: Nonce,
    msg_type: MessageType,
    path: MerklePath,
    srep: SignedResponse,
    cert: Certificate,
    index: u32,
}

impl Response {
    /// All responses will be *at least* this many bytes, and could be longer as the PATH and SREP
    /// values are variable-length.
    pub const MINIMUM_SIZE: usize = 404;

    /// RFC 5.2: A response MUST contain the tags SIG, NONC, TYPE, PATH, SREP, CERT,
    /// and INDX.
    const TAGS: [Tag; 7] = [
        Tag::SIG,
        Tag::NONC,
        Tag::TYPE,
        Tag::PATH,
        Tag::SREP,
        Tag::CERT,
        Tag::INDX,
    ];

    pub fn header(&self) -> &impl Header {
        &self.header
    }

    pub fn sig(&self) -> &Signature {
        &self.signature
    }

    pub fn nonc(&self) -> &Nonce {
        &self.nonce
    }

    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    pub fn path(&self) -> &MerklePath {
        &self.path
    }

    pub fn srep(&self) -> &SignedResponse {
        &self.srep
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn indx(&self) -> u32 {
        self.index
    }

    pub fn set_sig(&mut self, sig: Signature) {
        self.signature = sig;
    }

    pub fn set_nonc(&mut self, nonce: Nonce) {
        self.nonce = nonce;
    }

    /// Overwrite this Response's MerklePath with the provided one
    pub fn set_path(&mut self, path: MerklePath) {
        self.path = path;
        self.update_offsets();
    }

    /// Copy the contents of another MerklePath into this one, overwriting any existing data.
    pub fn copy_path(&mut self, path: &MerklePath) {
        self.path.copy_from(path);
        self.update_offsets();
    }

    pub fn set_srep(&mut self, srep: SignedResponse) {
        self.srep = srep;
        self.update_offsets()
    }

    pub fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
    }

    pub fn set_indx(&mut self, index: u32) {
        self.index = index;
    }

    /// Refresh offsets based on the current values of the fields
    fn update_offsets(&mut self) {
        self.header.offsets[0] = self.signature.wire_size() as u32;
        self.header.offsets[1] = self.header.offsets[0] + self.nonce.wire_size() as u32;
        self.header.offsets[2] = self.header.offsets[1] + self.msg_type.wire_size() as u32;
        self.header.offsets[3] = self.header.offsets[2] + self.path.wire_size() as u32;
        self.header.offsets[4] = self.header.offsets[3] + self.srep.wire_size() as u32;
        self.header.offsets[5] = self.header.offsets[4] + self.cert.wire_size() as u32;
    }
}

impl Default for Response {
    fn default() -> Self {
        let mut response = Self {
            header: Header7::default(),
            signature: Signature::default(),
            nonce: Nonce::default(),
            msg_type: MessageType::Response,
            path: MerklePath::default(),
            srep: SignedResponse::default(),
            cert: Certificate::default(),
            index: 0,
        };

        response.header.tags = Self::TAGS;
        // offsets are calculated in set_path() and set_srep()

        response
    }
}

impl FromWire for Response {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header7::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut response = Response {
            header,
            ..Default::default()
        };

        response.signature = Signature::from_wire(cursor)?;
        response.nonce = Nonce::from_wire(cursor)?;

        let msg_type = MessageType::from_wire(cursor)?;
        if msg_type != MessageType::Response {
            return Err(Error::InvalidMessageType(msg_type as u32));
        }

        let path_len = (response.header.offsets[3] - response.header.offsets[2]) as usize;
        response.path = MerklePath::from_wire_n(cursor, path_len)?;

        response.srep = SignedResponse::from_wire(cursor)?;
        response.cert = Certificate::from_wire(cursor)?;

        // cursor holds remainder of message
        response.index = cursor.try_get_u32_le()?;

        Ok(response)
    }
}

impl FromFrame for Response {}

impl ToWire for Response {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.signature.wire_size()
            + self.nonce.wire_size()
            + self.msg_type.wire_size()
            + self.path.wire_size()
            + self.srep.wire_size()
            + self.cert.wire_size()
            + size_of::<u32>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.capacity() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.capacity()));
        }

        self.header.to_wire(cursor)?;
        self.signature.to_wire(cursor)?;
        self.nonce.to_wire(cursor)?;
        self.msg_type.to_wire(cursor)?;
        self.path.to_wire(cursor)?;
        self.srep.to_wire(cursor)?;
        self.cert.to_wire(cursor)?;
        cursor.put_u32_le(self.index);

        Ok(())
    }
}

impl ToFrame for Response {}

/// Draft-08 compatible response format.
///
/// This response format is received from servers implementing IETF draft-ietf-ntp-roughtime-08
/// (e.g., Cloudflare's roughtime.cloudflare.com:2003).
///
/// # Wire Format
///
/// Draft-08 responses have 6 tags: SIG, VER, PATH, SREP, CERT, INDX (no NONC, no TYPE).
///
/// ```text
/// +------+------+------+------+------+------+
/// | SIG  | VER  | PATH | SREP | CERT | INDX |
/// +------+------+------+------+------+------+
/// ```
///
/// # Differences from Draft-14
///
/// - No NONC tag (draft-14 includes the nonce in response for verification)
/// - No TYPE tag (draft-14 uses TYPE to distinguish request/response)
/// - SREP has only 3 tags: RADI, MIDP, ROOT (draft-14 SREP has VER, RADI, MIDP, VERS, ROOT)
/// - Merkle proof uses only the 32-byte nonce as leaf hash (draft-14 uses full framed request)
///
/// # Validation
///
/// Draft-08 responses require different Merkle proof computation than draft-14.
/// The client crate provides validation methods for both protocol versions.
///
/// # Conversion
///
/// Draft-08 responses can be converted to the standard `Response` type using `From`:
///
/// ```ignore
/// let draft08_response: ResponseDraft08 = /* ... */;
/// let response: Response = Response::from(draft08_response);
/// ```
///
/// # Note
///
/// This type is primarily used by clients to parse incoming responses. The server-side
/// test utilities also use it for generating draft-08 format responses in tests.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ResponseDraft08 {
    header: Header6,
    signature: Signature,
    version: ProtocolVersion,
    path: MerklePath,
    srep: SignedResponseDraft08,
    cert: Certificate,
    index: u32,
}

impl ResponseDraft08 {
    /// Draft-08 response has 6 tags: SIG, VER, PATH, SREP, CERT, INDX
    const TAGS: [Tag; 6] = [
        Tag::SIG,
        Tag::VER,
        Tag::PATH,
        Tag::SREP,
        Tag::CERT,
        Tag::INDX,
    ];

    pub fn sig(&self) -> &Signature {
        &self.signature
    }

    pub fn ver(&self) -> ProtocolVersion {
        self.version
    }

    pub fn path(&self) -> &MerklePath {
        &self.path
    }

    pub fn srep(&self) -> &SignedResponseDraft08 {
        &self.srep
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn indx(&self) -> u32 {
        self.index
    }

    pub fn header(&self) -> &Header6 {
        &self.header
    }

    pub fn set_sig(&mut self, sig: Signature) {
        self.signature = sig;
    }

    pub fn set_srep(&mut self, srep: SignedResponseDraft08) {
        self.srep = srep;
        self.update_offsets();
    }

    pub fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
        self.update_offsets();
    }

    pub fn set_indx(&mut self, indx: u32) {
        self.index = indx;
    }

    /// Overwrite this Response's MerklePath with the provided one
    pub fn set_path(&mut self, path: MerklePath) {
        self.path = path;
        self.update_offsets();
    }

    /// Copy the contents of another MerklePath into this one, overwriting any existing data.
    pub fn copy_path(&mut self, path: &MerklePath) {
        self.path.copy_from(path);
        self.update_offsets();
    }

    fn update_offsets(&mut self) {
        // offsets[0]: end of SIG (64 bytes)
        self.header.offsets[0] = self.signature.wire_size() as u32;
        // offsets[1]: end of VER (4 bytes)
        self.header.offsets[1] = self.header.offsets[0] + self.version.wire_size() as u32;
        // offsets[2]: end of PATH
        self.header.offsets[2] = self.header.offsets[1] + self.path.wire_size() as u32;
        // offsets[3]: end of SREP
        self.header.offsets[3] = self.header.offsets[2] + self.srep.wire_size() as u32;
        // offsets[4]: end of CERT
        self.header.offsets[4] = self.header.offsets[3] + self.cert.wire_size() as u32;
    }
}

impl Default for ResponseDraft08 {
    fn default() -> Self {
        let mut response = Self {
            header: Header6::default(),
            signature: Signature::default(),
            version: ProtocolVersion::RfcDraft08,
            path: MerklePath::default(),
            srep: SignedResponseDraft08::default(),
            cert: Certificate::default(),
            index: 0,
        };

        response.header.tags = Self::TAGS;
        response
    }
}

impl FromWire for ResponseDraft08 {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let header = Header6::from_wire(cursor)?;
        header.check_offset_bounds(cursor.remaining())?;

        if header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

        let mut response = ResponseDraft08 {
            header,
            ..Default::default()
        };

        response.signature = Signature::from_wire(cursor)?;
        response.version = ProtocolVersion::from_wire(cursor)?;

        // PATH length from offsets (offset[2] - offset[1])
        let path_len = (response.header.offsets[2] - response.header.offsets[1]) as usize;
        response.path = MerklePath::from_wire_n(cursor, path_len)?;

        response.srep = SignedResponseDraft08::from_wire(cursor)?;
        response.cert = Certificate::from_wire(cursor)?;
        response.index = cursor.try_get_u32_le()?;

        Ok(response)
    }
}

impl FromFrame for ResponseDraft08 {}

impl ToWire for ResponseDraft08 {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.signature.wire_size()
            + self.version.wire_size()
            + self.path.wire_size()
            + self.srep.wire_size()
            + self.cert.wire_size()
            + size_of::<u32>() // index
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        self.signature.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        self.path.to_wire(cursor)?;
        self.srep.to_wire(cursor)?;
        self.cert.to_wire(cursor)?;
        cursor.put_u32_le(self.index);
        Ok(())
    }
}

impl ToFrame for ResponseDraft08 {}

impl From<ResponseDraft08> for Response {
    /// Convert a draft-08 response to draft-14 format for downstream compatibility.
    /// Sets NONC to empty and TYPE to MessageType::Response since draft-08 doesn't include them.
    fn from(draft08: ResponseDraft08) -> Self {
        let mut response = Response::default();
        response.set_sig(draft08.signature);
        // draft-08 doesn't include NONC in response, leave it as default (empty)
        response.set_path(draft08.path);
        response.set_srep(SignedResponse::from(draft08.srep));
        response.set_cert(draft08.cert);
        response.set_indx(draft08.index);
        response
    }
}

#[cfg(test)]
mod tests {
    use crate::cursor::ParseCursor;
    use crate::header::Header;
    use crate::response::{Response, ResponseDraft08};
    use crate::tag::Tag;
    use crate::tags::ProtocolVersion::{RfcDraft08, RfcDraft14};
    use crate::tags::{
        Certificate, MerklePath, MerkleRoot, MessageType, Nonce, Signature, SignedResponse,
        SignedResponseDraft08, SupportedVersions,
    };
    use crate::wire::{FromFrame, FromWire, ToWire};

    #[test]
    fn from_wire_on_known_bytes() {
        let mut raw = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619").to_vec();

        let mut cursor = ParseCursor::new(&mut raw);
        let response = Response::from_frame(&mut cursor).unwrap();

        // Response {
        //     header: Header7 {
        //         num_tags: 7,
        //         offsets: [ 64, 96, 100, 356, 452, 604, ],
        //         tags: [ SIG, NONC, TYPE, PATH, SREP, CERT, INDX, ],
        //     },
        //     signature: SIG(72c53051ad9773f484c6bdfd27e6595ce40a117ec3b86a41887b7135bd93f3238ef445939bd7d9c262f31e6a306ebeb41a4e436ef81ff21c8b9e0d3be22ae50a),
        //     nonce: NONC(4c16c619d7716fae49552b3393fd07cff4c6f16a1ab5a2f7ce5240f94a6d1f29),
        //     msg_type: Response,
        //     path: PATH { num_paths: 8, data: 7148a705f7c562f0cb1f278aabca93133269453042eb8d554da4d6f0a1fbd7202cd76bb0939d911c623831205caef0602e9a62a115de2117a869eb3775a481edbb6f543d60a509f50560885423496fd085d0f2a63787b91d0ade26fdf3a6352807b417d43fbde735f33fbb36b7f8fa9cc68b6462e17629e88086ee8b7aefee74f8dd1237cf5b5d6ab8409278374639298404fd21561ba7caca142b9d0e5d574ec56a648e3393c8c612281516cea5af523660d40b3fe57141af51646b60b98a3a761ecd09f131bedf9ecf9c557d9b511b28a1e6c7950f854c3febc71b7f01d5f616d0ea810ac7d01f8c412203a49821bc4befa651e413b352fef04c97f1ef5730 },
        //     srep: SignedResponse {
        //         header: Header5 {
        //             num_tags: 5,
        //             offsets: [ 4, 8, 16, 24, ],
        //             tags: [ VER, RADI, MIDP, VERS, ROOT, ],
        //         },
        //         version: RfcDraft14,
        //         radius: 5,
        //         midpoint: 1748359193,
        //         supported_versions: VERS {
        //             num_versions: 2,
        //             versions: [ Google, RfcDraft14, ],
        //         },
        //         merkle_root: ROOT(1ecf2ead5837a00dc01d2875bdb16c2be094da36115dce7966e320e31345bb97),
        //     },
        //     cert: CERT {
        //         header: Header2 {
        //             num_tags: 2,
        //             offsets: [ 64, ],
        //             tags: [ SIG, DELE, ],
        //         },
        //         signature: SIG(2df7d5397611739c683f54b95359b11781d079b28b09bcf13d42d85868db48b8bafcbf0492ca836f615d3d88775c455c9443368f959cb90644c7093430ed4502),
        //         delegation: DELE {
        //             header: Header3 {
        //                 num_tags: 3,
        //                 offsets: [ 32, 40, ],
        //                 tags: [ PUBK, MINT, MAXT, ],
        //             },
        //             public_key: PUBK(254e5d6fa2453dac9931cb7ae84c4e2790a69b390bac8f68b332db0d1c7dd6c7),
        //             min_time: 0,
        //             max_time: 18446744073709551615,
        //         },
        //     },
        //     index: 2
        // }

        assert_eq!(response.header().offsets(), [64, 96, 100, 356, 452, 604]);
        assert_eq!(
            response.header().tags(),
            [
                Tag::SIG,
                Tag::NONC,
                Tag::TYPE,
                Tag::PATH,
                Tag::SREP,
                Tag::CERT,
                Tag::INDX
            ]
        );
        assert_eq!(response.msg_type(), MessageType::Response);
        assert_eq!(response.path().as_ref().len(), 256);
        assert_eq!(response.indx(), 2);

        assert_eq!(
            response.sig().as_ref()[..8],
            [0x72, 0xc5, 0x30, 0x51, 0xad, 0x97, 0x73, 0xf4]
        );
        assert_eq!(
            response.nonc().as_ref()[..8],
            [0x4c, 0x16, 0xc6, 0x19, 0xd7, 0x71, 0x6f, 0xae]
        );
        assert_eq!(
            response.path().as_ref()[..8],
            [0x71, 0x48, 0xa7, 0x05, 0xf7, 0xc5, 0x62, 0xf0]
        );

        let srep = response.srep();
        assert_eq!(srep.header().offsets(), [4, 8, 16, 24]);
        assert_eq!(
            srep.header().tags(),
            [Tag::VER, Tag::RADI, Tag::MIDP, Tag::VERS, Tag::ROOT]
        );
        assert_eq!(*srep.ver(), RfcDraft14);
        assert_eq!(srep.radi(), 5);
        assert_eq!(srep.midp(), 1748359193);
        // The test data contains Google (0x0) which is now mapped to RfcDraft08
        assert_eq!(srep.vers().versions(), &[RfcDraft08, RfcDraft14]);
        assert_eq!(srep.root().as_ref().len(), 32);
        assert_eq!(
            srep.root().as_ref()[..8],
            [0x1e, 0xcf, 0x2e, 0xad, 0x58, 0x37, 0xa0, 0x0d]
        );

        let cert = response.cert();
        assert_eq!(cert.header().offsets(), [64]);
        assert_eq!(cert.header().tags(), [Tag::SIG, Tag::DELE]);
        assert_eq!(cert.sig().as_ref().len(), 64);
        assert_eq!(
            cert.sig().as_ref()[..8],
            [0x2d, 0xf7, 0xd5, 0x39, 0x76, 0x11, 0x73, 0x9c]
        );

        let dele = cert.dele();
        assert_eq!(dele.header().offsets(), [32, 40]);
        assert_eq!(dele.header().tags(), [Tag::PUBK, Tag::MINT, Tag::MAXT]);
        assert_eq!(dele.pubk().as_ref().len(), 32);
        assert_eq!(
            dele.pubk().as_ref()[..8],
            [0x25, 0x4e, 0x5d, 0x6f, 0xa2, 0x45, 0x3d, 0xac]
        );
        assert_eq!(dele.mint(), 0);
        assert_eq!(dele.maxt(), u64::MAX);
    }

    #[test]
    fn offsets_are_calculated_correctly() {
        let mut response = Response::default();
        assert_eq!(response.header.offsets, [0, 0, 0, 0, 0, 0]);

        let path = MerklePath::try_from([0x4e; 192].as_slice()).unwrap();
        response.set_path(path);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 380, 532]);

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[RfcDraft08, RfcDraft14]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 388, 540]);

        let mut srep = SignedResponse::default();
        srep.set_vers(&SupportedVersions::new(&[RfcDraft14]));
        response.set_srep(srep);
        assert_eq!(response.header.offsets, [64, 96, 100, 292, 384, 536]);
    }

    fn create_test_response() -> Response {
        let mut response = Response::default();
        response.set_sig(Signature::from([0x11u8; 64]));
        response.set_nonc(Nonce::from([0x22u8; 32]));

        let path = MerklePath::try_from([0x33u8; 64].as_slice()).unwrap();
        response.set_path(path);

        let mut srep = SignedResponse::default();
        srep.set_ver(RfcDraft14);
        srep.set_radi(5);
        srep.set_midp(1234567890);
        srep.set_vers(&SupportedVersions::new(&[RfcDraft08, RfcDraft14]));
        srep.set_root(&MerkleRoot::from([0x44u8; 32]));
        response.set_srep(srep);

        response.set_cert(Certificate::default());
        response.set_indx(7);

        response
    }

    #[test]
    fn response_wire_roundtrip() {
        let response1 = create_test_response();

        let mut buf = vec![0u8; response1.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            response1.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let response2 = Response::from_wire(&mut cursor).unwrap();

        assert_eq!(response1.sig(), response2.sig());
        assert_eq!(response1.nonc(), response2.nonc());
        assert_eq!(response1.msg_type(), response2.msg_type());
        assert_eq!(response1.path().as_ref(), response2.path().as_ref());
        assert_eq!(response1.srep().ver(), response2.srep().ver());
        assert_eq!(response1.srep().radi(), response2.srep().radi());
        assert_eq!(response1.srep().midp(), response2.srep().midp());
        assert_eq!(response1.srep().root(), response2.srep().root());
        assert_eq!(response1.indx(), response2.indx());
    }

    fn create_test_response_draft08() -> ResponseDraft08 {
        let mut response = ResponseDraft08::default();
        response.set_sig(Signature::from([0x11u8; 64]));

        let path = MerklePath::try_from([0x33u8; 64].as_slice()).unwrap();
        response.set_path(path);

        let mut srep = SignedResponseDraft08::default();
        srep.set_radi(5);
        srep.set_midp(1234567890);
        srep.set_root(&MerkleRoot::from([0x44u8; 32]));
        response.set_srep(srep);

        response.set_cert(Certificate::default());
        response.set_indx(7);

        response
    }

    #[test]
    fn response_draft08_wire_roundtrip() {
        let response1 = create_test_response_draft08();

        let mut buf = vec![0u8; response1.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            response1.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let response2 = ResponseDraft08::from_wire(&mut cursor).unwrap();

        assert_eq!(response1.sig(), response2.sig());
        assert_eq!(response1.ver(), response2.ver());
        assert_eq!(response1.path().as_ref(), response2.path().as_ref());
        assert_eq!(response1.srep().radi(), response2.srep().radi());
        assert_eq!(response1.srep().midp(), response2.srep().midp());
        assert_eq!(response1.srep().root(), response2.srep().root());
        assert_eq!(response1.indx(), response2.indx());
    }

    #[test]
    fn response_draft08_offsets_are_calculated_correctly() {
        let mut response = ResponseDraft08::default();

        let path = MerklePath::try_from([0x4e; 192].as_slice()).unwrap();
        response.set_path(path);

        // offsets[0]: SIG = 64
        // offsets[1]: VER = 64 + 4 = 68
        // offsets[2]: PATH = 68 + 192 = 260
        // offsets[3]: SREP = 260 + srep.wire_size()
        // offsets[4]: CERT = offset[3] + cert.wire_size()
        assert_eq!(response.header.offsets[0], 64);
        assert_eq!(response.header.offsets[1], 68);
        assert_eq!(response.header.offsets[2], 260);
    }

    #[test]
    fn response_draft08_from_wire_known_bytes() {
        // Response captured from Cloudflare roughtime.cloudflare.com:2002 (draft-08)
        // Response = RtMessage|6|{
        //   SIG(64) = 78fa5655b3fecd8e2f453d2af1a22a4cff271e1a3d6deca04358...
        //   VER(4) = 08000080
        //   PATH(0) = (empty)
        //   SREP(68) = RtMessage|3|{
        //     RADI(4) = 01000000
        //     MIDP(8) = d1969069 00000000
        //     ROOT(32) = d67b48c1304abae9ceb6eace990ac7830169...
        //   }
        //   CERT(152) = RtMessage|2|{
        //     SIG(64) = b5317d8ded8c7d4388f6656e100f7cdb5dab0278...
        //     DELE(72) = RtMessage|3|{
        //       PUBK(32) = 8d6d21dacbbf65f1d4b5b36b362b99092bb525a2...
        //       MINT(8) = df069069 00000000
        //       MAXT(8) = 5f589169 00000000
        //     }
        //   }
        //   INDX(4) = 00000000
        // }
        let mut raw = include_bytes!("../testdata/draft08-response.ec05ed44").to_vec();

        let mut cursor = ParseCursor::new(&mut raw);
        let response = ResponseDraft08::from_frame(&mut cursor).unwrap();

        // Verify header structure
        assert_eq!(response.header().offsets(), [64, 68, 68, 136, 288]);
        assert_eq!(
            response.header().tags(),
            [
                Tag::SIG,
                Tag::VER,
                Tag::PATH,
                Tag::SREP,
                Tag::CERT,
                Tag::INDX
            ]
        );

        // Verify SIG (first 8 bytes)
        assert_eq!(
            response.sig().as_ref()[..8],
            [0x78, 0xfa, 0x56, 0x55, 0xb3, 0xfe, 0xcd, 0x8e]
        );

        // Verify VER is draft-08
        assert_eq!(response.ver(), RfcDraft08);

        // Verify PATH is empty (index 0, leaf in merkle tree)
        assert_eq!(response.path().as_ref().len(), 0);

        // Verify INDX
        assert_eq!(response.indx(), 0);

        // Verify SREP fields
        let srep = response.srep();
        assert_eq!(srep.radi(), 1);
        assert_eq!(srep.midp(), 1771083473); // 0x6990_96d1 little-endian
        assert_eq!(
            srep.root().as_ref()[..8],
            [0xd6, 0x7b, 0x48, 0xc1, 0x30, 0x4a, 0xba, 0xe9]
        );

        // Verify CERT
        let cert = response.cert();
        assert_eq!(cert.header().offsets(), [64]);
        assert_eq!(cert.header().tags(), [Tag::SIG, Tag::DELE]);
        assert_eq!(
            cert.sig().as_ref()[..8],
            [0xb5, 0x31, 0x7d, 0x8d, 0xed, 0x8c, 0x7d, 0x43]
        );

        // Verify DELE
        let dele = cert.dele();
        assert_eq!(dele.header().offsets(), [32, 40]);
        assert_eq!(dele.header().tags(), [Tag::PUBK, Tag::MINT, Tag::MAXT]);
        assert_eq!(
            dele.pubk().as_ref()[..8],
            [0x8d, 0x6d, 0x21, 0xda, 0xcb, 0xbf, 0x65, 0xf1]
        );
    }
}
