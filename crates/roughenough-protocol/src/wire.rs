use Error::{BufferTooSmall, UnexpectedMagic};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::UnexpectedFraming;

/// RFC 5: The first field is a uint64 with the value 0x4d49544847554f52 ("ROUGHTIM" in ASCII).
///
/// Magic value 'ROUGHTIM' for framed Requests and Responses.
pub const FRAME_MAGIC: u64 = 0x524f55474854494d;

/// Overhead of framing: 8-byte magic + 4-byte length
pub const FRAME_OVERHEAD: usize = 12;

/// Minimum frame size for sanity checking. Draft-08 responses can be smaller than draft-14.
/// Actual validation happens during message parsing.
pub const MINIMUM_FRAME_SIZE: usize = 100;

/// Implementations can serialize themselves into the Roughtime wire format
pub trait ToWire {
    fn wire_size(&self) -> usize;
    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error>;

    /// Convenience method to serialize this message into a new `Vec<u8>`.
    ///
    /// In performance-critical cases consider `to_wire` instead.
    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; self.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        self.to_wire(&mut cursor)?;
        Ok(buf)
    }
}

/// Implementations can serialize themselves into a framed Roughtime message:
///  - 8-bytes of magic value ('ROUGHTIM')
///  - 4-bytes little endian value length
///  - Roughtime wire value
pub trait ToFrame: ToWire {
    fn frame_size(&self) -> usize {
        self.wire_size() + FRAME_OVERHEAD
    }

    fn to_frame(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        cursor.try_put_u64(FRAME_MAGIC)?;
        cursor.try_put_u32_le(self.wire_size() as u32)?;
        self.to_wire(cursor)
    }

    /// Convenience method to serialize this frame into a new `Vec<u8>`.
    ///
    /// In performance-critical cases consider `to_frame` instead.
    fn as_frame_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; self.frame_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        self.to_frame(&mut cursor)?;
        Ok(buf)
    }
}

pub trait FromWire: Sized {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error>;
}

/// Implementations can deserialize themselves from a framed Roughtime message:
///  - 8-bytes of magic value ('ROUGHTIM')
///  - 4-bytes little endian value length
///  - Roughtime wire value
pub trait FromFrame: FromWire {
    fn from_frame(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let magic = cursor.try_get_u64()?;

        if magic != FRAME_MAGIC {
            return Err(UnexpectedMagic(magic));
        }

        let len = cursor.try_get_u32_le()? as usize;

        if len < MINIMUM_FRAME_SIZE || cursor.remaining() < MINIMUM_FRAME_SIZE {
            let min = std::cmp::min(len, cursor.remaining());
            return Err(UnexpectedFraming(min));
        }

        if len > cursor.remaining() {
            return Err(BufferTooSmall(len, cursor.remaining()));
        }

        FromWire::from_wire(cursor)
    }
}

pub trait FromWireN: Sized {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error>;
}
