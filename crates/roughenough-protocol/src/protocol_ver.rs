use std::fmt::Debug;
use std::mem::size_of;
use std::str::FromStr;

use ProtocolVersion::{RfcDraft08, RfcDraft14};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidVersion;
use crate::wire::{FromWire, ToWire};

/// A `ProtocolVersion` represents a specific version of the Roughtime protocol. Each version
/// has a unique u32 identifier and SREP and DELE context strings.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    RfcDraft08 = 0x80000008,
    RfcDraft14 = 0x8000000c,
}

impl ProtocolVersion {
    pub fn dele_prefix(&self) -> &'static [u8] {
        match self {
            // Draft-08 uses the original context string with trailing dashes
            RfcDraft08 => b"RoughTime v1 delegation signature--\x00",
            // Draft-14 removed the trailing dashes
            RfcDraft14 => b"RoughTime v1 delegation signature\x00",
        }
    }

    pub fn srep_prefix(&self) -> &'static [u8] {
        match self {
            RfcDraft08 | RfcDraft14 => b"RoughTime v1 response signature\x00",
        }
    }

    /// Returns true if this version requires the TYPE tag in requests
    pub fn requires_type_tag(&self) -> bool {
        match self {
            RfcDraft08 => false,
            RfcDraft14 => true,
        }
    }
}

impl ToWire for ProtocolVersion {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        let value = *self as u32;
        cursor.put_u32_le(value);
        Ok(())
    }
}

impl FromWire for ProtocolVersion {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let value = cursor.try_get_u32_le()?;
        match value {
            // Accept 0x00000000 (legacy Google) as draft-08 for backward compatibility
            0x00000000 | 0x80000008 => Ok(RfcDraft08),
            0x8000000c => Ok(RfcDraft14),
            _ => Err(InvalidVersion(value)),
        }
    }
}

impl FromStr for ProtocolVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "8" | "draft-08" | "draft08" => Ok(RfcDraft08),
            "14" | "draft-14" | "draft14" | "ietf-roughtime" => Ok(RfcDraft14),
            _ => Err(InvalidVersion(u32::MAX)),
        }
    }
}
