# Roughtime Protocol Summary

## Core Protocol Overview

Roughtime is a cryptographic time synchronization protocol providing authenticated timestamps with proof of server malfeasance. It uses Ed25519 signatures and SHA-512 hashing (first 32 bytes).

## Protocol Versions

This implementation supports two protocol versions:

| Version | Value | Description |
|---------|-------|-------------|
| RFC draft-08 | 0x80000008 | IETF draft-08 (used by Cloudflare) |
| RFC draft-14 | 0x8000000c | IETF draft-14 (current RFC) |

For backward compatibility, responses containing the legacy Google version number
(0x00000000) are accepted and treated as draft-08.

### Key Differences Between Versions

**Request Format:**
- draft-08: VER, NONC, ZZZZ (no TYPE tag, no SRV commitment)
- draft-14: VER, NONC, TYPE, ZZZZ (optional SRV tag for server selection)

**Response Format:**
- draft-08: SREP contains 3 tags (RADI, MIDP, ROOT), no NONC/TYPE echo
- draft-14: SREP contains 5 tags (VER, RADI, MIDP, VERS, ROOT), includes NONC/TYPE echo

**DELE Signature Context:**
- draft-08: `"RoughTime v1 delegation signature--\0"` (with trailing dashes)
- draft-14: `"RoughTime v1 delegation signature\0"` (no trailing dashes)

**Response Size:**
- draft-08: ~352 bytes (smaller SREP)
- draft-14: ~420 bytes (larger SREP with VER/VERS tags)

### Legacy Google Protocol Compatibility

The original Google Roughtime protocol (version 0x00000000) is no longer a
selectable option. However, for backward compatibility, responses containing
version 0x00000000 are parsed and treated as draft-08.

This compatibility exists because:

1. Google's original proof-of-concept server was shut down (unreachable as of
   2024-07-01). No known servers still run the original Google protocol.
2. Servers like Cloudflare that advertise "Google-Roughtime" support actually
   implement IETF draft-08 and may return either version number.
3. The ecosystem has standardized on IETF Roughtime with 32-byte nonces.

Note: The original Google protocol had significant differences from IETF drafts
(64-byte nonces, no VER tag, 5-tag responses). This implementation does not
support those differences as no such servers are known to exist.

References:
- Ecosystem status: https://github.com/cloudflare/roughtime/blob/master/ecosystem.md
- Original Google protocol: https://int08h.com/post/roughtime-message-anatomy/

## Wire Format

- Packets: 8-byte magic 0x524f55474854494d ("ROUGHTIM" in ASCII), 4-byte length (LE), message body
- Requests: Must be exactly 1024 bytes total (pad with ZZZZ tag containing zeros)
- Responses: Variable size based on Merkle path length and VERS length
- Transport: UDP (single datagram) or TCP (multiple messages per connection)

## Message Format (TLV)

- Header: N pairs count (uint32), N-1 offsets (uint32 array), N tags (uint32 array)
- Values section follows header at specified offsets
- Tags must be sorted numerically, offsets must be multiples of 4 and increasing
- All integers are little-endian

## Request Tags

- VER: List of supported version numbers (sorted, unique)
- NONC: 32-byte random nonce
- TYPE: Must be 0 for requests (draft-14 only)
- SRV: Optional, H(0xff || server_pubkey) truncated to 32 bytes (draft-14 only)
- ZZZZ: Padding zeros to reach 1024 bytes

## Response Tags

- SIG: 64-byte Ed25519 signature over SREP
- NONC: Echo of request nonce (draft-14 only)
- TYPE: Must be 1 for responses (draft-14 only)
- PATH: Merkle tree path (32-byte hashes concatenated)
- INDX: Leaf index in Merkle tree (uint32)
- CERT: Contains DELE and SIG
- SREP: Signed response containing:
  - VER: Single version number (draft-14 only)
  - RADI: Accuracy radius in seconds (>=1, recommend >=3 for leap seconds)
  - MIDP: Timestamp (uint64 seconds since Unix epoch)
  - VERS: List of server's supported versions (draft-14 only)
  - ROOT: 32-byte Merkle tree root

## Certificate Structure (CERT)

- DELE: Delegation certificate containing:
  - MINT: Minimum valid timestamp
  - MAXT: Maximum valid timestamp
  - PUBK: 32-byte Ed25519 public key
- SIG: Signature over DELE using long-term key

## Merkle Tree

- Leaf nodes: H(0x00 || full_request_packet)
- Internal nodes: H(0x01 || left_child || right_child)
- H = SHA-512 truncated to first 32 bytes (SHA-512[0:32])
- PATH contains sibling hashes from leaf to root
- Maximum tree height should ensure PATH <= 32 hashes

## Signature Contexts

- Response signature: `"RoughTime v1 response signature\0"`
- Delegation signature (draft-14): `"RoughTime v1 delegation signature\0"`
- Delegation signature (draft-08): `"RoughTime v1 delegation signature--\0"`

## Client Protocol

1. Send request with random nonce
2. Verify response signatures and Merkle path
3. For chaining: next_nonce = H(response_packet || 32_random_bytes)
4. Check causality: MIDP[i] - RADI[i] <= MIDP[j] + RADI[j] for i < j

## Critical Implementation Notes

- Version values: draft-08 = 0x80000008, draft-14 = 0x8000000c (legacy 0x00000000 accepted as draft-08)
- Tags are 4 ASCII chars padded with zeros, uppercase only
- Responses must not exceed request size (amplification prevention)
- Servers batch requests using Merkle trees for efficiency
- All protocol versions support chained measurements

