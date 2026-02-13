# Changelog

## [Unreleased]

### Added
- Multi-protocol version support: RFC draft-08 (8), and RFC draft-14 (14)
- Protocol version flag `-P` for both client and server binaries
- Mixed protocol version support in chained measurements
- Server list JSON `protocolVersion` field for per-server protocol configuration

### Changed
- Default server port changed from 2002 to 2003
- Client and server use consistent `ProtocolVersionArg` enum for protocol selection
- DELE signature prefix is now protocol-version aware (draft-08 uses dashes)

### Fixed
- Draft-08 request type selection when public key is provided
- DELE signature validation for draft-08 servers (Cloudflare compatibility)

### Removed
- Protocol version support for the original Google Roughtime protocol

## [2.0.0] - 2025-10-06

- Initial release of Roughenough 2.0

## Versioning Policy

This project aspirationally follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and tries to 
adhere to it as closely/practically as possible:

- **MAJOR** version increments indicate incompatible API changes
- **MINOR** version increments add functionality in a backward compatible manner
- **PATCH** version increments make backward compatible bug fixes

Given a version number MAJOR.MINOR.PATCH:
- Breaking changes to public APIs or protocol implementation increment MAJOR
- New features that maintain backward compatibility increment MINOR
- Bug fixes and internal improvements increment PATCH


