# Roughtime

[![Build Status](https://github.com/sympower/roughenough/actions/workflows/rust.yml/badge.svg)](https://github.com/sympower/roughenough/actions/workflows/rust.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)

> **Fork Notice**: This is a fork of [int08h/roughenough](https://github.com/int08h/roughenough).
> This fork adds multi-protocol version support (Google, RFC draft-08, RFC draft-14) and other enhancements.

Roughenough is an implementation of the [IETF Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
secure time synchronization protocol. Roughenough provides both server and client components for cryptographically
verifiable time synchronization.

## Features

- **Multi-Protocol Support**: Supports Google Roughtime, RFC draft-08, and RFC draft-14 protocols
- **RFC Compliant**: Full implementation of the IETF Roughtime RFC specification
- **High Performance Server**: Performance oriented asynchronous UDP server
- **Flexible Client**: Command-line client with multiple output formats and server validation
- **Mixed Protocol Chaining**: Query servers using different protocol versions in a single chained measurement
- **Malfeasance Reporting**: Clients can (optionally) report malfeasance to a remote server for analysis
- **Key Management**: Multiple backends for secure key and identity protection (KMS, Secret Manager, Linux KRS,
  SSH agent, PKCS#11)

## Protocol Versions

Roughenough supports these protocol versions:

| Version  | Flag    | Description                         |
|----------|---------|-------------------------------------|
| draft-08 | `-P 8`  | IETF draft-08 (used by Cloudflare)  |
| draft-14 | `-P 14` | IETF draft-14 (default, latest RFC) |

Different servers support different protocol versions. For example:
- `roughtime.int08h.com:2003` supports draft-14
- `roughtime.cloudflare.com:2003` supports draft-08

### Server List JSON Format

When querying multiple servers with `-l servers.json`, you can specify the protocol version per server:

```json
{
  "servers": [
    {
      "name": "int08h",
      "publicKeyType": "ed25519",
      "publicKey": "gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=",
      "addresses": [
        { "protocol": "udp", "address": "roughtime.int08h.com:2003" }
      ],
      "protocolVersion": "14"
    },
    {
      "name": "cloudflare",
      "publicKeyType": "ed25519",
      "publicKey": "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=",
      "addresses": [
        { "protocol": "udp", "address": "roughtime.cloudflare.com:2003" }
      ],
      "protocolVersion": "8"
    }
  ]
}
```

The `protocolVersion` field accepts: `"0"` (Google), `"8"` (draft-08), or `"14"` (draft-14). If omitted, defaults to draft-14.

## Quick Start

### System Requirements

- MSRV 1.88, Rust 2024 edition 
- Linux, MacOS, or other Unix-like operating system
- Optional: cloud provider credentials for backend key storage

### Installation

Build all components:

```bash
cargo build --release
```

Build with all optional features:

```bash
# Enable all optional features
cargo build --release --all-features 
```

### Running the Server

```bash
# Debug build
cargo run --bin roughenough_server

# Release build with optimizations
cargo run --release --bin roughenough_server

# Run the server binary directly
target/release/roughenough_server

# Specify protocol version (0=Google, 8=draft-08, 14=draft-14)
cargo run --bin roughenough_server -- -P 8   # Run as draft-08 server
cargo run --bin roughenough_server -- -P 14  # Run as draft-14 server (default)
```

The server will start listening for UDP requests on the default port (2003).

### Running the Client

Basic usage:

```bash
# Query a Roughtime server (defaults to draft-14 protocol)
cargo run --bin roughenough_client -- roughtime.int08h.com 2003

# Verify server public key
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 -k <base64-or-hex-key>

# Multiple requests
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 -n 10

# Verbose output
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 -v

# Different time formats
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 --epoch  # Unix timestamp
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 --zulu   # ISO 8601 UTC

# Specify protocol version (0=Google, 8=draft-08, 14=draft-14)
cargo run --bin roughenough_client -- roughtime.cloudflare.com 2003 -P 8   # Query draft-08 server
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 -P 14      # Query draft-14 server

# Protocol debugging - dump raw bytes to console
cargo run --bin roughenough_client -- roughtime.int08h.com 2003 --dump-console
```

Query multiple servers from an RFC compliant JSON list:

```bash
cargo run --bin roughenough_client -- -l servers.json
```

Chained measurements across multiple servers (supports mixed protocol versions):

```bash
# Chain requests with nonce linking for causality validation
cargo run --bin roughenough_client -- -l servers.json -n 3

# Retry measurement if causality violations are detected (RFC 8.2)
cargo run --bin roughenough_client -- -l servers.json --causality-violation-retries 3
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p protocol

# Run integration tests
target/debug/roughenough_integration_test
```

## Project Structure

Roughtime is structured as a Cargo workspace with multiple crates:

- **protocol**: Core wire format handling, request/response types, data structures
- **merkle**: Merkle tree implementation with Roughtime-specific tweaks
- **server**: High-performance UDP server with async I/O and batching
- **client**: Command-line client for querying Roughtime servers
- **common**: Shared cryptography and encoding utilities
- **keys**: Key material handling with multiple secure storage backends
- **reporting-server**: Web server for collecting malfeasance reports
- **integration**: End-to-end integration tests
- **fuzz**: Fuzzing harness

## Optional Features

### Client Features

- **reporting**: Enable clients to report malfeasance to a remote server
  ```bash
  cargo build -p client --features reporting
  cargo run --bin roughenough_client -- -l servers.json --report
  ```

  Reporting options:
  - `--report-timeout <SECS>`: HTTP request timeout (default: 5 seconds)
  - `--report-retries <N>`: Retry failed submissions with exponential backoff (default: 0)

  With retries enabled, backoff doubles each attempt starting at 10s (10s, 20s, 40s, ...)
  per RFC 8.4. Worst-case wait time is `(retries + 1) * timeout + 10 * (2^retries - 1)` seconds.

### Keys Crate Features

See [doc/PROTECTION.md](doc/PROTECTION.md) for detailed information on seed protection strategies.

#### Runtime Protection (Online Key Backends)

- `online-linux-krs` (default): Store seed in Linux Kernel Keyring for runtime protection
- `online-ssh-agent` Use SSH agent for seed storage and signing operations
- `online-pkcs11` PKCS#11 hardware security module integration (Yubikey, HSM, etc)

#### Long-term Protection (Seed Storage)

- `longterm-aws-kms` AWS Key Management Service for seed encryption
- `longterm-gcp-kms` Google Cloud KMS for seed encryption
- `longterm-aws-secret-manager` AWS Secrets Manager for seed storage
- `longterm-gcp-secret-manager` Google Cloud Secret Manager for seed storage

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Thank you to all past and present contributors:

* Stuart Stock (stuart {at} int08h.com)
* Aaron Hill (aa1ronham {at} gmail.com)
* Peter Todd (pete {at} petertodd.org)
* Muncan90 (github.com/muncan90)
* Zicklag (github.com/zicklag)
* Greg at Unrelenting Tech (github.com/unrelentingtech)
* Eric Swanson (github.com/lachesis)
* Marcus Dansarie (github.com/dansarie)

## License

Copyright (c) 2017-2025 int08h LLC, Copyright (c) 2026 Sympower.

Roughenough is licensed under either of

* [Apache License, Version 2.0](LICENSE-APACHE) (http://www.apache.org/licenses/LICENSE-2.0)
* [MIT License](LICENSE-MIT) (http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, 
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
