# Security Policy

## Reporting a Vulnerability

This is a fork of [int08h/roughenough](https://github.com/int08h/roughenough).

For vulnerabilities affecting the core protocol implementation:
- Report to the upstream project: **stuart @ int08h.com**
- Also notify this fork: **security @ sympower.net**

For vulnerabilities specific to this fork's additions (multi-protocol support, etc.):
- Report to: **security @ sympower.net**

Please do not open public issues for security vulnerabilities.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

## Security Notes

### Cryptography
- Uses aws-lc-rs for Ed25519 signatures and SHA-512 hashing
- Follows Roughtime RFC specification (draft-ietf-ntp-roughtime-14)

### Key Protection
Online keys have multiple options for secure storage:
- Linux Kernel Retention Service (KRS)
- SSH agent
- PKCS#11 hardware
- AWS KMS and Secrets Manager
- GCP KMS and Secrets Manager

See `doc/PROTECTION.md` for details.
