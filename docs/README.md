# bsvz-frost Documentation

FROST (Flexible Round-Optimized Schnorr Threshold) signatures over **secp256k1**
with **SHA-256**, implemented in Zig on top of the
[bsvz](https://github.com/b-open-io/bsvz) secp256k1 backend, and verified
**byte-for-byte against the official
[ZcashFoundation/frost-secp256k1](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1)
test vectors**.

## Contents

| Document | Covers |
|----------|--------|
| [01-overview.md](01-overview.md) | What FROST is, project goals, architecture, module map |
| [02-getting-started.md](02-getting-started.md) | Requirements, build, run demo, run tests, use as a dependency |
| [03-ciphersuite.md](03-ciphersuite.md) | Ciphersuite parameters, hash functions (H1–H5, HDKG, HID), serialization formats |
| [04-protocol.md](04-protocol.md) | Trusted-dealer keygen, Round 1, Round 2, aggregation, cheater detection, reconstruction |
| [05-api-reference.md](05-api-reference.md) | Full public API reference per module |
| [06-interop.md](06-interop.md) | Zcash compatibility, test-vector verification, the bugs it caught |
| [07-security.md](07-security.md) | Security notes, nonce discipline, threat model |

## Quick facts

- **Ciphersuite**: FROST(secp256k1, SHA-256) — `CONTEXT_STRING = "FROST-secp256k1-SHA256-v1"`.
- **NOT BIP-340 / Taproot compatible**; use `frost-secp256k1-tr` for that.
- **Language**: Zig 0.16.0-dev.2535.
- **Dependency**: `b-open-io/bsvz` (pinned via `build.zig.zon`).
- **Tests**: 18 (12 unit + 2 naive + 2 shamir + 2 Zcash vector interop), green in Debug and ReleaseSafe.
