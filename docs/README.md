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
| [01-overview.md](01-overview.md) | What FROST is, project goals, architecture, module map (incl. wasm + js) |
| [02-getting-started.md](02-getting-started.md) | Requirements, build, run demo, run tests, wasm build, use as a dependency |
| [03-ciphersuite.md](03-ciphersuite.md) | Ciphersuite parameters, hash functions (H1–H5, HDKG, HID), serialization formats |
| [04-protocol.md](04-protocol.md) | Trusted-dealer keygen, DKG (part1/2/3), Round 1, Round 2, aggregation, cheater detection, reconstruction |
| [05-api-reference.md](05-api-reference.md) | Full public API reference per module (Zig); links out to wasm/JS docs |
| [06-interop.md](06-interop.md) | Zcash compatibility, test-vector verification, the bugs it caught |
| [07-security.md](07-security.md) | Security notes, nonce discipline, threat model |
| [08-testing.md](08-testing.md) | Test suite guide: negative/property tests, fuzz targets, how to run |
| [09-webassembly.md](09-webassembly.md) | WASM module ABI: exports, out-slot, error codes, host entropy |
| [10-wire-formats.md](10-wire-formats.md) | Byte layouts for every type and DKG/signing blob on the WASM boundary |
| [11-js-package.md](11-js-package.md) | JavaScript package: createFrost API, Node/browser usage, smoke test |

## Quick facts

- **Ciphersuite**: FROST(secp256k1, SHA-256) — `CONTEXT_STRING = "FROST-secp256k1-SHA256-v1"`.
- **NOT BIP-340 / Taproot compatible**; use `frost-secp256k1-tr` for that.
- **Language**: Zig 0.16.0 / 0.17.0 (both verified; also builds on earlier `0.16.0-dev` snapshots).
- **Dependency**: `b-open-io/bsvz` (pinned via `build.zig.zon`).
- **WebAssembly / JS**: `zig build wasm` → `src/wasm.zig` (`wasm32-freestanding`); wrapper package in `js/` (Node ≥ 18 + browsers), smoke-tested by `npm test`.
- **Tests**: 48 Zig tests in Debug/ReleaseSafe (16 unit + 2 naive + 2 shamir + 2 Zcash vector interop + 18 negative/property + 2 DKG functional + 3 DKG vector interop + 3 fuzz); 45 in ReleaseFast/ReleaseSmall (fuzz targets skipped), plus the Node wasm smoke test.
