# Overview

`bsvz-frost` implements the FROST threshold-signature protocol in Zig, using
the same primitives as Bitcoin SV (secp256k1 + SHA-256) through the `bsvz`
library. It is a port of
[ZcashFoundation/frost-secp256k1](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1)
and is verified byte-for-byte against that reference's official test vectors.

## What is FROST?

FROST (Flexible Round-Optimized Schnorr Threshold signatures) lets a group of
`n` participants hold shares of a single secret key so that any `t` of them
("threshold") can collaborate to produce a single standard Schnorr signature.
The resulting signature is indistinguishable from one produced by a single key
holder — no quorum metadata is embedded in it.

Two-round signing (RFC 9591):

1. Each participant generates two nonces and broadcasts their commitments.
2. Each participant computes a binding factor from the full set of commitments,
   then produces a signature share over a *shared* group commitment.
3. A coordinator sums the shares into a final Schnorr signature `(R, z)`.

Security properties (FROST is a threshold Schnorr scheme with *identifiable
abort*):

- **Unforgeability**: with fewer than `t` shares, no one can forge a signature.
- **Non-interactive key aggregation**: the group commitment `R` binds each
  participant's nonce to the full commitment list via binding factors.
- **Cheater detection**: with `t` shares of the verifying key, the coordinator
  can identify which participant produced an invalid share.

## Project goals

- Provide a FROST implementation for the BSV ecosystem, reusing `bsvz`
  primitives.
- Stay byte-for-byte compatible with the canonical Zcash FROST ciphersuite
  (not BIP-340).
- Be auditable: each module mirrors a section of the reference implementation,
  and correctness is proven by test vectors rather than round-trip tests.

## Architecture

The library is split into protocol modules mirroring the Zcash
`frost-core` structure, plus bsvz-interop primitives.

```
src/
  lib.zig         -- Public API re-exports and fullFrostSign() convenience
  error.zig       -- FrostError error set
  identifier.zig  -- Identifier (32-byte non-zero scalar)
  ciphersuite.zig -- Hash functions H1-H5, HDKG, HID (RFC 9380 hash_to_field)
  field.zig       -- Scalar field operations (std Secp256k1.scalar.Scalar)
  group.zig       -- Group element operations (std Secp256k1 point)
  keys.zig        -- Keygen, shares, KeyPackage, PublicKeyPackage, Lagrange
  dkg.zig         -- Distributed key generation (part1/part2/part3)
  round1.zig      -- Nonce generation and SigningCommitments
  round2.zig      -- SigningPackage, binding factors, signature shares
  aggregate.zig   -- Signature aggregation and cheater detection
  signature.zig   -- (R, z) Signature type, serialization
  scalar.zig      -- [32]u8 big-endian byte-scalar arithmetic (bsvz interop)
  shamir.zig      -- Plain Shamir split/reconstruct (byte scalars)
  naive.zig       -- Naive threshold Schnorr (evaluation only, not FROST)
  demo.zig        -- CLI demo: trusted dealer + full 3-of-5 signing flow
  tests.zig       -- Unit tests

tests/
  naive_test.zig     -- Integration tests for the naive scheme on real bsvz
  shamir_test.zig    -- Integration tests for Shamir on real bsvz
  vector_test.zig    -- Zcash official vectors.json end-to-end interop test
  security_test.zig  -- Negative/property (misuse-resistance) tests
  dkg_test.zig       -- Functional DKG: 3-party flow + threshold sign
  dkg_vector_test.zig -- Zcash official vectors_dkg.json interop test
  fuzz_test.zig      -- std.testing.fuzz targets
```

## Two layers of primitives

`bsvz-frost` contains two distinct stacks:

1. **Protocol layer (production)** — the FROST modules (`field.zig`,
   `group.zig`, `keys.zig`, `dkg.zig`, `round1.zig`, `round2.zig`,
   `aggregate.zig`, `signature.zig`, `identifier.zig`, `ciphersuite.zig`).
   These use the stdlib `Secp256k1` types for scalars/points and are
   Zcash-compatible.
2. **Interop layer (evaluation)** — `scalar.zig`, `shamir.zig`, `naive.zig`
   built on `bsvz.crypto.Point`. These use `[32]u8` big-endian byte scalars
   and provide a plain threshold-Schnorr scheme that is **not** FROST
   (no binding factors, no identifiable abort). See [05-api-reference.md](05-api-reference.md#naive---evaluation-scheme).

> **Important**: `naive` is for evaluation/interop only. Production code
> should use the FROST modules.

## Compatibility notes

- Matches `ZcashFoundation/frost-secp256k1` byte-for-byte (hashing via RFC 9380,
  commitment encoding, binding-factor preimages, signature format).
- **Not** compatible with BIP-340 (Taproot) Schnorr signatures — those use a
  different hash domain and even-y-only points.
