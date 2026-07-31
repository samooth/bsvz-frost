# bsvz-frost

FROST (Flexible Round-Optimized Schnorr Threshold) signatures over **secp256k1** with **SHA-256**, implemented in Zig on top of the [bsvz](https://github.com/b-open-io/bsvz) secp256k1 backend.

This is a port of [ZcashFoundation/frost-secp256k1](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1) to Zig, designed for integration with the BSV ecosystem via `bsvz` primitives. It is verified **byte-for-byte against the official Zcash test vectors**.

> **Note:** This ciphersuite is **NOT** compatible with Bitcoin BIP-340 (Taproot) signatures. Use `frost-secp256k1-tr` for Taproot compatibility.

## Features

- **Trusted Dealer Key Generation**: Split a secret into `t-of-n` Shamir shares
- **2-Round FROST Signing**: Round 1 (commitments) + Round 2 (signature shares)
- **Signature Aggregation**: Combine shares into a standard Schnorr signature
- **Cheater Detection**: Optional per-share verification to identify malicious signers
- **Secret Reconstruction**: Recover the original key from threshold shares via Lagrange interpolation
- **Single Schnorr Signing**: Standard non-threshold Schnorr signatures
- **Zcash Interop**: Byte-for-byte compatible with `ZcashFoundation/frost-secp256k1` (RFC 9380 `hash_to_field` hashing), proven by an official test-vector test
- **BSV-Ready**: Uses secp256k1 and SHA-256, the same primitives as Bitcoin SV

## Architecture

```
src/
  lib.zig         -- Public API and convenience functions
  error.zig       -- FrostError enum
  identifier.zig  -- Participant identifier (non-zero scalar)
  ciphersuite.zig -- FROST(secp256k1, SHA-256) hash functions (H1-H5, HDKG, HID)
  field.zig       -- Scalar field operations wrapper
  group.zig       -- secp256k1 group element operations wrapper
  keys.zig        -- Key generation, shares, KeyPackage, PublicKeyPackage
  round1.zig      -- Nonce generation, SigningNonces, SigningCommitments
  round2.zig      -- SigningPackage, signature share computation
  aggregate.zig   -- Signature aggregation with optional cheater detection
  signature.zig   -- Schnorr signature (R, z) type
  demo.zig        -- CLI demo: 3-of-5 trusted dealer + full signing flow
  tests.zig       -- Comprehensive unit tests
tests/
  naive_test.zig   -- Integration: naive threshold signing on real bsvz
  shamir_test.zig  -- Integration: Shamir split/reconstruct on real bsvz
  vector_test.zig  -- Interop: official Zcash frost-secp256k1 vectors.json
```

## Quick Start

### Build & Run Demo

```bash
zig build run
```

### Run Tests

```bash
zig build test
```

### Use as a Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .bsvz_frost = .{
        .path = "path/to/bsvz-frost",
    },
},
```

Then in your code:

```zig
const frost = @import("bsvz-frost");
```

## API Example

```zig
const std = @import("std");
const frost = @import("bsvz-frost");

// 1. Trusted dealer generates shares
const max_signers = 5;
const min_signers = 3;
const identifiers = try frost.keys.defaultIdentifiers(max_signers);
const shares, const pubkey = try frost.keys.generateWithDealer(max_signers, min_signers, identifiers);

// 2. Each participant verifies share and creates KeyPackage
var key_packages: [5]frost.KeyPackage = undefined;
for (shares, 0..) |share, i| {
    key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
}

// 3. Round 1: participants commit
var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
var nonces_map = std.AutoHashMap(frost.Identifier, frost.SigningNonces).init(allocator);
for (key_packages[0..min_signers]) |kp| {
    const nonces, const comm = frost.round1.commit(&kp.signing_share);
    try commitments.put(kp.identifier, comm);
    try nonces_map.put(kp.identifier, nonces);
}

// 4. Coordinator creates signing package
const signing_package = frost.SigningPackage.new(commitments, "message to sign");

// 5. Round 2: participants sign
var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
for (key_packages[0..min_signers]) |kp| {
    const nonces = nonces_map.get(kp.identifier).?;
    const share = try frost.round2.sign(&signing_package, &nonces, &kp);
    try signature_shares.put(kp.identifier, share);
}

// 6. Aggregate
const signature = try frost.aggregate.aggregateSimple(&signing_package, signature_shares, &pubkey);

// 7. Verify
try pubkey.verifying_key.verify("message to sign", signature);
```

## Ciphersuite Details

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| Hash | SHA-256 |
| Context String | `FROST-secp256k1-SHA256-v1` |
| H1 (binding factor) | RFC 9380 `hash_to_field` (ExpandMsgXmd\<Sha256\>, L=48), DST `CTX||rho` |
| H2 (challenge) | RFC 9380 `hash_to_field` (ExpandMsgXmd\<Sha256\>, L=48), DST `CTX||chal` |
| H3 (nonce) | RFC 9380 `hash_to_field` (ExpandMsgXmd\<Sha256\>, L=48), DST `CTX||nonce` |
| HDKG / HID | RFC 9380 `hash_to_field`, DST `CTX||dkg` / `CTX||id` |
| H4 (message) | `SHA-256(CTX||"msg"||msg)` |
| H5 (commitments) | `SHA-256(CTX||"com"||encoded_list)` |
| Point serialization | SEC1 compressed (33 bytes) |
| Scalar serialization | Big-endian (32 bytes) |
| Signature format | SEC1(R) || BE(z) (65 bytes) |

Hash-to-scalar functions H1/H2/H3/HDKG/HID follow RFC 9380 exactly as in the
Zcash reference: `expand_message_xmd` (SHA-256) with DST = `CONTEXT_STRING || tag`,
then the 48-byte output is reduced mod the curve order.

## Security Notes

- **Nonce reuse is catastrophic**: Each `SigningNonces` must be used for exactly **one** signing operation. Reuse leaks the signing share.
- **RNG quality matters**: Nonces are generated by hashing random bytes combined with the secret share (hedged against bad RNG).
- **Communication channels**: Secret shares and nonces must be sent over **confidential and authenticated** channels.
- **Coordinator trust**: The coordinator is trusted for liveness and DoS prevention, but learns nothing secret.

## Specification

Implements [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) -- The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures.

## License

MIT / Apache-2.0 (same as Zcash Foundation FROST)
