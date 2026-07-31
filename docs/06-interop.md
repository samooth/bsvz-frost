# Interop with ZcashFoundation/frost-secp256k1

`bsvz-frost` is verified **byte-for-byte** against the official
`ZcashFoundation/frost-secp256k1` reference. This document explains how that
compatibility was achieved and proven.

## Reference

- Ciphersuite crate: `frost-secp256k1/src/lib.rs`
- Protocol core: `frost-core/src/{lib,round1,round2,keys}.rs`
- Vectors: `frost-secp256k1/tests/helpers/vectors.json`

## Why "internally consistent" tests were not enough

Before this work the port passed its own 16 tests and produced valid Schnorr
signatures — yet **every byte differed** from Zcash. Round-trip tests can only
prove self-consistency. Cross-language compatibility requires comparing against
official test vectors at every intermediate stage.

## The four compatibility bugs found and fixed

### 1. Hash-to-scalar must be RFC 9380 `hash_to_field`

**Before:** `SHA-256(CTX || tag || msg)` reduced mod `n`.

**Reference:** `hash_to_field(msg, count=1, L=48, expand_message_xmd(SHA-256))`
with DST = `CTX || tag`. The 48-byte output is reduced mod `n`.

This affects H1 (binding factors), H2 (challenges), H3 (nonces), HDKG, and HID.
Confirmed by re-implementing `expand_message_xmd` in Python: the vector's
binding factor `9bee5aef...824a91` only matches the xmd construction.

**Fix:** `ciphersuite.zig` implements `expand_message_xmd` (b_0/b_1/b_2 with
`strxor`) and `hashToScalar = Scalar.fromBytes48(uniform_bytes, .big)`.

### 2. `challenge()` double-hashed the preimage

**Before:** `H2(SHA256(R || VK || msg))` — a nested hash.

**Reference:** `H2` applied directly to the raw preimage `serialize(R) || serialize(VK) || msg`.

**Fix:** `keys.challenge` builds the raw preimage and calls `cs.H2` once.

### 3. `encode_group_commitments` hashed internally

**Before:** the function returned `H5(...)` of the encoded list.

**Reference:** it returns the **raw** bytes
`serialize(id) || serialize(hiding) || serialize(binding)` per participant,
in **ascending identifier order** (k256 `BTreeMap` iteration); the caller
applies H5. The byte count of the encoding is significant.

**Fix:** `round1.encodeGroupCommitments` sorts identifiers ascending and returns
the raw concatenation; the caller hashes with H5.

### 4. `binding_factor_preimages` hashed internally

**Before:** the function returned `H1(...)` per participant.

**Reference:** the preimage is the raw concatenation
`serialize(VK)(33) || H4(msg)(32) || H5(encoded)(32) || serialize(id)(32)` =
**129 bytes** per participant. H1 is applied by the caller.

**Fix:** `round2.SigningPackage.bindingFactorPreimages` returns the raw
129-byte preimages (owned buffers).

## Verified-correct (kept as-is)

- H4 / H5 = `SHA-256(CTX || "msg" || msg)` / `SHA-256(CTX || "com" || encoded)`
- Nonce construction `H3(random || secret_enc)`
- Signature-share formula `z_i = d_i + e_i·ρ_i + λ_i·s_i·c`
- Per-share verification `z_i·G = D_i + (E_i)^ρ_i · (Y_i)^(λ_i·c)`
- Identifier serialization as 32-byte big-endian
- Aggregate verification `z·G = R + c·VK`

## Test-vector verification

`tests/vector_test.zig` replays the official fixture end-to-end:

- **Fixture used**: group secret `0d0041...a83114`, participants 1 and 3,
  threshold 2, message `"test"` (`74657374`).
- **Flow**: builds key packages from the vector's shares → derives nonces from
  the vector's fixed nonce randomness via
  `nonceGenerateFromRandomBytes` → checks nonces, commitments, binding-factor
  preimages, binding factors, signature shares, and the final 65-byte signature
  — **byte-for-byte** at every stage.
- Additional cross-checks of H4/H5 against values embedded in the fixture's
  `binding_factor_input`.

A second test asserts the exact H4/H5 digests.

## Reproducing the analysis

The key intermediate values can be re-derived independently:

- `expand_message_xmd` (SHA-256): implementable in ~15 lines in any language;
  the fixture's binding factor matches only this construction.
- Binding-factor preimage for identifier 1:
  `02f37c...b4f` ‖ `ff9b52...40fc` (H4) ‖ `fac8df...3631` (H5) ‖ `00...01`.

## Status

All 39 tests pass in Debug and ReleaseSafe, including the two vector interop
tests. The port matches the Zcash reference at every observable byte.
