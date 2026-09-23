# Wire Formats

This chapter specifies every byte layout used by the WebAssembly boundary and
the JavaScript package. The same serializers back the Zig in-memory types, so
interop tests and the JS wrapper both consume these layouts. All multi-byte
integers are **big-endian**.

Primitive encodings:

| Type | Encoding | Length |
|------|----------|--------|
| Scalar / Identifier | Big-endian integer mod curve order | 32 |
| Point (element, key, commitment) | SEC1 compressed | 33 |
| Signature | `SEC1(R) ‖ BE(z)` | 65 |
| Message | Raw bytes | variable |

## Fixed-size types

### KeyPackage (132 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 32 | `identifier` |
| 32 | 32 | `signing_share` (secret!) |
| 64 | 33 | `verifying_share` |
| 97 | 33 | `verifying_key` |
| 130 | 2 | `min_signers` (u16 BE) |

### SigningNonces (64 bytes)

`hiding(32) ‖ binding(32)` — secret; never leave the signer.

### SigningCommitments (66 bytes)

`hiding_point(33) ‖ binding_point(33)` — public.

### Signature (65 bytes)

`R(33) ‖ z(32)` — standard Schnorr encoding, not BIP-340.

### SignatureShare (32 bytes)

The response scalar `z_i`.

## Variable-size types

### SecretShare

`identifier(32) ‖ signing_share(32) ‖ coeff_count(2, BE) ‖ coeff_count × commitment(33)`

Minimum 66 bytes (`coeff_count = 0`). The coefficient commitments allow each
recipient to VSS-verify the share before building a KeyPackage.

### PublicKeyPackage

`verifying_key(33) ‖ min_signers(2, BE; 0 = null) ‖ count(2, BE) ‖ count × (identifier(32) ‖ verifying_share(33))`

Minimum 37 bytes. The verifying key alone (first 33 bytes) is what
`frost_verify` expects.

### SigningPackage

`count(2, BE) ‖ count × (identifier(32) ‖ commitments(66)) ‖ msg_len(4, BE) ‖ message`

Each participant entry is 98 bytes; total length is `2 + 98·count + 4 +
msg_len`. The participant list must be sorted in **ascending identifier
order** — this matches the canonical commitment-list encoding used in the
binding-factor preimage.

### Signature shares blob (aggregate input)

`count(2, BE) ‖ count × (identifier(32) ‖ signature_share(32))`

Each entry is 64 bytes. At least two entries must be present.

### Key packages blob (reconstruct input)

`count(2, BE) ‖ count × KeyPackage(132)`

Each entry is 132 bytes. Supply ≥ `t` packages to recover the group signing
key.

### Round-1 DKG broadcast package

`coeff_count(2, BE) ‖ coeff_count × commitment(33) ‖ proof_of_knowledge(65)`

Entry length is `2 + 33·t + 65` for threshold `t` (the polynomial has `t`
coefficients). On the wire this is always wrapped in a keyed list (below).

### Round-1 DKG secret package (kept private)

`identifier(32) ‖ min_signers(2, BE) ‖ max_signers(2, BE) ‖ coeff_count(2, BE) ‖ coeff_count × scalar(32)`

Minimum 38 bytes. Coefficient commitments are recomputed from the private
coefficients on deserialize.

### Round-2 DKG secret package (kept private)

`identifier(32) ‖ min_signers(2, BE) ‖ max_signers(2, BE) ‖ secret_share(32) ‖ coeff_count(2, BE) ‖ coeff_count × commitment(33)`

Minimum 70 bytes.

## Keyed list blobs

Several multi-party inputs are sent as a count-prefixed list of
`(identifier, payload)` entries:

`count(2, BE) ‖ count × (identifier(32) ‖ payload)`

Used for:

| Context | Payload |
|---------|---------|
| `frost_dkg_part2` broadcasts input / part3 `r1` input | Round-1 broadcast package (`2 + 33t + 65` bytes) |
| `frost_dkg_part2` success output shares / part3 `r2` input | Signing share (32 bytes) |
| Aggregate signature-shares input | Signature share (32 bytes) |
| Identifiable-abort output | (no payload — just `count ‖ count × identifier(32)`) |

**Keying conventions that matter:**

- **part2 broadcasts input**: keyed by the **sender's** id, self excluded
  (exactly `n − 1` entries expected).
- **part2 success output shares**: keyed by the **recipient's** id — these
  are the shares *you* must send to each other participant.
- **part3 `r2` input**: keyed by the **sender's** id — the shares *you
  received*, self excluded. Re-key the entries from each peer's part2 output
  under that peer's id before assembling this blob.

## Operation I/O summary

| Operation | Input | Output (success) |
|-----------|-------|------------------|
| `frost_keygen(t, n)` | scalars only | `count(2) ‖ count × SecretShare ‖ PublicKeyPackage` |
| `frost_keypackage_from_share` | SecretShare | KeyPackage (132) |
| `frost_round1_commit` | KeyPackage (132) | Nonces (64) ‖ Commitments (66) |
| `frost_round2_sign` | SigningPackage ‖ Nonces (64) ‖ KeyPackage (132) | SignatureShare (32) |
| `frost_aggregate` | SigningPackage ‖ shares-blob ‖ PublicKeyPackage ‖ mode(1) | Signature (65) |
| `frost_verify` | VerifyingKey (33) ‖ message ‖ Signature (65) | empty |
| `frost_reconstruct` | `[count ‖ count × KeyPackage]` | SigningKey (32) |
| `frost_dkg_part1(id, t, n)` | scalars only | `secret_len(2) ‖ secret ‖ broadcast` |
| `frost_dkg_part2` | secret ‖ broadcasts-blob | `secret2_len(2) ‖ secret2 ‖ shares-blob`, or cheater list |
| `frost_dkg_part3` | secret2 ‖ r1-blob ‖ r2-blob | KeyPackage (132) ‖ PublicKeyPackage, or cheater list |

`frost_keygen` assigns identifiers `1..n`. DKG identifiers passed to
`frost_dkg_part1` must be ≥ 1 (the low 2 bytes of the 32-byte identifier hold
the `u16`, big-endian, so small ids look like `00…00 00 01`).

Cheater-list output (DKG, `rc > 0`): `count(2, BE) ‖ count × identifier(32)`.

## Compatibility

These layouts are an implementation detail of the WASM/JS boundary in 0.1.x.
They are **not** an interchange format with other FROST implementations
(e.g. the Zcash reference's serde encoding); cross-language interop with those
uses the ciphersuite-level formats described in
[03-ciphersuite.md](03-ciphersuite.md) (point/scalar/signature encodings),
not these composite blobs.

ABI stability rules for 0.1.x: never renumber error codes, never change an
existing field order or width — append new operations or new trailing fields
only, with a version bump via `frost_version()`.
