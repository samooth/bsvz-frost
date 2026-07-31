# Ciphersuite

`bsvz-frost` implements the **FROST(secp256k1, SHA-256)** ciphersuite, identical
to `ZcashFoundation/frost-secp256k1`.

## Parameters

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| Group order `n` | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` |
| Hash | SHA-256 |
| Context string | `FROST-secp256k1-SHA256-v1` |
| Point serialization | SEC1 compressed (33 bytes) |
| Scalar serialization | Big-endian (32 bytes) |
| Signature format | `SEC1(R) \|\| BE(z)` (65 bytes) |

## Hash functions

The ciphersuite defines six domain-separated hash functions. They come in two
flavors:

### Hash-to-scalar: H1, H2, H3, HDKG, HID

These use **RFC 9380 `hash_to_field`** exactly as the Zcash reference:

```
hash_to_field(msg, count = 1, L = 48, expander = expand_message_xmd(SHA-256))
```

- `expand_message_xmd` with `b_in = 32` (SHA-256 block/output), `r_in = 64`
  (SHA-256 block size). It produces 48 bytes (`len_in_bytes = L · count`).
- DST is the concatenation `CONTEXT_STRING || tag`.
- The 48-byte uniform string is reduced mod `n` via
  `Secp256k1.scalar.Scalar.fromBytes48(bytes, .big)`.

| Function | DST (`CTX = "FROST-secp256k1-SHA256-v1"`) | Purpose |
|----------|-------------------------------------------|---------|
| `H1` | `CTX \|\| "rho"` | Binding factors |
| `H2` | `CTX \|\| "chal"` | Schnorr challenges |
| `H3` | `CTX \|\| "nonce"` | Nonce derivation from randomness |
| `HDKG` | `CTX \|\| "dkg"` | Distributed keygen hash |
| `HID` | `CTX \|\| "id"` | Identifier derivation |

> Using plain `SHA-256(CTX || tag || msg)` reduced mod `n` produces **different**
> scalars than the reference — this was one of the four compatibility bugs
> fixed (see [06-interop.md](06-interop.md)).

### Hash-to-array: H4, H5

Plain SHA-256 over the tagged input:

| Function | Input | Purpose |
|----------|-------|---------|
| `H4` | `SHA-256(CTX \|\| "msg" \|\| msg)` | Message binding in binding-factor preimages |
| `H5` | `SHA-256(CTX \|\| "com" \|\| encoded_commitments)` | Commitment-list binding |

## Signature format

A FROST aggregate signature is a standard Schnorr signature `(R, z)`:

- `R`: the group commitment — a group element, serialized **compressed SEC1**,
  33 bytes.
- `z`: the response scalar, serialized **big-endian**, 32 bytes.

Total: **65 bytes** (`Signature.serialize()` → `[65]u8`).

## Compatibility

- Verified byte-for-byte against the Zcash reference: H4/H5 outputs, binding
  factors, commitments, nonces, signature shares, and final signatures all
  match the official `vectors.json` fixture.
- **Not** BIP-340: BIP-340 uses a different challenge construction, an
  even-y-only `R`, and x-only keys. Use `frost-secp256k1-tr` for Taproot.
