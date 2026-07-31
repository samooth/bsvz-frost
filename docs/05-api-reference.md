# API Reference

All public symbols are re-exported from `@import("bsvz-frost")`. Types use the
stdlib `Secp256k1` scalar/point types; interop helpers use `[32]u8` big-endian
byte scalars.

## `Error`

`FrostError` error set (`error.zig`):

```
InvalidMinSigners, InvalidMaxSigners, IncorrectNumberOfIdentifiers,
DuplicatedIdentifier, UnknownIdentifier, IncorrectNumberOfCommitments,
IncorrectNumberOfShares, MissingCommitment, InvalidCommitment,
IdentityCommitment, InvalidSecretShare, InvalidSignatureShare,
InvalidSignature, MalformedScalar, MalformedElement, MalformedSigningKey,
InvalidZeroScalar, InvalidIdentityElement, InvalidCoefficient,
SerializationFailed, DeserializationFailed, DkgNotSupported,
IdentifierDerivationNotSupported, RandomnessError, InvalidNonce,
IncorrectNumberOfPackages, IncorrectPackage, PackageNotFound,
InvalidProofOfKnowledge
```

## `Identifier`

32-byte non-zero scalar identifying a participant.

- `fromU16(id: u16) !Identifier` — reject 0.
- `toU16() u16`
- `serialize() [32]u8` / `deserialize(bytes: [32]u8) !Identifier`
- `eql(other: Identifier) bool` / `lessThan(other: Identifier) bool`

## `Signature`

- `R: Secp256k1`, `z: Secp256k1.scalar.Scalar`
- `serialize() ![65]u8` — `SEC1(R) || BE(z)`
- `deserialize(bytes: [65]u8) !Signature`

## `Ciphersuite`

Hash functions (see [03-ciphersuite.md](03-ciphersuite.md)):

- `CONTEXT_STRING: []const u8 = "FROST-secp256k1-SHA256-v1"`
- `H1/H2/H3/HDKG/HID(msg: []const u8) Secp256k1.scalar.Scalar` — RFC 9380 `hash_to_field`
- `H4/H5(msg: []const u8) [32]u8` — `SHA-256(CTX || tag || msg)`

## `field`

Scalar field over the secp256k1 subgroup order. `Scalar = Secp256k1.scalar.Scalar`.

- `randomBytes(buffer: []u8) void`
- `scalarZero() Scalar` / `scalarOne() Scalar` / `scalarRandom() Scalar`
- `scalarInvert(s: Scalar) !Scalar` (rejects zero)
- `scalarSerialize(s: Scalar) [32]u8` / `scalarDeserialize(bytes: [32]u8) !Scalar`
- `scalarAdd(a, b) Scalar` / `scalarSub(a, b) Scalar` / `scalarMul(a, b) Scalar`
- `scalarNegate(s) Scalar` / `scalarIsZero(s) bool` / `scalarEql(a, b) bool`

## `group`

Group elements. `Element = Secp256k1`.

- `identity() Element` / `generator() Element`
- `elementSerialize(e) ![33]u8` — compressed SEC1 (rejects identity)
- `elementDeserialize(bytes: [33]u8) !Element`
- `elementAdd(a, b) Element` / `elementSub(a, b) Element` / `elementNegate(e) Element`
- `elementScalarMul(e, s) Element` / `elementScalarBaseMul(s) Element`
- `elementIsIdentity(e) bool` / `elementEql(a, b) bool`

## `scalar` — byte-scalar arithmetic (bsvz interop)

`[32]u8` big-endian, mod curve order. Not part of the FROST protocol layer.

- `zero() [32]u8` / `one() [32]u8` / `fromInt(value: u64) [32]u8`
- `fromBytes(bytes: [32]u8) ![32]u8` — validate canonical
- `reduce(bytes: [32]u8) [32]u8` — reduce mod `n`
- `random() [32]u8`
- `add(a, b) / sub(a, b) / mul(a, b) / inv(a) / neg(a) / eq(a, b) / isZero(a)`

## `shamir` — Shamir secret sharing (byte scalars)

- `Share { index: u32, value: [32]u8 }`
- `split(secret: [32]u8, threshold: u32, num_shares: u32, allocator) ![]Share`
- `reconstruct(shares: []const Share) [32]u8`

## `naive` — evaluation threshold Schnorr (NOT FROST)

Built on `bsvz.crypto.Point`. No binding factors, no identifiable abort —
**not for production** (see [01-overview.md](01-overview.md)).

- `PartialSignature { identifier: u32, R: bsvz.crypto.Point, s: [32]u8 }`
- `Signature { R: bsvz.crypto.Point, s: [32]u8 }`
- `challenge(publicKey, R, message) [32]u8` — `reduce(SHA-256(R || P || m))`
- `lagrangeCoefficient(i: u32, participant_ids: []const u32) [32]u8`
- `partialSign(share, nonce, identifier, participant_ids, group_pubkey, group_commitment, message) !PartialSignature`
- `aggregate(partial_sigs: []const PartialSignature) Signature`
- `verify(group_pubkey, message, sig) !bool`

## `keys` — key generation and shares

### SigningShare
- `fromScalar(s) SigningShare` / `toScalar() Scalar`
- `serialize() [32]u8` / `deserialize(bytes: [32]u8) !SigningShare`

### VerifyingShare
- `fromElement(e) / toElement() / fromSigningShare(ss) VerifyingShare`
- `serialize() ![33]u8` / `deserialize(bytes: [33]u8) !VerifyingShare`

### CoefficientCommitment / VerifiableSecretSharingCommitment
- `CoefficientCommitment: fromElement / value / serialize ![33]u8 / deserialize`
- `VerifiableSecretSharingCommitment { coefficients: []const CoefficientCommitment }`
  - `init(coefficients)` / `minSigners() u16` / `verifyingKey() !VerifyingKey`

### SecretShare
- `{ identifier, signing_share, commitment }`
- `verify() !{ VerifyingShare, VerifyingKey }` — VSS check

### KeyPackage
- `{ identifier, signing_share, verifying_share, verifying_key, min_signers }`
- `fromSecretShare(secret_share: SecretShare) !KeyPackage`

### PublicKeyPackage
- `{ verifying_shares: AutoHashMap(Identifier, VerifyingShare), verifying_key, min_signers: ?u16 }`
- `maxSigners() u16`
- `fromDkgCommitments(allocator, commitments: *AutoHashMap(Identifier, *const VerifiableSecretSharingCommitment)) !PublicKeyPackage`

### SigningKey
- `generate() SigningKey`
- `fromScalar(s) !SigningKey` / `toScalar() Scalar`
- `serialize() [32]u8` / `deserialize(bytes: [32]u8) !SigningKey`
- `sign(message: []const u8) !Signature` — plain single Schnorr

### VerifyingKey
- `fromElement(e) / fromSigningKey(sk) / toElement() / fromCommitment(c) !VerifyingKey`
- `serialize() ![33]u8` / `deserialize(bytes: [33]u8) !VerifyingKey`
- `verify(message, signature: Signature) !void`

### Functions
- `challenge(R: *const Element, verifying_key: *const VerifyingKey, msg) !Scalar`
  — `H2(serialize(R) || serialize(VK) || msg)`
- `defaultIdentifiers(max_signers: u16) ![]Identifier` — `1..max_signers`
- `generateWithDealer(max, min, identifiers) !{ []SecretShare, PublicKeyPackage }`
- `split(secret: *const SigningKey, max, min, identifiers) !{ []SecretShare, PublicKeyPackage }`
- `reconstruct(key_packages: []const KeyPackage) !SigningKey`
- `deriveInterpolatingValue(signer_id, key_packages) !Scalar`
- `computeLagrangeCoefficient(identifiers: []const Identifier, x_i) !Scalar`
- `evaluatePolynomial(identifier, coefficients: []const Scalar) Scalar`
- `evaluateVss(identifier, commitment: VerifiableSecretSharingCommitment) Element`
- `generateCoefficients(min_signers: u16) []Scalar`
- `generateSecretPolynomial(secret: SigningKey, max, min, coefficients: []Scalar) !{ []Scalar, VerifiableSecretSharingCommitment }`
- `sumCommitments(commitments: []const VerifiableSecretSharingCommitment) !VerifiableSecretSharingCommitment`

## `dkg` — distributed key generation

`dkg.part1/part2/part3` run FROST KeyGen without a trusted dealer (see
[04-protocol.md](04-protocol.md) §9).

### `round1`
- `Package { commitment, proof_of_knowledge: Signature }` — broadcast; `deinit()` frees the commitment.
- `SecretPackage { identifier, coefficients: []Scalar, commitment, min_signers, max_signers }` — kept secret; `deinit()`.

### `round2`
- `Package { signing_share: SigningShare }` — sent privately to one recipient.
- `SecretPackage { identifier, commitment, secret_share: Scalar, min_signers, max_signers }` — kept secret; `deinit()`.

### Functions
- `part1(identifier, max_signers, min_signers) !{ round1.SecretPackage, round1.Package }`
- `part2(secret_package: *const round1.SecretPackage, round1_packages: *AutoHashMap(Identifier, round1.Package), allocator) !{ round2.SecretPackage, AutoHashMap(Identifier, round2.Package) }`
- `part3(round2_secret_package: *const round2.SecretPackage, round1_packages: *AutoHashMap(Identifier, round1.Package), round2_packages: *AutoHashMap(Identifier, round2.Package), allocator) !{ KeyPackage, PublicKeyPackage }`

Allocations: `part2`/`part3` allocate with the supplied `allocator`; the
`SecretPackage` coefficient/commitment allocations are owned by the package and
released by `deinit()` (page allocator).

## `round1` — nonces and commitments

### Nonce
- `new(secret: *const SigningShare) Nonce` — fresh randomness
- `nonceGenerateFromRandomBytes(secret: *const SigningShare, random_bytes: [32]u8) Nonce`
  — `H3(random || serialize(secret))`
- `toScalar() Scalar` / `serialize() [32]u8` / `deserialize(bytes) !Nonce`

### NonceCommitment
- `fromElement(e) / value() / fromNonce(nonce) NonceCommitment`
- `serialize() ![33]u8` / `deserialize(bytes: [33]u8) !NonceCommitment`

### SigningNonces
- `{ hiding: Nonce, binding: Nonce, commitments: SigningCommitments }`
- `new(secret) SigningNonces` / `fromNonces(hiding, binding) SigningNonces`

### SigningCommitments
- `{ hiding: NonceCommitment, binding: NonceCommitment }`
- `new(hiding, binding)`
- `toGroupCommitmentShare(binding_factor: Scalar) Element` — `hiding + binding·rho`

### GroupCommitmentShare
- `fromElement(e)` / `toElement()`

### Functions
- `encodeGroupCommitments(signing_commitments: AutoHashMap(Identifier, SigningCommitments), allocator) ![]u8`
  — raw `id || hiding || binding` per participant, ascending by id
- `commit(secret: *const SigningShare) { SigningNonces, SigningCommitments }`
- `preprocess(num_nonces: u8, secret) { []SigningNonces, []SigningCommitments }`

## `round2` — signing

### SignatureShare
- `new(s: Scalar) / toScalar() / serialize() [32]u8 / deserialize(bytes) !SignatureShare`
- `verify(identifier, group_commitment_share: *const GroupCommitmentShare, verifying_share: *const VerifyingShare, lambda_i: Scalar, challenge: Scalar) !void`

### SigningPackage
- `{ signing_commitments: AutoHashMap(Identifier, SigningCommitments), message: []const u8 }`
- `new(commitments, message) SigningPackage`
- `signingCommitment(identifier) ?SigningCommitments`
- `bindingFactorPreimages(verifying_key: *const VerifyingKey, allocator) !AutoHashMap(Identifier, []u8)`
  — raw `serialize(VK) || H4(msg) || H5(encoded) || serialize(id)` per participant

### Functions
- `computeBindingFactorList(signing_package, verifying_key, allocator) !AutoHashMap(Identifier, Scalar)`
  — `H1` over each preimage
- `computeGroupCommitment(signing_package, binding_factor_list) !Element`
- `participatingIdentifiers(signing_package, allocator) ![]Identifier`
- `sign(signing_package, signer_nonces: *const SigningNonces, key_package: *const KeyPackage) !SignatureShare`

## `aggregate` — aggregation

- `CheaterDetection = enum { disabled, first_cheater, all_cheaters }`
- `aggregate(signing_package, signature_shares: AutoHashMap(Identifier, SignatureShare), pubkeys: *const PublicKeyPackage, cheater_detection) !Signature`
- `aggregateSimple(signing_package, signature_shares, pubkeys) !Signature`
- `verifySignatureShare(identifier, verifying_share, signature_share, signing_package, verifying_key) !void`

## `fullFrostSign` convenience

`frost.fullFrostSign(allocator, message, key_packages: []const KeyPackage, pubkeys: *const PublicKeyPackage, min_signers: u16) !Signature`
— runs rounds 1–7 in-process.

## Memory conventions

- Functions that return heap-allocated data (`[]u8`, `AutoHashMap`,
  `[]Identifier`, `[]SecretShare`) take an explicit `allocator` argument; the
  caller owns and frees the result.
- `AutoHashMap` is **managed** in Zig 0.16: `init(allocator)` + `deinit()` (no
  argument). A `deinit()` in a `defer` requires the map to be declared `var`.
- `encodeGroupCommitments` and `bindingFactorPreimages` return buffers the
  caller must free.
