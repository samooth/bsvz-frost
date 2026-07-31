# Protocol

This document walks through the FROST protocol as implemented, mirroring the
Zcash `frost-core` logic. Key generation can be done by a **trusted dealer**
or **distributed** (DKG, no trusted party); see §9.

## Notation

- `n` (max_signers): number of shares generated.
- `t` (min_signers): threshold — minimum participants to sign.
- `G`: secp256k1 generator.
- `H_i`: ciphersuite hash functions (see [03-ciphersuite.md](03-ciphersuite.md)).
- `id`: participant identifier (non-zero scalar, 32-byte big-endian).

## 1. Key generation (trusted dealer)

`keys.generateWithDealer(max, min, identifiers)` (or
`keys.split(secret, ...)` for an existing key):

1. Sample a random group secret `s` (`SigningKey`).
2. Build a degree-`(t-1)` polynomial
   `f(x) = a_0 + a_1·x + ... + a_{t-1}·x^{t-1}` with `a_0 = s` and the other
   coefficients random.
3. Each participant `i` gets `share_i = f(id_i)` (`SigningShare`).
4. Publish the coefficient commitments
   `[A_0, A_1, ..., A_{t-1}] = [a_0·G, a_1·G, ..., a_{t-1}·G]`
   (`VerifiableSecretSharingCommitment`). `A_0` is the **group verifying key**.

### Share verification (VSS)

`SecretShare.verify()` checks that a received share matches the published
commitments:

```
f(id)·G == Σ_k A_k · id^k
```

If it holds, the participant derives their `VerifyingShare = f(id)·G` and
constructs a `KeyPackage` (`fromSecretShare`).

### KeyPackage / PublicKeyPackage

- `KeyPackage { identifier, signing_share, verifying_share, verifying_key, min_signers }`
  — private data for one participant.
- `PublicKeyPackage { verifying_shares, verifying_key, min_signers }` — public
  data the coordinator needs to aggregate and verify.

## 2. Round 1: nonce generation and commitments

Each participant generates **two** nonces, one "hiding" and one "binding":

```
nonce = H3(random_bytes_32 || serialize(signing_share))
```

`Nonce.new(secret)` draws fresh `random_bytes`; `Nonce.nonceGenerateFromRandomBytes`
takes them as input (this is how the Zcash test vectors pin the RNG).

Commitments are the group elements:

```
hiding_commitment  = hiding_nonce · G
binding_commitment = binding_nonce · G
```

`round1.commit(secret)` returns `(SigningNonces, SigningCommitments)`. The
nonces are secret; the commitments are broadcast.

## 3. Coordinator assembles the SigningPackage

`SigningPackage.new(commitments_map, message)` bundles the map of
`identifier → SigningCommitments` plus the message to sign.

## 4. Binding factors

For every participant in the package, compute the binding-factor preimage:

```
preimage(id) = serialize(VK) || H4(msg) || H5(encoded) || serialize(id)
```

where

```
encoded = Σ_{id ascending}  serialize(id) || serialize(hiding_comm) || serialize(binding_comm)
```

- `serialize(VK)` is the compressed group verifying key (33 bytes).
- `H4(msg)` is 32 bytes, `H5(encoded)` is 32 bytes, `serialize(id)` is 32 bytes
  → preimages are **129 bytes**.
- The commitment list must be encoded in **ascending identifier order**
  (the reference uses a `BTreeMap`; the Zig port sorts explicitly, since
  `AutoHashMap` iteration order is nondeterministic).

The binding factor is then:

```
rho_i = H1(preimage(id_i))
```

`round2.computeBindingFactorList` returns a map `identifier → rho_i`.

## 5. Group commitment

```
R = Σ_i ( hiding_comm_i + binding_comm_i · rho_i )
```

`round2.computeGroupCommitment` rejects any identity commitment and any
identifier without a binding factor.

## 6. Round 2: signature shares

Each participant `i` computes:

```
lambda_i = Lagrange coefficient of id_i over the participating set
         = Π_{j ≠ i} id_j / (id_j - id_i)

c = H2(serialize(R) || serialize(VK) || msg)

z_i = hiding_nonce_i + binding_nonce_i · rho_i + lambda_i · share_i · c
```

`round2.sign` validates the commitment count and that the participant's own
commitment matches their nonces, then returns `SignatureShare { z_i }`.

### Per-share verification

`SignatureShare.verify` checks:

```
z_i · G == (hiding_comm_i + binding_comm_i · rho_i) + lambda_i·c · verifying_share_i
```

## 7. Aggregation

`aggregate.aggregateSimple` (no cheater detection) sums the shares:

```
z = Σ_i z_i
Signature = (R, z)
```

The result verifies as a standard Schnorr signature:

```
z·G == R + c · VK
```

### Cheater detection

`aggregate.aggregate(package, shares, pubkeys, cheater_detection)` with

- `.disabled` — plain aggregate.
- `.first_cheater` / `.all_cheaters` — if the aggregate fails to verify, each
  share is re-checked individually and the first (or all) invalid identifiers
  are collected. A cheater is reported via
  `FrostError.InvalidSignatureShare` (all) or `FrostError.InvalidSignature`
  (none found / verification failed for another reason).

`aggregate.verifySignatureShare(id, verifying_share, share, package, vk)`
independently verifies a single share before aggregation.

## 8. Secret reconstruction

`keys.reconstruct(key_packages)` recovers the original secret from any `t`
key packages using Lagrange interpolation at `x = 0`:

```
s = Σ_i lambda_i · share_i
```

## 9. Distributed key generation (DKG)

`dkg.part1/part2/part3` implement FROST KeyGen (RFC 9591 §7 / the FROST paper,
Figure 1): a variant of Pedersen's DKG in which every participant runs a
Feldman VSS as dealer in parallel, plus a zero-knowledge proof of knowledge of
their secret constant term to defeat rogue-key attacks when `t ≥ n/2`.
Mirrors the Zcash `keys::dkg` module byte-for-byte (proven against the official
`vectors_dkg.json`).

Communication pattern per participant `i`:

- **Round 1 (broadcast):** sample the secret polynomial
  `f_i(x) = a_{i0} + a_{i1}·x + ... + a_{i(t-1)}·x^{t-1}`, publish the
  commitment `C_i = [a_{i0}·G, ..., a_{i(t-1)}·G]` and the proof of knowledge
  `σ_i = (R_i, μ_i)` of `a_{i0}`:
  ```
  k ← Z_q,  R_i = k·G,  c_i = HDKG(serialize(id_i) || serialize(a_{i0}·G) || serialize(R_i))
  μ_i = k + a_{i0}·c_i
  ```
  `dkg.part1(id, n, t)` returns the kept `round1.SecretPackage` (identifier,
  coefficients, commitment, t, n) and the broadcast `round1.Package`
  (commitment, proof).

- **Round 2 (private shares):** each participant verifies every received proof
  (checking `R_ℓ == μ_ℓ·G - c_ℓ·(a_{ℓ0}·G)`), then sends each other
  participant `ℓ` the share `f_i(id_ℓ)` over a confidential, authenticated
  channel. `dkg.part2(secret_package, round1_packages)` returns the kept
  `round2.SecretPackage` (with `f_i(id_i)`) and the map of outgoing
  `round2.Package` shares.

- **Finalization (part3):** each participant verifies every received share
  against the sender's commitment (VSS, `g^{f_ℓ(i)} == Σ_k φ_{ℓk}·i^k`),
  sums them into the long-lived share `s_i = Σ_ℓ f_ℓ(i)`, and derives the
  group verifying key by summing all participants' commitments
  (`PublicKeyPackage.fromDkgCommitments`). Returns the `KeyPackage` and the
  `PublicKeyPackage` — all participants must agree on the same group key.

Errors: `IncorrectNumberOfPackages`, `UnknownIdentifier`,
`IncorrectNumberOfCommitments`, `InvalidProofOfKnowledge`, `IncorrectPackage`,
`PackageNotFound`, `InvalidSecretShare`.

## One-shot helper

`frost.fullFrostSign(allocator, message, key_packages, pubkeys, min_signers)`
runs rounds 1–7 in-process for local testing/demos. Production deployments
must implement the network distribution described above.

## Not implemented

- **Identifier derivation** (`HID`/`HDKG` havehing helpers exist in the
  ciphersuite but no derivation API is exposed).
- **1-round (preprocess) signing**: `round1.preprocess` exists for nonce
  pre-generation, but the 1-round protocol itself is not wired up.
