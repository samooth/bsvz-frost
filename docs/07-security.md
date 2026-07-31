# Security Notes

> **Production-readiness status: NOT PRODUCTION READY.**
> The reference implementation ([ZcashFoundation/frost-secp256k1](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1))
> was audited (ZK Labs, 2021), but **this Zig port is a separate, un-audited
> codebase**. Byte-for-byte test-vector compatibility proves the protocol math
> is correct — it does **not** prove this implementation is secure against
> side-channel attacks, misuse, or memory-safety bugs. Do not use with real
> keys or funds until this code has its own security review. See
> [Production Readiness](#production-readiness) below.

`bsvz-frost` implements a real threshold-signature protocol. This document
covers the operational security requirements and the threat model. It is not a
formal proof; see the
[FROST paper](https://eprint.iacr.org/2020/852) and
[RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) for analysis.

## Nonce discipline (critical)

- **Nonce reuse is catastrophic.** Each `SigningNonces` (hiding + binding) must
  be used for **exactly one** signing operation. Reusing a nonce pair with a
  different binding factor leaks the signing share:
  `z = d + e·ρ + λ·s·c` — two shares with the same `d`, `e` but different `c`
  solve for `s`.
- Do **not** reuse nonces across `SigningPackage`s, messages, or signing
  sessions. Generate fresh `SigningNonces` per session
  (`round1.commit` or `SigningNonces.new`).
- Nonces are secret. Only the **commitments** (the points) are broadcast.

## Randomness

- Nonces are derived as `H3(random_bytes || serialize(secret_share))` — the
  secret share is bound into the nonce, so the scheme is *hedged*: even a weak
  RNG does not directly expose the share (though it weakens entropy).
- `random_bytes` must still come from a cryptographically secure source.
  `field.randomBytes` uses the stdlib secure RNG via the Io layer.
- Secret shares and group secrets (`SigningKey.generate`) also require a
  strong RNG.

## Communication channels

- **Secret shares** (dealer → participants) must be sent over **confidential
  and authenticated** channels. Anyone holding `t` shares can reconstruct the
  group secret.
- **Nonces** are secret and must stay confidential (only commitments are
  public).
- **Commitments and shares** must be **authenticated** to prevent man-in-the-
  middle substitution of a participant's commitment or signature share.
- Binding factors are derived from the full, authenticated commitment list, so
  a commitment substituted after the fact invalidates every share — fail
  closed, but the DoS can be exploited if the channel is not authenticated.

## Coordinator trust

- The coordinator (aggregator) is trusted for **liveness** and **DoS
  prevention**, but learns nothing secret: it sees commitments, shares, and the
  final signature, which are all public outputs.
- With cheater detection enabled, the coordinator can identify which
  participant produced an invalid share — the "identifiable abort" property of
  FROST.

## Threat model

| Capability | Implication |
|------------|-------------|
| < `t` colluding participants | Cannot forge a signature; FROST is existentially unforgeable under the discrete-log assumption with the standard Fiat–Shamir arguments. |
| A malicious participant | Can abort (withhold a valid share); detected via cheater detection. Cannot learn others' shares from the published data. |
| Network eavesdropper | Learns public commitments/shares/signature only; useless without shares or nonces. |
| Share holder | Holds only their share; the group key remains protected unless `t` shares leak. |

## Implementation notes

- The aggregate signature is a **standard Schnorr signature**; verifying it is
  exactly `z·G = R + c·VK`. There is no quorum metadata in the signature.
- This ciphersuite is **NOT BIP-340**. Do not use these signatures where
  Taproot/BIP-340 is expected (Bitcoin Script taproot key paths). Use
  `frost-secp256k1-tr` for that.
- The `naive` module (`src/naive.zig`) is a plain threshold Schnorr scheme with
  **no binding factors and no identifiable abort**; it exists for evaluation
  and bsvz interop only. Do not use it in production — use the FROST modules.
- `shamir.split`/`reconstruct` provide raw Shamir sharing (useful for key
  backup) without FROST's VSS verification; use the `keys` module when
  participants must verify their shares.

## Known gaps / limitations

- **No identifier derivation.** `HID`/`HDKG` are exposed as ciphersuite hash
  functions but the derivation API is not wired up.
- **1-round signing not wired up.** `round1.preprocess` can pre-generate
  nonces, but the 1-round protocol itself is not exposed.
- The library does not implement side-channel hardening beyond what Zig's
  stdlib `Secp256k1` provides; deployment on devices should be reviewed
  against the local threat model.

## Production readiness

What the Zcash audit covers, and what it does not:

| Aspect | Status |
|--------|--------|
| FROST protocol design (RFC 9591) | Audited (by the Zcash Foundation's audit of the reference) |
| This port's byte-level correctness | Verified against official Zcash test vectors |
| This port's implementation security | **Un-audited** |
| DKG | Implemented and byte-verified against the official `vectors_dkg.json` (un-audited like the rest of the port) |
| Side-channel hardening | Not reviewed; stdlib `Secp256k1` is not guaranteed constant-time |
| Fuzzing / malformed-input testing | Fuzz targets written; coverage-guided run blocked by a build-runner bug on the current Zig dev toolchain (smoke-run in `zig build test`) |
| Misuse-resistance tests (nonce reuse, etc.) | Present — 18 negative/property tests in `tests/security_test.zig` |
| Stable toolchain | Uses Zig `0.16.0-dev` (unstable) |

Minimum bar before real keys/funds:
1. Independent security review of this Zig code.
2. Fuzzing and property tests (e.g. aggregate rejects wrong-subsets, shares
   verify, nonce reuse is caught). The negative/property suite ships now;
   run coverage-guided fuzzing once the toolchain's `--fuzz` bug is fixed.
3. Move to a stable Zig release and re-verify the vectors.
4. Review side-channel posture against the deployment's threat model.
5. Exercise the DKG operational procedures (channel authentication, share
   deletion) against the deployment's threat model.
