# Testing Guide

## Test binaries

`zig build test` runs six binaries under one step (39 tests, green in Debug
and ReleaseSafe):

| Binary | Focus | Count |
|--------|-------|-------|
| `src/tests.zig` | Unit tests for the FROST modules | 12 |
| `tests/naive_test.zig` | End-to-end threshold signing on real bsvz | 2 |
| `tests/shamir_test.zig` | Shamir split/reconstruct | 2 |
| `tests/vector_test.zig` | Official Zcash `vectors.json` byte-for-byte interop | 2 |
| `tests/security_test.zig` | Negative / property (misuse-resistance) | 18 |
| `tests/fuzz_test.zig` | `std.testing.fuzz` targets (corpus smoke-run) | 3 |

## Misuse-resistance suite (`security_test.zig`)

These tests exercise the library's *negative* paths: inputs a well-meaning
integration could get wrong, or an attacker could supply. The library must
reject them with the documented error rather than panic, leak, or emit an
invalid signature.

Key coverage:

- **Duplicated / invalid identifiers**: non-zero scalar check, duplicate ids
  in a subset, unknown lagrange-coefficient id.
- **Subset validation**: wrong participant count, below-threshold
  aggregation, missing shares.
- **Cheater detection**: a participant whose aggregated signature fails
  verification is identified via `aggregateWithCheaterDetection`.
- **Tamper detection**: tampered signature shares, tampered aggregate, wrong
  message in the package.
- **Commitment misuse**: a signer signing with nonces that were never
  committed, and identity commitments (rejected both at binding-factor
  encoding and at `computeGroupCommitment`).
- **Nonce reuse**: reuse of `SigningNonces` across two different messages
  does not leak the private key (signatures remain individually valid but
  derived with the same nonce — the library does not cache/ban reuse, so
  callers must enforce the RFC 9591 nonce discipline).
- **Malformed encodings**: non-canonical scalars, invalid SEC1 elements,
  malformed signing keys — all rejected with the correct error.
- **Round-trips**: identifiers, scalars, elements, and signatures serialize
  and deserialize without loss.

The helpers at the top of the file (`testKeygen`, `startSession`, `tamper`)
are shared by all tests; `testKeygen` runs the full trusted-dealer keygen on
real bsvz and returns key packages plus the public-key package.

## Fuzz targets (`fuzz_test.zig`)

Three `std.testing.fuzz` targets:

1. `fuzzDeserializers` — round-trip property for every wire type
   (identifier, scalar, element, commitment, signing share, signature).
2. `fuzzHashFunctions` — H1–H5, HDKG, HID over arbitrary input.
3. `fuzzScalarOps` — byte-level scalar arithmetic checked via canonical
   `reduce`.

On Zig 0.16.0-dev, coverage-guided fuzzing is not yet runnable: `zig build
--fuzz=N` crashes in the build runner itself (double-free in
`std.Build.Step.Run.rerunInFuzzMode`, in `Fuzz.zig`/`Run.zig`, not in this
library). Until that is fixed, the targets are exercised through `zig build
test`, which runs each `fuzz` target once with its corpus (and an empty seed
as smoke input). When the toolchain bug is fixed:

```bash
zig build --fuzz=1000 test   # coverage-guided libFuzzer mode
```

## Running subsets

```bash
zig build test                       # everything
zig build test -Doptimize=ReleaseSafe
zig test tests/security_test.zig     # single binary (must run via `zig build`
                                     # to pick up the bsvz-frost module path)
```

`zig fmt --check src/ tests/ build.zig` keeps formatting clean.
