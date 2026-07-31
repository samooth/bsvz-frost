# Getting Started

## Requirements

- **Zig 0.16.0-dev.2535+b5bd49460** (the version the project builds and tests
  against; the build system uses the modern `root_module` Build API).
- Network access for the first build (fetches the pinned `b-open-io/bsvz`
  dependency).

## Build & run the demo

```bash
zig build run
```

The demo walks through a full 3-of-5 trusted-dealer setup and signing:

1. Trusted dealer key generation (group verifying key + shares).
2. Participants verify their shares and create `KeyPackage`s.
3. Round 1: participants generate nonces and commitments.
4. Coordinator assembles a `SigningPackage`.
5. Round 2: each participant produces a signature share.
6. Aggregation into a final Schnorr signature.
7. Verification (valid).
8. A single (non-threshold) Schnorr signature for comparison.

## Run the tests

```bash
zig build test                 # Debug
zig build test -Doptimize=ReleaseSafe
```

This runs all six test binaries under one step:

| Binary | Contents | Count |
|--------|----------|-------|
| `src/tests.zig` | Unit tests for the FROST modules | 12 |
| `tests/naive_test.zig` | Naive threshold signing on real bsvz | 2 |
| `tests/shamir_test.zig` | Shamir split/reconstruct | 2 |
| `tests/vector_test.zig` | Official Zcash `vectors.json` interop | 2 |
| `tests/security_test.zig` | Negative/property (misuse-resistance) tests | 18 |
| `tests/fuzz_test.zig` | Fuzz targets (smoke-run with corpus + empty input) | 3 |
| **Total** | | **39** |

The vector test is the key compatibility proof: it rebuilds the whole signing
flow from the Zcash fixture's fixed nonce randomness and asserts byte-for-byte
equality at every stage (see [06-interop.md](06-interop.md)).

## Fuzzing

The three `std.testing.fuzz` targets (wire deserializers, hash functions, and
scalar operations) are registered as fuzz steps. On the current Zig
0.16.0-dev toolchain, `zig build --fuzz=N` crashes in the build runner itself
(a double-free in `std.Build.Step.Run.rerunInFuzzMode`), so coverage-guided
fuzzing is not yet runnable here. The targets still execute their corpus and
an empty seed under `zig build test` (the 3 fuzz entries above), so the
corpus is exercised in CI even without libFuzzer. Once the toolchain bug is
fixed, run:

```bash
zig build --fuzz=1000 test
```

## Use as a dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .bsvz_frost = .{
        .path = "path/to/bsvz-frost",
    },
},
```

In your `build.zig`, import the module (it re-exports everything under the
`bsvz-frost` name):

```zig
const frost_dep = b.dependency("bsvz_frost", .{
    .target = target,
    .optimize = optimize,
});
const frost_mod = frost_dep.module("bsvz-frost");
// frost_mod.addImport("bsvz", ...); // if your code also needs bsvz
```

In Zig code:

```zig
const frost = @import("bsvz-frost");
```

## Minimal end-to-end example

Trusted dealer + 2-of-3 signing:

```zig
const std = @import("std");
const frost = @import("bsvz-frost");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const max_signers: u16 = 3;
    const min_signers: u16 = 2;

    // 1. Trusted dealer generates shares.
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer allocator.free(identifiers);
    const shares, const pubkey = try frost.keys.generateWithDealer(
        max_signers, min_signers, identifiers,
    );
    defer allocator.free(shares);

    // 2. Participants verify their shares.
    var key_packages: [3]frost.KeyPackage = undefined;
    for (shares, 0..) |share, i| {
        key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
    }

    // 3. Round 1: commitments.
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    var nonces_map = std.AutoHashMap(frost.Identifier, frost.SigningNonces).init(allocator);
    defer nonces_map.deinit();
    for (key_packages[0..min_signers]) |kp| {
        const nonces, const comm = frost.round1.commit(&kp.signing_share);
        try commitments.put(kp.identifier, comm);
        try nonces_map.put(kp.identifier, nonces);
    }

    // 4. Signing package.
    const message = "message to sign";
    const signing_package = frost.SigningPackage.new(commitments, message);

    // 5. Round 2: signature shares.
    var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer signature_shares.deinit();
    for (key_packages[0..min_signers]) |kp| {
        const nonces = nonces_map.get(kp.identifier).?;
        const share = try frost.round2.sign(&signing_package, &nonces, &kp);
        try signature_shares.put(kp.identifier, share);
    }

    // 6. Aggregate.
    const signature = try frost.aggregate.aggregateSimple(&signing_package, signature_shares, &pubkey);

    // 7. Verify.
    try pubkey.verifying_key.verify(message, signature);
    std.debug.print("Signature valid!\n", .{});
}
```

Or use the one-shot convenience for local testing:

```zig
const signature = try frost.fullFrostSign(
    allocator, message, &key_packages, &pubkey, min_signers,
);
```

> Note: `fullFrostSign` runs every round in-process. In production, rounds
> happen across a network — see [04-protocol.md](04-protocol.md).
