# Lessons learned — Session 2

Everything non-obvious discovered while bringing the `bsvz-frost` repo up to date:
making it build on **Zig 0.16.0-dev.2535+b5bd49460**, fixing FROST protocol bugs,
and wiring in the real `b-open-io/bsvz` dependency — porting the `naive`/`shamir`
threshold modules against its *actual* crypto API.

## Toolchain / language (Zig 0.16)

1. **`std.ArrayList(T).init(alloc)` is gone** (confirmed again, LESSONS_1 item 1).
   `var list = std.ArrayList(T).empty;` → `list.append(allocator, item)` →
   `list.toOwnedSlice(allocator)`; free with `allocator.free(slice)` or
   `list.deinit(allocator)`.
2. **Unused parameter rule is stricter than `_`-prefixing.** `_identifier` still
   errors as "unused function parameter" — use a bare `_` for parameters that must
   exist for API shape but are unused.
3. **`std.crypto.random` is removed.** Secure randomness comes from the Io layer:
   `std.Io.Threaded.global_single_threaded.io().random(&buf)` in library code,
   `std.testing.io.random(&buf)` in tests. This is exactly what std crypto does
   internally (`Ed25519.KeyPair.generate(io)`).
4. **Uniform scalar sampling without rejection.** Fill 64 random bytes, then
   `Secp256k1.scalar.Scalar.fromBytes64(buf, .big).toBytes(.big)` — reduction mod
   the curve order, so no retry loop for non-canonical 32-byte values. The same
   `fromBytes64` trick reduces any hash/32-byte value to a canonical scalar.
5. **`zig fetch --save git+https://…`** pins a commit + hash into
   `build.zig.zon`. The dependency carries its own `minimum_zig_version` (bsvz
   declares `0.15.2`) yet compiled fine under 0.16-dev — the declared minimum is
   advisory, not enforced forward.

## Build system (zig build)

6. **`addExecutable`/`addTest` no longer take `root_source_file`** — they take
   `root_module: *Module`. Pattern that works:
   ```zig
   const m = b.createModule(.{ .root_source_file = b.path("src/x.zig"), .target = target, .optimize = optimize });
   m.addImport("dep", other_mod);
   const exe = b.addExecutable(.{ .name = "x", .root_module = m });
   ```
   `b.addModule(name, opts)` still exists for *public* modules.
7. **Dependency imports are per-module.** Importing `bsvz` into the frost module
   does NOT make it visible to the test/exe modules — each module that `@import`s
   it needs its own `mod.addImport("bsvz", bsvz_mod)`. `zig build test` then
   silently fails with "no module named 'bsvz'" otherwise.
8. **README promised `zig build run` but no `run` step existed** — add
   `b.addRunArtifact(exe)` + `b.step("run", …)`. The README is documentation, not
   a build contract.
9. **Fake fingerprint breaks the whole build.** `build.zig.zon` had
   `0x123456789abcdef0`; the error prints the computed value (use it, don't guess).
10. **Dependency compilation is lazy and incremental.** A scratch test importing
    `@import("bsvz")` (the full library: script, transaction, broadcast) proved
    it compiled on 0.16 before any porting work — do this smoke test first.

## stdlib secp256k1 API (0.16)

11. **`Secp256k1.AffinePoint` is gone.** The element type is the projective
    `Secp256k1` struct itself (the "Point" and "curve" collapsed).
12. **Serialization renamed:** `toSec1(compressed)` →
    `toCompressedSec1()` (33 B) / `toUncompressedSec1()` (65 B); `fromSec1(slice)`
    unchanged. `basePoint`/`identityElement` unchanged.
13. **No `isIdentity()`** — `Secp256k1.equivalent(a, Secp256k1.identityElement)`.
14. **Scalar API shifts:** `eql` → `equivalent`; `invert()` now returns a plain
    `Scalar` (no error union); `fromBytes(bytes, .big)` still returns
    `NonCanonicalError!Scalar`.

## Real bsvz API (b-open-io/bsvz)

15. **bsvz has NO scalar type.** `crypto.Point.mul`/`basePointMul` consume and
    produce `[32]u8` big-endian canonical scalars. The placeholder files assumed
    `bsvz.crypto.Scalar` (with `.fromInt/.random/.add/.mul/.inv/.eq`),
    `Point.generator`, `Point.eq`, `toCompressedBytes`, and `bsvz.crypto.hash256`
    — none of these exist.
16. **Real surface:** `Point.identity()`, `basePointMul([32]u8) !Point`,
    `mul([32]u8) !Point`, `add`, `negate`, `isIdentity`, `isOnCurve`,
    `toCompressedSec1() Sec1Bytes`, `toRaw64`, `xBytes32/yBytes32`, and
    `fromSec1/fromCompressedSec1/fromUncompressedSec1/fromRaw64`.
    `Sec1Bytes` has a padded `bytes: [65]u8` + `len` — use `.slice()`, not `.bytes`.
17. **Hashing is namespaced:** `bsvz.crypto.hash.hash256(data) → Hash256{bytes}`;
    `sha256` similarly. Not `crypto.hash256`. Point equality: compare
    `toCompressedSec1().slice()` byte-for-byte.
18. **bsvz wraps the stdlib** (`Point.inner: std.crypto.ecc.Secp256k1`), so its
    group API tracks the stdlib API — but the *scalar* arithmetic still has to be
    written by hand. For the port, implement a byte-scalar helper
    (`[32]u8` big-endian, mod curve order) on top of `Secp256k1.scalar.Scalar` and
    use `bsvz.crypto.Point` for all group ops.
19. **`primitives.keyshares` is NOT reusable for FROST-style shares.** Its u256
    arithmetic is mod the field prime `p`, not the subgroup order `n`, and its
    `Polynomial.valueAt` interpolates at a point, not a scalar share.

## Protocol / correctness bugs found

20. **FROST λ_i was computed over the wrong set.** `round2.sign` (and cheater
    detection / per-share verify) passed `&[_]KeyPackage{key_package.*}` — a
    one-element set — so the Lagrange coefficient was always 1 and the aggregate
    signature never verified. λ_i must be interpolated over the *full participant
    set* from the `SigningPackage`. Fix: collect identifiers via a
    `participatingIdentifiers(package, alloc)` helper and call
    `keys.computeLagrangeCoefficient(ids, id)`.
21. **Naive threshold Schnorr was mathematically broken, not just unported.**
    Each signer hashed their *own* `R_i` into the challenge, but verification
    hashes the *aggregated* `R` — the two `e` values differ, so verification can
    never pass. The correct construction is two-round: exchange `R_i`, sum into a
    shared group commitment `R`, and every signer hashes the *same* `R`.
22. **Watch declared types vs. produced types.** `encodeGroupCommitments`
    declared `![64]u8` but produced a 32-byte SHA-256; the binding-factor map was
    `[64]u8` holding 32-byte values. Both fixed to `[32]u8`.
23. **Error-set names are exact.** `InvalidCoefficients` (plural) doesn't exist;
    it's `InvalidCoefficient`.
24. **Smart/curly quotes in a string literal is a syntax error** (copied prose
    `"Message: "{s}"`); re-type quotes.

## Engineering

25. **Keep a smoke test for the new dependency** (`basePointMul(0)` is the
    identity) — it proves the dep graph links before the real port exists.
26. **Separate unit vs integration suites.** `src/tests.zig` for the library,
    `tests/naive_test.zig` + `tests/shamir_test.zig` as their own `addTest`
    binaries, all under one `test` step. 12 unit + 2 + 2 integration = 16.
27. **Run Debug AND ReleaseSafe** — optimized builds surface comptime-budget and
    unreachable-`catch` assumptions Debug tolerates.
28. **Ignore build artifacts before the first commit:** `.zig-cache/`, `zig-out/`,
    and `zig-pkg/` (vendored deps) must be in `.gitignore`.
29. **`zig fmt --check` before commit** (LESSONS_1 item 23, reconfirmed).

## Session 2 outcome

`bsvz-frost` builds and passes **16/16 tests** (12 unit, 2 naive, 2 shamir) under
Zig 0.16.0-dev.2535 in Debug and ReleaseSafe; the demo runs; `zig fmt` is clean.
Real `b-open-io/bsvz` is a pinned git dependency; `naive`/`shamir` are ported to
its actual `crypto.Point`/`hash` API via a byte-scalar helper; the FROST Lagrange
coefficient bug and the naive-challenge bug are fixed.
