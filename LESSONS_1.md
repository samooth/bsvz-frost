# Lessons learned — Session 1

Everything non-obvious discovered while porting AnchorChain's `privacy`
TypeScript package to Zig (`bsvz-zkp`), building on the `bsvz` secp256k1
backend. Environment: **Zig 0.16.0-dev.2535+b5bd49460**, `bsvz` pinned via
`build.zig.zon`.

## Toolchain / language (Zig 0.16)

1. **`std.ArrayList` constructor is gone.** `ArrayList(T).init(alloc)` no longer
   exists. Use `var list = std.ArrayList(T).empty;` and
   `list.append(allocator, item)`. To hand the buffer back:
   `list.toOwnedSlice(allocator)`. Every consumer must free with
   `allocator.free(slice)` or `list.deinit(allocator)`.
2. **`@setEvalBranchQuota` scope rule.** It must appear *inside* a `blk: { ... }`
   or `comptime { ... }` block, not at file scope. For comptime-evaluated
   constants that need a big budget (e.g. try-and-increment hash-to-curve for
   `G`/`H`/`BP_U`):
   ```zig
   pub const H = blk: {
       @setEvalBranchQuota(500_000);
       break :blk hashToPoint(default_h_domain);
   };
   ```
3. **`std.Random` has no `fill` method.** Use
   `std.Random.bytes(rng.*, out)` (pass the *pointer*, not the value).
4. **`Xoshiro256.init` takes a single `u64` seed** and produces a byte stream
   that *spills the little-endian u64s into the buffer in order*. If you need a
   specific byte sequence (for cross-language reproducibility) build the seed
   with `SplitMix64` and match the reference on bytes, not on "logical" random
   values.
5. **`std.fmt.fmtSliceHexLower` does not exist in 0.16.** Use
   `std.fmt.bytesToHex(&arr, .lower)`.
6. **Keywords shadowing.** `or` is a Zig keyword → an OR-proof field must be
   named something else (`or_proof`). A type/var named `u2` shadows the integer
   type inside that scope (broke Bulletproofs) → rename (`u_sq`, `uInv_sq`).
7. **`1 << 256` overflows `u256`** (it is `2^256 = 0 mod 2^256`). Any range
   guard `bits < 256` must be an explicit `if (bits < 256)` check before the
   shift, not an assumed bound.
8. **`u64` bit extraction silently truncates.** `value.toU256() >> i` as `u64`
   truncates high bits. Compare the shift result against `0`/`1` at `u256`
   width (`((v.toU256() >> @intCast(i)) & 1) == 1`) — bit proofs at ≥ 64 bits
   otherwise verify wrong.

## bsvz API

9. Point ops: `Point.mul([32]u8) !Point`, `basePointMul`, `add`, `negate()`
   (or `add(...negate())`), point equality via `inner.equivalent` (not `==`).
   The scalar `.bytes` field is the 32-byte big-endian form — pass
   `scalar.toBytes()` to `mul`, never raw structs.
10. `point.mul` returns `!Point`; on the internal library it is effectively
    infallible, so `catch unreachable` is fine internally — but *tests* should
    exercise real errors where the API exposes them.

## Protocol / compatibility pitfalls (AnchorChain)

11. **Double-hash = hash( hash(x) ), not hash(hash) stacking.** The first
    implementation called `sha256d` on the *already-hashed* digest, producing a
    triple hash. The `finish()` step must call plain `sha256` on the running
    SHA-256 digest so the total is double-SHA-256. Verified against `sha256sum`.
12. **AnchorChain's Fiat–Shamir challenge is byte-sensitive and stateless:**
    `SHA-256d( label ‖ sec1(p_0) ‖ … ‖ p_0 ‖ s_0_32 ‖ … )`, zero mapped to `1`.
    "Label-based" hashing means the *domain string is a first-class input*, not
    a tag on a persistent transcript object. Implement both a one-shot
    `challenge()` (drop-in) and an incremental `Hasher` that concatenates the
    same bytes.
13. **Try-and-increment hash-to-curve specifics.** Counter is a string suffix
    `domain + ":" + counter`, `0x02` (even-y) is tried *before* `0x03`, and the
    per-domain prefix matters: even tiny domain differences (e.g.
    `AnchorChain/pedersen/H/v1` vs `anchorchain/bp/g/v1`) change the point, and
    "H" vs "h" casing is intentional across modules.
14. **Blinding scheme difference is a real compat issue.** AnchorChain derives
    the *first* bit blinding last: `r_0 = r − Σ_{i≥1} 2^i·r_i` (no scalar
    inverse), and *retries* if `commit(0,0)` would occur. Deriving the *last*
    bit (with an inverse) yields a different proof. Match the scheme exactly,
    not just the math.
15. **Zero challenges / identity commitments.** Map a zero challenge to `1`
    (probability `2^-256` but cheap). `commit(0,0)` is the identity and must be
    avoided in range proofs (retry loop) — treating it as valid silently breaks
    binding for downstream consumers.
16. **Base point must be bound in the challenge.** AnchorChain hashes
    `[base, ...statements, ...a]` in both Schnorr and CDS-OR. Skipping the base
    allows base-point substitution in standalone use; bind it even when an outer
    transcript "covers" it.

## Verification methodology (cross-language)

17. **A pure reference implementation is worth its weight.** `crosscheck/ref.js`
    reimplements point math, hash-to-curve, challenge, and a deterministic
    PRNG (Xoshiro256++ seeded via SplitMix64) in ~plain Node — no SDK. It
    turned "looks right" into byte-exact equality (`crosscheck/run.sh` prints
    OK). Zig std and Node agree on every vector: G, H, BP_U, challenges,
    commitments, and a fixed-nonce Schnorr proof.
18. **Determinism is the key to cross-checking.** Real randomness cannot be
    diffed. Inject a seeded PRNG on both sides (Zig: `setRandomForTesting` with
    `std.Random.Xoshiro256`; JS: hand-rolled Xoshiro256++) and re-seed per proof
    so vectors are reproducible.
19. **Re-seed the PRNG per proof, not per suite.** Tests that reuse one seed
    stream produce different values each run after the first proof; re-seeding
    keeps fixtures stable.

## Engineering

20. **Free every nested temporary explicitly.** Zig has no GC and no automatic
    drop for `[]Point` slices. Vector-heavy code (Bulletproofs folding, proof
    assembly) must `defer allocator.free(...)` each intermediate; run under a
    LeakSanitizer-equivalent (test suites caught leaks).
21. **Structure proof types to mirror the TS shape** (`InnerProductProof` =
    `{A,S,T1,T2,taux,mu,tHat,aL,aR,bL,bR,L,R}`) — it makes the port auditable
    line-by-line and keeps deinit/verify symmetric.
22. **Versioned, self-describing test suites.** Six suites named after modules
    with negative cases (wrong value, wrong blinding, wrong bit width, wrong
    set size, tampered proof) catch silent reversion to insecure behavior.
23. **`zig fmt` before commit; run Debug + ReleaseSafe.** Optimized builds shake
    out comptime-budget and integer-width assumptions that Debug tolerates.

## Session 1 outcome

All six primitives (Pedersen, Schnorr, CDS-OR, linear range, Bulletproofs,
membership, conservation) ported, 53/53 tests passing in Debug + ReleaseSafe,
byte-for-byte cross-checked against the AnchorChain reference, docs refreshed.
