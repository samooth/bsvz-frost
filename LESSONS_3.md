# Lessons learned — Session 3

Everything non-obvious discovered while making `bsvz-frost` **byte-for-byte
compatible with the official ZcashFoundation/frost-secp256k1 reference** instead
of just "internally consistent". Environment: Zig 0.16.0-dev.2535+b5bd49460,
reference repo cloned to `/tmp/opencode/frost`.

## The big lesson: "works" ≠ "compatible"

The port passed its own 16 tests and produced valid Schnorr signatures — but
none of its bytes matched Zcash. Four protocol-level bugs hid behind the
self-consistency. Cross-language compat can only be proven against **official
test vectors** (`frost-secp256k1/tests/helpers/vectors.json`), not round-trip
tests.

## Protocol bugs found and fixed

1. **Ciphersuite hashes are RFC 9380 `hash_to_field`, not plain SHA-256.**
   H1/H2/H3/HDKG/HID used `SHA-256(CTX||tag||msg)` reduced mod `n`. The
   reference uses `hash_to_field(..., ExpandMsgXmd<Sha256>, count=1, L=48)`:
   `expand_message_xmd` (b_in=32, r_in=64) with
   `DST = CONTEXT_STRING ‖ tag`, then reduce the 48-byte output mod `n`.
   Confirmed by re-implementing `expand_message_xmd` in Python — the vector's
   binding factor `9bee5aef...824a91` only matches the xmd construction.
2. **`challenge()` double-hashed.** `keys.challenge` computed
   `H2(SHA256(R‖VK‖msg))`; the reference applies H2 directly to the raw
   `R‖VK‖msg` preimage (33+33+len bytes).
3. **`encode_group_commitments` hashed inside the function.** The port returned
   `H5(...)` of the encoded list; the reference returns the **raw**
   `id(32) ‖ hiding(33) ‖ binding(33)` per participant (sorted ascending by
   identifier, k256 `BTreeMap` order) and the *caller* hashes with H5.
4. **`binding_factor_preimages` hashed inside too.** The port returned
   `H1(...)` per participant; the reference preimage is the raw
   `serialize(VK)(33) ‖ H4(msg)(32) ‖ H5(encoded)(32) ‖ serialize(id)(32)`
   = **129 bytes**. Byte count matters: any extra/missing byte changes H1.

## Zig 0.16 API notes from this session

5. **Managed `AutoHashMap` needs `var`, not `const`.** `deinit(self: *Self)`
   takes a mutable pointer — `const m = try f(); m.deinit()` fails with
   "expected type '*T', found '*const T'". Declare `var` at every
   allocate/`deinit` site (also `defer m.deinit()`).
6. **`std.mem.sort(T, items, ctx, lessThanFn)` is stable** (stdlib 0.16). Use it
   to order identifiers ascending before encoding — `AutoHashMap` iteration
   order is **nondeterministic** and the reference sorts with `BTreeMap`.
7. **`Secp256k1.scalar.Scalar.fromBytes48([48]u8, .big)`** reduces 384-bit
   input mod the curve order — exactly what RFC 9380 `hash_to_field` requires
   for L=48, count=1. No manual reduction needed.
8. **`std.fmt.charToDigit` returns an error union** in 0.16 — every call in a
   hex parser needs `catch unreachable`.
9. **`std.ArrayList(T).empty` + `appendSlice(allocator, ...)`** is the way to
   build a known-length preimage (see `keys.challenge`).

## Verification methodology

10. **Reverse-engineer from vectors, don't guess.** Read the reference in this
    order: `frost-secp256k1/src/lib.rs` (hash choices), then
    `frost-core/src/{lib,round1,round2,keys}.rs` (protocol), then
    `vectors.json`. Write a throwaway Python/Rust script that re-derives an
    intermediate value (binding factor, H4, H5) *from the vector* — this proves
    the hashing theory before touching Zig.
11. **A full end-to-end vector test is the deliverable.** `tests/vector_test.zig`
    rebuilds the entire signing flow from the vector's fixed nonce randomness
    (`nonce_generate_from_random_bytes(secret, random)`), then asserts
    byte-for-byte equality at every stage: nonces, commitments, binding-factor
    preimages, binding factors, signature shares, and the final 65-byte
    signature. If the final signature matches, every hash and byte layout is
    right.
12. **Nonce randomness is injectable.** `Nonce.nonceGenerateFromRandomBytes`
    (as in the reference) lets tests pin the RNG; `Nonce.new` just wraps it with
    real randomness.

## Engineering

13. **Keep integration tests as separate `addTest` binaries** under one `test`
    step; the vector test needs no `bsvz` import, only `bsvz-frost`.
14. **Test count grew to 39** (12 unit + 2 naive + 2 shamir + 2 vector + 18
    negative/property + 3 fuzz) in the Phase 0 hardening session. Run Debug
    *and* ReleaseSafe before committing.

## Session 3 outcome

`bsvz-frost` now matches `ZcashFoundation/frost-secp256k1` byte-for-byte: all
four hash/encoding bugs fixed, and a new end-to-end test-vector test proves
interop against the official `vectors.json` fixture (participants 1 & 3, t=2,
message `"test"`). All 39 tests pass in Debug and ReleaseSafe (the Phase 0
hardening session later added the misuse-resistance and fuzz suites).

## Session 4 addendum — DKG (FROST KeyGen)

15. **DKG vectors exist too.** `frost-secp256k1/tests/helpers/vectors_dkg.json`
    covers 3 participants, t=2, group VK
    `037b5b0c...930de47`. The DKG proof of knowledge is
    `c = HDKG(serialize(id) ‖ serialize(a00·G) ‖ serialize(R))`,
    `μ = k + a00·c`, verified as `R == μ·G - c·(a00·G)` — the hash of the
    commitment is *inside* the proof, unlike the challenge in signing.
16. **`VerifiableSecretSharingCommitment.verifyingKey()` allocates.** It returns
    owned coefficient elements that must be freed; `sumCommitments` had to
    return heap-allocated commitments to avoid stack-array aliasing when
    multiple participants' commitments are summed.
17. **Zig array-in-struct aliasing:** a slice pointing at a stack array that gets
    reused across loop iterations aliases subsequent iterations' data. The
    vector test had to heap-allocate the summed commitment per participant.
18. **Error precedence in negative tests:** a tampered PoK must first pass the
    package-count check, so the tamper test needs 2 round-1 packages (not 1)
    to reach the PoK verification and produce `InvalidProofOfKnowledge`.
19. **DKG test count grew to 44** (previous 39 + 2 DKG functional + 3 DKG
    vector). Rogue-key attack motivation: PoK on the constant term prevents an
    adversary from biasing the group key when `t ≥ n/2`.
