# WebAssembly Module

`bsvz-frost` ships a WebAssembly build of the FROST protocol for browser and
Node.js hosts. The module (`src/wasm.zig`, built for `wasm32-freestanding`)
exposes a C-style ABI over its linear memory; a thin JavaScript wrapper in
`js/` turns that ABI into a typed, synchronous API. See
[11-js-package.md](11-js-package.md) for the wrapper itself and
[10-wire-formats.md](10-wire-formats.md) for the byte layouts used on both
sides of the boundary.

## Building

```bash
zig build wasm                        # → zig-out/bin/lib/bsvz-frost.wasm
zig build wasm -Doptimize=ReleaseSmall # optimized (what the JS package ships)
```

The `npm run build` script inside `js/` runs the ReleaseSmall build and copies
the artifact to `js/bsvz_frost.wasm` (that copy is gitignored; rebuild it
before packaging or testing).

The module is single-threaded, has no libc, no start function, and exports its
own `memory`. The build explicitly whitelists every export symbol
(`export_symbol_names` in `build.zig`), so no Zig internals leak across the
boundary.

## ABI overview

| Concern | Mechanism |
|---------|-----------|
| Memory | `frost_alloc` / `frost_dealloc` — JS allocates inputs, writes bytes, frees them |
| Results | Single global out-slot read via `frost_out_ptr` / `frost_out_len` / `frost_out_err` |
| Status | Each op returns `i32`: `0` = ok, `< 0` = error code, `> 0` = cheater count (DKG) |
| Errors | Stable numeric `WasmError` codes shared with the JS `ErrorCode` table |
| Entropy | Host writes 64 bytes through `frost_seed_buffer`, then calls `frost_seed(len)` |

The ABI is stable across the 0.1.x series: existing error codes are **never
renumbered**, only appended, and existing wire formats are never silently
changed.

### Memory

- `frost_alloc(len) → ?[*]u8` — allocate `len` bytes in linear memory
  (returns null on OOM).
- `frost_dealloc(ptr, len)` — free a buffer previously returned by
  `frost_alloc` with the **same** `len`.

JS copies every input into a freshly allocated buffer, invokes the op, then
immediately frees the buffer. The host never keeps pointers across calls.

### Result out-slot

Every operation writes its result into one global slot:

```
frost_out_ptr() → base pointer (valid until the next operation)
frost_out_len() → byte length (u32)
frost_out_err() → sticky error code for the last op (i32, 0 = ok)
```

**The host must copy the result out of linear memory before issuing the next
operation** — the next call frees and overwrites the slot. Linear memory can
also grow, invalidating any previously captured `ArrayBuffer` view; always
re-fetch `m.memory.buffer` after an allocation. The JS wrapper handles both
rules for you (`readOut()` slices into a fresh `Uint8Array`).

### Return codes

| Condition | Return value | Out-slot / `frost_out_err` |
|-----------|--------------|----------------------------|
| Success | `0` | Result bytes; `out_err = 0`. |
| Failure | Positive `WasmError` code (`1`–`28` or `127`) | Empty; `out_err` = same code. |
| Identifiable abort (`frost_dkg_part2` / `frost_dkg_part3` only) | Positive cheater count | `[count u16 BE][count × id32]`; `out_err = 0`. |

Errors and cheater counts are distinguished by `frost_out_err`: the JS wrapper
checks the return code first, and only for the two DKG ops — where a positive
return with `out_err == 0` means cheaters — does it parse the list and throw
`FrostError` with code `IDENTIFIABLE_ABORT` (27) carrying the hex ids.
Any other non-zero return (or non-zero `out_err`) throws `FrostError` with
that code.

## Error codes

`WasmError` in `src/wasm.zig` is the single source of truth; the JS package
mirrors it 1:1 as `ErrorCode`. **Never renumber; only append.**

| Code | Name | Typical cause |
|------|------|---------------|
| 0 | `OK` | Success. |
| 1 | `INVALID_MIN_SIGNERS` | `t < 2` or `t > n`. |
| 2 | `INVALID_MAX_SIGNERS` | `n < 2`. |
| 3 | `INCORRECT_NUMBER_OF_IDENTIFIERS` | Identifier list length ≠ n. |
| 4 | `DUPLICATED_IDENTIFIER` | Duplicate id in a participant set. |
| 5 | `UNKNOWN_IDENTIFIER` | Lagrange id not in the set. |
| 6 | `INCORRECT_NUMBER_OF_COMMITMENTS` | Commitment count ≠ expected signers. |
| 7 | `INCORRECT_NUMBER_OF_SHARES` | Too few shares / key packages for t. |
| 8 | `MISSING_COMMITMENT` | A required commitment is absent. |
| 9 | `INVALID_COMMITMENT` | Commitment bytes fail to parse / mismatch. |
| 10 | `IDENTITY_COMMITMENT` | Group commitment is the identity point. |
| 11 | `INVALID_SECRET_SHARE` | Share fails the VSS check. |
| 12 | `INVALID_SIGNATURE_SHARE` | A signature share fails verification. |
| 13 | `INVALID_SIGNATURE` | Final signature fails verification. |
| 14 | `MALFORMED_SCALAR` | Non-canonical / bad scalar bytes. |
| 15 | `MALFORMED_ELEMENT` | Bad SEC1 point encoding. |
| 16 | `MALFORMED_SIGNING_KEY` | Zero or otherwise invalid signing key. |
| 17 | `INVALID_ZERO_SCALAR` | Inversion of zero requested. |
| 18 | `INVALID_IDENTITY_ELEMENT` | Cannot serialize the identity point. |
| 19 | `INVALID_COEFFICIENT` | Invalid polynomial coefficient. |
| 20 | `SERIALIZATION_FAILED` | Allocation/internal error while writing. |
| 21 | `DESERIALIZATION_FAILED` | Truncated or unparseable input bytes. |
| 22 | `RANDOMNESS_ERROR` | CSPRNG failure / out-slot OOM. |
| 23 | `INCORRECT_NUMBER_OF_PACKAGES` | Wrong number of DKG packages. |
| 24 | `INCORRECT_PACKAGE` | Structurally wrong DKG package. |
| 25 | `PACKAGE_NOT_FOUND` | Expected package missing from the map. |
| 26 | `INVALID_PROOF_OF_KNOWLEDGE` | DKG Schnorr PoK failed (rogue-key defence). |
| 27 | `IDENTIFIABLE_ABORT` | Cheaters identified (thrown by the JS wrapper). |
| 28 | `OUT_OF_MEMORY` | Host allocation failed inside the module. |
| 127 | `UNKNOWN` | Unmapped error. |

A few `FrostError` members that have no dedicated numeric slot
(`DkgNotSupported`, `IdentifierDerivationNotSupported`, `InvalidNonce`) are
mapped onto `DESERIALIZATION_FAILED` (21); std crypto errors
(`InvalidEncoding`, `NonCanonical`, `IdentityElement`) map onto 21 / 14 / 18.

## Entropy (host seeding)

`wasm32-freestanding` has no OS, so the module cannot open `/dev/urandom`.
`field.zig` and `scalar.zig` call `frost_random_bytes` when building for the
wasm root module, which draws from a `DefaultCsprng` inside `src/wasm.zig`.

**If the host never seeds, `frost_random_bytes` zeroes the buffer** — keygen
and nonce generation would then be fully deterministic and catastrophic. The
seeding protocol is:

1. `ptr = frost_seed_buffer()` — pointer to a fixed 64-byte buffer.
2. Host writes 1..64 bytes of strong entropy at `ptr`
   (`crypto.getRandomValues` in the browser / Node ≥ 18).
3. `frost_seed(len)` — initializes the CSPRNG from those bytes.

Call this **once, before the first keygen / DKG / nonce-generation call**.
The JS wrapper's `seed()` method does all three steps; calling it with no
argument draws 64 bytes from the host CSPRNG.

## Exported operations

| Export | Signature (conceptual) | In → Out |
|--------|------------------------|----------|
| `frost_version` | `() → [*:0]const u8` | Version string, e.g. `0.1.0-wasm1`. |
| `frost_keygen` | `(t, n) i32` | — → `[count u16][count × SecretShare][PublicKeyPackage]` (ids are `1..n`). |
| `frost_keypackage_from_share` | `(ptr, len) i32` | SecretShare → KeyPackage(132). |
| `frost_round1_commit` | `(ptr, len) i32` | KeyPackage(132) → Nonces(64) ‖ Commitments(66). |
| `frost_round2_sign` | `(sp, nonces, kp) i32` | SigningPackage ‖ Nonces(64) ‖ KeyPackage(132) → SignatureShare(32). |
| `frost_aggregate` | `(sp, shares, pk, mode) i32` | SigningPackage ‖ shares-blob ‖ PublicKeyPackage ‖ mode → Signature(65). |
| `frost_verify` | `(vk, msg, sig) i32` | VerifyingKey(33) ‖ message ‖ Signature(65) → `0` / error. |
| `frost_reconstruct` | `(blob, len) i32` | `[count u16][count × KeyPackage]` → SigningKey(32). |
| `frost_dkg_part1` | `(id, t, n) i32` | — → `[secret_len u16][secret][broadcast]`. |
| `frost_dkg_part2` | `(secret, broadcasts) i32` | own secret ‖ n−1 broadcasts (self excluded) → success blob or cheater list (`rc > 0`). |
| `frost_dkg_part3` | `(secret2, r1, r2) i32` | own secret2 ‖ r1 (self excluded) ‖ r2 keyed by **sender** (self excluded) → KeyPackage ‖ PublicKeyPackage, or cheater list (`rc > 0`). |

`mode` for `frost_aggregate`: `0` = cheater detection disabled, `1` = first
cheater, `2` = all cheaters (any other value falls back to `0`).

Participant identifiers in DKG calls are 1-based small integers (`id ≥ 1`);
`frost_keygen` assigns `1..n` automatically. All multi-byte integers on the
boundary are **big-endian**.

## Usage from raw wasm (without the JS package)

```js
const { instance } = await WebAssembly.instantiate(bytes, {});
const m = instance.exports;

// Seed once before any keygen/nonce operation.
const seedPtr = m.frost_seed_buffer();
new Uint8Array(m.memory.buffer, seedPtr, 64).set(crypto.getRandomValues(new Uint8Array(64)));
m.frost_seed(64);

const rc = m.frost_keygen(2, 3);
if (rc !== 0) throw new Error(`frost_keygen failed: ${rc}`);
const ptr = m.frost_out_ptr(), len = m.frost_out_len();
const result = new Uint8Array(m.memory.buffer.slice(ptr, ptr + len)); // copy!
```

Prefer the JS package — it handles allocation, copying, memory growth, and
error mapping for you.
