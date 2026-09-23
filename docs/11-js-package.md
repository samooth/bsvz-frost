# JavaScript Package

The `js/` directory is an ES module wrapper around the WebAssembly build: it
instantiates the module, copies buffers across the linear-memory boundary,
maps error codes onto a `FrostError` exception class, and exposes a
synchronous high-level API. See [09-webassembly.md](09-webassembly.md) for the
underlying ABI and [10-wire-formats.md](10-wire-formats.md) for byte layouts.

## Install / build

```bash
# from js/
npm run build   # zig build wasm -Doptimize=ReleaseSmall + copy to ./bsvz_frost.wasm
npm test        # rebuild, then run the Node smoke test (full protocol round-trip)
```

Requirements: Zig 0.16.0 or 0.17.0 on `PATH` (for the build step) and
Node ≥ 18 (ESM + `WebAssembly` + `globalThis.crypto`). The packaged files are
`index.js`, `index.d.ts`, and `bsvz_frost.wasm` (the `.wasm` is gitignored —
always run `npm run build` / `prepack` before publishing).

## Loading

```js
import { createFrost } from 'bsvz-frost';

const frost = await createFrost();          // loads bundled ./bsvz_frost.wasm
// or, explicitly (what the smoke test does):
import { readFileSync } from 'node:fs';
const frost2 = await createFrost({ wasmBytes: readFileSync('./bsvz_frost.wasm') });
```

`createFrost` is async (instantiation + optional fetch). Every method on the
returned API is **synchronous**: each call completes its wasm invocation
before returning and hands you a fresh `Uint8Array` copied out of linear
memory.

**Always call `frost.seed()` before the first keygen / DKG / nonce
operation.** Without host entropy the module's CSPRNG stays unseeded and
returns zeros. `seed()` with no argument draws 64 bytes from
`crypto.getRandomValues`; you may pass 1..64 explicit bytes instead.

## API

Type aliases (`Identifier`, `KeyPackage`, `Signature`, …) are all
`Uint8Array`s; TypeScript declarations live in `index.d.ts`.

### Lifecycle

| Method | Description |
|--------|-------------|
| `seed(entropy?)` | Seed the module CSPRNG (64 random bytes by default). Call once before crypto ops. |
| `version()` | Module protocol version string (e.g. `"0.1.0-wasm1"`). |
| `raw` | Underlying `WebAssembly.Exports`, for low-level use. |
| `memView()` | Current view of linear memory (re-fetch after `alloc` — the buffer can grow). |
| `alloc(len)` / `free(ptr, len)` | Manual linear-memory allocation. |

### Key management

```js
const { shares, publicKeyPackage } = frost.keygen(t, n);
// shares[i]: SecretShare wire blob (has id in first 32 bytes)
// publicKeyPackage: PublicKeyPackage blob

const keypackage = frost.keypackageFromShare(shares[0]); // verifies VSS, → 132 bytes
const signingKey = frost.reconstruct(keypackagesBlob);   // [count u16][count × KeyPackage]
```

`keygen(t, n)` uses identifiers `1..n`. `reconstruct` needs ≥ `t` key
packages packed as `[count u16 BE][count × KeyPackage(132)]`.

### Signing (trusted dealer or DKG result)

```js
// Round 1 — each participant, independently:
const { nonces, commitments } = frost.round1Commit(keypackage);
// Publish only `commitments` (66B). Keep `nonces` (64B) secret and single-use.

// Coordinator: assemble the signing package (see wire formats for layout):
// [count u16][count × (id32 ‖ commitments66)][msg_len u32][msg]
// participant entries in ascending id order.

// Round 2 — each participant:
const share = frost.round2Sign(signingPackage, nonces, keypackage); // 32B

// Coordinator: pack shares as [count u16][count × (id32 ‖ share32)] and aggregate:
const signature = frost.aggregate(signingPackage, sharesBlob, publicKeyPackage, mode);
// mode: 0 = no cheater detection, 1 = first cheater, 2 = all cheaters

// Anyone with the group verifying key (first 33 bytes of publicKeyPackage):
frost.verify(verifyingKey, message, signature); // true, or throws FrostError
```

**Nonce discipline:** each `nonces` value from `round1Commit` must be used
for exactly **one** `round2Sign` call, against one signing package. Reusing a
nonce pair leaks the signing share (see [07-security.md](07-security.md)).

### Distributed key generation

Identifiers are 1-based integers (`id ≥ 1`).

```js
// Part 1 — every participant:
const out1 = frost.dkgPart1(id, t, n);
// [secret_len u16][secret blob][broadcast blob] — keep secret, publish broadcast.

// Part 2 — every participant, with the n-1 broadcasts from OTHERS (self excluded),
// packed as [count u16][count × (id32 ‖ broadcast)]:
const out2 = frost.dkgPart2(secret, broadcastsBlob);
// success: [secret2_len u16][secret2][count u16][count × (id32 ‖ share32)]
//   shares here are keyed by RECIPIENT — send entry for peer X to peer X.
// cheaters: throws FrostError(IDENTIFIABLE_ABORT) with hex ids in the message.

// Part 3 — every participant:
const { keypackage, publicKeyPackage } = frost.dkgPart3(secret2, r1Blob, r2Blob);
// r1: [count][count × (id32 ‖ broadcast)] from others (self excluded), keyed by SENDER.
// r2: [count][count × (id32 ‖ share32)] — the shares YOU RECEIVED, keyed by SENDER
//     (re-key each peer's part2 output under that peer's id).
// cheaters: throws FrostError(IDENTIFIABLE_ABORT), same as part2.
```

All participants must end up with the same `publicKeyPackage`.

## Errors

Every failed wasm call throws a `FrostError` (subclass of `Error`) with a
numeric `code` from the frozen `ErrorCode` table — the same stable codes the
wasm module returns (`OK = 0` … `OUT_OF_MEMORY = 28`, `UNKNOWN = 127`; see
[09-webassembly.md](09-webassembly.md) for the full table). Identifiable
aborts are surfaced as `ErrorCode.IDENTIFIABLE_ABORT` with the cheaters
hex-listed in `error.message`.

```js
import { createFrost, ErrorCode, FrostError } from 'bsvz-frost';

try {
  frost.keygen(1, 3); // t < 2
} catch (e) {
  if (e instanceof FrostError && e.code === ErrorCode.INVALID_MIN_SIGNERS) {
    // expected
  }
}
```

Type errors from argument validation (wrong byte lengths, bad types) throw
plain `TypeError`s before any wasm call.

## Environments

- **Node ≥ 18** — ESM only (`"type": "module"`). Default wasm loading uses
  `readFileSync`; seeding uses `globalThis.crypto.getRandomValues`.
- **Browsers** — default wasm loading uses `fetch(new URL('./bsvz_frost.wasm',
  import.meta.url))`; seeding uses `crypto.getRandomValues`. Serve the `.wasm`
  file with a correct MIME type (`application/wasm`) or pass `wasmBytes`
  yourself (e.g. from a bundler asset).

There are no dependencies, no workers, and no shared state beyond one module
instance — create one `FrostApi` per session if you need isolated state.

## Smoke test

`npm test` runs `run-node.mjs`, which exercises the full protocol end-to-end
against the freshly built module:

1. Seed, trusted-dealer `keygen(2, 3)`, derive key packages.
2. Round 1 commitments → signing package → round 2 shares → aggregate →
   verify (plus negative verify cases).
3. `reconstruct` from two key packages.
4. Full 3-party DKG (part1/2/3) with 1-based ids, including share re-keying.
5. Error-code assertions (`INVALID_MIN_SIGNERS`, `DESERIALIZATION_FAILED`,
   `INVALID_SIGNATURE`) and the low-level alloc/free API.

Expected output:

```
wasm-test OK: FROST protocol round-trips correctly
```
