// bsvz-frost — WebAssembly module loader and JS API for FROST threshold signatures.
//
// The Zig shim (src/wasm.zig) exposes a C-ABI over pointer/length pairs into
// the module's linear memory. After each operation, JS reads the result from
// the out-slot (frost_out_ptr/len) and checks frost_out_err for errors.
//
// All crypto operations are synchronous and single-threaded.

const ID_LEN = 32;
const SCALAR_LEN = 32;
const POINT_LEN = 33;
const KEYPACKAGE_LEN = 132;
const NONCES_LEN = 64;
const COMMITMENTS_LEN = 66;
const SIGNING_PACKAGE_OVERHEAD = 6;

export const ErrorCode = Object.freeze({
  OK: 0,
  INVALID_MIN_SIGNERS: 1,
  INVALID_MAX_SIGNERS: 2,
  INCORRECT_NUMBER_OF_IDENTIFIERS: 3,
  DUPLICATED_IDENTIFIER: 4,
  UNKNOWN_IDENTIFIER: 5,
  INCORRECT_NUMBER_OF_COMMITMENTS: 6,
  INCORRECT_NUMBER_OF_SHARES: 7,
  MISSING_COMMITMENT: 8,
  INVALID_COMMITMENT: 9,
  IDENTITY_COMMITMENT: 10,
  INVALID_SECRET_SHARE: 11,
  INVALID_SIGNATURE_SHARE: 12,
  INVALID_SIGNATURE: 13,
  MALFORMED_SCALAR: 14,
  MALFORMED_ELEMENT: 15,
  MALFORMED_SIGNING_KEY: 16,
  INVALID_ZERO_SCALAR: 17,
  INVALID_IDENTITY_ELEMENT: 18,
  INVALID_COEFFICIENT: 19,
  SERIALIZATION_FAILED: 20,
  DESERIALIZATION_FAILED: 21,
  RANDOMNESS_ERROR: 22,
  INCORRECT_NUMBER_OF_PACKAGES: 23,
  INCORRECT_PACKAGE: 24,
  PACKAGE_NOT_FOUND: 25,
  INVALID_PROOF_OF_KNOWLEDGE: 26,
  IDENTIFIABLE_ABORT: 27,
  OUT_OF_MEMORY: 28,
  UNKNOWN: 127,
});

export class FrostError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FrostError';
    this.code = code;
  }
}

async function defaultWasmBytes() {
  const url = new URL('./bsvz_frost.wasm', import.meta.url);
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { readFileSync } = await import('node:fs');
    return readFileSync(url);
  }
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`bsvz-frost: failed to load wasm (${res.status} ${res.statusText})`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

function bytesOf(v, len, what) {
  if (typeof v === 'bigint' || typeof v === 'number') {
    const hex = BigInt.asUintN(len * 8, typeof v === 'number' ? BigInt(v) : v)
      .toString(16)
      .padStart(len * 2, '0');
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  if (v instanceof Uint8Array) {
    if (v.length !== len) throw new TypeError(`bsvz-frost: ${what} must be ${len} bytes`);
    return v;
  }
  throw new TypeError(`bsvz-frost: ${what} must be a bigint or Uint8Array`);
}

function randomBytes(n) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('bsvz-frost: global crypto.getRandomValues unavailable; pass entropy to seed()');
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

function hex(buf) {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function createFrost({ wasmBytes } = {}) {
  const bytes = wasmBytes ?? (await defaultWasmBytes());
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const m = instance.exports;
  if (typeof m.frost_version !== 'function') {
    throw new Error('bsvz-frost: not a bsvz_frost.wasm module (missing frost_version)');
  }

  const memView = () => new Uint8Array(m.memory.buffer);
  const read = (off, len) => memView().slice(off, off + len);

  function frostError(rc) {
    return new FrostError(rc, `bsvz-frost error code ${rc}`);
  }

  function checkRc(rc) {
    if (rc !== 0) throw frostError(rc);
  }

  function readOut() {
    const ptr = m.frost_out_ptr();
    const len = m.frost_out_len();
    const err = m.frost_out_err();
    if (err !== 0) throw frostError(err);
    if (len === 0) return new Uint8Array(0);
    // Copy into a fresh ArrayBuffer so the result survives WASM memory growth.
    const src = memView().slice(ptr, ptr + len);
    return new Uint8Array(src);
  }

  // --- Key Management -------------------------------------------------------

  const keygen = (t, n) => {
    const rc = m.frost_keygen(t, n);
    if (rc !== 0) throw frostError(rc);
    const out = readOut();
    // out = [n u16][n x SecretShare(variable)][PublicKeyPackage]
    const count = (out[0] << 8) | out[1];
    const shares = [];
    let off = 2;
    for (let i = 0; i < count; i++) {
      const coeff_count = (out[off + 64] << 8) | out[off + 65];
      const share_len = 66 + coeff_count * 33;
      shares.push(new Uint8Array(out.slice(off, off + share_len)));
      off += share_len;
    }
    const publicKeyPackage = new Uint8Array(out.slice(off));
    return { shares, publicKeyPackage };
  };

  const keypackageFromShare = (shareBytes) => {
    const ptr = m.frost_alloc(shareBytes.length);
    if (ptr === null) throw new Error('bsvz-frost: alloc failed');
    memView().set(shareBytes, ptr);
    const rc = m.frost_keypackage_from_share(ptr, shareBytes.length);
    m.frost_dealloc(ptr, shareBytes.length);
    if (rc !== 0) throw frostError(rc);
    return readOut();
  };

  // --- Signing --------------------------------------------------------------

  const round1Commit = (keypackageBytes) => {
    if (keypackageBytes.length !== KEYPACKAGE_LEN) {
      throw new TypeError(`bsvz-frost: keypackage must be ${KEYPACKAGE_LEN} bytes`);
    }
    const ptr = m.frost_alloc(KEYPACKAGE_LEN);
    if (ptr === null) throw new Error('bsvz-frost: alloc failed');
    memView().set(keypackageBytes, ptr);
    const rc = m.frost_round1_commit(ptr, KEYPACKAGE_LEN);
    m.frost_dealloc(ptr, KEYPACKAGE_LEN);
    if (rc !== 0) throw frostError(rc);
    const out = readOut();
    // out = SigningNonces(64) + SigningCommitments(66) = 130 bytes
    return {
      nonces: new Uint8Array(out.slice(0, NONCES_LEN)),
      commitments: new Uint8Array(out.slice(NONCES_LEN)),
    };
  };

  const round2Sign = (signingPackageBytes, noncesBytes, keypackageBytes) => {
    if (noncesBytes.length !== NONCES_LEN) {
      throw new TypeError(`bsvz-frost: nonces must be ${NONCES_LEN} bytes`);
    }
    if (keypackageBytes.length !== KEYPACKAGE_LEN) {
      throw new TypeError(`bsvz-frost: keypackage must be ${KEYPACKAGE_LEN} bytes`);
    }
    const spPtr = m.frost_alloc(signingPackageBytes.length);
    const noncesPtr = m.frost_alloc(NONCES_LEN);
    const kpPtr = m.frost_alloc(KEYPACKAGE_LEN);
    if (spPtr === null || noncesPtr === null || kpPtr === null) {
      if (spPtr !== null) m.frost_dealloc(spPtr, signingPackageBytes.length);
      if (noncesPtr !== null) m.frost_dealloc(noncesPtr, NONCES_LEN);
      if (kpPtr !== null) m.frost_dealloc(kpPtr, KEYPACKAGE_LEN);
      throw new Error('bsvz-frost: alloc failed');
    }
    memView().set(signingPackageBytes, spPtr);
    memView().set(noncesBytes, noncesPtr);
    memView().set(keypackageBytes, kpPtr);
    const rc = m.frost_round2_sign(spPtr, signingPackageBytes.length, noncesPtr, NONCES_LEN, kpPtr, KEYPACKAGE_LEN);
    m.frost_dealloc(spPtr, signingPackageBytes.length);
    m.frost_dealloc(noncesPtr, NONCES_LEN);
    m.frost_dealloc(kpPtr, KEYPACKAGE_LEN);
    if (rc !== 0) throw frostError(rc);
    return readOut(); // SignatureShare(32)
  };

  function allocPtr(bytes) {
    if (bytes.length === 0) return 0;
    const p = m.frost_alloc(bytes.length);
    if (p === null || p === undefined) throw new Error('bsvz-frost: alloc failed');
    return p;
  }

  const aggregate = (signingPackageBytes, sharesBytes, publicKeyPackageBytes, cheaterMode = 0) => {
    const spPtr = allocPtr(signingPackageBytes);
    const sharesPtr = allocPtr(sharesBytes);
    const pkPtr = allocPtr(publicKeyPackageBytes);
    if (signingPackageBytes.length > 0) memView().set(signingPackageBytes, spPtr);
    if (sharesBytes.length > 0) memView().set(sharesBytes, sharesPtr);
    if (publicKeyPackageBytes.length > 0) memView().set(publicKeyPackageBytes, pkPtr);
    const rc = m.frost_aggregate(spPtr, signingPackageBytes.length, sharesPtr, sharesBytes.length, pkPtr, publicKeyPackageBytes.length, cheaterMode);
    if (spPtr !== 0) m.frost_dealloc(spPtr, signingPackageBytes.length);
    if (sharesPtr !== 0) m.frost_dealloc(sharesPtr, sharesBytes.length);
    if (pkPtr !== 0) m.frost_dealloc(pkPtr, publicKeyPackageBytes.length);
    if (rc !== 0) throw frostError(rc);
    return readOut(); // Signature(65)
  };

  const verify = (verifyingKeyBytes, message, signatureBytes) => {
    if (verifyingKeyBytes.length !== POINT_LEN) {
      throw new TypeError(`bsvz-frost: verifying key must be ${POINT_LEN} bytes`);
    }
    if (signatureBytes.length !== 65) {
      throw new TypeError('bsvz-frost: signature must be 65 bytes');
    }
    const vkPtr = m.frost_alloc(POINT_LEN);
    const msgPtr = m.frost_alloc(message.length);
    const sigPtr = m.frost_alloc(65);
    if (vkPtr === null || msgPtr === null || sigPtr === null) {
      if (vkPtr !== null) m.frost_dealloc(vkPtr, POINT_LEN);
      if (msgPtr !== null) m.frost_dealloc(msgPtr, message.length);
      if (sigPtr !== null) m.frost_dealloc(sigPtr, 65);
      throw new Error('bsvz-frost: alloc failed');
    }
    memView().set(verifyingKeyBytes, vkPtr);
    memView().set(message, msgPtr);
    memView().set(signatureBytes, sigPtr);
    const rc = m.frost_verify(vkPtr, POINT_LEN, msgPtr, message.length, sigPtr, 65);
    m.frost_dealloc(vkPtr, POINT_LEN);
    m.frost_dealloc(msgPtr, message.length);
    m.frost_dealloc(sigPtr, 65);
    if (rc !== 0) throw frostError(rc);
    return true;
  };

  const reconstruct = (keypackagesBytes) => {
    const ptr = m.frost_alloc(keypackagesBytes.length);
    if (ptr === null) throw new Error('bsvz-frost: alloc failed');
    memView().set(keypackagesBytes, ptr);
    const rc = m.frost_reconstruct(ptr, keypackagesBytes.length);
    m.frost_dealloc(ptr, keypackagesBytes.length);
    if (rc !== 0) throw frostError(rc);
    return readOut(); // SigningKey(32)
  };

  // --- DKG ------------------------------------------------------------------

  const dkgPart1 = (id, t, n) => {
    const rc = m.frost_dkg_part1(id, t, n);
    if (rc !== 0) throw frostError(rc);
    return readOut(); // [secret_len u16][secret][broadcast]
  };

  const dkgPart2 = (secretBytes, broadcastsBytes) => {
    const secretPtr = m.frost_alloc(secretBytes.length);
    const bcPtr = m.frost_alloc(broadcastsBytes.length);
    if (secretPtr === null || bcPtr === null) {
      if (secretPtr !== null) m.frost_dealloc(secretPtr, secretBytes.length);
      if (bcPtr !== null) m.frost_dealloc(bcPtr, broadcastsBytes.length);
      throw new Error('bsvz-frost: alloc failed');
    }
    memView().set(secretBytes, secretPtr);
    memView().set(broadcastsBytes, bcPtr);
    const rc = m.frost_dkg_part2(secretPtr, secretBytes.length, bcPtr, broadcastsBytes.length);
    m.frost_dealloc(secretPtr, secretBytes.length);
    m.frost_dealloc(bcPtr, broadcastsBytes.length);
    if (rc > 0) {
      // Identifiable abort: rc = cheater count, out-slot contains [count u16][count x id32]
      const out = readOut();
      const count = (out[0] << 8) | out[1];
      const cheaters = [];
      let off = 2;
      for (let i = 0; i < count; i++) {
        cheaters.push(out.slice(off, off + ID_LEN));
        off += ID_LEN;
      }
      throw new FrostError(ErrorCode.IDENTIFIABLE_ABORT, `cheaters: ${cheaters.map((c) => hex(c)).join(', ')}`);
    }
    if (rc < 0) throw frostError(rc);
    return readOut(); // [secret2_len][secret2][count][(id32 | share32)]
  };

  const dkgPart3 = (secret2Bytes, r1Bytes, r2Bytes) => {
    const s2Ptr = m.frost_alloc(secret2Bytes.length);
    const r1Ptr = m.frost_alloc(r1Bytes.length);
    const r2Ptr = m.frost_alloc(r2Bytes.length);
    if (s2Ptr === null || r1Ptr === null || r2Ptr === null) {
      if (s2Ptr !== null) m.frost_dealloc(s2Ptr, secret2Bytes.length);
      if (r1Ptr !== null) m.frost_dealloc(r1Ptr, r1Bytes.length);
      if (r2Ptr !== null) m.frost_dealloc(r2Ptr, r2Bytes.length);
      throw new Error('bsvz-frost: alloc failed');
    }
    memView().set(secret2Bytes, s2Ptr);
    memView().set(r1Bytes, r1Ptr);
    memView().set(r2Bytes, r2Ptr);
    const rc = m.frost_dkg_part3(s2Ptr, secret2Bytes.length, r1Ptr, r1Bytes.length, r2Ptr, r2Bytes.length);
    m.frost_dealloc(s2Ptr, secret2Bytes.length);
    m.frost_dealloc(r1Ptr, r1Bytes.length);
    m.frost_dealloc(r2Ptr, r2Bytes.length);
    if (rc > 0) {
      const out = readOut();
      const count = (out[0] << 8) | out[1];
      const cheaters = [];
      let off = 2;
      for (let i = 0; i < count; i++) {
        cheaters.push(out.slice(off, off + ID_LEN));
        off += ID_LEN;
      }
      throw new FrostError(ErrorCode.IDENTIFIABLE_ABORT, `cheaters: ${cheaters.map((c) => hex(c)).join(', ')}`);
    }
    if (rc < 0) throw frostError(rc);
    const out = readOut();
    // out = KeyPackage(132) + PublicKeyPackage
    const keypackage = out.slice(0, KEYPACKAGE_LEN);
    const publicKeyPackage = out.slice(KEYPACKAGE_LEN);
    return { keypackage, publicKeyPackage };
  };

  // --- Lifecycle ------------------------------------------------------------

  const api = {
    version: () => {
      const ptr = m.frost_version();
      const len = new Uint8Array(m.memory.buffer, ptr).indexOf(0);
      return new TextDecoder().decode(read(ptr, len));
    },
     seed(entropy) {
      const bytes = entropy ?? randomBytes(64);
      if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 64) {
        throw new TypeError('bsvz-frost: seed expects 1..64 bytes');
      }
      const bufPtr = m.frost_seed_buffer();
      const buf = new Uint8Array(memView().buffer, bufPtr, 64);
      buf.set(bytes);
      m.frost_seed(bytes.length);
    },
    keygen,
    keypackageFromShare,
    round1Commit,
    round2Sign,
    aggregate,
    verify,
    reconstruct,
    dkgPart1,
    dkgPart2,
    dkgPart3,
    // low-level access to the raw shim and linear memory
    raw: m,
    memView,
    alloc: (len) => m.frost_alloc(len),
    free: (ptr, len) => m.frost_dealloc(ptr, len),
  };

  return api;
}

export default createFrost;
