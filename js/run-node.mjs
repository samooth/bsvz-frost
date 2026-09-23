// Node smoke test for the bsvz-frost wasm module.
//
// Loads the module, runs a complete FROST signing session through the JS API,
// and asserts correct behavior including negative cases.

import { readFileSync } from 'node:fs';
import { createFrost, ErrorCode } from './index.js';

// build.zig / npm test pass the artifact path as the last argument.
const artifact = process.argv[process.argv.length - 1];

const frost = await createFrost({ wasmBytes: readFileSync(artifact) });

const SCALAR = 32;
const POINT = 33;
const KEYPACKAGE = 132;
const NONCES = 64;
const COMMITMENTS = 66;
const SIGNATURE = 65;

function assert(cond, msg) {
  if (!cond) throw new Error('assertion failed: ' + msg);
}
function tamper(buf, idx = 0) {
  const t = new Uint8Array(buf);
  t[idx] ^= 1;
  return t;
}

assert(frost.version() === '0.1.0-wasm1', 'version');

frost.seed(); // exercises the host-entropy path

// --- Key generation ---------------------------------------------------------

const { shares, publicKeyPackage } = frost.keygen(2, 3);
assert(shares.length === 3, 'keygen returns 3 shares');
assert(publicKeyPackage.length > 0, 'keygen returns public key package');

// Derive KeyPackage from SecretShare
const kp0 = frost.keypackageFromShare(shares[0]);
assert(kp0.length === KEYPACKAGE, 'keypackage length');

// --- Round 1 -----------------------------------------------------------------

const participant0 = frost.round1Commit(kp0);
assert(participant0.nonces.length === NONCES, 'nonces length');
assert(participant0.commitments.length === COMMITMENTS, 'commitments length');

const participant1 = frost.round1Commit(frost.keypackageFromShare(shares[1]));

// --- Round 2 -----------------------------------------------------------------

const message = new TextEncoder().encode('hello frost');

// Build a proper signing package from round1 commitments
function buildSigningPackage(commitmentsWithIds, message) {
  const count = commitmentsWithIds.length;
  const buf = new Uint8Array(2 + count * 98 + 4 + message.length);
  const view = new DataView(buf.buffer);
  view.setUint16(0, count, false); // big-endian
  let off = 2;
  for (const {id, commitments} of commitmentsWithIds) {
    buf.set(id, off);
    off += 32;
    buf.set(commitments, off);
    off += 66;
  }
  view.setUint32(off, message.length, false);
  off += 4;
  buf.set(message, off);
  return buf;
}

const signingPackage = buildSigningPackage([
  {id: shares[0].slice(0, 32), commitments: participant0.commitments},
  {id: shares[1].slice(0, 32), commitments: participant1.commitments}
], message);

// Round 2: produce signature shares
const share0 = frost.round2Sign(signingPackage, participant0.nonces, kp0);
assert(share0.length === 32, 'signature share length');

const kp1 = frost.keypackageFromShare(shares[1]);
const share1 = frost.round2Sign(signingPackage, participant1.nonces, kp1);
assert(share1.length === 32, 'signature share length');

// Build shares blob for aggregate: [count u16][count x (id32 | share32)]
function buildSharesBlob(ids, shares) {
  const buf = new Uint8Array(2 + ids.length * 64);
  const view = new DataView(buf.buffer);
  view.setUint16(0, ids.length, false);
  let off = 2;
  for (let i = 0; i < ids.length; i++) {
    buf.set(ids[i], off);
    off += 32;
    buf.set(shares[i], off);
    off += 32;
  }
  return buf;
}

// Extract identifiers from key packages (first 32 bytes)
const id0 = kp0.slice(0, 32);
const id1 = kp1.slice(0, 32);
const sharesBlob = buildSharesBlob([id0, id1], [share0, share1]);

// Aggregate
const signature = frost.aggregate(signingPackage, sharesBlob, publicKeyPackage, 0);
assert(signature.length === 65, 'signature length');

// --- Verify ------------------------------------------------------------------

const vk = publicKeyPackage.slice(0, POINT);
assert(frost.verify(vk, message, signature), 'verify valid signature');

try {
  frost.verify(vk, message, tamper(signature, 0));
  assert(false, 'verify tampered signature should throw');
} catch (e) {
  assert(e.code === ErrorCode.INVALID_SIGNATURE, 'tampered signature → invalid_signature');
}
try {
  frost.verify(tamper(vk, 0), message, signature);
  assert(false, 'verify wrong key should throw');
} catch (e) {
  assert(e.code !== 0, 'wrong key → error');
}

// --- Reconstruct ------------------------------------------------------------

// wire format: [count u16 BE][count x KeyPackage(132)]
function buildKeypackagesBlob(kps) {
  const buf = new Uint8Array(2 + kps.length * KEYPACKAGE);
  const view = new DataView(buf.buffer);
  view.setUint16(0, kps.length, false);
  let off = 2;
  for (const kp of kps) {
    buf.set(kp, off);
    off += KEYPACKAGE;
  }
  return buf;
}
const reconstructed = frost.reconstruct(
  buildKeypackagesBlob([
    frost.keypackageFromShare(shares[0]),
    frost.keypackageFromShare(shares[1]),
  ])
);
assert(reconstructed.length === SCALAR, 'reconstructed key length');

// --- DKG ---------------------------------------------------------------------

// Identifier 0 is invalid; DKG participants use 1-based ids.
const dkgIds = [1, 2, 3];
const DKG_N = 3;
const DKG_T = 2;

// part1 out = [secret_len u16 BE][secret][broadcast]
function splitPart1(r1) {
  const secretLen = (r1[0] << 8) | r1[1];
  return {
    secret: r1.slice(2, 2 + secretLen),
    broadcast: r1.slice(2 + secretLen),
  };
}

function idBytes(id) {
  const b = new Uint8Array(32);
  b[30] = (id >> 8) & 0xff;
  b[31] = id & 0xff;
  return b;
}

// broadcasts blob for a given recipient: [count u16][count x (id32 | r1_package)]
function buildBroadcasts(entries) {
  let total = 2;
  for (const [, pkg] of entries) total += 32 + pkg.length;
  const buf = new Uint8Array(total);
  const view = new DataView(buf.buffer);
  view.setUint16(0, entries.length, false);
  let off = 2;
  for (const [id, pkg] of entries) {
    buf.set(idBytes(id), off); off += 32;
    buf.set(pkg, off); off += pkg.length;
  }
  return buf;
}

const r1Outputs = dkgIds.map((id) => frost.dkgPart1(id, DKG_T, DKG_N));
const parts = r1Outputs.map(splitPart1);

// Each participant runs part2 with its secret + n-1 broadcasts from others.
const r2Outputs = dkgIds.map((selfId, i) => {
  const others = dkgIds
    .map((id, j) => [id, parts[j].broadcast])
    .filter(([id]) => id !== selfId);
  return frost.dkgPart2(parts[i].secret, buildBroadcasts(others));
});

// part2 out = [secret2_len u16 BE][secret2][count u16][count x (id32 | share32)]
function splitPart2(r2) {
  const secret2Len = (r2[0] << 8) | r2[1];
  const secret2 = r2.slice(2, 2 + secret2Len);
  const countOff = 2 + secret2Len;
  const count = (r2[countOff] << 8) | r2[countOff + 1];
  const shares = [];
  let off = countOff + 2;
  for (let k = 0; k < count; k++) {
    shares.push({ id: r2.slice(off, off + 32), share: r2.slice(off + 32, off + 64) });
    off += 64;
  }
  return { secret2, shares };
}

const p2 = r2Outputs.map(splitPart2);

// part3 for participant 1 (id=1):
//   secret2 = own part2 secret
//   r1 = [count][id | pkg] from OTHER participants
//   r2 = [count][id | share] from OTHER participants
function r1BlobFor(selfIdx) {
  const others = dkgIds
    .map((id, j) => [id, parts[j].broadcast])
    .filter(([id], j) => j !== selfIdx);
  return buildBroadcasts(others);
}
function r2BlobFor(selfIdx) {
  // part3 needs shares RECEIVED from others, keyed by SENDER id:
  // from each other participant's part2 output, extract the entry addressed
  // to self, then re-key it under the sender's id.
  const selfId = dkgIds[selfIdx];
  const received = [];
  for (let j = 0; j < dkgIds.length; j++) {
    if (j === selfIdx) continue;
    const entry = p2[j].shares.find((s) => {
      const id = (s.id[30] << 8) | s.id[31];
      return id === selfId;
    });
    if (!entry) throw new Error(`dkg: missing share for participant ${selfId} from ${dkgIds[j]}`);
    received.push({ id: idBytes(dkgIds[j]), share: entry.share });
  }
  const buf = new Uint8Array(2 + received.length * 64);
  const view = new DataView(buf.buffer);
  view.setUint16(0, received.length, false);
  let off = 2;
  for (const { id, share } of received) {
    buf.set(id, off); off += 32;
    buf.set(share, off); off += 32;
  }
  return buf;
}

const selfIdx = 0; // participant id=1
const { keypackage, publicKeyPackage: pkp } = frost.dkgPart3(
  p2[selfIdx].secret2,
  r1BlobFor(selfIdx),
  r2BlobFor(selfIdx),
);
assert(keypackage.length === KEYPACKAGE, 'dkg keypackage length');
assert(pkp.length > 0, 'dkg public key package length');

// --- Error handling ---------------------------------------------------------

try {
  frost.keygen(1, 3); // t < 2
  assert(false, 'should throw');
} catch (e) {
  assert(e.code === ErrorCode.INVALID_MIN_SIGNERS, 'invalid_min_signers');
}

try {
  frost.verify(tamper(vk, 0), message, new Uint8Array(SIGNATURE));
  assert(false, 'should throw');
} catch (e) {
  assert(e.code === ErrorCode.DESERIALIZATION_FAILED, 'deserialization failed');
}

// --- Low-level memory API ---------------------------------------------------

const buf = frost.alloc(33);
assert(buf !== 0, 'raw alloc');
assert(frost.memView().length > 0, 'memView');
frost.free(buf, 33);

console.log('wasm-test OK: FROST protocol round-trips correctly');
