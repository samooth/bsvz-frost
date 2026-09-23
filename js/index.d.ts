// Type declarations for bsvz-frost (wasm module JS API).

export type Identifier = Uint8Array;   // 32-byte participant id
export type Scalar = Uint8Array;       // 32-byte scalar
export type Point = Uint8Array;        // 33-byte compressed SEC1
export type Signature = Uint8Array;    // 65-byte signature
export type KeyPackage = Uint8Array;   // 132-byte key package
export type SecretShare = Uint8Array;  // 66-byte secret share
export type PublicKeyPackage = Uint8Array;
export type SigningNonces = Uint8Array;     // 64-byte
export type SigningCommitments = Uint8Array; // 66-byte
export type SigningPackage = Uint8Array;
export type SignatureShare = Uint8Array;    // 32-byte
export type SigningKey = Uint8Array;        // 32-byte
export type VerifyingKey = Uint8Array;      // 33-byte

export const ID_LEN: 32;
export const SCALAR_LEN: 32;
export const POINT_LEN: 33;
export const KEYPACKAGE_LEN: 132;
export const NONCES_LEN: 64;
export const COMMITMENTS_LEN: 66;

export const ErrorCode: Readonly<{
  OK: 0;
  INVALID_MIN_SIGNERS: 1;
  INVALID_MAX_SIGNERS: 2;
  INCORRECT_NUMBER_OF_IDENTIFIERS: 3;
  DUPLICATED_IDENTIFIER: 4;
  UNKNOWN_IDENTIFIER: 5;
  INCORRECT_NUMBER_OF_COMMITMENTS: 6;
  INCORRECT_NUMBER_OF_SHARES: 7;
  MISSING_COMMITMENT: 8;
  INVALID_COMMITMENT: 9;
  IDENTITY_COMMITMENT: 10;
  INVALID_SECRET_SHARE: 11;
  INVALID_SIGNATURE_SHARE: 12;
  INVALID_SIGNATURE: 13;
  MALFORMED_SCALAR: 14;
  MALFORMED_ELEMENT: 15;
  MALFORMED_SIGNING_KEY: 16;
  INVALID_ZERO_SCALAR: 17;
  INVALID_IDENTITY_ELEMENT: 18;
  INVALID_COEFFICIENT: 19;
  SERIALIZATION_FAILED: 20;
  DESERIALIZATION_FAILED: 21;
  RANDOMNESS_ERROR: 22;
  INCORRECT_NUMBER_OF_PACKAGES: 23;
  INCORRECT_PACKAGE: 24;
  PACKAGE_NOT_FOUND: 25;
  INVALID_PROOF_OF_KNOWLEDGE: 26;
  IDENTIFIABLE_ABORT: 27;
  UNKNOWN: 127;
}>;

export class FrostError extends Error {
  code: number;
  name: 'FrostError';
}

export interface CreateFrostOptions {
  /** Prebuilt module bytes; defaults to the bundled bsvz_frost.wasm. */
  wasmBytes?: Uint8Array | ArrayBuffer;
}

export interface KeygenResult {
  shares: SecretShare[];
  publicKeyPackage: PublicKeyPackage;
}

export interface Round1Result {
  nonces: SigningNonces;
  commitments: SigningCommitments;
}

export interface DkgPart3Result {
  keypackage: KeyPackage;
  publicKeyPackage: PublicKeyPackage;
}

export interface FrostApi {
  /** Module protocol version. */
  version(): string;
  /**
   * Seed the module CSPRNG. Without an argument, draws 64 bytes from
   * host `crypto.getRandomValues`. Must be called before keygen / DKG.
   */
  seed(entropy?: Uint8Array): void;
  /** Trusted dealer key generation. Returns n secret shares and a public key package. */
  keygen(t: number, n: number): KeygenResult;
  /** Derive a KeyPackage from a SecretShare. */
  keypackageFromShare(share: SecretShare): KeyPackage;
  /** Round 1: generate signing nonces and commitments from a KeyPackage. */
  round1Commit(keypackage: KeyPackage): Round1Result;
  /** Round 2: produce a signature share given the signing package, nonces, and keypackage. */
  round2Sign(signingPackage: SigningPackage, nonces: SigningNonces, keypackage: KeyPackage): SignatureShare;
  /** Aggregate signature shares into a complete signature. */
  aggregate(signingPackage: SigningPackage, shares: Uint8Array, publicKeyPackage: PublicKeyPackage, cheaterMode?: number): Signature;
  /** Verify a signature against a message and verifying key. */
  verify(verifyingKey: VerifyingKey, message: Uint8Array, signature: Signature): boolean;
  /** Reconstruct the signing key from t key packages. */
  reconstruct(keypackages: Uint8Array): SigningKey;
  /** DKG Part 1: generate round 1 secret and broadcast package. */
  dkgPart1(id: number, t: number, n: number): Uint8Array;
  /** DKG Part 2: process round 1 packages and generate round 2 outgoing shares. */
  dkgPart2(secret: Uint8Array, broadcasts: Uint8Array): Uint8Array;
  /** DKG Part 3: process round 2 shares and produce final keypackage. */
  dkgPart3(secret2: Uint8Array, r1: Uint8Array, r2: Uint8Array): DkgPart3Result;
  /** Raw wasm exports for low-level use. */
  raw: WebAssembly.Exports;
  /** Current linear memory view (re-fetch after alloc: the buffer can grow). */
  memView(): Uint8Array;
  /** Allocate bytes in wasm linear memory; pair with free(). */
  alloc(len: number): number;
  /** Free a buffer from alloc(). */
  free(ptr: number, len: number): void;
}

export function createFrost(options?: CreateFrostOptions): Promise<FrostApi>;
export default createFrost;
