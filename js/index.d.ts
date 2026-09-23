// Type declarations for the bsvz-frost WebAssembly JS API.
//
// Byte lengths match the WASM wire formats: scalars/identifiers are 32-byte
// big-endian, points are 33-byte compressed SEC1, signatures are 65 bytes,
// and key packages are 132 bytes.

/** 32-byte participant identifier. */
export type Identifier = Uint8Array;
/** 32-byte big-endian scalar. */
export type Scalar = Uint8Array;
/** 33-byte compressed SEC1 point. */
export type Point = Uint8Array;
/** 65-byte Schnorr signature (R ‖ z). */
export type Signature = Uint8Array;
/** 132-byte key package. */
export type KeyPackage = Uint8Array;
/** Variable-length secret share (66 + coeff_count × 33 bytes). */
export type SecretShare = Uint8Array;
/** Public key package (variable length). */
export type PublicKeyPackage = Uint8Array;
/** 64-byte secret nonces (hiding ‖ binding). */
export type SigningNonces = Uint8Array;
/** 66-byte public commitments (hiding ‖ binding). */
export type SigningCommitments = Uint8Array;
/** Serialized signing package (commitments + message). */
export type SigningPackage = Uint8Array;
/** 32-byte signature share. */
export type SignatureShare = Uint8Array;
/** 32-byte signing key. */
export type SigningKey = Uint8Array;
/** 33-byte verifying key. */
export type VerifyingKey = Uint8Array;

/** Length constants for the fixed-size wire types. */
export const ID_LEN: 32;
export const SCALAR_LEN: 32;
export const POINT_LEN: 33;
export const KEYPACKAGE_LEN: 132;
export const NONCES_LEN: 64;
export const COMMITMENTS_LEN: 66;

/**
 * Stable error codes (mirrors the WASM WasmError enum). Never renumber;
 * only append new codes in future versions.
 */
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
  OUT_OF_MEMORY: 28;
  UNKNOWN: 127;
}>;

/** Error thrown by any API method that fails a WASM operation. */
export class FrostError extends Error {
  /** One of the ErrorCode numeric values. */
  code: number;
  name: 'FrostError';
}

/** Options for createFrost. */
export interface CreateFrostOptions {
  /** Prebuilt module bytes; defaults to the bundled bsvz_frost.wasm. */
  wasmBytes?: Uint8Array | ArrayBuffer;
}

/** Result of trusted-dealer keygen: n secret shares + public key package. */
export interface KeygenResult {
  shares: SecretShare[];
  publicKeyPackage: PublicKeyPackage;
}

/** Result of Round 1: secret nonces (keep local) + public commitments. */
export interface Round1Result {
  nonces: SigningNonces;
  commitments: SigningCommitments;
}

/** Result of DKG Part 3: this participant's KeyPackage + shared PublicKeyPackage. */
export interface DkgPart3Result {
  keypackage: KeyPackage;
  publicKeyPackage: PublicKeyPackage;
}

/**
 * High-level synchronous API over the FROST WASM module.
 * All methods complete their WASM call before returning; results are copied
 * out of linear memory into fresh TypedArrays.
 */
export interface FrostApi {
  /** Module protocol version string. */
  version(): string;
  /**
   * Seed the module CSPRNG. Without an argument, draws 64 bytes from
   * host `crypto.getRandomValues`. Must be called before keygen / DKG.
   */
  seed(entropy?: Uint8Array): void;
  /** Trusted dealer key generation. Returns n secret shares and a public key package. */
  keygen(t: number, n: number): KeygenResult;
  /** Derive a KeyPackage from a SecretShare (verifies the share first). */
  keypackageFromShare(share: SecretShare): KeyPackage;
  /** Round 1: generate signing nonces and commitments from a KeyPackage. */
  round1Commit(keypackage: KeyPackage): Round1Result;
  /** Round 2: produce a signature share given the signing package, nonces, and keypackage. */
  round2Sign(signingPackage: SigningPackage, nonces: SigningNonces, keypackage: KeyPackage): SignatureShare;
  /**
   * Aggregate signature shares into a complete signature.
   * shares: [count u16 BE][count × (id32 ‖ share32)].
   * cheaterMode: 0 = disabled, 1 = first cheater only, 2 = all cheaters.
   */
  aggregate(signingPackage: SigningPackage, shares: Uint8Array, publicKeyPackage: PublicKeyPackage, cheaterMode?: number): Signature;
  /** Verify a signature against a message and verifying key; throws on failure. */
  verify(verifyingKey: VerifyingKey, message: Uint8Array, signature: Signature): boolean;
  /** Reconstruct the signing key from ≥ t key packages: [count u16 BE][count × KeyPackage(132)]. */
  reconstruct(keypackages: Uint8Array): SigningKey;
  /** DKG Part 1 (id ≥ 1): returns [secret_len u16][secret][broadcast]. */
  dkgPart1(id: number, t: number, n: number): Uint8Array;
  /** DKG Part 2: process n-1 broadcasts (self excluded); throws IDENTIFIABLE_ABORT on cheaters. */
  dkgPart2(secret: Uint8Array, broadcasts: Uint8Array): Uint8Array;
  /** DKG Part 3: verify shares and produce KeyPackage + PublicKeyPackage; throws IDENTIFIABLE_ABORT on cheaters. */
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

/** Instantiate the WASM module and return the high-level API. */
export function createFrost(options?: CreateFrostOptions): Promise<FrostApi>;
export default createFrost;
