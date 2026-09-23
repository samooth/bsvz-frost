//! FROST error types.
//!
//! Every failure path in the library returns one of these (or, for std crypto
//! inputs, a std error such as error.InvalidEncoding). The WASM layer maps
//! each member onto a stable numeric code for the JS boundary; those numeric
//! values must never be renumbered.
const std = @import("std");

/// Error set covering all FROST protocol and serialization failures.
pub const FrostError = error{
    /// min_signers < 2 or min_signers > max_signers.
    InvalidMinSigners,
    /// max_signers < 2.
    InvalidMaxSigners,
    /// Caller supplied the wrong number of identifiers for the requested n.
    IncorrectNumberOfIdentifiers,
    /// Duplicate identifier in the participant list.
    DuplicatedIdentifier,
    /// Lagrange interpolation was asked about an identifier not in the set.
    UnknownIdentifier,
    /// Commitment list length does not match the expected participant count.
    IncorrectNumberOfCommitments,
    /// Not enough signature shares / key packages to meet the threshold.
    IncorrectNumberOfShares,
    /// A required commitment is missing from the signing package.
    MissingCommitment,
    /// Commitment bytes failed to parse or do not match the local nonces.
    InvalidCommitment,
    /// Group commitment is the identity point (forbidden).
    IdentityCommitment,
    /// A secret share does not satisfy the VSS verification equation.
    InvalidSecretShare,
    /// A signature share failed its individual verification equation.
    InvalidSignatureShare,
    /// The final aggregate signature failed verification.
    InvalidSignature,
    /// Scalar bytes are non-canonical or otherwise malformed.
    MalformedScalar,
    /// Point bytes are not a valid SEC1 encoding / not on the curve.
    MalformedElement,
    /// A signing key is zero or otherwise invalid.
    MalformedSigningKey,
    /// Operation required the inverse of zero.
    InvalidZeroScalar,
    /// Cannot serialize the identity element (no valid compressed encoding).
    InvalidIdentityElement,
    /// Polynomial coefficient is zero or otherwise invalid for the operation.
    InvalidCoefficient,
    /// Serialization failed (allocation or internal error during write).
    SerializationFailed,
    /// Input bytes are truncated, misaligned, or fail to parse.
    DeserializationFailed,
    /// DKG is not supported in this build / context.
    DkgNotSupported,
    /// Identifier derivation is not supported in this build / context.
    IdentifierDerivationNotSupported,
    /// CSPRNG failed to produce usable entropy.
    RandomnessError,
    /// Nonce is zero or otherwise unusable.
    InvalidNonce,
    /// Wrong number of DKG packages supplied for the ceremony size.
    IncorrectNumberOfPackages,
    /// A DKG package is structurally wrong (e.g. missing from one map).
    IncorrectPackage,
    /// Expected package not found in the supplied map.
    PackageNotFound,
    /// Schnorr proof of knowledge verification failed (rogue-key defence).
    InvalidProofOfKnowledge,
    /// Allocation failed.
    OutOfMemory,
};
