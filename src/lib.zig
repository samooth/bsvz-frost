//! bsvz-frost: FROST threshold signatures over secp256k1 for BSV
//!
//! A Zig implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures using the secp256k1 curve and SHA-256, compatible with the
//! Bitcoin SV ecosystem via bsvz primitives.
//!
//! Based on ZcashFoundation/frost-secp256k1 and RFC 9591.
//! NOT compatible with BIP-340 (Taproot); use frost-secp256k1-tr for that.

const std = @import("std");

// Public API re-exports
pub const Error = @import("error.zig").FrostError;
pub const Identifier = @import("identifier.zig").Identifier;
pub const Signature = @import("signature.zig").Signature;

// Ciphersuite
pub const Ciphersuite = @import("ciphersuite.zig");
pub const CONTEXT_STRING = Ciphersuite.CONTEXT_STRING;

// Field & Group primitives
pub const field = @import("field.zig");
pub const group = @import("group.zig");

// bsvz-interop byte scalars and threshold primitives built on bsvz.crypto
pub const scalar = @import("scalar.zig");
pub const shamir = @import("shamir.zig");
pub const naive = @import("naive.zig");
pub const Share = shamir.Share;

// Keys module
pub const keys = @import("keys.zig");
pub const SigningKey = keys.SigningKey;
pub const VerifyingKey = keys.VerifyingKey;
pub const SigningShare = keys.SigningShare;
pub const VerifyingShare = keys.VerifyingShare;
pub const SecretShare = keys.SecretShare;
pub const KeyPackage = keys.KeyPackage;
pub const PublicKeyPackage = keys.PublicKeyPackage;
pub const VerifiableSecretSharingCommitment = keys.VerifiableSecretSharingCommitment;
pub const CoefficientCommitment = keys.CoefficientCommitment;

// Distributed key generation (FROST KeyGen)
pub const dkg = @import("dkg.zig");

// Round 1
pub const round1 = @import("round1.zig");
pub const Nonce = round1.Nonce;
pub const NonceCommitment = round1.NonceCommitment;
pub const SigningNonces = round1.SigningNonces;
pub const SigningCommitments = round1.SigningCommitments;
pub const GroupCommitmentShare = round1.GroupCommitmentShare;

// Round 2
pub const round2 = @import("round2.zig");
pub const SignatureShare = round2.SignatureShare;
pub const SigningPackage = round2.SigningPackage;

// Aggregation
pub const aggregate = @import("aggregate.zig");
pub const CheaterDetection = aggregate.CheaterDetection;

/// Convenience: full 2-round FROST signing flow for testing/demo.
/// In production, rounds happen across network boundaries.
pub fn fullFrostSign(
    allocator: std.mem.Allocator,
    message: []const u8,
    key_packages: []const keys.KeyPackage,
    pubkeys: *const keys.PublicKeyPackage,
    min_signers: u16,
) !Signature {
    // Round 1: each participant commits
    var commitments = std.AutoHashMap(Identifier, SigningCommitments).init(allocator);
    defer commitments.deinit();
    var nonces_list = std.AutoHashMap(Identifier, SigningNonces).init(allocator);
    defer nonces_list.deinit();
    for (key_packages[0..min_signers]) |kp| {
        const nonces, const comm = round1.commit(&kp.signing_share);
        try commitments.put(kp.identifier, comm);
        try nonces_list.put(kp.identifier, nonces);
    }
    // Coordinator creates signing package
    const signing_package = round2.SigningPackage.new(commitments, message);
    // Round 2: each participant signs
    var signature_shares = std.AutoHashMap(Identifier, SignatureShare).init(allocator);
    defer signature_shares.deinit();
    for (key_packages[0..min_signers]) |kp| {
        const nonces = nonces_list.get(kp.identifier) orelse return Error.MissingCommitment;
        const share = try round2.sign(&signing_package, &nonces, &kp);
        try signature_shares.put(kp.identifier, share);
    }
    // Aggregate
    return try aggregate.aggregateSimple(&signing_package, signature_shares, pubkeys);
}
