//! FROST signature aggregation and verification.
//!
//! Sums the participants' signature shares into a single Schnorr signature
//! (R, z) and optionally runs identifiable-abort cheater detection when the
//! aggregate fails to verify.
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const round1 = @import("round1.zig");
const round2 = @import("round2.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const Signature = @import("signature.zig").Signature;

/// Cheater-detection mode for aggregation on failure.
pub const CheaterDetection = enum {
    /// Do not run share-level checks; fail with InvalidSignature only.
    disabled,
    /// On failure, verify shares until the first bad one, then abort.
    first_cheater,
    /// On failure, verify every share and report all bad ones.
    all_cheaters,
};

/// Aggregate signature shares into the final Schnorr signature.
///
/// Checks that every commitment has a matching share and that the count
/// meets the threshold, sums z_i, builds R from the binding factors, and
/// verifies the result. On failure with cheater detection enabled, runs
/// share-level verification to identify the culprit(s).
pub fn aggregate(
    signing_package: *const round2.SigningPackage,
    signature_shares: std.AutoHashMap(Identifier, round2.SignatureShare),
    pubkeys: *const keys.PublicKeyPackage,
    cheater_detection: CheaterDetection,
) !Signature {
    if (signing_package.signing_commitments.count() != signature_shares.count()) {
        return FrostError.UnknownIdentifier;
    }
    if (pubkeys.min_signers) |min| {
        if (signature_shares.count() < min) return FrostError.IncorrectNumberOfShares;
    }
    // Every commitment must have a corresponding share (and verifying share
    // when cheater detection is enabled).
    var sc_it = signing_package.signing_commitments.iterator();
    while (sc_it.next()) |entry| {
        if (!signature_shares.contains(entry.key_ptr.*)) return FrostError.UnknownIdentifier;
        if (cheater_detection != .disabled) {
            if (!pubkeys.verifying_shares.contains(entry.key_ptr.*)) return FrostError.UnknownIdentifier;
        }
    }
    var binding_factor_list = try round2.computeBindingFactorList(signing_package, &pubkeys.verifying_key, std.heap.page_allocator);
    defer binding_factor_list.deinit();
    const group_commitment = try round2.computeGroupCommitment(signing_package, &binding_factor_list);
    // Sum signature shares: z = Σ z_i.
    var z = field.scalarZero();
    var ss_it = signature_shares.iterator();
    while (ss_it.next()) |entry| {
        z = field.scalarAdd(z, entry.value_ptr.*.toScalar());
    }
    const signature = Signature{ .R = group_commitment, .z = z };
    // Verify the aggregate signature.
    const verification_result = pubkeys.verifying_key.verify(signing_package.message, signature);
    switch (cheater_detection) {
        .disabled => {
            try verification_result;
        },
        .first_cheater, .all_cheaters => {
            if (verification_result) |_| {} else |_| {
                try detectCheater(signing_package, signature_shares, pubkeys, binding_factor_list, group_commitment, cheater_detection);
            }
        },
    }
    return signature;
}

/// Aggregate without cheater detection (fail fast on invalid signature).
pub fn aggregateSimple(
    signing_package: *const round2.SigningPackage,
    signature_shares: std.AutoHashMap(Identifier, round2.SignatureShare),
    pubkeys: *const keys.PublicKeyPackage,
) !Signature {
    return aggregate(signing_package, signature_shares, pubkeys, .disabled);
}

/// On aggregate failure, verify each signature share individually and
/// collect the identifier(s) whose share does not check out. Returns
/// InvalidSignatureShare if any culprit was found, else InvalidSignature.
fn detectCheater(
    signing_package: *const round2.SigningPackage,
    signature_shares: std.AutoHashMap(Identifier, round2.SignatureShare),
    pubkeys: *const keys.PublicKeyPackage,
    binding_factor_list: std.AutoHashMap(Identifier, field.Scalar),
    group_commitment: group.Element,
    cheater_detection: CheaterDetection,
) !void {
    const challenge = try keys.challenge(&group_commitment, &pubkeys.verifying_key, signing_package.message);
    const identifiers = try round2.participatingIdentifiers(signing_package, std.heap.page_allocator);
    defer std.heap.page_allocator.free(identifiers);
    var all_culprits = std.ArrayList(Identifier).empty;
    defer all_culprits.deinit(std.heap.page_allocator);
    var ss_it = signature_shares.iterator();
    while (ss_it.next()) |entry| {
        const identifier = entry.key_ptr.*;
        const signature_share = entry.value_ptr.*;
        const verifying_share = pubkeys.verifying_shares.get(identifier) orelse {
            try all_culprits.append(std.heap.page_allocator, identifier);
            if (cheater_detection == .first_cheater) break;
            continue;
        };
        const lambda_i = try keys.computeLagrangeCoefficient(identifiers, identifier);
        const commitment = signing_package.signingCommitment(identifier) orelse continue;
        const binding_factor = binding_factor_list.get(identifier) orelse continue;
        const R_share = commitment.toGroupCommitmentShare(binding_factor);
        const result = signature_share.verify(identifier, &round1.GroupCommitmentShare.fromElement(R_share), &verifying_share, lambda_i, challenge);
        if (result) |_| {} else |_| {
            try all_culprits.append(std.heap.page_allocator, identifier);
            if (cheater_detection == .first_cheater) break;
        }
    }
    if (all_culprits.items.len > 0) {
        return FrostError.InvalidSignatureShare;
    }
    return FrostError.InvalidSignature;
}

/// Verify a single signature share against the signing package without
/// aggregating. Useful for pre-aggregation checks.
pub fn verifySignatureShare(
    identifier: Identifier,
    verifying_share: *const keys.VerifyingShare,
    signature_share: *const round2.SignatureShare,
    signing_package: *const round2.SigningPackage,
    verifying_key: *const keys.VerifyingKey,
) !void {
    var binding_factor_list = try round2.computeBindingFactorList(signing_package, verifying_key, std.heap.page_allocator);
    defer binding_factor_list.deinit();
    const group_commitment = try round2.computeGroupCommitment(signing_package, &binding_factor_list);
    const challenge = try keys.challenge(&group_commitment, verifying_key, signing_package.message);
    const identifiers = try round2.participatingIdentifiers(signing_package, std.heap.page_allocator);
    defer std.heap.page_allocator.free(identifiers);
    const lambda_i = try keys.computeLagrangeCoefficient(identifiers, identifier);
    const commitment = signing_package.signingCommitment(identifier) orelse return FrostError.MissingCommitment;
    const binding_factor = binding_factor_list.get(identifier) orelse return FrostError.UnknownIdentifier;
    const R_share = commitment.toGroupCommitmentShare(binding_factor);
    try signature_share.verify(identifier, &round1.GroupCommitmentShare.fromElement(R_share), verifying_share, lambda_i, challenge);
}
