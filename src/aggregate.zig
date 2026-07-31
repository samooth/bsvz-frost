//! FROST signature aggregation and verification
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const round1 = @import("round1.zig");
const round2 = @import("round2.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const Signature = @import("signature.zig").Signature;

pub const CheaterDetection = enum {
    disabled,
    first_cheater,
    all_cheaters,
};

/// Aggregate signature shares into final Schnorr signature.
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
    // Check all identifiers present
    var sc_it = signing_package.signing_commitments.iterator();
    while (sc_it.next()) |entry| {
        if (!signature_shares.contains(entry.key_ptr.*)) return FrostError.UnknownIdentifier;
        if (cheater_detection != .disabled) {
            if (!pubkeys.verifying_shares.contains(entry.key_ptr.*)) return FrostError.UnknownIdentifier;
        }
    }
    var binding_factor_list = try round2.computeBindingFactorList(signing_package, &pubkeys.verifying_key, std.heap.page_allocator);
    defer binding_factor_list.deinit();
    const group_commitment = try round2.computeGroupCommitment(signing_package, binding_factor_list);
    // Sum signature shares
    var z = field.scalarZero();
    var ss_it = signature_shares.iterator();
    while (ss_it.next()) |entry| {
        z = field.scalarAdd(z, entry.value_ptr.*.toScalar());
    }
    const signature = Signature{ .R = group_commitment, .z = z };
    // Verify aggregate signature
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

/// Simple aggregate without cheater detection.
pub fn aggregateSimple(
    signing_package: *const round2.SigningPackage,
    signature_shares: std.AutoHashMap(Identifier, round2.SignatureShare),
    pubkeys: *const keys.PublicKeyPackage,
) !Signature {
    return aggregate(signing_package, signature_shares, pubkeys, .disabled);
}

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

/// Verify a single signature share.
pub fn verifySignatureShare(
    identifier: Identifier,
    verifying_share: *const keys.VerifyingShare,
    signature_share: *const round2.SignatureShare,
    signing_package: *const round2.SigningPackage,
    verifying_key: *const keys.VerifyingKey,
) !void {
    var binding_factor_list = try round2.computeBindingFactorList(signing_package, verifying_key, std.heap.page_allocator);
    defer binding_factor_list.deinit();
    const group_commitment = try round2.computeGroupCommitment(signing_package, binding_factor_list);
    const challenge = try keys.challenge(&group_commitment, verifying_key, signing_package.message);
    const identifiers = try round2.participatingIdentifiers(signing_package, std.heap.page_allocator);
    defer std.heap.page_allocator.free(identifiers);
    const lambda_i = try keys.computeLagrangeCoefficient(identifiers, identifier);
    const commitment = signing_package.signingCommitment(identifier) orelse return FrostError.MissingCommitment;
    const binding_factor = binding_factor_list.get(identifier) orelse return FrostError.UnknownIdentifier;
    const R_share = commitment.toGroupCommitmentShare(binding_factor);
    try signature_share.verify(identifier, &round1.GroupCommitmentShare.fromElement(R_share), verifying_share, lambda_i, challenge);
}
