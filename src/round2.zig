//! FROST Round 2: signature share generation
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const round1 = @import("round1.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const cs = @import("ciphersuite.zig");
const Signature = @import("signature.zig").Signature;

/// A participant's signature share.
pub const SignatureShare = struct {
    share: field.Scalar,

    pub fn new(scalar: field.Scalar) SignatureShare {
        return SignatureShare{ .share = scalar };
    }

    pub fn toScalar(self: SignatureShare) field.Scalar {
        return self.share;
    }

    pub fn serialize(self: SignatureShare) [32]u8 {
        return field.scalarSerialize(self.share);
    }

    pub fn deserialize(bytes: [32]u8) !SignatureShare {
        const s = try field.scalarDeserialize(bytes);
        return SignatureShare{ .share = s };
    }

    pub fn verify(
        self: SignatureShare,
        _: Identifier,
        group_commitment_share: *const round1.GroupCommitmentShare,
        verifying_share: *const keys.VerifyingShare,
        lambda_i: field.Scalar,
        challenge: field.Scalar,
    ) !void {
        const lhs = group.elementScalarBaseMul(self.share);
        const rhs1 = group_commitment_share.toElement();
        const rhs2 = group.elementScalarMul(verifying_share.toElement(), field.scalarMul(challenge, lambda_i));
        const rhs = group.elementAdd(rhs1, rhs2);
        if (!group.elementEql(lhs, rhs)) {
            return FrostError.InvalidSignatureShare;
        }
    }
};

/// SigningPackage: coordinator distributes this to participants.
pub const SigningPackage = struct {
    signing_commitments: std.AutoHashMap(Identifier, round1.SigningCommitments),
    message: []const u8,

    pub fn new(signing_commitments: std.AutoHashMap(Identifier, round1.SigningCommitments), message: []const u8) SigningPackage {
        return SigningPackage{ .signing_commitments = signing_commitments, .message = message };
    }

    pub fn signingCommitment(self: SigningPackage, identifier: Identifier) ?round1.SigningCommitments {
        return self.signing_commitments.get(identifier);
    }

    /// Compute the raw binding factor preimages (inputs to H1) for each
    /// participant, following `SigningPackage::binding_factor_preimages` in
    /// the reference implementation:
    ///
    ///     serialize(VK) || H4(msg) || H5(encoded_commitments) || serialize(id)
    pub fn bindingFactorPreimages(
        self: SigningPackage,
        verifying_key: *const keys.VerifyingKey,
        allocator: std.mem.Allocator,
    ) !std.AutoHashMap(Identifier, []u8) {
        var result = std.AutoHashMap(Identifier, []u8).init(allocator);
        const vk_bytes = try verifying_key.serialize();
        const msg_hash = cs.H4(self.message);
        const encoded = try round1.encodeGroupCommitments(self.signing_commitments, allocator);
        defer allocator.free(encoded);
        const com_hash = cs.H5(encoded);
        var it = self.signing_commitments.iterator();
        while (it.next()) |entry| {
            var preimage = std.ArrayList(u8).empty;
            errdefer preimage.deinit(allocator);
            try preimage.appendSlice(allocator, &vk_bytes);
            try preimage.appendSlice(allocator, &msg_hash);
            try preimage.appendSlice(allocator, &com_hash);
            const id_bytes = entry.key_ptr.*.serialize();
            try preimage.appendSlice(allocator, &id_bytes);
            try result.put(entry.key_ptr.*, try preimage.toOwnedSlice(allocator));
        }
        return result;
    }
};

/// Compute binding factor list.
pub fn computeBindingFactorList(
    signing_package: *const SigningPackage,
    verifying_key: *const keys.VerifyingKey,
    allocator: std.mem.Allocator,
) !std.AutoHashMap(Identifier, field.Scalar) {
    var result = std.AutoHashMap(Identifier, field.Scalar).init(allocator);
    var preimages = try signing_package.bindingFactorPreimages(verifying_key, allocator);
    defer {
        var pit = preimages.valueIterator();
        while (pit.next()) |p| allocator.free(p.*);
        preimages.deinit();
    }
    var it = preimages.iterator();
    while (it.next()) |entry| {
        const bf = cs.H1(entry.value_ptr.*);
        try result.put(entry.key_ptr.*, bf);
    }
    return result;
}

/// Compute group commitment.
pub fn computeGroupCommitment(signing_package: *const SigningPackage, binding_factor_list: std.AutoHashMap(Identifier, field.Scalar)) !group.Element {
    var group_commitment = group.identity();
    var it = signing_package.signing_commitments.iterator();
    while (it.next()) |entry| {
        const commitment = entry.value_ptr.*;
        if (group.elementIsIdentity(commitment.hiding.value()) or group.elementIsIdentity(commitment.binding.value())) {
            return FrostError.IdentityCommitment;
        }
        const binding_factor = binding_factor_list.get(entry.key_ptr.*) orelse return FrostError.UnknownIdentifier;
        group_commitment = group.elementAdd(group_commitment, commitment.hiding.value());
        const binding_term = group.elementScalarMul(commitment.binding.value(), binding_factor);
        group_commitment = group.elementAdd(group_commitment, binding_term);
    }
    return group_commitment;
}

/// Compute signature share.
fn computeSignatureShare(
    signer_nonces: *const round1.SigningNonces,
    binding_factor: field.Scalar,
    lambda_i: field.Scalar,
    key_package: *const keys.KeyPackage,
    challenge: field.Scalar,
) SignatureShare {
    const z_share = field.scalarAdd(
        field.scalarAdd(
            signer_nonces.hiding.toScalar(),
            field.scalarMul(signer_nonces.binding.toScalar(), binding_factor),
        ),
        field.scalarMul(
            field.scalarMul(lambda_i, key_package.signing_share.toScalar()),
            challenge,
        ),
    );
    return SignatureShare.new(z_share);
}

/// Collect the identifiers participating in a signing session.
pub fn participatingIdentifiers(signing_package: *const SigningPackage, allocator: std.mem.Allocator) ![]Identifier {
    var list = std.ArrayList(Identifier).empty;
    defer list.deinit(allocator);
    var it = signing_package.signing_commitments.keyIterator();
    while (it.next()) |id| {
        try list.append(allocator, id.*);
    }
    return list.toOwnedSlice(allocator);
}

/// Round 2: sign.
pub fn sign(
    signing_package: *const SigningPackage,
    signer_nonces: *const round1.SigningNonces,
    key_package: *const keys.KeyPackage,
) !SignatureShare {
    if (signing_package.signing_commitments.count() < key_package.min_signers) {
        return FrostError.IncorrectNumberOfCommitments;
    }
    const commitment = signing_package.signingCommitment(key_package.identifier) orelse return FrostError.MissingCommitment;
    if (!std.meta.eql(signer_nonces.commitments, commitment)) {
        return FrostError.InvalidCommitment;
    }
    var binding_factor_list = try computeBindingFactorList(signing_package, &key_package.verifying_key, std.heap.page_allocator);
    defer binding_factor_list.deinit();
    const binding_factor = binding_factor_list.get(key_package.identifier) orelse return FrostError.UnknownIdentifier;
    const group_commitment = try computeGroupCommitment(signing_package, binding_factor_list);
    const identifiers = try participatingIdentifiers(signing_package, std.heap.page_allocator);
    defer std.heap.page_allocator.free(identifiers);
    const lambda_i = try keys.computeLagrangeCoefficient(identifiers, key_package.identifier);
    const challenge = try keys.challenge(&group_commitment, &key_package.verifying_key, signing_package.message);
    return computeSignatureShare(signer_nonces, binding_factor, lambda_i, key_package, challenge);
}
