//! FROST Round 1: nonce generation and commitments
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const cs = @import("ciphersuite.zig");

/// A signing nonce (secret scalar).
pub const Nonce = struct {
    scalar: field.Scalar,

    pub fn new(secret: *const keys.SigningShare) Nonce {
        var random_bytes: [32]u8 = undefined;
        field.randomBytes(&random_bytes);
        return nonceGenerateFromRandomBytes(secret, random_bytes);
    }

    pub fn nonceGenerateFromRandomBytes(secret: *const keys.SigningShare, random_bytes: [32]u8) Nonce {
        const secret_enc = secret.serialize();
        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &random_bytes);
        @memcpy(input[32..64], &secret_enc);
        const scalar = cs.H3(&input);
        return Nonce{ .scalar = scalar };
    }

    pub fn toScalar(self: Nonce) field.Scalar {
        return self.scalar;
    }

    pub fn serialize(self: Nonce) [32]u8 {
        return field.scalarSerialize(self.scalar);
    }

    pub fn deserialize(bytes: [32]u8) !Nonce {
        const s = try field.scalarDeserialize(bytes);
        return Nonce{ .scalar = s };
    }
};

/// A commitment to a signing nonce (group element).
pub const NonceCommitment = struct {
    element: group.Element,

    pub fn fromElement(element: group.Element) NonceCommitment {
        return NonceCommitment{ .element = element };
    }

    pub fn value(self: NonceCommitment) group.Element {
        return self.element;
    }

    pub fn fromNonce(nonce: *const Nonce) NonceCommitment {
        return NonceCommitment{ .element = group.elementScalarBaseMul(nonce.scalar) };
    }

    pub fn serialize(self: NonceCommitment) ![33]u8 {
        return group.elementSerialize(self.element);
    }

    pub fn deserialize(bytes: [33]u8) !NonceCommitment {
        const e = try group.elementDeserialize(bytes);
        return NonceCommitment{ .element = e };
    }
};

/// Hiding and binding nonces with precomputed commitments.
pub const SigningNonces = struct {
    hiding: Nonce,
    binding: Nonce,
    commitments: SigningCommitments,

    pub fn new(secret: *const keys.SigningShare) SigningNonces {
        const hiding = Nonce.new(secret);
        const binding = Nonce.new(secret);
        return fromNonces(hiding, binding);
    }

    pub fn fromNonces(hiding: Nonce, binding: Nonce) SigningNonces {
        const hiding_commitment = NonceCommitment.fromNonce(&hiding);
        const binding_commitment = NonceCommitment.fromNonce(&binding);
        const commitments = SigningCommitments.new(hiding_commitment, binding_commitment);
        return SigningNonces{
            .hiding = hiding,
            .binding = binding,
            .commitments = commitments,
        };
    }
};

/// Published commitments for Round 1.
pub const SigningCommitments = struct {
    hiding: NonceCommitment,
    binding: NonceCommitment,

    pub fn new(hiding: NonceCommitment, binding: NonceCommitment) SigningCommitments {
        return SigningCommitments{ .hiding = hiding, .binding = binding };
    }

    pub fn toGroupCommitmentShare(self: SigningCommitments, binding_factor: field.Scalar) group.Element {
        const binding_term = group.elementScalarMul(self.binding.value(), binding_factor);
        return group.elementAdd(self.hiding.value(), binding_term);
    }
};

/// One signer's share of the group commitment.
pub const GroupCommitmentShare = struct {
    element: group.Element,

    pub fn fromElement(element: group.Element) GroupCommitmentShare {
        return GroupCommitmentShare{ .element = element };
    }

    pub fn toElement(self: GroupCommitmentShare) group.Element {
        return self.element;
    }
};

/// Encode group commitments list for hashing.
pub fn encodeGroupCommitments(signing_commitments: std.AutoHashMap(Identifier, SigningCommitments)) ![32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var it = signing_commitments.iterator();
    while (it.next()) |entry| {
        const id_bytes = entry.key_ptr.*.serialize();
        hasher.update(&id_bytes);
        const hiding_bytes = try entry.value_ptr.*.hiding.serialize();
        hasher.update(&hiding_bytes);
        const binding_bytes = try entry.value_ptr.*.binding.serialize();
        hasher.update(&binding_bytes);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Generate one nonce/commitment pair (standard 2-round FROST).
pub fn commit(secret: *const keys.SigningShare) struct { SigningNonces, SigningCommitments } {
    const nonces = SigningNonces.new(secret);
    return .{ nonces, nonces.commitments };
}

/// Preprocess: generate multiple nonce/commitment pairs.
pub fn preprocess(num_nonces: u8, secret: *const keys.SigningShare) struct { []SigningNonces, []SigningCommitments } {
    var nonces = std.heap.page_allocator.alloc(SigningNonces, num_nonces) catch return .{ &[_]SigningNonces{}, &[_]SigningCommitments{} };
    var commitments = std.heap.page_allocator.alloc(SigningCommitments, num_nonces) catch return .{ &[_]SigningNonces{}, &[_]SigningCommitments{} };
    for (0..num_nonces) |i| {
        const n = SigningNonces.new(secret);
        nonces[i] = n;
        commitments[i] = n.commitments;
    }
    return .{ nonces, commitments };
}
