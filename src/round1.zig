//! FROST Round 1: nonce generation and commitments.
//!
//! Each participant samples a fresh hiding/binding nonce pair from its secret
//! share, derives public commitments (g^nonce), and publishes only the
//! commitments. Nonces are single-use: reuse across sessions leaks the share.
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const cs = @import("ciphersuite.zig");

/// A signing nonce (secret scalar). Must be used for exactly one session.
pub const Nonce = struct {
    /// The secret nonce scalar.
    scalar: field.Scalar,

    /// Derive a fresh nonce from random bytes + the signing share (H3).
    pub fn new(secret: *const keys.SigningShare) Nonce {
        var random_bytes: [32]u8 = undefined;
        field.randomBytes(&random_bytes);
        return nonceGenerateFromRandomBytes(secret, random_bytes);
    }

    /// Deterministic nonce from explicit randomness (used by test vectors).
    pub fn nonceGenerateFromRandomBytes(secret: *const keys.SigningShare, random_bytes: [32]u8) Nonce {
        const secret_enc = secret.serialize();
        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &random_bytes);
        @memcpy(input[32..64], &secret_enc);
        const scalar = cs.H3(&input);
        return Nonce{ .scalar = scalar };
    }

    /// Unwrap the raw scalar.
    pub fn toScalar(self: Nonce) field.Scalar {
        return self.scalar;
    }

    /// Serialize to 32 big-endian bytes.
    pub fn serialize(self: Nonce) [32]u8 {
        return field.scalarSerialize(self.scalar);
    }

    /// Parse 32 bytes; rejects non-canonical encodings.
    pub fn deserialize(bytes: [32]u8) !Nonce {
        const s = try field.scalarDeserialize(bytes);
        return Nonce{ .scalar = s };
    }
};

/// A commitment to a signing nonce (group element g^nonce).
pub const NonceCommitment = struct {
    /// The curve point commitment.
    element: group.Element,

    /// Wrap an existing curve point.
    pub fn fromElement(element: group.Element) NonceCommitment {
        return NonceCommitment{ .element = element };
    }

    /// Unwrap the raw curve point.
    pub fn value(self: NonceCommitment) group.Element {
        return self.element;
    }

    /// Derive the commitment g^nonce from a secret nonce.
    pub fn fromNonce(nonce: *const Nonce) NonceCommitment {
        return NonceCommitment{ .element = group.elementScalarBaseMul(nonce.scalar) };
    }

    /// Compressed SEC1 serialization (33 bytes).
    pub fn serialize(self: NonceCommitment) ![33]u8 {
        return group.elementSerialize(self.element);
    }

    /// Parse a compressed SEC1 point (33 bytes).
    pub fn deserialize(bytes: [33]u8) !NonceCommitment {
        const e = try group.elementDeserialize(bytes);
        return NonceCommitment{ .element = e };
    }
};

/// Hiding and binding nonces with precomputed commitments. The nonces stay
/// local; only `commitments` is published.
pub const SigningNonces = struct {
    /// Hiding nonce (combined with hiding commitment in the group commit).
    hiding: Nonce,
    /// Binding nonce (scaled by the binding factor).
    binding: Nonce,
    /// Public commitments derived from the two nonces.
    commitments: SigningCommitments,

    /// Sample a fresh nonce pair from the signing share.
    pub fn new(secret: *const keys.SigningShare) SigningNonces {
        const hiding = Nonce.new(secret);
        const binding = Nonce.new(secret);
        return fromNonces(hiding, binding);
    }

    /// Build from explicit nonces (derives the commitments).
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

    /// Wire format (64 bytes): hiding_nonce(32) ‖ binding_nonce(32).
    /// Commitments are re-derived on load via g^nonce.
    pub fn serialize(self: SigningNonces) [64]u8 {
        var out: [64]u8 = undefined;
        @memcpy(out[0..32], &self.hiding.serialize());
        @memcpy(out[32..64], &self.binding.serialize());
        return out;
    }

    /// Parse the 64-byte wire format and re-derive commitments.
    pub fn deserialize(bytes: [64]u8) !SigningNonces {
        return fromNonces(
            try Nonce.deserialize(bytes[0..32].*),
            try Nonce.deserialize(bytes[32..64].*),
        );
    }
};

/// Published commitments for Round 1 (sent to the coordinator).
pub const SigningCommitments = struct {
    /// Commitment to the hiding nonce.
    hiding: NonceCommitment,
    /// Commitment to the binding nonce.
    binding: NonceCommitment,

    /// Wrap the two commitments.
    pub fn new(hiding: NonceCommitment, binding: NonceCommitment) SigningCommitments {
        return SigningCommitments{ .hiding = hiding, .binding = binding };
    }

    /// Wire format (66 bytes): hiding(33) ‖ binding(33).
    pub fn serialize(self: SigningCommitments) ![66]u8 {
        var out: [66]u8 = undefined;
        @memcpy(out[0..33], &(try self.hiding.serialize()));
        @memcpy(out[33..66], &(try self.binding.serialize()));
        return out;
    }

    /// Parse the 66-byte wire format.
    pub fn deserialize(bytes: [66]u8) !SigningCommitments {
        return SigningCommitments{
            .hiding = try NonceCommitment.deserialize(bytes[0..33].*),
            .binding = try NonceCommitment.deserialize(bytes[33..66].*),
        };
    }

    /// One signer's contribution to the group commitment:
    /// R_i = hiding + binding · binding_factor.
    pub fn toGroupCommitmentShare(self: SigningCommitments, binding_factor: field.Scalar) group.Element {
        const binding_term = group.elementScalarMul(self.binding.value(), binding_factor);
        return group.elementAdd(self.hiding.value(), binding_term);
    }
};

/// One signer's share of the group commitment (R_i).
pub const GroupCommitmentShare = struct {
    /// The curve point R_i.
    element: group.Element,

    /// Wrap an existing curve point.
    pub fn fromElement(element: group.Element) GroupCommitmentShare {
        return GroupCommitmentShare{ .element = element };
    }

    /// Unwrap the raw curve point.
    pub fn toElement(self: GroupCommitmentShare) group.Element {
        return self.element;
    }
};

/// Encode the list of group signing commitments as raw bytes.
///
/// Implements `encode_group_commitments` from the spec: for each participant
/// (in ascending identifier order) the serialized identifier followed by the
/// serialized hiding and binding commitments. The caller hashes this with H5.
///
/// `signing_commitments` must contain the map of participant identifiers to
/// the signing commitments they issued.
pub fn encodeGroupCommitments(
    signing_commitments: std.AutoHashMap(Identifier, SigningCommitments),
    allocator: std.mem.Allocator,
) ![]u8 {
    var ids = std.ArrayList(Identifier).empty;
    defer ids.deinit(allocator);
    var it = signing_commitments.keyIterator();
    while (it.next()) |id| {
        try ids.append(allocator, id.*);
    }
    std.mem.sort(Identifier, ids.items, {}, idLessThan);

    var bytes = std.ArrayList(u8).empty;
    errdefer bytes.deinit(allocator);
    for (ids.items) |id| {
        const comm = signing_commitments.get(id) orelse continue;
        const id_bytes = id.serialize();
        try bytes.appendSlice(allocator, &id_bytes);
        const hiding_bytes = try comm.hiding.serialize();
        try bytes.appendSlice(allocator, &hiding_bytes);
        const binding_bytes = try comm.binding.serialize();
        try bytes.appendSlice(allocator, &binding_bytes);
    }
    return bytes.toOwnedSlice(allocator);
}

/// Sort helper: ascending order on identifier bytes.
fn idLessThan(_: void, a: Identifier, b: Identifier) bool {
    return a.lessThan(b);
}

/// Generate one nonce/commitment pair (standard 2-round FROST). Returns the
/// secret nonces and the public commitments to publish.
pub fn commit(secret: *const keys.SigningShare) struct { SigningNonces, SigningCommitments } {
    const nonces = SigningNonces.new(secret);
    return .{ nonces, nonces.commitments };
}

/// Preprocess: generate `num_nonces` independent nonce/commitment pairs for
/// future sessions (pre-signing).
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
