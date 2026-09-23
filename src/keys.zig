//! FROST key generation, key shares, and key packages.
//!
//! Covers trusted-dealer keygen (split/reconstruct), the KeyPackage /
//! PublicKeyPackage wire types used across the protocol, and the Lagrange
//! interpolation helpers used for threshold reconstruction and signing.
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const Signature = @import("signature.zig").Signature;
const field = @import("field.zig");
const group = @import("group.zig");
const cs = @import("ciphersuite.zig");

/// Re-export: scalar field element type.
pub const Scalar = field.Scalar;
/// Re-export: curve point type.
pub const Element = group.Element;

/// A secret scalar value representing a signer's share of the group secret.
pub const SigningShare = struct {
    /// The raw scalar share (32-byte big-endian on the wire).
    scalar: Scalar,

    /// Wrap an existing scalar as a signing share.
    pub fn fromScalar(scalar: Scalar) SigningShare {
        return SigningShare{ .scalar = scalar };
    }

    /// Unwrap the raw scalar.
    pub fn toScalar(self: SigningShare) Scalar {
        return self.scalar;
    }

    /// Serialize to 32 big-endian bytes.
    pub fn serialize(self: SigningShare) [32]u8 {
        return field.scalarSerialize(self.scalar);
    }

    /// Parse 32 bytes; rejects non-canonical encodings.
    pub fn deserialize(bytes: [32]u8) !SigningShare {
        const s = try field.scalarDeserialize(bytes);
        return SigningShare{ .scalar = s };
    }
};

/// A public group element representing a single signer's verification share.
pub const VerifyingShare = struct {
    /// The curve point Y_i = g^{x_i}.
    element: Element,

    /// Wrap an existing curve point.
    pub fn fromElement(element: Element) VerifyingShare {
        return VerifyingShare{ .element = element };
    }

    /// Unwrap the raw curve point.
    pub fn toElement(self: VerifyingShare) Element {
        return self.element;
    }

    /// Compressed SEC1 serialization (33 bytes).
    pub fn serialize(self: VerifyingShare) ![33]u8 {
        return group.elementSerialize(self.element);
    }

    /// Parse a compressed SEC1 point (33 bytes).
    pub fn deserialize(bytes: [33]u8) !VerifyingShare {
        const e = try group.elementDeserialize(bytes);
        return VerifyingShare{ .element = e };
    }

    /// Derive Y_i = g^{x_i} directly from a secret share.
    pub fn fromSigningShare(signing_share: SigningShare) VerifyingShare {
        const element = group.elementScalarBaseMul(signing_share.scalar);
        return VerifyingShare{ .element = element };
    }

    /// Compute the public verification share Y_i = ∏_k φ_k^{i^k} from a group
    /// commitment (the sum of all participants' DKG commitments).
    pub fn fromCommitment(identifier: Identifier, commitment: VerifiableSecretSharingCommitment) VerifyingShare {
        return VerifyingShare{ .element = evaluateVss(identifier, commitment) };
    }
};

/// Commitment to one coefficient of the secret polynomial (φ_k = g^{a_k}).
pub const CoefficientCommitment = struct {
    /// The curve point commitment to a single coefficient.
    element: Element,

    /// Wrap an existing curve point as a coefficient commitment.
    pub fn fromElement(element: Element) CoefficientCommitment {
        return CoefficientCommitment{ .element = element };
    }

    /// Unwrap the raw curve point.
    pub fn value(self: CoefficientCommitment) Element {
        return self.element;
    }

    /// Compressed SEC1 serialization (33 bytes).
    pub fn serialize(self: CoefficientCommitment) ![33]u8 {
        return group.elementSerialize(self.element);
    }

    /// Parse a compressed SEC1 point (33 bytes).
    pub fn deserialize(bytes: [33]u8) !CoefficientCommitment {
        const e = try group.elementDeserialize(bytes);
        return CoefficientCommitment{ .element = e };
    }
};

/// Verifiable secret sharing commitment: the list of coefficient commitments
/// φ_0 … φ_{t-1} that define a degree-(t-1) polynomial. The number of
/// coefficients equals min_signers (threshold).
pub const VerifiableSecretSharingCommitment = struct {
    /// Coefficient commitments, length == min_signers.
    coefficients: []const CoefficientCommitment,

    /// Wrap a coefficient slice as a commitment (borrowed, not owned).
    pub fn init(coefficients: []const CoefficientCommitment) VerifiableSecretSharingCommitment {
        return VerifiableSecretSharingCommitment{ .coefficients = coefficients };
    }

    /// Threshold implied by the commitment length.
    pub fn minSigners(self: VerifiableSecretSharingCommitment) u16 {
        return @intCast(self.coefficients.len);
    }

    /// The group verifying key φ_0 (first coefficient commitment).
    pub fn verifyingKey(self: VerifiableSecretSharingCommitment) !VerifyingKey {
        if (self.coefficients.len == 0) return FrostError.MissingCommitment;
        return VerifyingKey.fromElement(self.coefficients[0].value());
    }
};

/// A secret share generated by a trusted dealer: identifier, signing share,
/// and the VSS commitment used to verify it.
pub const SecretShare = struct {
    /// Participant identifier.
    identifier: Identifier,
    /// This participant's signing share x_i.
    signing_share: SigningShare,
    /// The dealer's VSS commitment (for share verification).
    commitment: VerifiableSecretSharingCommitment,

    /// Verify g^{share} == evaluateVss(id, commitment). Returns the derived
    /// verifying share and group verifying key on success.
    pub fn verify(self: SecretShare) !struct { VerifyingShare, VerifyingKey } {
        const f_result = group.elementScalarBaseMul(self.signing_share.toScalar());
        const result = evaluateVss(self.identifier, self.commitment);
        if (!group.elementEql(f_result, result)) {
            return FrostError.InvalidSecretShare;
        }
        const verifying_share = VerifyingShare.fromElement(result);
        const verifying_key = try self.commitment.verifyingKey();
        return .{ verifying_share, verifying_key };
    }

    /// Wire format: id(32) ‖ share(32) ‖ coeff_count(2, BE) ‖ coeff_count × 33.
    pub fn serialize(self: SecretShare, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(allocator);
        try buf.appendSlice(allocator, &self.identifier.serialize());
        try buf.appendSlice(allocator, &self.signing_share.serialize());
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, @intCast(self.commitment.coefficients.len), .big);
        try buf.appendSlice(allocator, &tmp);
        for (self.commitment.coefficients) |coeff| {
            try buf.appendSlice(allocator, &(try coeff.serialize()));
        }
        return buf.toOwnedSlice(allocator);
    }

    /// Parse the wire format produced by serialize; rejects truncated input.
    pub fn deserialize(allocator: std.mem.Allocator, bytes: []const u8) !SecretShare {
        if (bytes.len < 66) return FrostError.DeserializationFailed;
        const id = try Identifier.deserialize(bytes[0..32].*);
        const share = try SigningShare.deserialize(bytes[32..64].*);
        const coeff_count = std.mem.readInt(u16, bytes[64..66], .big);
        if (bytes.len < 66 + coeff_count * 33) return FrostError.DeserializationFailed;
        const coeffs = try allocator.alloc(CoefficientCommitment, coeff_count);
        errdefer allocator.free(@constCast(coeffs));
        const off: usize = 66;
        for (coeffs, 0..) |*c, i| {
            const s = bytes.ptr[off + i * 33 .. off + i * 33 + 33];
            var tmp: [33]u8 = undefined;
            @memcpy(tmp[0..], s);
            c.* = try CoefficientCommitment.deserialize(tmp);
        }
        return SecretShare{
            .identifier = id,
            .signing_share = share,
            .commitment = VerifiableSecretSharingCommitment.init(coeffs),
        };
    }
};

/// A participant's complete FROST key material: identifier, secret share,
/// verifying share, group verifying key, and threshold.
pub const KeyPackage = struct {
    /// Participant identifier.
    identifier: Identifier,
    /// Long-lived signing share (secret).
    signing_share: SigningShare,
    /// Public verification share Y_i.
    verifying_share: VerifyingShare,
    /// Group verifying key (same for all participants).
    verifying_key: VerifyingKey,
    /// Threshold t (min_signers).
    min_signers: u16,

    /// Build a KeyPackage from a SecretShare, verifying the share first.
    pub fn fromSecretShare(secret_share: SecretShare) !KeyPackage {
        const vs, const vk = try secret_share.verify();
        return KeyPackage{
            .identifier = secret_share.identifier,
            .signing_share = secret_share.signing_share,
            .verifying_share = vs,
            .verifying_key = vk,
            .min_signers = secret_share.commitment.minSigners(),
        };
    }

    /// Wire format (132 bytes): id(32) ‖ share(32) ‖ vshare(33) ‖ vk(33) ‖ min_signers(2, BE).
    pub fn serialize(self: KeyPackage) ![132]u8 {
        var out: [132]u8 = undefined;
        @memcpy(out[0..32], &self.identifier.serialize());
        @memcpy(out[32..64], &self.signing_share.serialize());
        @memcpy(out[64..97], &(try self.verifying_share.serialize()));
        @memcpy(out[97..130], &(try self.verifying_key.serialize()));
        std.mem.writeInt(u16, out[130..132], self.min_signers, .big);
        return out;
    }

    /// Parse the fixed 132-byte wire format produced by serialize.
    pub fn deserialize(bytes: [132]u8) !KeyPackage {
        const id = try Identifier.deserialize(bytes[0..32].*);
        const share = try SigningShare.deserialize(bytes[32..64].*);
        const vshare = try VerifyingShare.deserialize(bytes[64..97].*);
        const vk = try VerifyingKey.deserialize(bytes[97..130].*);
        const min = std.mem.readInt(u16, bytes[130..132], .big);
        return KeyPackage{
            .identifier = id,
            .signing_share = share,
            .verifying_share = vshare,
            .verifying_key = vk,
            .min_signers = min,
        };
    }
};

/// Public data shared among participants: the group verifying key, every
/// participant's verifying share, and the threshold.
pub const PublicKeyPackage = struct {
    /// Map of participant identifier → verifying share.
    verifying_shares: std.AutoHashMap(Identifier, VerifyingShare),
    /// Group verifying key.
    verifying_key: VerifyingKey,
    /// Threshold t, if known (null when not applicable).
    min_signers: ?u16,

    /// Number of verifying shares (= max signers).
    pub fn maxSigners(self: PublicKeyPackage) u16 {
        return @intCast(self.verifying_shares.count());
    }

    /// Build the public key package from the DKG commitments of all
    /// participants (each mapped by their identifier). The group verifying
    /// key is the sum of every participant's first commitment, and each
    /// verifying share is derived by evaluating the summed commitment.
    pub fn fromDkgCommitments(
        allocator: std.mem.Allocator,
        commitments: *const std.AutoHashMap(Identifier, *const VerifiableSecretSharingCommitment),
    ) !PublicKeyPackage {
        var ids = std.ArrayList(Identifier).empty;
        defer ids.deinit(allocator);
        var it = commitments.keyIterator();
        while (it.next()) |id| {
            try ids.append(allocator, id.*);
        }
        std.mem.sort(Identifier, ids.items, {}, idLessThan);

        var commit_list = std.ArrayList(VerifiableSecretSharingCommitment).empty;
        defer commit_list.deinit(allocator);
        for (ids.items) |id| {
            try commit_list.append(allocator, commitments.get(id).?.*);
        }
        const group_commitment = try sumCommitments(commit_list.items);
        defer std.heap.page_allocator.free(group_commitment.coefficients);

        var verifying_shares = std.AutoHashMap(Identifier, VerifyingShare).init(allocator);
        errdefer verifying_shares.deinit();
        for (ids.items) |id| {
            try verifying_shares.put(id, VerifyingShare.fromCommitment(id, group_commitment));
        }
        return PublicKeyPackage{
            .verifying_shares = verifying_shares,
            .verifying_key = try group_commitment.verifyingKey(),
            .min_signers = group_commitment.minSigners(),
        };
    }

    /// Free the verifying-shares map.
    pub fn deinit(self: *PublicKeyPackage) void {
        self.verifying_shares.deinit();
    }

    /// Wire format: vk(33) ‖ min(2, 0=null) ‖ count(2) ‖ count × (id(32) ‖ vshare(33)).
    /// Entries are sorted by ascending identifier bytes.
    pub fn serialize(self: PublicKeyPackage, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(allocator);
        try buf.appendSlice(allocator, &(try self.verifying_key.serialize()));
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, self.min_signers orelse 0, .big);
        try buf.appendSlice(allocator, &tmp);
        std.mem.writeInt(u16, &tmp, @intCast(self.verifying_shares.count()), .big);
        try buf.appendSlice(allocator, &tmp);
        var ids = std.ArrayList(Identifier).empty;
        defer ids.deinit(allocator);
        var it = self.verifying_shares.keyIterator();
        while (it.next()) |id| try ids.append(allocator, id.*);
        std.mem.sort(Identifier, ids.items, {}, idLessThan);
        for (ids.items) |id| {
            try buf.appendSlice(allocator, &id.serialize());
            try buf.appendSlice(allocator, &(try self.verifying_shares.get(id).?.serialize()));
        }
        return buf.toOwnedSlice(allocator);
    }

    /// Parse the wire format produced by serialize; rejects truncated input.
    pub fn deserialize(allocator: std.mem.Allocator, bytes: []const u8) !PublicKeyPackage {
        if (bytes.len < 37) return FrostError.DeserializationFailed;
        const vk = try VerifyingKey.deserialize(bytes[0..33].*);
        const min = std.mem.readInt(u16, bytes[33..35], .big);
        const count = std.mem.readInt(u16, bytes[35..37], .big);
        if (bytes.len < 37 + count * 65) return FrostError.DeserializationFailed;
        var shares = std.AutoHashMap(Identifier, VerifyingShare).init(allocator);
        errdefer shares.deinit();
        var off: usize = 37;
        for (0..count) |_| {
            var id_tmp: [32]u8 = undefined;
            @memcpy(id_tmp[0..], bytes.ptr[off .. off + 32]);
            const id = try Identifier.deserialize(id_tmp);
            off += 32;
            var vs_tmp: [33]u8 = undefined;
            @memcpy(vs_tmp[0..], bytes.ptr[off .. off + 33]);
            const vs = try VerifyingShare.deserialize(vs_tmp);
            off += 33;
            try shares.put(id, vs);
        }
        return PublicKeyPackage{
            .verifying_shares = shares,
            .verifying_key = vk,
            .min_signers = if (min == 0) null else min,
        };
    }
};

/// Sort helper: ascending order on identifier bytes.
fn idLessThan(_: void, a: Identifier, b: Identifier) bool {
    return a.lessThan(b);
}

/// Sum the coefficient commitments from all participants into one group
/// commitment. Each coefficient position is added element-wise; all inputs
/// must have the same length.
pub fn sumCommitments(commitments: []const VerifiableSecretSharingCommitment) !VerifiableSecretSharingCommitment {
    if (commitments.len == 0) return FrostError.IncorrectNumberOfCommitments;
    const degree = commitments[0].coefficients.len;
    var summed = std.heap.page_allocator.alloc(CoefficientCommitment, degree) catch return FrostError.RandomnessError;
    for (0..degree) |k| {
        var acc = group.identity();
        for (commitments) |comm| {
            if (comm.coefficients.len != degree) return FrostError.IncorrectNumberOfCommitments;
            acc = group.elementAdd(acc, comm.coefficients[k].value());
        }
        summed[k] = CoefficientCommitment.fromElement(acc);
    }
    return VerifiableSecretSharingCommitment.init(summed);
}

/// A signing key (the group secret scalar).
pub const SigningKey = struct {
    /// The secret scalar (non-zero).
    scalar: Scalar,

    /// Generate a fresh random non-zero signing key from the CSPRNG.
    pub fn generate() SigningKey {
        var bytes: [32]u8 = undefined;
        var attempts: usize = 0;
        while (attempts < 100) : (attempts += 1) {
            field.randomBytes(&bytes);
            const s = Secp256k1.scalar.Scalar.fromBytes(bytes, .big) catch continue;
            if (!s.isZero()) return SigningKey{ .scalar = s };
        }
        return SigningKey{ .scalar = Secp256k1.scalar.Scalar.zero };
    }

    /// Wrap a scalar as a signing key; rejects the zero scalar.
    pub fn fromScalar(scalar: Scalar) !SigningKey {
        if (scalar.isZero()) return FrostError.MalformedSigningKey;
        return SigningKey{ .scalar = scalar };
    }

    /// Unwrap the raw scalar.
    pub fn toScalar(self: SigningKey) Scalar {
        return self.scalar;
    }

    /// Serialize to 32 big-endian bytes.
    pub fn serialize(self: SigningKey) [32]u8 {
        return field.scalarSerialize(self.scalar);
    }

    /// Parse 32 bytes; rejects zero and non-canonical encodings.
    pub fn deserialize(bytes: [32]u8) !SigningKey {
        const s = try field.scalarDeserialize(bytes);
        return fromScalar(s);
    }

    /// Produce a standard single-signer Schnorr signature (not threshold).
    pub fn sign(self: SigningKey, message: []const u8) !Signature {
        const public = VerifyingKey.fromSigningKey(self);
        const k = field.scalarRandom();
        const R = group.elementScalarBaseMul(k);
        const c = try challenge(&R, &public, message);
        const z = k.add(c.mul(self.scalar));
        return Signature{ .R = R, .z = z };
    }
};

/// A verifying key (the group public key point).
pub const VerifyingKey = struct {
    /// The curve point X = g^x.
    element: Element,

    /// Wrap an existing curve point.
    pub fn fromElement(element: Element) VerifyingKey {
        return VerifyingKey{ .element = element };
    }

    /// Derive X = g^x from a signing key.
    pub fn fromSigningKey(signing_key: SigningKey) VerifyingKey {
        return VerifyingKey{ .element = group.elementScalarBaseMul(signing_key.scalar) };
    }

    /// Unwrap the raw curve point.
    pub fn toElement(self: VerifyingKey) Element {
        return self.element;
    }

    /// Compressed SEC1 serialization (33 bytes).
    pub fn serialize(self: VerifyingKey) ![33]u8 {
        return group.elementSerialize(self.element);
    }

    /// Parse a compressed SEC1 point (33 bytes).
    pub fn deserialize(bytes: [33]u8) !VerifyingKey {
        const e = try group.elementDeserialize(bytes);
        return VerifyingKey{ .element = e };
    }

    /// Verify a Schnorr signature: check z·G == R + c·X where
    /// c = H2(R ‖ X ‖ msg). Returns InvalidSignature on failure.
    pub fn verify(self: VerifyingKey, message: []const u8, signature: Signature) !void {
        const zB = group.elementScalarBaseMul(signature.z);
        const cA = group.elementScalarMul(self.element, try challenge(&signature.R, &self, message));
        const check = group.elementSub(zB, group.elementAdd(cA, signature.R));
        if (!group.elementIsIdentity(check)) {
            return FrostError.InvalidSignature;
        }
    }

    /// Extract the verifying key from a VSS commitment's first coefficient.
    pub fn fromCommitment(commitment: VerifiableSecretSharingCommitment) !VerifyingKey {
        return commitment.verifyingKey();
    }
};

/// Compute the Schnorr challenge c = H2(R ‖ X ‖ msg) via the ciphersuite H2.
pub fn challenge(R: *const Element, verifying_key: *const VerifyingKey, msg: []const u8) !Scalar {
    const r_bytes = group.elementSerialize(R.*) catch @as([33]u8, @splat(0));
    const vk_bytes = group.elementSerialize(verifying_key.element) catch @as([33]u8, @splat(0));
    var preimage = std.ArrayList(u8).empty;
    defer preimage.deinit(std.heap.page_allocator);
    try preimage.appendSlice(std.heap.page_allocator, &r_bytes);
    try preimage.appendSlice(std.heap.page_allocator, &vk_bytes);
    try preimage.appendSlice(std.heap.page_allocator, msg);
    return cs.H2(preimage.items);
}

/// Evaluate the secret polynomial at `identifier` using Horner's method.
pub fn evaluatePolynomial(identifier: Identifier, coefficients: []const Scalar) Scalar {
    var value = field.scalarZero();
    const id_scalar = field.scalarDeserialize(identifier.serialize()) catch field.scalarZero();
    var i: usize = coefficients.len;
    while (i > 1) {
        i -= 1;
        value = field.scalarAdd(value, coefficients[i]);
        value = field.scalarMul(value, id_scalar);
    }
    value = field.scalarAdd(value, coefficients[0]);
    return value;
}

/// Evaluate the VSS verification equation ∏_k φ_k^{i^k} for `identifier`.
pub fn evaluateVss(identifier: Identifier, commitment: VerifiableSecretSharingCommitment) Element {
    const id_scalar = field.scalarDeserialize(identifier.serialize()) catch field.scalarZero();
    var i_to_the_k = field.scalarOne();
    var sum = group.identity();
    for (commitment.coefficients) |comm| {
        sum = group.elementAdd(sum, group.elementScalarMul(comm.value(), i_to_the_k));
        i_to_the_k = field.scalarMul(i_to_the_k, id_scalar);
    }
    return sum;
}

/// Generate `min_signers` random polynomial coefficients (a_1 … a_{t-1}).
/// The caller supplies the length; the constant term is set separately.
pub fn generateCoefficients(min_signers: u16) []Scalar {
    var coeffs = std.heap.page_allocator.alloc(Scalar, min_signers) catch return &[_]Scalar{};
    for (0..min_signers) |i| {
        coeffs[i] = field.scalarRandom();
    }
    return coeffs;
}

/// Build the full coefficient list (secret ‖ extra coefficients) and the
/// corresponding VSS commitment. Validates threshold bounds.
pub fn generateSecretPolynomial(secret: SigningKey, max_signers: u16, min_signers: u16, coefficients: []Scalar) !struct { []Scalar, VerifiableSecretSharingCommitment } {
    if (min_signers < 2 or max_signers < 2 or min_signers > max_signers) {
        return FrostError.InvalidMinSigners;
    }
    if (coefficients.len != min_signers - 1) {
        return FrostError.InvalidCoefficient;
    }
    var all_coeffs = std.heap.page_allocator.alloc(Scalar, min_signers) catch return FrostError.RandomnessError;
    all_coeffs[0] = secret.scalar;
    @memcpy(all_coeffs[1..], coefficients);
    var commitment_coeffs = std.heap.page_allocator.alloc(CoefficientCommitment, min_signers) catch return FrostError.RandomnessError;
    for (all_coeffs, 0..) |c, i| {
        commitment_coeffs[i] = CoefficientCommitment.fromElement(group.elementScalarBaseMul(c));
    }
    return .{ all_coeffs, VerifiableSecretSharingCommitment.init(commitment_coeffs) };
}

/// Evaluate the polynomial at each identifier to produce per-participant
/// secret shares.
fn generateSecretShares(secret: SigningKey, max_signers: u16, min_signers: u16, coefficients: []Scalar, identifiers: []const Identifier) ![]SecretShare {
    const all_coeffs, const commitment = try generateSecretPolynomial(secret, max_signers, min_signers, coefficients);
    var shares = std.heap.page_allocator.alloc(SecretShare, max_signers) catch return FrostError.RandomnessError;
    for (identifiers, 0..) |id, i| {
        const signing_share = SigningShare.fromScalar(evaluatePolynomial(id, all_coeffs));
        shares[i] = SecretShare{
            .identifier = id,
            .signing_share = signing_share,
            .commitment = commitment,
        };
    }
    return shares;
}

/// Default identifiers 1 … max_signers (id 0 is invalid).
pub fn defaultIdentifiers(max_signers: u16) ![]Identifier {
    var ids = std.heap.page_allocator.alloc(Identifier, max_signers) catch return FrostError.RandomnessError;
    for (1..max_signers + 1) |i| {
        ids[i - 1] = try Identifier.fromU16(@intCast(i));
    }
    return ids;
}

/// Trusted-dealer key generation: sample a fresh secret, split into
/// max_signers shares with threshold min_signers, and derive the public key
/// package.
pub fn generateWithDealer(max_signers: u16, min_signers: u16, identifiers: []const Identifier) !struct { []SecretShare, PublicKeyPackage } {
    const key = SigningKey.generate();
    return try split(&key, max_signers, min_signers, identifiers);
}

/// Split an existing signing key into max_signers FROST shares with the given
/// threshold. Validates identifier count and uniqueness.
pub fn split(secret: *const SigningKey, max_signers: u16, min_signers: u16, identifiers: []const Identifier) !struct { []SecretShare, PublicKeyPackage } {
    if (min_signers < 2 or max_signers < 2 or min_signers > max_signers) {
        return FrostError.InvalidMinSigners;
    }
    if (identifiers.len != max_signers) {
        return FrostError.IncorrectNumberOfIdentifiers;
    }
    // Reject duplicate identifiers (O(n²), fine for small n).
    for (identifiers, 0..) |id1, i| {
        for (identifiers[i + 1 ..]) |id2| {
            if (id1.eql(id2)) return FrostError.DuplicatedIdentifier;
        }
    }
    const coefficients = generateCoefficients(min_signers - 1);
    const shares = try generateSecretShares(secret.*, max_signers, min_signers, coefficients, identifiers);
    const verifying_key = VerifyingKey.fromSigningKey(secret.*);
    var verifying_shares = std.AutoHashMap(Identifier, VerifyingShare).init(std.heap.page_allocator);
    for (shares) |share| {
        const vs = VerifyingShare.fromSigningShare(share.signing_share);
        try verifying_shares.put(share.identifier, vs);
    }
    const pubkey_package = PublicKeyPackage{
        .verifying_shares = verifying_shares,
        .verifying_key = verifying_key,
        .min_signers = min_signers,
    };
    return .{ shares, pubkey_package };
}

/// Reconstruct the original signing key from at least min_signers key
/// packages using Lagrange interpolation at x = 0.
pub fn reconstruct(key_packages: []const KeyPackage) !SigningKey {
    if (key_packages.len == 0) return FrostError.IncorrectNumberOfShares;
    var min_signers: u16 = key_packages[0].min_signers;
    for (key_packages) |kp| {
        if (kp.min_signers < min_signers) min_signers = kp.min_signers;
    }
    if (key_packages.len < min_signers) return FrostError.IncorrectNumberOfShares;
    var secret = field.scalarZero();
    for (key_packages) |kp| {
        const lambda = try deriveInterpolatingValue(kp.identifier, key_packages);
        secret = field.scalarAdd(secret, field.scalarMul(lambda, kp.signing_share.toScalar()));
    }
    return SigningKey.fromScalar(secret);
}

/// Compute the Lagrange coefficient for `signer_id` over the identifiers
/// present in `key_packages`.
pub fn deriveInterpolatingValue(signer_id: Identifier, key_packages: []const KeyPackage) !Scalar {
    var ids = std.ArrayList(Identifier).empty;
    defer ids.deinit(std.heap.page_allocator);
    for (key_packages) |kp| {
        try ids.append(std.heap.page_allocator, kp.identifier);
    }
    return computeLagrangeCoefficient(ids.items, signer_id);
}

/// Lagrange coefficient λ_i = ∏_{j≠i} x_j / (x_j − x_i) for x_i = x_i over
/// the given identifier set. Fails if x_i is not in the set.
pub fn computeLagrangeCoefficient(identifiers: []const Identifier, x_i: Identifier) !Scalar {
    if (identifiers.len == 0) return FrostError.IncorrectNumberOfIdentifiers;
    var num = field.scalarOne();
    var den = field.scalarOne();
    var x_i_found = false;
    const x_i_scalar = field.scalarDeserialize(x_i.serialize()) catch field.scalarZero();
    for (identifiers) |x_j| {
        if (x_i.eql(x_j)) {
            x_i_found = true;
            continue;
        }
        const x_j_scalar = field.scalarDeserialize(x_j.serialize()) catch field.scalarZero();
        num = field.scalarMul(num, x_j_scalar);
        den = field.scalarMul(den, field.scalarSub(x_j_scalar, x_i_scalar));
    }
    if (!x_i_found) return FrostError.UnknownIdentifier;
    const den_inv = try field.scalarInvert(den);
    return field.scalarMul(num, den_inv);
}
