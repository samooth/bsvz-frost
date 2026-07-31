//! Distributed Key Generation (FROST KeyGen, RFC 9591 / FROST paper Figure 1).
//!
//! Mirrors the Zcash Foundation `frost-core` `keys::dkg` module: a variant of
//! Pedersen's DKG where each participant runs a Feldman VSS as dealer in
//! parallel, plus a Schnorr-style proof of knowledge of their secret constant
//! term (a_{i0}) to defeat rogue-key attacks when t >= n/2.
//!
//! Communication pattern (per participant i):
//!   round1: broadcast (commitment C_i, proof of knowledge sigma_i)
//!   round2: one private/authenticated share f_i(j) to each other participant j
//!   round3 (part3): compute long-lived share s_i = sum_j f_j(i) and the
//!     group public key from the summed commitments.
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const Signature = @import("signature.zig").Signature;
const field = @import("field.zig");
const group = @import("group.zig");
const cs = @import("ciphersuite.zig");
const keys = @import("keys.zig");

pub const Scalar = field.Scalar;
pub const Element = group.Element;
pub const VerifiableSecretSharingCommitment = keys.VerifiableSecretSharingCommitment;
pub const SigningShare = keys.SigningShare;
pub const KeyPackage = keys.KeyPackage;
pub const PublicKeyPackage = keys.PublicKeyPackage;

const alloc = std.heap.page_allocator;

/// DKG Round 1 structures.
pub const round1 = struct {
    /// The package broadcast by each participant in round 1 (commitment C_i
    /// and proof of knowledge sigma_i). Safe to publish to all participants.
    pub const Package = struct {
        commitment: VerifiableSecretSharingCommitment,
        proof_of_knowledge: Signature,

        pub fn deinit(self: *Package) void {
            alloc.free(self.commitment.coefficients);
        }
    };

    /// The secret package kept by each participant between round 1 and 2.
    /// MUST NOT be sent to anyone.
    pub const SecretPackage = struct {
        identifier: Identifier,
        coefficients: []Scalar,
        commitment: VerifiableSecretSharingCommitment,
        min_signers: u16,
        max_signers: u16,

        pub fn deinit(self: *SecretPackage) void {
            alloc.free(self.coefficients);
            alloc.free(self.commitment.coefficients);
        }
    };
};

/// DKG Round 2 structures.
pub const round2 = struct {
    /// One secret share sent privately from a participant to a recipient.
    /// MUST be sent on a confidential, authenticated channel.
    pub const Package = struct {
        signing_share: SigningShare,
    };

    /// The secret package kept between round 2 and the finalization step.
    /// MUST NOT be sent to anyone.
    pub const SecretPackage = struct {
        identifier: Identifier,
        commitment: VerifiableSecretSharingCommitment,
        secret_share: Scalar,
        min_signers: u16,
        max_signers: u16,

        pub fn deinit(self: *SecretPackage) void {
            alloc.free(self.commitment.coefficients);
        }
    };
};

fn validateNumOfSigners(min_signers: u16, max_signers: u16) !void {
    if (min_signers < 2) return FrostError.InvalidMinSigners;
    if (max_signers < 2) return FrostError.InvalidMaxSigners;
    if (min_signers > max_signers) return FrostError.InvalidMinSigners;
}

fn cloneCommitment(commitment: VerifiableSecretSharingCommitment) !VerifiableSecretSharingCommitment {
    const coeffs = try alloc.alloc(keys.CoefficientCommitment, commitment.coefficients.len);
    @memcpy(coeffs, commitment.coefficients);
    return VerifiableSecretSharingCommitment.init(coeffs);
}

/// Challenge c_i = HDKG(identifier || phi_{i0} || R) used in the proof of
/// knowledge, where phi_{i0} is the commitment to the constant coefficient.
fn challenge(identifier: Identifier, verifying_key: *const keys.VerifyingKey, R: Element) !Scalar {
    var preimage = std.ArrayList(u8).empty;
    defer preimage.deinit(alloc);
    try preimage.appendSlice(alloc, &identifier.serialize());
    const vk_bytes = try verifying_key.serialize();
    try preimage.appendSlice(alloc, &vk_bytes);
    const r_bytes = try group.elementSerialize(R);
    try preimage.appendSlice(alloc, &r_bytes);
    return cs.HDKG(preimage.items);
}

/// Compute the proof of knowledge sigma_i = (R_i, mu_i) of the secret constant
/// term a_{i0}: k <- Z_q, R_i = g^k, c_i = H(i, Phi, g^{a_{i0}}, R_i),
/// mu_i = k + a_{i0} * c_i.
fn computeProofOfKnowledge(
    identifier: Identifier,
    coefficients: []const Scalar,
    commitment: VerifiableSecretSharingCommitment,
) !Signature {
    const k = field.scalarRandom();
    const R = group.elementScalarBaseMul(k);
    const vk = try commitment.verifyingKey();
    const c = try challenge(identifier, &vk, R);
    const a_i0 = coefficients[0];
    const mu = field.scalarAdd(k, field.scalarMul(a_i0, c));
    return Signature{ .R = R, .z = mu };
}

/// Verify the proof of knowledge from participant `identifier`:
/// check R_ell == g^mu_ell - phi_{ell0}^c_ell.
fn verifyProofOfKnowledge(
    identifier: Identifier,
    commitment: VerifiableSecretSharingCommitment,
    proof: *const Signature,
) !void {
    const phi = try commitment.verifyingKey();
    const c = try challenge(identifier, &phi, proof.R);
    const g_mu = group.elementScalarBaseMul(proof.z);
    const phi_c = group.elementScalarMul(phi.element, c);
    const check = group.elementAdd(proof.R, phi_c);
    if (!group.elementEql(g_mu, check)) {
        return FrostError.InvalidProofOfKnowledge;
    }
}

/// Part 1 of the DKG: sample a secret polynomial f_i, its commitment C_i, and
/// a proof of knowledge of the constant term. Returns the participant's
/// secret package (kept) and the broadcast package.
pub fn part1(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
) !struct { round1.SecretPackage, round1.Package } {
    try validateNumOfSigners(min_signers, max_signers);

    // Round 1, Step 1 & 3: sample (a_{i0}, ..., a_{i(t-1)}) and commit to
    // each coefficient phi_{ij} = g^{a_{ij}}.
    const secret = keys.SigningKey.generate();
    const coefficients = try alloc.alloc(Scalar, min_signers - 1);
    errdefer alloc.free(coefficients);
    for (coefficients) |*c| c.* = field.scalarRandom();
    const all_coeffs, const commitment = try keys.generateSecretPolynomial(secret, max_signers, min_signers, coefficients);
    alloc.free(coefficients);

    // Round 1, Step 2: proof of knowledge of a_{i0}.
    const proof = try computeProofOfKnowledge(identifier, all_coeffs, commitment);

    const secret_package = round1.SecretPackage{
        .identifier = identifier,
        .coefficients = all_coeffs,
        .commitment = commitment,
        .min_signers = min_signers,
        .max_signers = max_signers,
    };
    const package = round1.Package{
        .commitment = try cloneCommitment(commitment),
        .proof_of_knowledge = proof,
    };
    return .{ secret_package, package };
}

/// Part 2 of the DKG: verify every received round 1 package (proof of
/// knowledge), then compute the share f_i(j) to send to each other
/// participant j. Keeps f_i(i) for itself.
pub fn part2(
    secret_package: *const round1.SecretPackage,
    round1_packages: *const std.AutoHashMap(Identifier, round1.Package),
    allocator: std.mem.Allocator,
) !struct { round2.SecretPackage, std.AutoHashMap(Identifier, round2.Package) } {
    if (round1_packages.count() != secret_package.max_signers - 1) {
        return FrostError.IncorrectNumberOfPackages;
    }
    if (round1_packages.contains(secret_package.identifier)) {
        return FrostError.UnknownIdentifier;
    }
    var it = round1_packages.valueIterator();
    while (it.next()) |pkg| {
        if (pkg.commitment.minSigners() != secret_package.min_signers) {
            return FrostError.IncorrectNumberOfCommitments;
        }
    }

    var round2_packages = std.AutoHashMap(Identifier, round2.Package).init(allocator);
    errdefer round2_packages.deinit();
    var it2 = round1_packages.iterator();
    while (it2.next()) |entry| {
        const ell = entry.key_ptr.*;
        // Round 1, Step 5: verify sigma_ell.
        try verifyProofOfKnowledge(ell, entry.value_ptr.commitment, &entry.value_ptr.proof_of_knowledge);
        // Round 2, Step 1: secure share (ell, f_i(ell)).
        const share = keys.evaluatePolynomial(ell, secret_package.coefficients);
        try round2_packages.put(ell, .{ .signing_share = SigningShare.fromScalar(share) });
    }
    const fii = keys.evaluatePolynomial(secret_package.identifier, secret_package.coefficients);

    const secret_pkg2 = round2.SecretPackage{
        .identifier = secret_package.identifier,
        .commitment = try cloneCommitment(secret_package.commitment),
        .secret_share = fii,
        .min_signers = secret_package.min_signers,
        .max_signers = secret_package.max_signers,
    };
    return .{ secret_pkg2, round2_packages };
}

/// Part 3 of the DKG: verify each received share f_ell(i) against the
/// sender's commitment, sum them into the long-lived signing share
/// s_i = sum_ell f_ell(i), and derive the group verifying key from the sum
/// of all participants' commitments.
pub fn part3(
    round2_secret_package: *const round2.SecretPackage,
    round1_packages: *const std.AutoHashMap(Identifier, round1.Package),
    round2_packages: *const std.AutoHashMap(Identifier, round2.Package),
    allocator: std.mem.Allocator,
) !struct { KeyPackage, PublicKeyPackage } {
    if (round1_packages.count() != round2_secret_package.max_signers - 1) {
        return FrostError.IncorrectNumberOfPackages;
    }
    if (round1_packages.contains(round2_secret_package.identifier)) {
        return FrostError.UnknownIdentifier;
    }
    if (round2_packages.contains(round2_secret_package.identifier)) {
        return FrostError.UnknownIdentifier;
    }
    if (round1_packages.count() != round2_packages.count()) {
        return FrostError.IncorrectNumberOfPackages;
    }
    var keys_iter = round1_packages.keyIterator();
    while (keys_iter.next()) |id| {
        if (!round2_packages.contains(id.*)) {
            return FrostError.IncorrectPackage;
        }
    }

    var signing_share = field.scalarZero();
    var it = round2_packages.iterator();
    while (it.next()) |entry| {
        const f_ell_i = entry.value_ptr.signing_share;
        // Round 2, Step 2: verify g^{f_ell(i)} == product_k phi_{ell k}^{i^k}.
        const commitment = round1_packages.get(entry.key_ptr.*) orelse return FrostError.PackageNotFound;
        const lhs = group.elementScalarBaseMul(f_ell_i.toScalar());
        const rhs = keys.evaluateVss(round2_secret_package.identifier, commitment.commitment);
        if (!group.elementEql(lhs, rhs)) {
            return FrostError.InvalidSecretShare;
        }
        // Round 2, Step 3: accumulate s_i = sum f_ell(i).
        signing_share = field.scalarAdd(signing_share, f_ell_i.toScalar());
    }
    signing_share = field.scalarAdd(signing_share, round2_secret_package.secret_share);
    const ss = SigningShare.fromScalar(signing_share);

    // Round 2, Step 4: public verification share Y_i = g^{s_i}.
    const verifying_share = keys.VerifyingShare.fromSigningShare(ss);

    // Group public key from the sum of all participants' commitments.
    var commitments = std.AutoHashMap(Identifier, *const VerifiableSecretSharingCommitment).init(allocator);
    defer commitments.deinit();
    var it2 = round1_packages.iterator();
    while (it2.next()) |entry| {
        try commitments.put(entry.key_ptr.*, &entry.value_ptr.commitment);
    }
    try commitments.put(round2_secret_package.identifier, &round2_secret_package.commitment);
    const public_key_package = try keys.PublicKeyPackage.fromDkgCommitments(allocator, &commitments);

    const key_package = KeyPackage{
        .identifier = round2_secret_package.identifier,
        .signing_share = ss,
        .verifying_share = verifying_share,
        .verifying_key = public_key_package.verifying_key,
        .min_signers = round2_secret_package.min_signers,
    };
    return .{ key_package, public_key_package };
}
