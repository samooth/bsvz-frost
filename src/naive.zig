//! Naive threshold Schnorr signing over secp256k1, built on the bsvz crypto
//! primitives. Key is split via Shamir. To sign, t participants first
//! exchange nonce commitments, then each produces a partial response over the
//! shared group commitment; the responses aggregate into a standard Schnorr
//! signature.
//!
//! SECURITY: unlike FROST, this scheme has no binding factors and no
//! identifiable abort — it is intended for evaluation/interop, not
//! production. Use the FROST modules for production guarantees.
const std = @import("std");
const bsvz = @import("bsvz");
const scalar = @import("scalar.zig");

pub const PartialSignature = struct {
    identifier: u32,
    R: bsvz.crypto.Point, // nonce commitment
    s: [32]u8, // partial response
};

pub const Signature = struct {
    R: bsvz.crypto.Point,
    s: [32]u8,
};

/// Derive the Schnorr challenge e = H(R || P || m), reduced mod the curve order.
pub fn challenge(publicKey: bsvz.crypto.Point, R: bsvz.crypto.Point, message: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const r_bytes = R.toCompressedSec1();
    const p_bytes = publicKey.toCompressedSec1();
    hasher.update(r_bytes.slice());
    hasher.update(p_bytes.slice());
    hasher.update(message);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return scalar.reduce(hash);
}

/// Compute Lagrange coefficient lambda_i for participant i over the signing set.
pub fn lagrangeCoefficient(i: u32, participant_ids: []const u32) [32]u8 {
    var lambda = scalar.one();
    const xi = scalar.fromInt(i);

    for (participant_ids) |m| {
        if (m == i) continue;
        const xm = scalar.fromInt(m);
        const diff = scalar.sub(xm, xi);
        const term = scalar.mul(xm, scalar.inv(diff));
        lambda = scalar.mul(lambda, term);
    }
    return lambda;
}

/// A single participant's signing round.
/// Input: share x_j, nonce k_j, the shared group commitment R (sum of every
/// participant's R_j), group pubkey P, message.
/// Output: partial signature (R_j, s_j).
pub fn partialSign(
    share: [32]u8,
    nonce: [32]u8,
    identifier: u32,
    participant_ids: []const u32,
    group_pubkey: bsvz.crypto.Point,
    group_commitment: bsvz.crypto.Point,
    message: []const u8,
) !PartialSignature {
    const R = try bsvz.crypto.Point.basePointMul(nonce);
    const e = challenge(group_pubkey, group_commitment, message);
    const lambda = lagrangeCoefficient(identifier, participant_ids);
    const ex = scalar.mul(e, share);
    const exl = scalar.mul(ex, lambda);
    const s = scalar.add(nonce, exl);
    return .{ .identifier = identifier, .R = R, .s = s };
}

/// Aggregate partial signatures into a final Schnorr signature.
pub fn aggregate(partial_sigs: []const PartialSignature) Signature {
    var R = bsvz.crypto.Point.identity();
    var s = scalar.zero();
    for (partial_sigs) |ps| {
        R = R.add(ps.R);
        s = scalar.add(s, ps.s);
    }
    return .{ .R = R, .s = s };
}

/// Verify a threshold signature using standard Schnorr verification.
/// Returns true when s*G == R + e*P.
pub fn verify(group_pubkey: bsvz.crypto.Point, message: []const u8, sig: Signature) !bool {
    const e = challenge(group_pubkey, sig.R, message);
    const sG = try bsvz.crypto.Point.basePointMul(sig.s);
    const eP = try group_pubkey.mul(e);
    const rhs = sig.R.add(eP);
    const sG_bytes = sG.toCompressedSec1();
    const rhs_bytes = rhs.toCompressedSec1();
    return std.mem.eql(u8, sG_bytes.slice(), rhs_bytes.slice());
}
