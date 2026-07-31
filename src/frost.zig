const std = @import("std");
const bsvz = @import("bsvz");

/// FROST (Flexible Round-Optimized Schnorr Threshold signatures) — RFC 9591.
///
/// NOTE: This is a PLACEHOLDER. Full FROST implementation requires:
///   - Distributed Key Generation (DKG) with verifiable secret sharing
///   - Two-round signing ceremony with nonce commitments
///   - Identifiable abort (detect malicious signers)
///   - Repairable Threshold Scheme (RTS) for share refresh
///
/// For production use before v0.2.0, use naive threshold Schnorr (naive.zig)
/// with nonce commitment and single-session enforcement.
///
/// Planned implementation paths:
///   A. Pure Zig over bsvz (4-6 months, requires audit)
///   B. Binding to bancaditalia/secp256k1-frost (C, 2-3 weeks)
///   C. Binding to ZcashFoundation/frost via C ABI wrapper (Rust→C→Zig, 4-6 weeks)
pub const FrostParticipant = struct {
    identifier: u32,
    threshold: u32,
    n: u32,
    // Placeholder fields
    secret_share: bsvz.crypto.Scalar,
    public_share: bsvz.crypto.Point,
    group_public_key: bsvz.crypto.Point,
};

pub const NonceCommitment = struct {
    hiding: bsvz.crypto.Point,
    binding: bsvz.crypto.Point,
};

pub fn init(identifier: u32, threshold: u32, n: u32) FrostParticipant {
    _ = identifier;
    _ = threshold;
    _ = n;
    @panic("FROST not yet implemented. Use naive threshold Schnorr.");
}
