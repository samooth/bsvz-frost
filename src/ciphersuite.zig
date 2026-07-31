//! FROST(secp256k1, SHA-256) ciphersuite implementation
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const CONTEXT_STRING = "FROST-secp256k1-SHA256-v1";

/// Hash arbitrary data to a 32-byte output using SHA-256.
fn hashToArraySegments(segments: []const []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (segments) |segment| {
        h.update(segment);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Hash arbitrary data to a 32-byte output using SHA-256.
fn hashToArray(inputs: []const []const u8) [32]u8 {
    return hashToArraySegments(inputs);
}

/// RFC 9380 `expand_message_xmd` using SHA-256 (b_in=32, r_in=64).
///
/// Produces `len_in_bytes = 48` bytes, as required by `hash_to_field` for
/// FROST(secp256k1, SHA-256) (count=1, L=48).
fn expandMessageXmd(msg: []const u8, dst: []const u8) [48]u8 {
    // DST_prime = DST || I2OSP(len(DST), 1)
    var dst_prime: [64]u8 = undefined;
    @memcpy(dst_prime[0..dst.len], dst);
    dst_prime[dst.len] = @intCast(dst.len);
    const dst_prime_slice = dst_prime[0 .. dst.len + 1];

    const z_pad = [_]u8{0} ** 64; // I2OSP(0, 64)
    const l_i_b_str = [_]u8{ 0x00, 0x30 }; // I2OSP(48, 2)

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    const b0 = hashToArraySegments(&[_][]const u8{ &z_pad, msg, &l_i_b_str, &[_]u8{0x00}, dst_prime_slice });

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    const b1 = hashToArraySegments(&[_][]const u8{ &b0, &[_]u8{0x01}, dst_prime_slice });

    // b_2 = H(strxor(b_1, b_0) || I2OSP(2, 1) || DST_prime)
    var x: [32]u8 = undefined;
    for (0..32) |i| x[i] = b1[i] ^ b0[i];
    const b2 = hashToArraySegments(&[_][]const u8{ &x, &[_]u8{0x02}, dst_prime_slice });

    var out: [48]u8 = undefined;
    @memcpy(out[0..32], &b1);
    @memcpy(out[32..48], b2[0..16]);
    return out;
}

/// Hash arbitrary data to a scalar modulo the curve order, using the
/// RFC 9380 `hash_to_field` construction (count=1, L=48) with
/// `expand_message_xmd` as the expander, matching the Zcash reference
/// implementation of FROST(secp256k1, SHA-256).
fn hashToScalar(domain: []const []const u8, msg: []const u8) Secp256k1.scalar.Scalar {
    // DST is the concatenation of the domain separation components.
    var dst_buf: [64]u8 = undefined;
    var dst_len: usize = 0;
    for (domain) |d| {
        @memcpy(dst_buf[dst_len .. dst_len + d.len], d);
        dst_len += d.len;
    }
    const dst = dst_buf[0..dst_len];

    const uniform_bytes = expandMessageXmd(msg, dst);
    // OS2IP(uniform_bytes) mod p, reduced by the curve order.
    return Secp256k1.scalar.Scalar.fromBytes48(uniform_bytes, .big);
}

/// H1: binding factor hash
pub fn H1(msg: []const u8) Secp256k1.scalar.Scalar {
    return hashToScalar(&[_][]const u8{ CONTEXT_STRING, "rho" }, msg);
}

/// H2: challenge hash
pub fn H2(msg: []const u8) Secp256k1.scalar.Scalar {
    return hashToScalar(&[_][]const u8{ CONTEXT_STRING, "chal" }, msg);
}

/// H3: nonce hash
pub fn H3(msg: []const u8) Secp256k1.scalar.Scalar {
    return hashToScalar(&[_][]const u8{ CONTEXT_STRING, "nonce" }, msg);
}

/// H4: message hash
pub fn H4(msg: []const u8) [32]u8 {
    return hashToArray(&[_][]const u8{ CONTEXT_STRING, "msg", msg });
}

/// H5: commitment list hash
pub fn H5(msg: []const u8) [32]u8 {
    return hashToArray(&[_][]const u8{ CONTEXT_STRING, "com", msg });
}

/// HDKG: DKG hash
pub fn HDKG(msg: []const u8) Secp256k1.scalar.Scalar {
    return hashToScalar(&[_][]const u8{ CONTEXT_STRING, "dkg" }, msg);
}

/// HID: identifier derivation hash
pub fn HID(msg: []const u8) Secp256k1.scalar.Scalar {
    return hashToScalar(&[_][]const u8{ CONTEXT_STRING, "id" }, msg);
}
