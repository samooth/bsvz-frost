//! FROST(secp256k1, SHA-256) ciphersuite implementation
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;

pub const CONTEXT_STRING = "FROST-secp256k1-SHA256-v1";

/// Hash arbitrary data to a 32-byte output using SHA-256.
fn hashToArray(inputs: []const []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (inputs) |input| {
        h.update(input);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Hash arbitrary data to a scalar modulo the curve order.
/// Uses the "hash_to_field" approach: hash with domain separation,
/// interpret as big integer, reduce modulo curve order.
fn hashToScalar(domain: []const []const u8, msg: []const u8) Secp256k1.scalar.Scalar {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (domain) |d| {
        h.update(d);
    }
    h.update(msg);
    var out: [32]u8 = undefined;
    h.final(&out);
    // Reduce modulo curve order. In Zig stdlib, fromBytes should handle this.
    return Secp256k1.scalar.Scalar.fromBytes(out, .big) catch {
        // Fallback: if fromBytes fails, we can try again with a counter
        // (should be extremely rare with SHA-256 and 256-bit order)
        var counter: u8 = 0;
        while (true) : (counter += 1) {
            var h2 = std.crypto.hash.sha2.Sha256.init(.{});
            for (domain) |d| {
                h2.update(d);
            }
            h2.update(msg);
            h2.update(&[_]u8{counter});
            var out2: [32]u8 = undefined;
            h2.final(&out2);
            if (Secp256k1.scalar.Scalar.fromBytes(out2, .big)) |s| {
                return s;
            } else |_| {}
        }
    };
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
