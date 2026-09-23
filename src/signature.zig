//! Schnorr signature types.
//!
//! Wire format (65 bytes): compressed SEC1 R (33) ‖ big-endian z (32).
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;

/// A Schnorr signature (R, z) where R is a point and z is a scalar.
pub const Signature = struct {
    /// The nonce commitment (group element).
    R: Secp256k1,
    /// The response scalar.
    z: Secp256k1.scalar.Scalar,

    /// Serialize to 65 bytes: R (33, compressed SEC1) ‖ z (32, big-endian).
    pub fn serialize(self: Signature) ![65]u8 {
        var out: [65]u8 = undefined;
        const r_bytes = self.R.toCompressedSec1();
        @memcpy(out[0..33], &r_bytes);
        const z_bytes = self.z.toBytes(.big);
        @memcpy(out[33..65], &z_bytes);
        return out;
    }

    /// Parse a 65-byte signature; rejects invalid R or non-canonical z.
    pub fn deserialize(bytes: [65]u8) !Signature {
        const R = try Secp256k1.fromSec1(bytes[0..33]);
        const z = try Secp256k1.scalar.Scalar.fromBytes(bytes[33..65].*, .big);
        return Signature{ .R = R, .z = z };
    }
};
