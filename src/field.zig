//! Scalar field operations for secp256k1.
//!
//! Thin wrappers over Zig's Secp256k1 scalar type with FROST-friendly error
//! handling. Entropy comes from the comptime hook `frost_random_bytes` when
//! present (wasm builds), or the OS CSPRNG otherwise.
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;

/// A scalar modulo the secp256k1 curve order n.
pub const Scalar = Secp256k1.scalar.Scalar;

/// Fill a buffer with cryptographically secure random bytes.
///
/// On WASM/freestanding builds, provide entropy by declaring
/// `pub fn frost_random_bytes(buffer: []u8) void` in the root module.
/// Zig's comptime hook picks it up automatically; without a declaration the
/// OS CSPRNG is used.
pub fn randomBytes(buffer: []u8) void {
    if (@hasDecl(@import("root"), "frost_random_bytes")) {
        @import("root").frost_random_bytes(buffer.ptr, buffer.len);
    } else {
        std.Io.Threaded.global_single_threaded.io().random(buffer);
    }
}

/// The additive identity (0 mod n).
pub fn scalarZero() Scalar {
    return Secp256k1.scalar.Scalar.zero;
}

/// The multiplicative identity (1 mod n).
pub fn scalarOne() Scalar {
    return Secp256k1.scalar.Scalar.one;
}

/// Sample a uniformly random non-zero scalar (retries on the negligible
/// zero case, then falls back to zero after 100 attempts).
pub fn scalarRandom() Scalar {
    var bytes: [32]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        randomBytes(&bytes);
        const s = Secp256k1.scalar.Scalar.fromBytes(bytes, .big) catch continue;
        if (!s.isZero()) return s;
    }
    return scalarZero();
}

/// Modular inverse; zero has no inverse, so returns InvalidZeroScalar.
pub fn scalarInvert(s: Scalar) !Scalar {
    if (s.isZero()) return FrostError.InvalidZeroScalar;
    return s.invert();
}
/// Big-endian 32-byte serialization.
pub fn scalarSerialize(s: Scalar) [32]u8 {
    return s.toBytes(.big);
}

/// Parse a big-endian 32-byte scalar; rejects non-canonical encodings.
pub fn scalarDeserialize(bytes: [32]u8) !Scalar {
    return Secp256k1.scalar.Scalar.fromBytes(bytes, .big);
}

/// a + b mod n.
pub fn scalarAdd(a: Scalar, b: Scalar) Scalar {
    return a.add(b);
}

/// a - b mod n.
pub fn scalarSub(a: Scalar, b: Scalar) Scalar {
    return a.sub(b);
}

/// a * b mod n.
pub fn scalarMul(a: Scalar, b: Scalar) Scalar {
    return a.mul(b);
}

/// -a mod n.
pub fn scalarNegate(s: Scalar) Scalar {
    return s.neg();
}

/// True iff s == 0.
pub fn scalarIsZero(s: Scalar) bool {
    return s.isZero();
}

/// Constant-time-ish equality via the scalar type's equivalent() method.
pub fn scalarEql(a: Scalar, b: Scalar) bool {
    return a.equivalent(b);
}
