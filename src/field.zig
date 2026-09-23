//! Scalar field operations for secp256k1
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;

pub const Scalar = Secp256k1.scalar.Scalar;

/// Fill a buffer with cryptographically secure random bytes.
///
/// On WASM/freestanding builds, provide entropy by declaring
/// `pub fn frost_random_bytes(buffer: []u8) void` in the root module
/// (e.g. `src/wasm.zig`). Zig's comptime hook picks it up automatically.
pub fn randomBytes(buffer: []u8) void {
    if (@hasDecl(@import("root"), "frost_random_bytes")) {
        @import("root").frost_random_bytes(buffer.ptr, buffer.len);
    } else {
        std.Io.Threaded.global_single_threaded.io().random(buffer);
    }
}

pub fn scalarZero() Scalar {
    return Secp256k1.scalar.Scalar.zero;
}

pub fn scalarOne() Scalar {
    return Secp256k1.scalar.Scalar.one;
}

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

pub fn scalarInvert(s: Scalar) !Scalar {
    if (s.isZero()) return FrostError.InvalidZeroScalar;
    return s.invert();
}
pub fn scalarSerialize(s: Scalar) [32]u8 {
    return s.toBytes(.big);
}

pub fn scalarDeserialize(bytes: [32]u8) !Scalar {
    return Secp256k1.scalar.Scalar.fromBytes(bytes, .big);
}

pub fn scalarAdd(a: Scalar, b: Scalar) Scalar {
    return a.add(b);
}

pub fn scalarSub(a: Scalar, b: Scalar) Scalar {
    return a.sub(b);
}

pub fn scalarMul(a: Scalar, b: Scalar) Scalar {
    return a.mul(b);
}

pub fn scalarNegate(s: Scalar) Scalar {
    return s.neg();
}

pub fn scalarIsZero(s: Scalar) bool {
    return s.isZero();
}

pub fn scalarEql(a: Scalar, b: Scalar) bool {
    return a.equivalent(b);
}
