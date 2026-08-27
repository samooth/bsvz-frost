//! Byte-scalar (32-byte big-endian) arithmetic over the secp256k1 subgroup
//! order, for interop with the bsvz `crypto.Point` API, which consumes and
//! produces `[32]u8` big-endian scalars.
const std = @import("std");

const Scalar = std.crypto.ecc.Secp256k1.scalar.Scalar;

fn parse(bytes: [32]u8) Scalar {
    return Scalar.fromBytes(bytes, .big) catch unreachable;
}

/// The zero scalar.
pub fn zero() [32]u8 {
    return @as([32]u8, @splat(0));
}

/// The one scalar.
pub fn one() [32]u8 {
    var bytes = @as([32]u8, @splat(0));
    bytes[31] = 1;
    return bytes;
}

/// Encode a u64 as a canonical scalar.
pub fn fromInt(value: u64) [32]u8 {
    var bytes = @as([32]u8, @splat(0));
    std.mem.writeInt(u64, bytes[24..32], value, .big);
    return bytes;
}

/// Validate canonical scalar bytes.
pub fn fromBytes(bytes: [32]u8) ![32]u8 {
    _ = try Scalar.fromBytes(bytes, .big);
    return bytes;
}

/// Reduce arbitrary 32 bytes modulo the curve order.
pub fn reduce(bytes: [32]u8) [32]u8 {
    var buf = @as([64]u8, @splat(0));
    @memcpy(buf[0..32], &bytes);
    return Scalar.fromBytes64(buf, .big).toBytes(.big);
}

/// Generate a random scalar.
pub fn random() [32]u8 {
    var buf: [64]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&buf);
    return Scalar.fromBytes64(buf, .big).toBytes(.big);
}

/// a + b (mod n).
pub fn add(a: [32]u8, b: [32]u8) [32]u8 {
    return parse(a).add(parse(b)).toBytes(.big);
}

/// a - b (mod n).
pub fn sub(a: [32]u8, b: [32]u8) [32]u8 {
    return parse(a).sub(parse(b)).toBytes(.big);
}

/// a * b (mod n).
pub fn mul(a: [32]u8, b: [32]u8) [32]u8 {
    return parse(a).mul(parse(b)).toBytes(.big);
}

/// a^-1 (mod n); zero has no inverse and maps to zero.
pub fn inv(a: [32]u8) [32]u8 {
    if (isZero(a)) return zero();
    return parse(a).invert().toBytes(.big);
}

/// -a (mod n).
pub fn neg(a: [32]u8) [32]u8 {
    return parse(a).neg().toBytes(.big);
}

/// Constant-time equality of two canonical scalars.
pub fn eq(a: [32]u8, b: [32]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

/// True if the scalar is zero.
pub fn isZero(a: [32]u8) bool {
    return std.mem.allEqual(u8, &a, 0);
}
