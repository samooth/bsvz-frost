//! Group operations for secp256k1.
//!
//! Thin wrappers over Zig's Secp256k1 point type. All points are compressed
//! SEC1 (33 bytes). The identity (point at infinity) is not a valid wire
//! encoding and is rejected by elementSerialize.
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;
const field = @import("field.zig");

/// A secp256k1 curve point.
pub const Element = Secp256k1;
/// A scalar modulo the curve order (shared with field.zig).
pub const Scalar = field.Scalar;

/// The point at infinity (identity element).
pub fn identity() Element {
    return Secp256k1.identityElement;
}

/// The standard base point G.
pub fn generator() Element {
    return Secp256k1.basePoint;
}

/// Compressed SEC1 serialization (33 bytes). Rejects the identity, which has
/// no valid compressed encoding.
pub fn elementSerialize(element: Element) ![33]u8 {
    if (elementIsIdentity(element)) return FrostError.InvalidIdentityElement;
    return element.toCompressedSec1();
}

/// Parse a compressed SEC1 point (33 bytes); rejects invalid encodings and
/// points not on the curve.
pub fn elementDeserialize(bytes: [33]u8) !Element {
    return Secp256k1.fromSec1(&bytes);
}

/// Point addition a + b.
pub fn elementAdd(a: Element, b: Element) Element {
    return Secp256k1.add(a, b);
}

/// Point subtraction a - b (as a + (-b)).
pub fn elementSub(a: Element, b: Element) Element {
    return Secp256k1.add(a, b.neg());
}

/// Point negation -e.
pub fn elementNegate(e: Element) Element {
    return e.neg();
}

/// Scalar multiplication e * s; identity on failure (shouldn't happen for
/// valid inputs).
pub fn elementScalarMul(element: Element, scalar: Scalar) Element {
    const scalar_bytes = scalar.toBytes(.big);
    return element.mul(scalar_bytes, .big) catch identity();
}

/// Base-point multiplication G * s; identity on failure.
pub fn elementScalarBaseMul(scalar: Scalar) Element {
    const scalar_bytes = scalar.toBytes(.big);
    return generator().mul(scalar_bytes, .big) catch identity();
}

/// True iff e is the point at infinity.
pub fn elementIsIdentity(e: Element) bool {
    return Secp256k1.equivalent(e, Secp256k1.identityElement);
}

/// Point equality (constant-time via the scalar/point type's equivalent()).
pub fn elementEql(a: Element, b: Element) bool {
    return a.equivalent(b);
}
