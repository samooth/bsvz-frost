//! Group operations for secp256k1
const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const FrostError = @import("error.zig").FrostError;
const field = @import("field.zig");

pub const Element = Secp256k1;
pub const Scalar = field.Scalar;

pub fn identity() Element {
    return Secp256k1.identityElement;
}

pub fn generator() Element {
    return Secp256k1.basePoint;
}

pub fn elementSerialize(element: Element) ![33]u8 {
    if (elementIsIdentity(element)) return FrostError.InvalidIdentityElement;
    return element.toCompressedSec1();
}

pub fn elementDeserialize(bytes: [33]u8) !Element {
    return Secp256k1.fromSec1(&bytes);
}

pub fn elementAdd(a: Element, b: Element) Element {
    return Secp256k1.add(a, b);
}

pub fn elementSub(a: Element, b: Element) Element {
    return Secp256k1.add(a, b.neg());
}

pub fn elementNegate(e: Element) Element {
    return e.neg();
}

pub fn elementScalarMul(element: Element, scalar: Scalar) Element {
    const scalar_bytes = scalar.toBytes(.big);
    return element.mul(scalar_bytes, .big) catch identity();
}

pub fn elementScalarBaseMul(scalar: Scalar) Element {
    const scalar_bytes = scalar.toBytes(.big);
    return generator().mul(scalar_bytes, .big) catch identity();
}

pub fn elementIsIdentity(e: Element) bool {
    return Secp256k1.equivalent(e, Secp256k1.identityElement);
}

pub fn elementEql(a: Element, b: Element) bool {
    return a.equivalent(b);
}
