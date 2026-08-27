//! Fuzz targets for deserialization and hash functions.
//!
//! Under `zig build test` these run as smoke tests (empty input + any corpus
//! seeds). Under `zig build --fuzz=NNN` (or `--fuzz` for continuous) they run
//! as coverage-guided libFuzzer targets, mutating inputs to find crashes,
//! leaks, and assertion failures in the library's untrusted-input paths.
//!
//! Property asserted: deserialization never panics, never leaks, never
//! accepts something it later cannot round-trip, and hash functions never
//! produce surprising failures on arbitrary input.
const std = @import("std");
const frost = @import("bsvz-frost");

/// Deserialize every fixed-width wire type from the input buffer.
fn fuzzDeserializers(allocator: std.mem.Allocator, input: []const u8) anyerror!void {
    _ = allocator;
    // 32-byte scalar types.
    if (input.len >= 32) {
        const bytes = input[0..32].*;
        if (frost.SigningKey.deserialize(bytes)) |sk| {
            try std.testing.expectEqualSlices(u8, &bytes, &sk.serialize());
        } else |_| {}
        if (frost.SigningShare.deserialize(bytes)) |s| {
            try std.testing.expectEqualSlices(u8, &bytes, &s.serialize());
        } else |_| {}
        if (frost.SignatureShare.deserialize(bytes)) |s| {
            try std.testing.expectEqualSlices(u8, &bytes, &s.serialize());
        } else |_| {}
        if (frost.Nonce.deserialize(bytes)) |n| {
            try std.testing.expectEqualSlices(u8, &bytes, &n.serialize());
        } else |_| {}
        if (frost.Identifier.deserialize(bytes)) |id| {
            try std.testing.expectEqualSlices(u8, &bytes, &id.serialize());
        } else |_| {}
        _ = frost.Ciphersuite.H1(input[0..32]);
        _ = frost.Ciphersuite.H2(input[0..32]);
        _ = frost.Ciphersuite.H3(input[0..32]);
    }
    // 33-byte element types.
    if (input.len >= 33) {
        const bytes = input[0..33].*;
        if (frost.VerifyingKey.deserialize(bytes)) |vk| {
            const out = try vk.serialize();
            try std.testing.expectEqualSlices(u8, &bytes, &out);
        } else |_| {}
        if (frost.VerifyingShare.deserialize(bytes)) |vs| {
            const out = try vs.serialize();
            try std.testing.expectEqualSlices(u8, &bytes, &out);
        } else |_| {}
        if (frost.NonceCommitment.deserialize(bytes)) |nc| {
            const out = try nc.serialize();
            try std.testing.expectEqualSlices(u8, &bytes, &out);
        } else |_| {}
    }
    // 65-byte signature.
    if (input.len >= 65) {
        const bytes = input[0..65].*;
        if (frost.Signature.deserialize(bytes)) |sig| {
            const out = try sig.serialize();
            try std.testing.expectEqualSlices(u8, &bytes, &out);
        } else |_| {}
    }
}

/// Hash functions must accept arbitrary bytes without panicking.
fn fuzzHashFunctions(allocator: std.mem.Allocator, input: []const u8) anyerror!void {
    _ = allocator;
    _ = frost.Ciphersuite.H1(input);
    _ = frost.Ciphersuite.H2(input);
    _ = frost.Ciphersuite.H3(input);
    _ = frost.Ciphersuite.H4(input);
    _ = frost.Ciphersuite.H5(input);
    _ = frost.Ciphersuite.HDKG(input);
    _ = frost.Ciphersuite.HID(input);
}

/// The byte-scalar arithmetic must behave like arithmetic (never trap on
/// arbitrary canonical inputs).
fn fuzzScalarOps(allocator: std.mem.Allocator, input: []const u8) anyerror!void {
    _ = allocator;
    if (input.len < 64) return;
    const a = input[0..32].*;
    const b = input[32..64].*;
    // Canonicalize so scalar ops have well-defined inputs.
    const ca = frost.scalar.reduce(a);
    const cb = frost.scalar.reduce(b);
    const sum = frost.scalar.add(ca, cb);
    _ = frost.scalar.sub(sum, cb);
    _ = frost.scalar.mul(ca, cb);
    _ = frost.scalar.neg(ca);
    if (!frost.scalar.isZero(ca)) _ = frost.scalar.inv(ca);
}

test "fuzz deserializers" {
    try std.testing.fuzz(std.testing.allocator, fuzzDeserializers, .{});
}

test "fuzz hash functions" {
    try std.testing.fuzz(std.testing.allocator, fuzzHashFunctions, .{});
}

test "fuzz scalar ops" {
    try std.testing.fuzz(std.testing.allocator, fuzzScalarOps, .{});
}
