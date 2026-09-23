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
//!
//! Compatible with both the pre-0.16.0-stable `std.testing.fuzz` API (callback
//! takes `[]const u8`) and the stable Smith-based API (callback takes
//! `*std.testing.Smith`).
const std = @import("std");
const frost = @import("bsvz-frost");

/// Stable 0.16.0+ / 0.17.0 pass a Smith; older 0.16.0-dev snapshots pass raw bytes.
const has_smith = @hasDecl(std.testing, "Smith");

/// Callback parameter type for std.testing.fuzz on this toolchain.
const FuzzInput = if (has_smith) *std.testing.Smith else []const u8;

/// Materialize a byte buffer from a fuzz callback argument.
/// Smith mode: drains corpus bytes when present, otherwise asks Smith to fill.
fn inputBytes(input: FuzzInput, buf: []u8) []const u8 {
    if (comptime has_smith) {
        if (input.in) |in| {
            const n = @min(in.len, buf.len);
            @memcpy(buf[0..n], in[0..n]);
            input.in = in[n..];
            return buf[0..n];
        }
        // Coverage-fuzz mode (no preset corpus): generate a full buffer.
        input.bytes(buf);
        return buf;
    }
    return input[0..@min(input.len, buf.len)];
}

/// Deserialize every fixed-width wire type from the input buffer.
fn fuzzDeserializers(allocator: std.mem.Allocator, input: FuzzInput) anyerror!void {
    _ = allocator;
    var buf: [128]u8 = undefined;
    const input_data = inputBytes(input, &buf);
    // 32-byte scalar types.
    if (input_data.len >= 32) {
        const bytes = input_data[0..32].*;
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
        _ = frost.Ciphersuite.H1(input_data[0..32]);
        _ = frost.Ciphersuite.H2(input_data[0..32]);
        _ = frost.Ciphersuite.H3(input_data[0..32]);
    }
    // 33-byte element types.
    if (input_data.len >= 33) {
        const bytes = input_data[0..33].*;
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
    if (input_data.len >= 65) {
        const bytes = input_data[0..65].*;
        if (frost.Signature.deserialize(bytes)) |sig| {
            const out = try sig.serialize();
            try std.testing.expectEqualSlices(u8, &bytes, &out);
        } else |_| {}
    }
}

/// Hash functions must accept arbitrary bytes without panicking.
fn fuzzHashFunctions(allocator: std.mem.Allocator, input: FuzzInput) anyerror!void {
    _ = allocator;
    var buf: [256]u8 = undefined;
    const data = inputBytes(input, &buf);
    _ = frost.Ciphersuite.H1(data);
    _ = frost.Ciphersuite.H2(data);
    _ = frost.Ciphersuite.H3(data);
    _ = frost.Ciphersuite.H4(data);
    _ = frost.Ciphersuite.H5(data);
    _ = frost.Ciphersuite.HDKG(data);
    _ = frost.Ciphersuite.HID(data);
}

/// The byte-scalar arithmetic must behave like arithmetic (never trap on
/// arbitrary canonical inputs).
fn fuzzScalarOps(allocator: std.mem.Allocator, input: FuzzInput) anyerror!void {
    _ = allocator;
    var buf: [64]u8 = undefined;
    const data = inputBytes(input, &buf);
    if (data.len < 64) return;
    const a = data[0..32].*;
    const b = data[32..64].*;
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
