//! Shamir secret sharing over the secp256k1 subgroup order, using byte
//! scalars compatible with the bsvz `crypto.Point` API.
const std = @import("std");
const scalar = @import("scalar.zig");

pub const Share = struct {
    index: u32, // 1-based participant identifier
    value: [32]u8, // big-endian scalar mod the curve order
};

/// Split secret into n shares with threshold t (any t shares reconstruct).
/// Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
pub fn split(secret: [32]u8, threshold: u32, num_shares: u32, allocator: std.mem.Allocator) ![]Share {
    std.debug.assert(threshold >= 1);
    std.debug.assert(num_shares >= threshold);

    var coeffs = try allocator.alloc([32]u8, threshold);
    defer allocator.free(coeffs);
    coeffs[0] = secret;
    for (1..threshold) |i| {
        coeffs[i] = scalar.random();
    }

    var shares = try allocator.alloc(Share, num_shares);
    errdefer allocator.free(shares);

    for (1..num_shares + 1) |x| {
        var y = scalar.zero();
        var x_pow = scalar.one();
        const x_scalar = scalar.fromInt(@intCast(x));
        for (coeffs) |coeff| {
            y = scalar.add(y, scalar.mul(coeff, x_pow));
            x_pow = scalar.mul(x_pow, x_scalar);
        }
        shares[x - 1] = .{ .index = @intCast(x), .value = y };
    }
    return shares;
}

/// Reconstruct secret from any t shares using Lagrange interpolation at x=0.
pub fn reconstruct(shares: []const Share) [32]u8 {
    std.debug.assert(shares.len > 0);
    var secret = scalar.zero();

    for (shares) |share_j| {
        var lambda = scalar.one();
        const xj = scalar.fromInt(share_j.index);

        for (shares) |share_m| {
            if (share_m.index == share_j.index) continue;
            const xm = scalar.fromInt(share_m.index);
            // lambda *= xm / (xm - xj)
            const diff = scalar.sub(xm, xj);
            const term = scalar.mul(xm, scalar.inv(diff));
            lambda = scalar.mul(lambda, term);
        }
        secret = scalar.add(secret, scalar.mul(share_j.value, lambda));
    }
    return secret;
}
