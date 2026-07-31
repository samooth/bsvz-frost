const std = @import("std");
const frost = @import("bsvz-frost");

test "shamir split and reconstruct 2-of-3" {
    const secret = frost.scalar.fromInt(12345);
    const shares = try frost.shamir.split(secret, 2, 3, std.testing.allocator);
    defer std.testing.allocator.free(shares);

    // Reconstruct from shares 1 and 2
    const subset = &[_]frost.Share{ shares[0], shares[1] };
    const recovered = frost.shamir.reconstruct(subset);
    try std.testing.expect(frost.scalar.eq(secret, recovered));

    // Reconstruct from shares 1 and 3
    const subset2 = &[_]frost.Share{ shares[0], shares[2] };
    const recovered2 = frost.shamir.reconstruct(subset2);
    try std.testing.expect(frost.scalar.eq(secret, recovered2));
}

test "shamir split and reconstruct 3-of-5" {
    const secret = frost.scalar.fromInt(99999);
    const shares = try frost.shamir.split(secret, 3, 5, std.testing.allocator);
    defer std.testing.allocator.free(shares);

    const subset = &[_]frost.Share{ shares[0], shares[2], shares[4] };
    const recovered = frost.shamir.reconstruct(subset);
    try std.testing.expect(frost.scalar.eq(secret, recovered));
}
