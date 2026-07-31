const std = @import("std");
const bsvz = @import("bsvz");
const frost = @import("bsvz-frost");

test "naive threshold 2-of-3 sign and verify" {
    const master_secret = frost.scalar.fromInt(42);
    const group_pubkey = try bsvz.crypto.Point.basePointMul(master_secret);

    const shares = try frost.shamir.split(master_secret, 2, 3, std.testing.allocator);
    defer std.testing.allocator.free(shares);

    const message = bsvz.crypto.hash.hash256("test message");

    // Participants 1 and 2 exchange nonce commitments and agree on R
    const nonce1 = frost.scalar.random();
    const nonce2 = frost.scalar.random();
    const R1 = try bsvz.crypto.Point.basePointMul(nonce1);
    const R2 = try bsvz.crypto.Point.basePointMul(nonce2);
    const R = R1.add(R2);

    const participant_ids = &[_]u32{ 1, 2 };
    const ps1 = try frost.naive.partialSign(shares[0].value, nonce1, 1, participant_ids, group_pubkey, R, &message.bytes);
    const ps2 = try frost.naive.partialSign(shares[1].value, nonce2, 2, participant_ids, group_pubkey, R, &message.bytes);

    const sig = frost.naive.aggregate(&[_]frost.naive.PartialSignature{ ps1, ps2 });
    try std.testing.expect(try frost.naive.verify(group_pubkey, &message.bytes, sig));
}

test "naive threshold wrong subset fails" {
    const master_secret = frost.scalar.fromInt(42);
    const group_pubkey = try bsvz.crypto.Point.basePointMul(master_secret);

    const shares = try frost.shamir.split(master_secret, 2, 3, std.testing.allocator);
    defer std.testing.allocator.free(shares);

    const message = bsvz.crypto.hash.hash256("test message");

    // Use the same share twice (participant 1 duplicated — invalid)
    const nonce1 = frost.scalar.random();
    const R1 = try bsvz.crypto.Point.basePointMul(nonce1);
    const R = R1.add(R1);

    const participant_ids = &[_]u32{ 1, 1 };
    const ps1 = try frost.naive.partialSign(shares[0].value, nonce1, 1, participant_ids, group_pubkey, R, &message.bytes);
    const ps_fake = try frost.naive.partialSign(shares[0].value, nonce1, 1, participant_ids, group_pubkey, R, &message.bytes);

    const sig = frost.naive.aggregate(&[_]frost.naive.PartialSignature{ ps1, ps_fake });
    try std.testing.expect(!(try frost.naive.verify(group_pubkey, &message.bytes, sig)));
}
