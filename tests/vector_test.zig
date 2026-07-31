//! Interop test against the official ZcashFoundation/frost-secp256k1 test
//! vectors (tests/helpers/vectors.json in the frost repo).
const std = @import("std");
const frost = @import("bsvz-frost");

const allocator = std.testing.allocator;

fn fromHex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (0..n) |i| {
        out[i] = (std.fmt.charToDigit(s[i * 2], 16) catch unreachable) * 16 + (std.fmt.charToDigit(s[i * 2 + 1], 16) catch unreachable);
    }
    return out;
}

fn expectHex(comptime n: usize, s: []const u8, actual: []const u8) !void {
    const expected = fromHex(n, s);
    try std.testing.expectEqualSlices(u8, &expected, actual);
}

test "Zcash frost-secp256k1 vectors.json end-to-end" {
    // -- inputs --
    const group_secret_hex = "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114";
    const verifying_key_hex = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f";
    const message_hex = "74657374";

    const share1_hex = "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c";
    const share3_hex = "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc";

    const hiding_rand1_hex = "bda8e748e599187762cff956f03dc6ea13fc8e04491a0427b7e6e78600f41c52";
    const binding_rand1_hex = "2ca682429bf05df435b9927b8edb1d748278f3e42fa11ef358e49bbf4a1b780d";
    const hiding_rand3_hex = "70818dd5170672c4a4285fd593d4f222417f941f3118e1244955e7a1098a35d8";
    const binding_rand3_hex = "74ca2da071ed4a2a6cad5087d6758b48a558ab5861c61117fee05757e4b1309e";

    const hiding_nonce1_hex = "09764379667f9a9fa61928947bd925a7f162b21886b750d3b11c226d16b32f58";
    const binding_nonce1_hex = "b2d3f8cb9da70984354c3fc3511b1f6ed21b7205941cb5553565d2ecade8c694";
    const hiding_nonce3_hex = "0d92e255e5b42ebc2863f8198d946fc10f388c4983073c18cbb77b88e3bf2e34";
    const binding_nonce3_hex = "1c7243ce00a499b1e7ce3403e7b731d0c820cf108feb8c5ee7c29b4ef43be5e0";

    const hiding_comm1_hex = "0305e62a1d3f57a0b17ade569a3a4043e2a1fc3bd0b102614a8d8cc68e3322ad89";
    const binding_comm1_hex = "03b634c2aed7f85b8eec22e97e5f916ab43a3518821480e15da2af7cffcb060a30";
    const hiding_comm3_hex = "036f878da0dc19ba7da9f2d9e795e2674e62ff06c990fc4464cc1ed55a2acce46b";
    const binding_comm3_hex = "025350e2a9e32e7b1fe0161e990623600b2d301b3307641469129cff7936c4d2ce";

    const bfi1_hex = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fcfac8df6fa81b3f4d9ced4be2474894308232dc0be75dbf81f5a103579a8236310000000000000000000000000000000000000000000000000000000000000001";
    const bfi3_hex = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fcfac8df6fa81b3f4d9ced4be2474894308232dc0be75dbf81f5a103579a8236310000000000000000000000000000000000000000000000000000000000000003";

    const binding_factor1_hex = "9bee5aef4012de4b94c9fc1a9a9572181079e293bf1d7545a5af0ef86f824a91";
    const binding_factor3_hex = "cfe0db2197c94cc355b6ab05610f27f4a874898009c8bf007f2a4e2ce2c8306d";

    const sig_share1_hex = "ca54b18d7449377cfa680760a5770b9e64e201f7ea36b068effeca5fce2155e5";
    const sig_share3_hex = "da13d054e83052568706a6d161d80f112a6bc3f76aa903c022585ae7e091e65e";

    const final_sig_hex = "024c1ad4e031872661fa6ebd05dfc7fb30db08b38d79f0edbc82051ae931381bc6a46881e25c7989d3816eae32074f1ab0d49ee908a59713ed5284c6bade7cfb02";

    // 1. Group public key matches G * secret.
    const secret_scalar = try frost.SigningKey.deserialize(fromHex(32, group_secret_hex));
    const vk = frost.VerifyingKey.fromSigningKey(secret_scalar);
    try expectHex(33, verifying_key_hex, &(try vk.serialize()));

    // 2. Key packages for participants 1 and 3 (shares from the vector).
    const id1 = try frost.Identifier.fromU16(1);
    const id3 = try frost.Identifier.fromU16(3);
    const min_signers: u16 = 2;

    const share1 = try frost.SigningShare.deserialize(fromHex(32, share1_hex));
    const share3 = try frost.SigningShare.deserialize(fromHex(32, share3_hex));

    const kp1 = frost.KeyPackage{
        .identifier = id1,
        .signing_share = share1,
        .verifying_share = frost.VerifyingShare.fromSigningShare(share1),
        .verifying_key = vk,
        .min_signers = min_signers,
    };
    const kp3 = frost.KeyPackage{
        .identifier = id3,
        .signing_share = share3,
        .verifying_share = frost.VerifyingShare.fromSigningShare(share3),
        .verifying_key = vk,
        .min_signers = min_signers,
    };

    // 3. Round 1: nonces derived from the vector randomness must match.
    const hiding1 = frost.Nonce.nonceGenerateFromRandomBytes(&share1, fromHex(32, hiding_rand1_hex));
    const binding1 = frost.Nonce.nonceGenerateFromRandomBytes(&share1, fromHex(32, binding_rand1_hex));
    const hiding3 = frost.Nonce.nonceGenerateFromRandomBytes(&share3, fromHex(32, hiding_rand3_hex));
    const binding3 = frost.Nonce.nonceGenerateFromRandomBytes(&share3, fromHex(32, binding_rand3_hex));

    try expectHex(32, hiding_nonce1_hex, &hiding1.serialize());
    try expectHex(32, binding_nonce1_hex, &binding1.serialize());
    try expectHex(32, hiding_nonce3_hex, &hiding3.serialize());
    try expectHex(32, binding_nonce3_hex, &binding3.serialize());

    const nonces1 = frost.SigningNonces.fromNonces(hiding1, binding1);
    const nonces3 = frost.SigningNonces.fromNonces(hiding3, binding3);

    // 4. Commitments match.
    try expectHex(33, hiding_comm1_hex, &(try nonces1.commitments.hiding.serialize()));
    try expectHex(33, binding_comm1_hex, &(try nonces1.commitments.binding.serialize()));
    try expectHex(33, hiding_comm3_hex, &(try nonces3.commitments.hiding.serialize()));
    try expectHex(33, binding_comm3_hex, &(try nonces3.commitments.binding.serialize()));

    // 5. Signing package (commitments sorted by identifier).
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    try commitments.put(id1, nonces1.commitments);
    try commitments.put(id3, nonces3.commitments);
    const message = fromHex(4, message_hex);
    const signing_package = frost.SigningPackage.new(commitments, &message);

    // 6. Binding factor preimages and factors must match the vector.
    var bfi = try signing_package.bindingFactorPreimages(&vk, allocator);
    defer {
        var it = bfi.valueIterator();
        while (it.next()) |p| allocator.free(p.*);
        bfi.deinit();
    }
    try expectHex(129, bfi1_hex, bfi.get(id1).?);
    try expectHex(129, bfi3_hex, bfi.get(id3).?);

    var bfs = try frost.round2.computeBindingFactorList(&signing_package, &vk, allocator);
    defer bfs.deinit();
    try expectHex(32, binding_factor1_hex, &bfs.get(id1).?.toBytes(.big));
    try expectHex(32, binding_factor3_hex, &bfs.get(id3).?.toBytes(.big));

    // 7. Signature shares must match.
    const share_sig1 = try frost.round2.sign(&signing_package, &nonces1, &kp1);
    const share_sig3 = try frost.round2.sign(&signing_package, &nonces3, &kp3);
    try expectHex(32, sig_share1_hex, &share_sig1.serialize());
    try expectHex(32, sig_share3_hex, &share_sig3.serialize());

    // 8. Aggregate and verify against the final signature bytes.
    var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer signature_shares.deinit();
    try signature_shares.put(id1, share_sig1);
    try signature_shares.put(id3, share_sig3);

    var verifying_shares = std.AutoHashMap(frost.Identifier, frost.VerifyingShare).init(allocator);
    defer verifying_shares.deinit();
    try verifying_shares.put(id1, kp1.verifying_share);
    try verifying_shares.put(id3, kp3.verifying_share);

    const pubkey_package = frost.PublicKeyPackage{
        .verifying_shares = verifying_shares,
        .verifying_key = vk,
        .min_signers = min_signers,
    };
    const sig = try frost.aggregate.aggregateSimple(&signing_package, signature_shares, &pubkey_package);

    try expectHex(65, final_sig_hex, &(try sig.serialize()));
    try pubkey_package.verifying_key.verify(&message, sig);
}

test "Zcash vectors.json binding factor preimage uses H4 and H5" {
    // Cross-check H4/H5 against the values embedded in the vector's
    // binding_factor_input for identifier 1.
    const expected_h4 = "ff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc";
    const expected_h5 = "fac8df6fa81b3f4d9ced4be2474894308232dc0be75dbf81f5a103579a823631";
    const h4 = frost.Ciphersuite.H4(&fromHex(4, "74657374"));
    try expectHex(32, expected_h4, &h4);
    const h5 = frost.Ciphersuite.H5(&fromHex(196, "00000000000000000000000000000000000000000000000000000000000000010305e62a1d3f57a0b17ade569a3a4043e2a1fc3bd0b102614a8d8cc68e3322ad8903b634c2aed7f85b8eec22e97e5f916ab43a3518821480e15da2af7cffcb060a300000000000000000000000000000000000000000000000000000000000000003036f878da0dc19ba7da9f2d9e795e2674e62ff06c990fc4464cc1ed55a2acce46b025350e2a9e32e7b1fe0161e990623600b2d301b3307641469129cff7936c4d2ce"));
    try expectHex(32, expected_h5, &h5);
}
