//! bsvz-frost unit tests
const std = @import("std");
const frost = @import("bsvz-frost");
const bsvz = @import("bsvz");
const Secp256k1 = std.crypto.ecc.Secp256k1;

test "bsvz dependency links" {
    const g = try bsvz.crypto.Point.basePointMul(@as([32]u8, @splat(0)));
    try std.testing.expect(g.isIdentity());
}

test "identifier creation" {
    const id1 = try frost.Identifier.fromU16(1);
    try std.testing.expectEqual(id1.toU16(), 1);
    const id2 = try frost.Identifier.fromU16(65535);
    try std.testing.expectEqual(id2.toU16(), 65535);
    try std.testing.expectError(frost.Error.InvalidMinSigners, frost.Identifier.fromU16(0));
}

test "identifier derivation" {
    const cases = [_]struct {
        input: []const u8,
        expected: [32]u8,
    }{
        .{ .input = "username1", .expected = [_]u8{ 0x14, 0x61, 0x64, 0x99, 0xa1, 0xe9, 0x0c, 0xaa, 0xf7, 0xef, 0x3e, 0xd5, 0x1e, 0x50, 0x04, 0x69, 0x1f, 0x87, 0x4b, 0xc9, 0xec, 0xfe, 0x42, 0xfb, 0x69, 0x7b, 0x74, 0xdd, 0x72, 0x1d, 0xc9, 0x9a } },
        .{ .input = "username2", .expected = [_]u8{ 0x6e, 0x5e, 0x6f, 0xc3, 0x96, 0x0b, 0x3c, 0x96, 0xce, 0x28, 0x34, 0x09, 0xf5, 0x56, 0xfc, 0x45, 0x49, 0x0d, 0x29, 0xcb, 0x19, 0x7e, 0xbb, 0xa1, 0x3e, 0xa6, 0x26, 0xa9, 0x42, 0x89, 0x6e, 0x69 } },
        .{ .input = "alice@example.com", .expected = [_]u8{ 0x96, 0x1c, 0xce, 0x17, 0x5d, 0xd5, 0xf9, 0x86, 0x4d, 0x7f, 0x25, 0x5d, 0x5a, 0xa9, 0xe8, 0xcf, 0x4e, 0x51, 0x3f, 0x8a, 0x57, 0xdf, 0x7b, 0xcb, 0x0d, 0xd4, 0x47, 0x93, 0xc1, 0x89, 0x80, 0xc7 } },
    };
    for (cases) |case| {
        const id = try frost.Identifier.derive(case.input);
        try std.testing.expectEqualSlices(u8, &case.expected, &id.serialize());
    }
    const id1 = try frost.Identifier.derive("username1");
    const id2 = try frost.Identifier.derive("username2");
    try std.testing.expect(id1.lessThan(id2) or id2.lessThan(id1));
}

test "signing key generation" {
    const sk = frost.SigningKey.generate();
    try std.testing.expect(!sk.scalar.isZero());
    const vk = frost.VerifyingKey.fromSigningKey(sk);
    try std.testing.expect(!frost.group.elementIsIdentity(vk.element));
}

test "single schnorr signature" {
    const sk = frost.SigningKey.generate();
    const vk = frost.VerifyingKey.fromSigningKey(sk);
    const msg = "test message";
    const sig = try sk.sign(msg);
    try vk.verify(msg, sig);
}

test "trusted dealer keygen" {
    const max_signers: u16 = 3;
    const min_signers: u16 = 2;
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    const shares, const pubkey = try frost.keys.generateWithDealer(max_signers, min_signers, identifiers);
    defer std.heap.page_allocator.free(shares);

    try std.testing.expectEqual(pubkey.maxSigners(), max_signers);
    try std.testing.expectEqual(pubkey.min_signers.?, min_signers);

    // Verify each share
    for (shares) |share| {
        const kp = try frost.KeyPackage.fromSecretShare(share);
        try std.testing.expect(!kp.signing_share.toScalar().isZero());
    }
}

test "full frost 3-of-5 signing" {
    const max_signers: u16 = 5;
    const min_signers: u16 = 3;
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    const shares, const pubkey = try frost.keys.generateWithDealer(max_signers, min_signers, identifiers);
    defer std.heap.page_allocator.free(shares);

    var key_packages = try std.heap.page_allocator.alloc(frost.KeyPackage, max_signers);
    defer std.heap.page_allocator.free(key_packages);
    for (shares, 0..) |share, i| {
        key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
    }

    const allocator = std.testing.allocator;
    const sig = try frost.fullFrostSign(allocator, "hello frost", key_packages, &pubkey, min_signers);
    try pubkey.verifying_key.verify("hello frost", sig);
}

test "serialize/deserialize scalar" {
    const s = frost.field.scalarRandom();
    const bytes = frost.field.scalarSerialize(s);
    const s2 = try frost.field.scalarDeserialize(bytes);
    try std.testing.expect(s.equivalent(s2));
}

test "serialize/deserialize element" {
    const e = frost.group.generator();
    const bytes = try frost.group.elementSerialize(e);
    const e2 = try frost.group.elementDeserialize(bytes);
    try std.testing.expect(e.equivalent(e2));
}

test "lagrange coefficient computation" {
    const id1 = try frost.Identifier.fromU16(1);
    const id2 = try frost.Identifier.fromU16(2);
    const id3 = try frost.Identifier.fromU16(3);
    const ids = &[_]frost.Identifier{ id1, id2, id3 };
    const lambda = try frost.keys.computeLagrangeCoefficient(ids, id1);
    try std.testing.expect(!lambda.isZero());
}

test "secret reconstruction" {
    const max_signers: u16 = 5;
    const min_signers: u16 = 3;
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    const shares, const pubkey = try frost.keys.generateWithDealer(max_signers, min_signers, identifiers);
    defer std.heap.page_allocator.free(shares);

    var key_packages = try std.heap.page_allocator.alloc(frost.KeyPackage, max_signers);
    defer std.heap.page_allocator.free(key_packages);
    for (shares, 0..) |share, i| {
        key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
    }

    const reconstructed = try frost.keys.reconstruct(key_packages[0..min_signers]);
    // The reconstructed key should produce the same verifying key
    const reconstructed_vk = frost.VerifyingKey.fromSigningKey(reconstructed);
    try std.testing.expect(reconstructed_vk.element.equivalent(pubkey.verifying_key.element));
}

test "nonce determinism from random bytes" {
    const sk = frost.SigningKey.generate();
    const share = frost.SigningShare.fromScalar(sk.scalar);
    const random_bytes = @as([32]u8, @splat(0xAB));
    const n1 = frost.Nonce.nonceGenerateFromRandomBytes(&share, random_bytes);
    const n2 = frost.Nonce.nonceGenerateFromRandomBytes(&share, random_bytes);
    try std.testing.expect(n1.toScalar().equivalent(n2.toScalar()));
}

test "hash functions produce non-zero scalars" {
    const h1 = frost.Ciphersuite.H1("test");
    const h2 = frost.Ciphersuite.H2("test");
    const h3 = frost.Ciphersuite.H3("test");
    try std.testing.expect(!h1.isZero());
    try std.testing.expect(!h2.isZero());
    try std.testing.expect(!h3.isZero());
}

test "runFullDkg ceremony produces agreeing participants and a valid signature" {
    const allocator = std.testing.allocator;
    const identifiers = try frost.keys.defaultIdentifiers(3);
    defer std.heap.page_allocator.free(identifiers);

    var ceremony = try frost.runFullDkg(allocator, identifiers, 2);
    defer ceremony.deinit();

    try std.testing.expectEqual(@as(usize, 3), ceremony.participants.len);
    for (ceremony.participants) |p| {
        try std.testing.expect(p.verifying_key.equivalent(ceremony.public_key_package.verifying_key.element));
        try p.verifyShare();
    }

    // Two-round signing through the participant state machine (2-of-3).
    const nonces0 = ceremony.participants[0].round1Commit();
    const nonces1 = ceremony.participants[1].round1Commit();
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    try commitments.put(ceremony.participants[0].identifier, nonces0.commitments);
    try commitments.put(ceremony.participants[1].identifier, nonces1.commitments);
    const message = "frost participant state machine";
    const signing_package = frost.SigningPackage.new(commitments, message);
    const share0 = try ceremony.participants[0].round2Sign(&signing_package, &nonces0);
    const share1 = try ceremony.participants[1].round2Sign(&signing_package, &nonces1);
    var shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer shares.deinit();
    try shares.put(ceremony.participants[0].identifier, share0);
    try shares.put(ceremony.participants[1].identifier, share1);
    const signature = try frost.aggregate.aggregateSimple(&signing_package, shares, &ceremony.public_key_package);
    try ceremony.public_key_package.verifying_key.verify(message, signature);
}

test "FrostParticipant.init wraps a key package and rejects bad thresholds" {
    const allocator = std.testing.allocator;
    const identifiers = try frost.keys.defaultIdentifiers(3);
    defer std.heap.page_allocator.free(identifiers);
    const shares, var pubkey = try frost.keys.generateWithDealer(3, 2, identifiers);
    defer {
        std.heap.page_allocator.free(shares);
        pubkey.verifying_shares.deinit();
    }

    const kp = try frost.KeyPackage.fromSecretShare(shares[0]);
    const participant = try frost.FrostParticipant.init(allocator, &kp);
    defer participant.deinit();
    try std.testing.expect(participant.identifier.eql(kp.identifier));
    try participant.verifyShare();

    var bad_kp = kp;
    bad_kp.min_signers = 1;
    try std.testing.expectError(frost.Error.InvalidMinSigners, frost.FrostParticipant.init(allocator, &bad_kp));
}

test "dkg part3 identifiable abort names the share cheater" {
    const allocator = std.testing.allocator;
    const max_signers: u16 = 3;
    const min_signers: u16 = 2;
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    // Round 1 for all participants.
    var r1_secrets: [3]frost.dkg.round1.SecretPackage = undefined;
    var r1_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
    defer r1_packages.deinit();
    for (identifiers, 0..) |id, i| {
        const secret, const broadcast = try frost.dkg.part1(id, max_signers, min_signers);
        r1_secrets[i] = secret;
        try r1_packages.put(id, broadcast);
    }
    defer {
        for (&r1_secrets) |*sp| sp.deinit();
        var it = r1_packages.valueIterator();
        while (it.next()) |p| p.deinit();
    }

    // Round 2: every participant produces outgoing shares.
    var r2_secrets: [3]frost.dkg.round2.SecretPackage = undefined;
    var outgoing: [3]std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package) = undefined;
    for (&outgoing) |*m| m.* = std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package).init(allocator);
    defer {
        for (&r2_secrets) |*sp| sp.deinit();
        for (&outgoing) |*m| m.deinit();
    }
    for (0..3) |i| {
        var others = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
        defer others.deinit();
        for (identifiers) |id| {
            if (id.eql(identifiers[i])) continue;
            try others.put(id, r1_packages.get(id).?);
        }
        switch (try frost.dkg.part2(&r1_secrets[i], &others, allocator)) {
            .ok => |ok| {
                r2_secrets[i] = ok.secret_package;
                outgoing[i] = ok.outgoing;
            },
            .cheaters => |ids| {
                allocator.free(ids);
                return error.UnexpectedCheater;
            },
        }
    }

    // Participant 0 receives a tampered share from participant 1 (identifier
    // 2) and an honest share from participant 2.
    var incoming = std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package).init(allocator);
    defer incoming.deinit();
    for (1..3) |j| {
        var pkg = outgoing[j].get(identifiers[0]).?;
        if (j == 1) {
            // Corrupt the share so it no longer matches the VSS commitment.
            pkg.signing_share = frost.SigningShare.fromScalar(
                frost.field.scalarAdd(pkg.signing_share.scalar, frost.field.scalarOne()),
            );
        }
        try incoming.put(identifiers[j], pkg);
    }
    var r1_others = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
    defer r1_others.deinit();
    for (1..3) |j| {
        try r1_others.put(identifiers[j], r1_packages.get(identifiers[j]).?);
    }

    switch (try frost.dkg.part3(&r2_secrets[0], &r1_others, &incoming, allocator)) {
        .cheaters => |cheater_ids| {
            defer allocator.free(cheater_ids);
            try std.testing.expectEqual(@as(usize, 1), cheater_ids.len);
            try std.testing.expect(cheater_ids[0].eql(identifiers[1]));
        },
        .ok => return error.ExpectedIdentifiableAbort,
    }
}
