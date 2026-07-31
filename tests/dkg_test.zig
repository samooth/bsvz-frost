//! Functional tests for distributed key generation: full 3-party DKG flow
//! without a trusted dealer, then a threshold signature with the resulting
//! key packages.
const std = @import("std");
const frost = @import("bsvz-frost");

const allocator = std.testing.allocator;

/// Run the full 3-party DKG (t=2, n=3). Each participant keeps its round 1
/// secret package, broadcasts a round 1 package, receives shares in round 2,
/// and finalizes into a KeyPackage + PublicKeyPackage.
const DkgResult = struct {
    key_packages: [3]frost.KeyPackage,
    pubkey_package: frost.PublicKeyPackage,
};

fn runDkg(max_signers: u16, min_signers: u16) !DkgResult {
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    // Round 1: every participant generates its secret package and broadcast
    // package.
    var round1_secret: [3]frost.dkg.round1.SecretPackage = undefined;
    var round1_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
    defer round1_packages.deinit();
    for (identifiers, 0..) |id, i| {
        const secret_pkg, const broadcast = try frost.dkg.part1(id, max_signers, min_signers);
        round1_secret[i] = secret_pkg;
        try round1_packages.put(id, broadcast);
    }
    defer {
        for (&round1_secret) |*sp| sp.deinit();
        var it = round1_packages.valueIterator();
        while (it.next()) |p| p.deinit();
    }

    // Round 2: every participant verifies the other broadcast packages and
    // computes the share to send to each other participant.
    var round2_secret: [3]frost.dkg.round2.SecretPackage = undefined;
    var outgoing = [3]std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package){ .init(allocator), .init(allocator), .init(allocator) };
    defer {
        for (&round2_secret) |*sp| sp.deinit();
        for (&outgoing) |*m| m.deinit();
    }
    for (0..3) |i| {
        var others = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
        defer others.deinit();
        for (identifiers) |id| {
            if (id.eql(round1_secret[i].identifier)) continue;
            try others.put(id, round1_packages.get(id).?);
        }
        const r2_secret, const r2_packages = try frost.dkg.part2(&round1_secret[i], &others, allocator);
        round2_secret[i] = r2_secret;
        outgoing[i] = r2_packages;
    }

    // Round 3: each participant finalizes with the shares it received.
    var key_packages: [3]frost.KeyPackage = undefined;
    var pubkey_package: frost.PublicKeyPackage = undefined;
    for (0..3) |i| {
        var incoming = std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package).init(allocator);
        defer incoming.deinit();
        for (identifiers) |id| {
            if (id.eql(round1_secret[i].identifier)) continue;
            // Participant i receives from participant j the share j computed
            // for i.
            for (0..3) |j| {
                if (round1_secret[j].identifier.eql(id)) {
                    try incoming.put(id, outgoing[j].get(round1_secret[i].identifier).?);
                }
            }
        }
        var r1_others = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
        defer r1_others.deinit();
        for (identifiers) |id| {
            if (id.eql(round1_secret[i].identifier)) continue;
            try r1_others.put(id, round1_packages.get(id).?);
        }

        const kp, var pub_pkg = try frost.dkg.part3(&round2_secret[i], &r1_others, &incoming, allocator);
        key_packages[i] = kp;
        // Keep only the last participant's public key package; all agree.
        if (i < 2) pub_pkg.verifying_shares.deinit();
        pubkey_package = pub_pkg;
    }

    return .{ .key_packages = key_packages, .pubkey_package = pubkey_package };
}

test "DKG 3-party flow produces agreeing key packages and a valid signature" {
    var result = try runDkg(3, 2);
    defer result.pubkey_package.verifying_shares.deinit();

    // All participants agree on the group verifying key.
    for (result.key_packages) |kp| {
        try std.testing.expect(result.pubkey_package.verifying_key.element.equivalent(kp.verifying_key.element));
    }

    // The public key package contains all three verifying shares.
    try std.testing.expectEqual(@as(u16, 3), result.pubkey_package.maxSigners());

    // Threshold sign with participants 0 and 1 (2-of-3).
    const message = "DKG test message";
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    var nonces = std.AutoHashMap(frost.Identifier, frost.SigningNonces).init(allocator);
    defer nonces.deinit();
    for (result.key_packages[0..2]) |kp| {
        const n = frost.SigningNonces.new(&kp.signing_share);
        try commitments.put(kp.identifier, n.commitments);
        try nonces.put(kp.identifier, n);
    }
    const signing_package = frost.SigningPackage.new(commitments, message);

    var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer signature_shares.deinit();
    for (result.key_packages[0..2]) |kp| {
        const n = nonces.get(kp.identifier).?;
        const share = try frost.round2.sign(&signing_package, &n, &kp);
        try signature_shares.put(kp.identifier, share);
    }
    const signature = try frost.aggregate.aggregateSimple(&signing_package, signature_shares, &result.pubkey_package);
    try result.pubkey_package.verifying_key.verify(message, signature);
}

test "DKG key packages allow threshold reconstruction" {
    var result = try runDkg(3, 2);
    defer result.pubkey_package.verifying_shares.deinit();

    const reconstructed = try frost.keys.reconstruct(result.key_packages[0..2]);

    // The reconstructed group secret must verify against the group public key.
    const vk = frost.VerifyingKey.fromSigningKey(reconstructed);
    try std.testing.expect(vk.element.equivalent(result.pubkey_package.verifying_key.element));
}
