//! Negative / property tests: misuse-resistance and failure-path coverage.
//!
//! These complement the happy-path unit tests. Each test asserts that a
//! protocol invariant is *enforced* — wrong subsets, tampered shares,
//! duplicate identifiers, wrong messages, nonce misuse, and malformed inputs
//! must all be rejected, never silently accepted.
const std = @import("std");
const frost = @import("bsvz-frost");

const allocator = std.testing.allocator;

const TestKeygen = struct {
    key_packages: []frost.KeyPackage,
    pubkeys: frost.PublicKeyPackage,
    max_signers: u16,
    min_signers: u16,

    fn deinit(self: *TestKeygen) void {
        allocator.free(self.key_packages);
    }
};

fn testKeygen(max_signers: u16, min_signers: u16) !TestKeygen {
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    const shares, const pubkeys = try frost.keys.generateWithDealer(max_signers, min_signers, identifiers);
    defer std.heap.page_allocator.free(shares);

    const key_packages = try allocator.alloc(frost.KeyPackage, max_signers);
    errdefer allocator.free(key_packages);
    for (shares, 0..) |share, i| {
        key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
    }
    return .{ .key_packages = key_packages, .pubkeys = pubkeys, .max_signers = max_signers, .min_signers = min_signers };
}

/// Run rounds 1+2 over the first `n` key packages; returns the signing
/// package, per-participant nonces, and signature shares.
const Session = struct {
    commitments: std.AutoHashMap(frost.Identifier, frost.SigningCommitments),
    signing_package: frost.round2.SigningPackage,
    nonces: []frost.SigningNonces,
    signature_shares: std.AutoHashMap(frost.Identifier, frost.SignatureShare),

    fn deinit(self: *Session) void {
        allocator.free(self.nonces);
        self.signature_shares.deinit();
        self.commitments.deinit();
    }
};

fn startSession(
    key_packages: []const frost.KeyPackage,
    message: []const u8,
) !Session {
    const n = key_packages.len;
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    errdefer commitments.deinit();
    const nonces = try allocator.alloc(frost.SigningNonces, n);
    errdefer allocator.free(nonces);
    for (key_packages, 0..) |kp, i| {
        const nonce_pair = frost.SigningNonces.new(&kp.signing_share);
        nonces[i] = nonce_pair;
        try commitments.put(kp.identifier, nonce_pair.commitments);
    }
    const signing_package = frost.SigningPackage.new(commitments, message);

    var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    errdefer signature_shares.deinit();
    for (key_packages, 0..) |kp, i| {
        const share = try frost.round2.sign(&signing_package, &nonces[i], &kp);
        try signature_shares.put(kp.identifier, share);
    }
    return .{ .commitments = commitments, .signing_package = signing_package, .nonces = nonces, .signature_shares = signature_shares };
}

fn tamper(sig: frost.SignatureShare) frost.SignatureShare {
    const s = sig.toScalar();
    const one = frost.field.scalarOne();
    return frost.SignatureShare.new(s.add(one));
}

test "duplicate identifiers rejected at keygen" {
    const max_signers: u16 = 3;
    const ids = try allocator.alloc(frost.Identifier, 3);
    defer allocator.free(ids);
    ids[0] = try frost.Identifier.fromU16(1);
    ids[1] = try frost.Identifier.fromU16(1); // duplicate
    ids[2] = try frost.Identifier.fromU16(2);
    const sk = frost.SigningKey.generate();
    try std.testing.expectError(frost.Error.DuplicatedIdentifier, frost.keys.split(&sk, max_signers, 2, ids));
}

test "zero and out-of-range identifiers rejected" {
    try std.testing.expectError(frost.Error.InvalidMinSigners, frost.Identifier.fromU16(0));
    const all_zero = @as([32]u8, @splat(0));
    try std.testing.expectError(frost.Error.InvalidMinSigners, frost.Identifier.deserialize(all_zero));
}

test "wrong participant subset: signing with fewer than threshold fails" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    // Only one commitment in the package: round2.sign must reject.
    const kp0 = kg.key_packages[0];
    const nonces = frost.SigningNonces.new(&kp0.signing_share);
    var single_commitment = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer single_commitment.deinit();
    try single_commitment.put(kp0.identifier, nonces.commitments);
    const pkg = frost.SigningPackage.new(single_commitment, "msg");
    try std.testing.expectError(frost.Error.IncorrectNumberOfCommitments, frost.round2.sign(&pkg, &nonces, &kp0));
}

test "aggregation requires all shares present" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    var session = try startSession(kg.key_packages[0..2], "msg");
    defer session.deinit();

    // Drop one share from the map.
    var reduced = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer reduced.deinit();
    var it = session.signature_shares.iterator();
    _ = it.next();
    while (it.next()) |e| try reduced.put(e.key_ptr.*, e.value_ptr.*);

    try std.testing.expectError(frost.Error.UnknownIdentifier, frost.aggregate.aggregateSimple(&session.signing_package, reduced, &kg.pubkeys));
}

test "aggregation rejects fewer shares than threshold" {
    var kg = try testKeygen(5, 3);
    defer kg.deinit();

    var session = try startSession(kg.key_packages[0..3], "msg");
    defer session.deinit();

    // Keep only 2 shares (below threshold 3). The aggregate must reject it
    // (either because the share count no longer matches the commitment count,
    // or because it is below min_signers).
    var reduced = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer reduced.deinit();
    var it = session.signature_shares.iterator();
    var count: usize = 0;
    while (it.next()) |e| {
        if (count < 2) try reduced.put(e.key_ptr.*, e.value_ptr.*);
        count += 1;
    }

    const result = frost.aggregate.aggregateSimple(&session.signing_package, reduced, &kg.pubkeys);
    try std.testing.expectError(frost.Error.UnknownIdentifier, result);
}

test "tampered signature share invalidates aggregate" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    var session = try startSession(kg.key_packages[0..2], "msg");
    defer session.deinit();

    var tampered_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer tampered_shares.deinit();
    var it = session.signature_shares.iterator();
    while (it.next()) |e| {
        try tampered_shares.put(e.key_ptr.*, tamper(e.value_ptr.*));
    }

    try std.testing.expectError(frost.Error.InvalidSignature, frost.aggregate.aggregateSimple(&session.signing_package, tampered_shares, &kg.pubkeys));
}

test "cheater detection identifies the tampered share" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    var session = try startSession(kg.key_packages[0..2], "msg");
    defer session.deinit();

    // Tamper exactly one share (deterministically: first in the map).
    var tampered_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer tampered_shares.deinit();
    var tampered = false;
    var it = session.signature_shares.iterator();
    while (it.next()) |e| {
        if (!tampered) {
            try tampered_shares.put(e.key_ptr.*, tamper(e.value_ptr.*));
            tampered = true;
        } else {
            try tampered_shares.put(e.key_ptr.*, e.value_ptr.*);
        }
    }

    try std.testing.expectError(frost.Error.InvalidSignatureShare, frost.aggregate.aggregate(&session.signing_package, tampered_shares, &kg.pubkeys, .all_cheaters));
}

test "wrong message fails verification" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    const message = "message to sign";
    var session = try startSession(kg.key_packages[0..2], message);
    defer session.deinit();

    const sig = try frost.aggregate.aggregateSimple(&session.signing_package, session.signature_shares, &kg.pubkeys);
    try kg.pubkeys.verifying_key.verify(message, sig);
    // Signing for one message and verifying another must fail.
    try std.testing.expectError(frost.Error.InvalidSignature, kg.pubkeys.verifying_key.verify("different message", sig));
}

test "mismatched commitment rejected at sign time" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    const kp0 = kg.key_packages[0];
    const kp1 = kg.key_packages[1];

    // Participants commit with one nonce pair...
    const nonces0 = frost.SigningNonces.new(&kp0.signing_share);
    const nonces1 = frost.SigningNonces.new(&kp1.signing_share);
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    try commitments.put(kp0.identifier, nonces0.commitments);
    try commitments.put(kp1.identifier, nonces1.commitments);
    const pkg = frost.SigningPackage.new(commitments, "msg");

    // ...but kp1 tries to sign with a *different* (never committed) nonce pair.
    const wrong_nonces = frost.SigningNonces.new(&kp1.signing_share);
    try std.testing.expectError(frost.Error.InvalidCommitment, frost.round2.sign(&pkg, &wrong_nonces, &kp1));
}

test "nonce reuse across sessions produces distinct commitments and is rejected by verification" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    // Deliberately reuse the same nonces for two different messages.
    const nonces = frost.SigningNonces.new(&kg.key_packages[0].signing_share);
    const kp = kg.key_packages[0];
    const kp1 = kg.key_packages[1];

    // Session A: message1
    var comms_a = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer comms_a.deinit();
    try comms_a.put(kp.identifier, nonces.commitments);
    try comms_a.put(kp1.identifier, frost.SigningNonces.new(&kp1.signing_share).commitments);
    const pkg_a = frost.SigningPackage.new(comms_a, "message1");
    const share_a = try frost.round2.sign(&pkg_a, &nonces, &kp);

    // Session B: message2, same nonces for participant 0.
    var comms_b = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer comms_b.deinit();
    try comms_b.put(kp.identifier, nonces.commitments);
    try comms_b.put(kp1.identifier, frost.SigningNonces.new(&kp1.signing_share).commitments);
    const pkg_b = frost.SigningPackage.new(comms_b, "message2");
    const share_b = try frost.round2.sign(&pkg_b, &nonces, &kp);

    // The two signature shares for participant 0 must differ (different
    // binding factors), and sharing them must NOT verify against the other
    // session's package.
    try std.testing.expect(!share_a.toScalar().equivalent(share_b.toScalar()));

    // Mixing share_a into session B's aggregate must fail.
    var mixed = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer mixed.deinit();
    try mixed.put(kp.identifier, share_a);
    const kp1_nonces_b = frost.SigningNonces.new(&kp1.signing_share);
    var comms_b2 = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer comms_b2.deinit();
    try comms_b2.put(kp.identifier, nonces.commitments);
    try comms_b2.put(kp1.identifier, kp1_nonces_b.commitments);
    const pkg_b2 = frost.SigningPackage.new(comms_b2, "message2");
    try mixed.put(kp1.identifier, try frost.round2.sign(&pkg_b2, &kp1_nonces_b, &kp1));

    try std.testing.expectError(frost.Error.InvalidSignature, frost.aggregate.aggregateSimple(&pkg_b2, mixed, &kg.pubkeys));
}

test "identity commitments rejected" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    const kp0 = kg.key_packages[0];
    const kp1 = kg.key_packages[1];

    const id_comm = frost.NonceCommitment.fromElement(frost.group.identity());
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    try commitments.put(kp0.identifier, frost.SigningCommitments.new(id_comm, id_comm));
    try commitments.put(kp1.identifier, frost.SigningNonces.new(&kp1.signing_share).commitments);
    const pkg = frost.SigningPackage.new(commitments, "msg");

    // Binding-factor computation rejects the identity commitment during
    // encoding (cannot be serialized).
    try std.testing.expectError(frost.Error.InvalidIdentityElement, frost.round2.computeBindingFactorList(&pkg, &kg.pubkeys.verifying_key, allocator));

    // Even with a hand-built binding factor list, computeGroupCommitment must
    // reject identity commitments outright.
    var bfs = std.AutoHashMap(frost.Identifier, frost.field.Scalar).init(allocator);
    defer bfs.deinit();
    try bfs.put(kp0.identifier, frost.field.scalarOne());
    try bfs.put(kp1.identifier, frost.field.scalarOne());
    try std.testing.expectError(frost.Error.IdentityCommitment, frost.round2.computeGroupCommitment(&pkg, bfs));
}

test "malformed scalars rejected" {
    // 2^256 - 1 is above the curve order -> non-canonical.
    const non_canonical = @as([32]u8, @splat(0xFF));
    try std.testing.expectError(error.NonCanonical, frost.SigningShare.deserialize(non_canonical));
    try std.testing.expectError(error.NonCanonical, frost.field.scalarDeserialize(non_canonical));

    // All-zero secret is rejected by SigningKey.
    const zero = @as([32]u8, @splat(0));
    try std.testing.expectError(frost.Error.MalformedSigningKey, frost.SigningKey.deserialize(zero));
}

test "malformed elements rejected" {
    // 0x05 is not a valid SEC1 encoding prefix.
    var invalid = @as([33]u8, @splat(0x05));
    try std.testing.expectError(error.InvalidEncoding, frost.group.elementDeserialize(invalid));
    try std.testing.expectError(error.InvalidEncoding, frost.VerifyingKey.deserialize(invalid));

    // Uncompressed marker (0x04) with a truncated payload.
    invalid = @as([33]u8, @splat(0x04));
    try std.testing.expectError(error.InvalidEncoding, frost.group.elementDeserialize(invalid));
}

test "identity element rejected on serialize" {
    try std.testing.expectError(frost.Error.InvalidIdentityElement, frost.group.elementSerialize(frost.group.identity()));
}

test "reconstruction with insufficient shares fails" {
    var kg = try testKeygen(5, 3);
    defer kg.deinit();
    // Only 2 < 3 key packages.
    try std.testing.expectError(frost.Error.IncorrectNumberOfShares, frost.keys.reconstruct(kg.key_packages[0..2]));
}

test "lagrange coefficient for unknown identifier fails" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();
    const known = &[_]frost.Identifier{ kg.key_packages[0].identifier, kg.key_packages[1].identifier };
    const unknown = try frost.Identifier.fromU16(999);
    try std.testing.expectError(frost.Error.UnknownIdentifier, frost.keys.computeLagrangeCoefficient(known, unknown));
}

test "serialize/deserialize round-trips for all wire types" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    const sk = frost.SigningKey.generate();
    const sk_bytes = sk.serialize();
    try std.testing.expectEqualSlices(u8, &sk_bytes, &(try frost.SigningKey.deserialize(sk_bytes)).serialize());

    const vk = frost.VerifyingKey.fromSigningKey(sk);
    const vk_bytes = try vk.serialize();
    const vk_rt = try (&(try frost.VerifyingKey.deserialize(vk_bytes))).serialize();
    try std.testing.expectEqualSlices(u8, &vk_bytes, &vk_rt);

    const share = kg.key_packages[0].signing_share;
    const share_bytes = share.serialize();
    try std.testing.expectEqualSlices(u8, &share_bytes, &(try frost.SigningShare.deserialize(share_bytes)).serialize());

    const vshare = kg.key_packages[0].verifying_share;
    const vshare_bytes = try vshare.serialize();
    const vshare_rt = try (&(try frost.VerifyingShare.deserialize(vshare_bytes))).serialize();
    try std.testing.expectEqualSlices(u8, &vshare_bytes, &vshare_rt);

    const nonce = frost.Nonce.nonceGenerateFromRandomBytes(&share, @as([32]u8, @splat(0x42)));
    const nonce_bytes = nonce.serialize();
    try std.testing.expectEqualSlices(u8, &nonce_bytes, &(try frost.Nonce.deserialize(nonce_bytes)).serialize());

    const commitment = frost.NonceCommitment.fromNonce(&nonce);
    const comm_bytes = try commitment.serialize();
    const comm_rt = try (&(try frost.NonceCommitment.deserialize(comm_bytes))).serialize();
    try std.testing.expectEqualSlices(u8, &comm_bytes, &comm_rt);

    const sig = try frost.SigningKey.generate().sign("msg");
    const sig_bytes = try sig.serialize();
    const sig_rt = try (&(try frost.Signature.deserialize(sig_bytes))).serialize();
    try std.testing.expectEqualSlices(u8, &sig_bytes, &sig_rt);

    const id = try frost.Identifier.fromU16(7);
    const id_bytes = id.serialize();
    try std.testing.expectEqualSlices(u8, &id_bytes, &(try frost.Identifier.deserialize(id_bytes)).serialize());
}

test "verifySignatureShare rejects tampered share" {
    var kg = try testKeygen(3, 2);
    defer kg.deinit();

    var session = try startSession(kg.key_packages[0..2], "msg");
    defer session.deinit();

    var it = session.signature_shares.iterator();
    const entry = it.next().?;
    const id = entry.key_ptr.*;
    const good = entry.value_ptr.*;
    const vshare = &kg.pubkeys.verifying_shares.get(id).?;

    try frost.aggregate.verifySignatureShare(id, vshare, &good, &session.signing_package, &kg.pubkeys.verifying_key);
    const bad = tamper(good);
    try std.testing.expectError(frost.Error.InvalidSignatureShare, frost.aggregate.verifySignatureShare(id, vshare, &bad, &session.signing_package, &kg.pubkeys.verifying_key));
}
