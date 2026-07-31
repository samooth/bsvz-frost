//! bsvz-frost unit tests
const std = @import("std");
const frost = @import("bsvz-frost");
const bsvz = @import("bsvz");
const Secp256k1 = std.crypto.ecc.Secp256k1;

test "bsvz dependency links" {
    const g = try bsvz.crypto.Point.basePointMul(.{0} ** 32);
    try std.testing.expect(g.isIdentity());
}

test "identifier creation" {
    const id1 = try frost.Identifier.fromU16(1);
    try std.testing.expectEqual(id1.toU16(), 1);
    const id2 = try frost.Identifier.fromU16(65535);
    try std.testing.expectEqual(id2.toU16(), 65535);
    try std.testing.expectError(frost.Error.InvalidMinSigners, frost.Identifier.fromU16(0));
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
    const random_bytes = [_]u8{0xAB} ** 32;
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
