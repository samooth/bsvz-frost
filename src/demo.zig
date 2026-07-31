//! Demo: Trusted dealer keygen + 2-round FROST signing
const std = @import("std");
const frost = @import("bsvz-frost");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const max_signers: u16 = 5;
    const min_signers: u16 = 3;

    std.debug.print("\n=== bsvz-frost Demo ===\n", .{});
    std.debug.print("FROST(secp256k1, SHA-256) threshold signature\n", .{});
    std.debug.print("Max signers: {d}, Min signers: {d}\n\n", .{ max_signers, min_signers });

    // 1. Trusted dealer key generation
    std.debug.print("[1] Trusted Dealer Key Generation\n", .{});
    const identifiers = try frost.keys.defaultIdentifiers(max_signers);
    defer std.heap.page_allocator.free(identifiers);

    const secret_shares, const pubkey_package = try frost.keys.generateWithDealer(
        max_signers,
        min_signers,
        identifiers,
    );
    defer std.heap.page_allocator.free(secret_shares);

    std.debug.print("    Group verifying key generated\n", .{});

    // 2. Each participant verifies their share and creates a KeyPackage
    std.debug.print("[2] Participants verify shares and create KeyPackages\n", .{});
    var key_packages = try allocator.alloc(frost.KeyPackage, max_signers);
    defer allocator.free(key_packages);

    for (secret_shares, 0..) |share, i| {
        key_packages[i] = try frost.KeyPackage.fromSecretShare(share);
        std.debug.print("    Participant {d}: share verified\n", .{i + 1});
    }

    // 3. Round 1: Participants generate nonces and commitments
    std.debug.print("[3] Round 1: Nonce & Commitment Generation\n", .{});
    var commitments = std.AutoHashMap(frost.Identifier, frost.SigningCommitments).init(allocator);
    defer commitments.deinit();
    var nonces_map = std.AutoHashMap(frost.Identifier, frost.SigningNonces).init(allocator);
    defer nonces_map.deinit();

    for (key_packages[0..min_signers]) |kp| {
        const nonces, const comm = frost.round1.commit(&kp.signing_share);
        try commitments.put(kp.identifier, comm);
        try nonces_map.put(kp.identifier, nonces);
        std.debug.print("    Participant {d}: committed\n", .{kp.identifier.toU16()});
    }

    // 4. Coordinator creates SigningPackage
    std.debug.print("[4] Coordinator assembles SigningPackage\n", .{});
    const message = "message to sign";
    const signing_package = frost.SigningPackage.new(commitments, message);
    std.debug.print("    Message: \"{s}\"\n", .{message});

    // 5. Round 2: Each participant generates signature share
    std.debug.print("[5] Round 2: Signature Share Generation\n", .{});
    var signature_shares = std.AutoHashMap(frost.Identifier, frost.SignatureShare).init(allocator);
    defer signature_shares.deinit();

    for (key_packages[0..min_signers]) |kp| {
        const nonces = nonces_map.get(kp.identifier) orelse return error.MissingCommitment;
        const share = try frost.round2.sign(&signing_package, &nonces, &kp);
        try signature_shares.put(kp.identifier, share);
        std.debug.print("    Participant {d}: share generated\n", .{kp.identifier.toU16()});
    }

    // 6. Coordinator aggregates signature shares
    std.debug.print("[6] Aggregation\n", .{});
    const signature = try frost.aggregate.aggregateSimple(
        &signing_package,
        signature_shares,
        &pubkey_package,
    );
    std.debug.print("    Signature aggregated successfully\n", .{});

    // 7. Verify the aggregate signature
    std.debug.print("[7] Verification\n", .{});
    try pubkey_package.verifying_key.verify(message, signature);
    std.debug.print("    Signature VALID!\n", .{});

    // 8. Demonstrate single signing for comparison
    std.debug.print("\n[8] Single (non-threshold) Schnorr signature\n", .{});
    const single_key = frost.SigningKey.generate();
    const single_sig = try single_key.sign(message);
    const single_vk = frost.VerifyingKey.fromSigningKey(single_key);
    try single_vk.verify(message, single_sig);
    std.debug.print("    Single signature VALID!\n", .{});

    std.debug.print("\n=== Demo Complete ===\n", .{});
}
