//! Interop test against the official ZcashFoundation/frost-secp256k1 DKG test
//! vectors (tests/helpers/vectors_dkg.json in the frost repo).
//!
//! The fixture provides, for each participant i in 1..=3 (t=2, n=3): the
//! secret a_{i0}, the extra coefficient, the VSS commitments, the proof of
//! knowledge, the shares f_i(j) sent to each other participant, and the
//! resulting signing share / verifying share. We rebuild the DKG flow from
//! part2 + part3 exactly as the reference `check_dkg_keygen` does and assert
//! byte-for-byte equality of the final KeyPackage and PublicKeyPackage.
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

const Vec = struct {
    identifier: u16,
    signing_key: []const u8,
    coefficient: []const u8,
    vss_commitments: [2][]const u8,
    proof_of_knowledge: []const u8,
    signing_shares: [2][]const u8, // shares sent TO participants {1,2,3}\{self}, ascending
    verifying_share: []const u8,
    signing_share: []const u8,
};

const vectors = [_]Vec{
    .{
        .identifier = 1,
        .signing_key = "e7a3cf1fdb1e17d4c3e8a7f663803ef305d03bdfdc930b824b0664c6b853156d",
        .coefficient = "819adb51466d687c3944f8dad799a09551af9c083c918a50d9a24a883ae86e2a",
        .vss_commitments = .{
            "02dd81b7019efd1d38352b8df26a47d8e6bcb4ce7db71b2f9739b01031105294e2",
            "03cad1d1bc9d75de15ed0b4cb49dbde670d70988aa96d7982a25ee5484c97d3efc",
        },
        .proof_of_knowledge = "0304df6af7f67b0d5f49ea2116f2d561a0a535c184836779f0f0677ff0838740ce20a0cb076384312f8817e030ca20379bab9247ee56fc3576b0b092f01c005691",
        .signing_shares = .{
            "3c4ae6fe69d55280cb06a0551f8563e526ee6f133a99433addcbb722a4c6f438",
            "e2454ec522749fc08388fed9c120b6ada8e1fd1e00026624c95b273f94dbf8a8",
        },
        .verifying_share = "02b2597e19a037ba2eef224402a50652be93c1ab5bbd6195fc07ae6f6ecfa1304d",
        .signing_share = "87cee034add572924bbd40001bbffa1db1f28a4bf52efebb4c2ad0978c71edf5",
    },
    .{
        .identifier = 2,
        .signing_key = "ea163e297661aadf460b3de39a7550bd9b8fb2d07f1e1db5af098720156591a5",
        .coefficient = "5234a8d4f373a7a184fb627185101326460d99296ac3c5c0ee948e8f5f97a3d4",
        .vss_commitments = .{
            "0280709e1bc38ca14a42f04dde31b33308d5a7ed7ef79a87c0cc14200783b519ac",
            "03490b38389a84ea57fde7b369962a92c53b367c221d5cd4728a7c6dfddb337c51",
        },
        .proof_of_knowledge = "02afffa1f80fd46f2bac01bf7967649014a3a5236a62f32f98ce11fec20ee7229072c534d89a6b7b4c16129780404e172c3bdb527a77d40d760b80cc6538bcd4c4",
        .signing_shares = .{
            "ead985c267f8e8cd367299ac12b3801eee809709a66d7fe83e789b4a5dedb080",
            "39ee690094ac23a2373b35714ae7d3dc0e07e380bf547bf71758903d291a3e0b",
        },
        .verifying_share = "03037adc4e0f796b96fc639ac194c1e167ccc5dd57505c813b0533b2bcd6d6ddaa",
        .signing_share = "b3477e9659ee0691bdafd1e40230cb07aed5a5e05bd6649f625f12acbb304556",
    },
    .{
        .identifier = 3,
        .signing_key = "8a9c3489b03d1bdecfd6c84237599980890d39d49167b016bb8b5fb530677204",
        .coefficient = "57a91a3b723783e1b3b2369789c71d2d1fd4c3496e9ab60e0dcfc78a647486a4",
        .vss_commitments = .{
            "03f26b76678fe0174196430bb94e4e688044ae7bae2ccd7fef21c354429eb8bd61",
            "020d7a0d25b4ebed5157daf56aba2b89c3e0522f3bc293cc5e138f10e9c5efa465",
        },
        .proof_of_knowledge = "02ad586ef180cda6bae1d2144ee090d277c77b789c8261349a247073626373cd8723b0ea6a62e8bc37372567ab4ef221d5e0a6c46d57d3746f6e5fde863298a542",
        .signing_shares = .{
            "6c746113ae6651496fb79286ea4d20b58581562b33b669fd58488745c89fdd69",
            "e0b438a850bca1c3d4fd653829a58a31b309a1661020cebcbaf4d44163f63be0",
        },
        .verifying_share = "02f2198ff3f1e1de2249cdc59eb4ec926936892fa39fc1582861ad2e84681624b3",
        .signing_share = "dec01cf806069a912fa263c7e8a19bf1abb8c174c27dca83789354c1e9ee9cb7",
    },
};

const group_vk_hex = "037b5b0c4b6c91a16fb78499e8a74cc792f9ea79cb94860fcb90f801472930de47";

test "Zcash frost-secp256k1 vectors_dkg.json byte-for-byte" {
    const min_signers: u16 = 2;
    const max_signers: u16 = 3;

    // Each participant i sees the other participants' round 1 packages and
    // the round 2 shares sent to i, then finalizes its key package.
    for (vectors) |vi| {
        const self_id = try frost.Identifier.fromU16(vi.identifier);

        // Round 1 packages from the other participants. Each package's
        // commitment coefficients were heap-allocated above.
        var round1_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
        defer {
            var it = round1_packages.valueIterator();
            while (it.next()) |p| allocator.free(p.commitment.coefficients);
            round1_packages.deinit();
        }
        // Round 2 packages (shares sent to i) from the other participants.
        var round2_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round2.Package).init(allocator);
        defer round2_packages.deinit();

        var j: usize = 0;
        for (vectors) |vj| {
            if (vj.identifier == vi.identifier) continue;
            const other_id = try frost.Identifier.fromU16(vj.identifier);

            // Commitments must outlive the loop iteration; heap-allocate them.
            const comm_coeffs = try allocator.alloc(frost.CoefficientCommitment, 2);
            errdefer allocator.free(comm_coeffs);
            comm_coeffs[0] = try frost.CoefficientCommitment.deserialize(fromHex(33, vj.vss_commitments[0]));
            comm_coeffs[1] = try frost.CoefficientCommitment.deserialize(fromHex(33, vj.vss_commitments[1]));
            const commitment = frost.VerifiableSecretSharingCommitment.init(comm_coeffs);
            const sig_bytes = fromHex(65, vj.proof_of_knowledge);
            const proof = try frost.Signature.deserialize(sig_bytes);
            try round1_packages.put(other_id, .{ .commitment = commitment, .proof_of_knowledge = proof });

            const share = try frost.SigningShare.deserialize(fromHex(32, vi.signing_shares[j]));
            try round2_packages.put(other_id, .{ .signing_share = share });
            j += 1;
        }

        // Rebuild the participant's own round 1 secret package: coefficients
        // are [a_{i0}, a_{i1}] and the commitment is regenerated from them.
        const secret = try frost.SigningKey.deserialize(fromHex(32, vi.signing_key));
        var coeffs = [_]frost.field.Scalar{try frost.field.scalarDeserialize(fromHex(32, vi.coefficient))};
        const all_coeffs, const commitment = try frost.keys.generateSecretPolynomial(secret, max_signers, min_signers, &coeffs);
        defer std.heap.page_allocator.free(all_coeffs);
        defer std.heap.page_allocator.free(commitment.coefficients);

        // The regenerated commitment must match the vector's VSS commitments.
        for (commitment.coefficients, 0..) |c, k| {
            try expectHex(33, vi.vss_commitments[k], &(try c.serialize()));
        }

        const round1_secret = frost.dkg.round1.SecretPackage{
            .identifier = self_id,
            .coefficients = all_coeffs,
            .commitment = commitment,
            .min_signers = min_signers,
            .max_signers = max_signers,
        };

        var round2_secret, var outgoing = try frost.dkg.part2(&round1_secret, &round1_packages, allocator);
        defer {
            round2_secret.deinit();
            outgoing.deinit();
        }

        const key_package, var pubkey_package = try frost.dkg.part3(&round2_secret, &round1_packages, &round2_packages, allocator);
        defer pubkey_package.verifying_shares.deinit();

        // Final signing share and verifying share match the vector.
        try expectHex(32, vi.signing_share, &key_package.signing_share.serialize());
        try expectHex(33, vi.verifying_share, &(try key_package.verifying_share.serialize()));
        try expectHex(33, group_vk_hex, &(try pubkey_package.verifying_key.serialize()));

        // Every participant agrees on the group verifying key.
        try std.testing.expectEqual(pubkey_package.verifying_key.element, key_package.verifying_key.element);

        // All verifying shares in the public key package match the vectors.
        var it = pubkey_package.verifying_shares.iterator();
        while (it.next()) |entry| {
            for (vectors) |vk| {
                if (vk.identifier == entry.key_ptr.toU16()) {
                    try expectHex(33, vk.verifying_share, &(try entry.value_ptr.serialize()));
                }
            }
        }
    }
}

test "dkg part2 verifies proof of knowledge" {
    const min_signers: u16 = 2;
    const max_signers: u16 = 3;

    const vi = vectors[0];
    const self_id = try frost.Identifier.fromU16(vi.identifier);

    // Build this participant's own secret package from the vector.
    const secret = try frost.SigningKey.deserialize(fromHex(32, vi.signing_key));
    var coeffs = [_]frost.field.Scalar{try frost.field.scalarDeserialize(fromHex(32, vi.coefficient))};
    const all_coeffs, const commitment = try frost.keys.generateSecretPolynomial(secret, max_signers, min_signers, &coeffs);
    defer std.heap.page_allocator.free(all_coeffs);
    defer std.heap.page_allocator.free(commitment.coefficients);
    const round1_secret = frost.dkg.round1.SecretPackage{
        .identifier = self_id,
        .coefficients = all_coeffs,
        .commitment = commitment,
        .min_signers = min_signers,
        .max_signers = max_signers,
    };

    // Build round 1 packages from participants 2 (tampered PoK) and 3 (valid).
    const vj = vectors[1];
    const vk3 = vectors[2];
    const other_id = try frost.Identifier.fromU16(vj.identifier);
    const other_id3 = try frost.Identifier.fromU16(vk3.identifier);

    const comm_coeffs2 = try allocator.alloc(frost.CoefficientCommitment, 2);
    defer allocator.free(comm_coeffs2);
    comm_coeffs2[0] = try frost.CoefficientCommitment.deserialize(fromHex(33, vj.vss_commitments[0]));
    comm_coeffs2[1] = try frost.CoefficientCommitment.deserialize(fromHex(33, vj.vss_commitments[1]));
    const comm_coeffs3 = try allocator.alloc(frost.CoefficientCommitment, 2);
    defer allocator.free(comm_coeffs3);
    comm_coeffs3[0] = try frost.CoefficientCommitment.deserialize(fromHex(33, vk3.vss_commitments[0]));
    comm_coeffs3[1] = try frost.CoefficientCommitment.deserialize(fromHex(33, vk3.vss_commitments[1]));

    const tampered_proof_bytes = fromHex(65, vj.proof_of_knowledge);
    var tampered_proof = try frost.Signature.deserialize(tampered_proof_bytes);
    tampered_proof.z = tampered_proof.z.add(frost.field.scalarOne());
    const valid_proof = try frost.Signature.deserialize(fromHex(65, vk3.proof_of_knowledge));

    var round1_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
    defer round1_packages.deinit();
    try round1_packages.put(other_id, .{
        .commitment = frost.VerifiableSecretSharingCommitment.init(comm_coeffs2),
        .proof_of_knowledge = tampered_proof,
    });
    try round1_packages.put(other_id3, .{
        .commitment = frost.VerifiableSecretSharingCommitment.init(comm_coeffs3),
        .proof_of_knowledge = valid_proof,
    });

    try std.testing.expectError(frost.Error.InvalidProofOfKnowledge, frost.dkg.part2(&round1_secret, &round1_packages, allocator));
}

test "dkg part2 rejects wrong number of packages" {
    const min_signers: u16 = 2;
    const max_signers: u16 = 3;

    const vi = vectors[0];
    const self_id = try frost.Identifier.fromU16(vi.identifier);
    const secret = try frost.SigningKey.deserialize(fromHex(32, vi.signing_key));
    var coeffs = [_]frost.field.Scalar{try frost.field.scalarDeserialize(fromHex(32, vi.coefficient))};
    const all_coeffs, const commitment = try frost.keys.generateSecretPolynomial(secret, max_signers, min_signers, &coeffs);
    defer std.heap.page_allocator.free(all_coeffs);
    defer std.heap.page_allocator.free(commitment.coefficients);
    const round1_secret = frost.dkg.round1.SecretPackage{
        .identifier = self_id,
        .coefficients = all_coeffs,
        .commitment = commitment,
        .min_signers = min_signers,
        .max_signers = max_signers,
    };

    var round1_packages = std.AutoHashMap(frost.Identifier, frost.dkg.round1.Package).init(allocator);
    defer round1_packages.deinit();

    try std.testing.expectError(frost.Error.IncorrectNumberOfPackages, frost.dkg.part2(&round1_secret, &round1_packages, allocator));
}
