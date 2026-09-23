//! FROST (Flexible Round-Optimized Schnorr Threshold) participant — RFC 9591.
//!
//! `FrostParticipant` is the high-level per-signer state machine that wires
//! the DKG ceremony (`dkg.part1`/`part2`/`part3`) and the two-round signing
//! ceremony (`round1`/`round2`) into a single object.
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const keys = @import("keys.zig");
const group = @import("group.zig");
const round1 = @import("round1.zig");
const round2 = @import("round2.zig");
const dkg = @import("dkg.zig");

/// A FROST signer holding its long-lived key material.
///
/// Typical signing flow (RFC 9591 two-round ceremony):
///   1. each signer calls `round1Commit` and publishes `nonces.commitments`
///   2. the coordinator collects the commitments into a `round2.SigningPackage`
///   3. each signer calls `round2Sign` with the nonces from step 1 and sends
///      the resulting `round2.SignatureShare` back to the coordinator
///   4. the coordinator aggregates the shares with `aggregate.aggregate`
///
/// SECURITY: the `SigningNonces` from `round1Commit` are valid for exactly
/// one signing session. Reusing them for a second session leaks the signing
/// share. Generate fresh nonces for every message signed.
pub const FrostParticipant = struct {
    allocator: std.mem.Allocator,
    identifier: Identifier,
    signing_share: keys.SigningShare,
    verifying_share: group.Element,
    verifying_key: group.Element,
    min_signers: u16,

    /// Wrap an existing `KeyPackage` (output of `dkg.part3`, `runFullDkg`, or
    /// `keys.KeyPackage.fromSecretShare`). Returns an error instead of
    /// panicking on invalid state; the caller owns the result and must call
    /// `deinit`.
    pub fn init(allocator: std.mem.Allocator, key_package: *const keys.KeyPackage) !*FrostParticipant {
        if (key_package.min_signers < 2) return FrostError.InvalidMinSigners;
        const self = try allocator.create(FrostParticipant);
        errdefer allocator.destroy(self);
        self.* = FrostParticipant{
            .allocator = allocator,
            .identifier = key_package.identifier,
            .signing_share = key_package.signing_share,
            .verifying_share = key_package.verifying_share.element,
            .verifying_key = key_package.verifying_key.element,
            .min_signers = key_package.min_signers,
        };
        return self;
    }

    /// Free the participant.
    pub fn deinit(self: *FrostParticipant) void {
        self.allocator.destroy(self);
    }

    /// Round 1: generate fresh nonces; publish `nonces.commitments` to the
    /// coordinator. The returned `SigningNonces` are secret, stay local, and
    /// must be passed to `round2Sign` for this session only.
    pub fn round1Commit(self: *const FrostParticipant) round1.SigningNonces {
        return round1.SigningNonces.new(&self.signing_share);
    }

    /// Round 2: compute this signer's signature share for `signing_package`,
    /// using the `nonces` produced by `round1Commit` in this session.
    pub fn round2Sign(
        self: *const FrostParticipant,
        signing_package: *const round2.SigningPackage,
        nonces: *const round1.SigningNonces,
    ) !round2.SignatureShare {
        const key_package = keys.KeyPackage{
            .identifier = self.identifier,
            .signing_share = self.signing_share,
            .verifying_share = keys.VerifyingShare.fromElement(self.verifying_share),
            .verifying_key = keys.VerifyingKey.fromElement(self.verifying_key),
            .min_signers = self.min_signers,
        };
        return round2.sign(signing_package, nonces, &key_package);
    }

    /// Check `g^signing_share == verifying_share`: catches a corrupted or
    /// swapped long-lived share before it is used in a signing session.
    pub fn verifyShare(self: *const FrostParticipant) !void {
        const derived = group.elementScalarBaseMul(self.signing_share.scalar);
        if (!group.elementEql(derived, self.verifying_share)) {
            return FrostError.InvalidSecretShare;
        }
    }
};

/// Result of `runFullDkg`: every signer plus the group public key package
/// all participants agreed on. Call `deinit` when done.
pub const DkgCeremony = struct {
    /// Allocator that owns participants and the public key package.
    allocator: std.mem.Allocator,
    /// One participant per identifier, in input order.
    participants: []*FrostParticipant,
    /// The agreed group verifying key and all verifying shares.
    public_key_package: keys.PublicKeyPackage,

    /// Free all participants and the public key package.
    pub fn deinit(self: *DkgCeremony) void {
        for (self.participants) |p| p.deinit();
        self.allocator.free(self.participants);
        self.public_key_package.verifying_shares.deinit();
    }
};

/// Run a complete in-process DKG ceremony for `identifiers` (t-of-n with
/// t = `min_signers`) and return one `FrostParticipant` per identifier.
///
/// This convenience runs all three DKG rounds in a single process — it is
/// intended for demos, tests, and single-host setups. Real deployments run
/// `dkg.part1`/`part2`/`part3` across the network: round-1 packages are
/// public, but round-2 shares MUST travel over confidential, authenticated
/// channels. If any participant is detected as a cheater the ceremony aborts
/// with `InvalidProofOfKnowledge` (part2) or `InvalidSecretShare` (part3);
/// use `dkg.part2`/`dkg.part3` directly when you need the cheater
/// identifiers for identifiable abort.
pub fn runFullDkg(
    allocator: std.mem.Allocator,
    identifiers: []const Identifier,
    min_signers: u16,
) !DkgCeremony {
    if (identifiers.len < 2 or identifiers.len > std.math.maxInt(u16)) {
        return FrostError.InvalidMaxSigners;
    }
    const n: u16 = @intCast(identifiers.len);
    if (min_signers < 2 or min_signers > n) return FrostError.InvalidMinSigners;
    for (identifiers, 0..) |id, i| {
        for (identifiers[i + 1 ..]) |other| {
            if (id.eql(other)) return FrostError.DuplicatedIdentifier;
        }
    }

    // Round 1: every participant samples a polynomial and broadcasts a
    // commitment + proof of knowledge.
    var r1_secrets = try allocator.alloc(dkg.round1.SecretPackage, identifiers.len);
    defer allocator.free(r1_secrets);
    var r1_secrets_len: usize = 0;
    defer for (r1_secrets[0..r1_secrets_len]) |*sp| sp.deinit();
    var r1_broadcasts = try allocator.alloc(dkg.round1.Package, identifiers.len);
    defer allocator.free(r1_broadcasts);
    var r1_broadcasts_len: usize = 0;
    defer for (r1_broadcasts[0..r1_broadcasts_len]) |*p| p.deinit();
    for (identifiers, 0..) |id, i| {
        const secret, const broadcast = try dkg.part1(id, n, min_signers);
        r1_secrets[i] = secret;
        r1_secrets_len = i + 1;
        r1_broadcasts[i] = broadcast;
        r1_broadcasts_len = i + 1;
    }

    // Round 2: each participant verifies the other participants' proofs of
    // knowledge (identifiable abort: `.cheaters`) and computes the share to
    // send to each other participant.
    var r2_secrets = try allocator.alloc(dkg.round2.SecretPackage, identifiers.len);
    defer allocator.free(r2_secrets);
    var r2_secrets_len: usize = 0;
    defer for (r2_secrets[0..r2_secrets_len]) |*sp| sp.deinit();
    var outgoing = try allocator.alloc(std.AutoHashMap(Identifier, dkg.round2.Package), identifiers.len);
    defer allocator.free(outgoing);
    var outgoing_len: usize = 0;
    defer for (outgoing[0..outgoing_len]) |*m| m.deinit();
    for (0..identifiers.len) |i| {
        var others = std.AutoHashMap(Identifier, dkg.round1.Package).init(allocator);
        defer others.deinit();
        for (identifiers, 0..) |id, j| {
            if (j == i) continue;
            try others.put(id, r1_broadcasts[j]);
        }
        switch (try dkg.part2(&r1_secrets[i], &others, allocator)) {
            .ok => |ok| {
                r2_secrets[i] = ok.secret_package;
                r2_secrets_len = i + 1;
                outgoing[i] = ok.outgoing;
                outgoing_len = i + 1;
            },
            .cheaters => |cheater_ids| {
                allocator.free(cheater_ids);
                return FrostError.InvalidProofOfKnowledge;
            },
        }
    }

    // Round 3: each participant verifies the shares it received against the
    // senders' commitments (identifiable abort: `.cheaters`) and finalizes.
    var participants = try allocator.alloc(*FrostParticipant, identifiers.len);
    var participants_len: usize = 0;
    errdefer {
        for (participants[0..participants_len]) |p| p.deinit();
        allocator.free(participants);
    }
    var public_key_package: ?keys.PublicKeyPackage = null;
    errdefer {
        if (public_key_package) |*pk| pk.verifying_shares.deinit();
    }
    for (0..identifiers.len) |i| {
        var r1_others = std.AutoHashMap(Identifier, dkg.round1.Package).init(allocator);
        defer r1_others.deinit();
        var incoming = std.AutoHashMap(Identifier, dkg.round2.Package).init(allocator);
        defer incoming.deinit();
        for (identifiers, 0..) |id, j| {
            if (j == i) continue;
            try r1_others.put(id, r1_broadcasts[j]);
            // Participant j computed this share for participant i.
            try incoming.put(id, outgoing[j].get(identifiers[i]).?);
        }
        switch (try dkg.part3(&r2_secrets[i], &r1_others, &incoming, allocator)) {
            .ok => |ok| {
                // Every participant derives the same group key from the
                // summed commitments; keep only the last copy.
                if (public_key_package) |*pk| pk.verifying_shares.deinit();
                public_key_package = ok.public_key_package;
                participants[participants_len] = try FrostParticipant.init(allocator, &ok.key_package);
                participants_len += 1;
            },
            .cheaters => |cheater_ids| {
                allocator.free(cheater_ids);
                return FrostError.InvalidSecretShare;
            },
        }
    }

    return .{
        .allocator = allocator,
        .participants = participants,
        .public_key_package = public_key_package.?,
    };
}
