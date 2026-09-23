//! WASM root module for bsvz-frost (wasm32-freestanding, browser + Node).
//!
//! ABI (stable across 0.1.x):
//!   Memory:   frost_alloc / frost_dealloc  (wasm-managed, JS must free inputs)
//!   Result:   frost_out_ptr / frost_out_len / frost_out_err  (last-op slot)
//!   Ops:      return i32 status (0 = ok, <0 = error code, >0 = cheater count)
//!             On ok: result bytes are in the out-slot; JS must copy before
//!             the next op overwrites them. On identifiable abort (>0): the
//!             out-slot contains [count u16][count x id32].
//!
//! Error codes are a stable ABI shared with the JS package (ErrorCode table
//! in the JS API). Never renumber existing codes; only append new ones.
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Identifier = @import("identifier.zig").Identifier;
const Signature = @import("signature.zig").Signature;
const keys = @import("keys.zig");
const round1 = @import("round1.zig");
const round2 = @import("round2.zig");
const aggregate = @import("aggregate.zig");
const dkg = @import("dkg.zig");
const field = @import("field.zig");
const group = @import("group.zig");

// Wasm allocator: WasmAllocator over memory.grow; requires -fsingle-threaded.
var wasm_allocator = std.heap.wasm_allocator;

/// Stable error codes exposed across the WASM boundary. The JS package maps
/// these 1:1 onto its ErrorCode table; never renumber, only append.
pub const WasmError = enum(i32) {
    ok = 0,
    invalid_min_signers = 1,
    invalid_max_signers = 2,
    incorrect_number_of_identifiers = 3,
    duplicated_identifier = 4,
    unknown_identifier = 5,
    incorrect_number_of_commitments = 6,
    incorrect_number_of_shares = 7,
    missing_commitment = 8,
    invalid_commitment = 9,
    identity_commitment = 10,
    invalid_secret_share = 11,
    invalid_signature_share = 12,
    invalid_signature = 13,
    malformed_scalar = 14,
    malformed_element = 15,
    malformed_signing_key = 16,
    invalid_zero_scalar = 17,
    invalid_identity_element = 18,
    invalid_coefficient = 19,
    serialization_failed = 20,
    deserialization_failed = 21,
    randomness_error = 22,
    incorrect_number_of_packages = 23,
    incorrect_package = 24,
    package_not_found = 25,
    invalid_proof_of_knowledge = 26,
    identifiable_abort = 27,
    out_of_memory = 28,
    unknown = 127,
};

/// Map a library error (FrostError or std crypto) onto a stable WasmError code.
fn toWasm(err: anyerror) i32 {
    return switch (err) {
        FrostError.InvalidMinSigners => @intFromEnum(WasmError.invalid_min_signers),
        FrostError.InvalidMaxSigners => @intFromEnum(WasmError.invalid_max_signers),
        FrostError.IncorrectNumberOfIdentifiers => @intFromEnum(WasmError.incorrect_number_of_identifiers),
        FrostError.DuplicatedIdentifier => @intFromEnum(WasmError.duplicated_identifier),
        FrostError.UnknownIdentifier => @intFromEnum(WasmError.unknown_identifier),
        FrostError.IncorrectNumberOfCommitments => @intFromEnum(WasmError.incorrect_number_of_commitments),
        FrostError.IncorrectNumberOfShares => @intFromEnum(WasmError.incorrect_number_of_shares),
        FrostError.MissingCommitment => @intFromEnum(WasmError.missing_commitment),
        FrostError.InvalidCommitment => @intFromEnum(WasmError.invalid_commitment),
        FrostError.IdentityCommitment => @intFromEnum(WasmError.identity_commitment),
        FrostError.InvalidSecretShare => @intFromEnum(WasmError.invalid_secret_share),
        FrostError.InvalidSignatureShare => @intFromEnum(WasmError.invalid_signature_share),
        FrostError.InvalidSignature => @intFromEnum(WasmError.invalid_signature),
        FrostError.MalformedScalar => @intFromEnum(WasmError.malformed_scalar),
        FrostError.MalformedElement => @intFromEnum(WasmError.malformed_element),
        FrostError.MalformedSigningKey => @intFromEnum(WasmError.malformed_signing_key),
        FrostError.InvalidZeroScalar => @intFromEnum(WasmError.invalid_zero_scalar),
        FrostError.InvalidIdentityElement => @intFromEnum(WasmError.invalid_identity_element),
        FrostError.InvalidCoefficient => @intFromEnum(WasmError.invalid_coefficient),
        FrostError.SerializationFailed => @intFromEnum(WasmError.serialization_failed),
        FrostError.DeserializationFailed => @intFromEnum(WasmError.deserialization_failed),
        FrostError.DkgNotSupported => @intFromEnum(WasmError.deserialization_failed),
        FrostError.IdentifierDerivationNotSupported => @intFromEnum(WasmError.deserialization_failed),
        FrostError.RandomnessError => @intFromEnum(WasmError.randomness_error),
        FrostError.InvalidNonce => @intFromEnum(WasmError.deserialization_failed),
        FrostError.IncorrectNumberOfPackages => @intFromEnum(WasmError.incorrect_number_of_packages),
        FrostError.IncorrectPackage => @intFromEnum(WasmError.incorrect_package),
        FrostError.PackageNotFound => @intFromEnum(WasmError.package_not_found),
        FrostError.InvalidProofOfKnowledge => @intFromEnum(WasmError.invalid_proof_of_knowledge),
        FrostError.OutOfMemory => @intFromEnum(WasmError.out_of_memory),
        // std crypto errors (Secp256k1.fromSec1, Scalar.fromBytes, …)
        error.InvalidEncoding => @intFromEnum(WasmError.deserialization_failed),
        error.NonCanonical => @intFromEnum(WasmError.malformed_scalar),
        error.IdentityElement => @intFromEnum(WasmError.invalid_identity_element),
        else => @intFromEnum(WasmError.unknown),
    };
}

// Result slot: single global buffer holding the last operation's output.
// JS reads frost_out_ptr/len/err after every call and must copy before the
// next op overwrites it.
var out_data: []u8 = &.{};
var out_err: i32 = 0;

/// Replace the out-slot contents with `bytes` (duped into wasm memory) and
/// record `err`. Frees any previous out-slot allocation.
fn out_set(bytes: []const u8, err: i32) void {
    if (out_data.len > 0) wasm_allocator.free(out_data);
    out_data = &.{};
    out_err = err;
    if (bytes.len == 0) return;
    out_data = wasm_allocator.dupe(u8, bytes) catch {
        out_err = @intFromEnum(WasmError.randomness_error);
        return;
    };
}

// Entropy for freestanding targets (web wasm / browser / Node).
// The host MUST call frost_seed before the first operation that samples
// randomness; without it, frost_random_bytes zeroes the buffer.
const host_seed_capacity = 64;
var host_seed: [host_seed_capacity]u8 = undefined;
var host_seed_len: usize = 0;
var csprng: ?std.Random.DefaultCsprng = null;

/// Return a pointer to the 64-byte host seed buffer. The host writes its
/// entropy here, then calls frost_seed(len).
export fn frost_seed_buffer() [*]u8 {
    return &host_seed;
}

/// Initialise the CSPRNG from the first `len` bytes of the host seed buffer.
/// Call once after writing entropy via frost_seed_buffer.
export fn frost_seed(len: usize) void {
    if (len > host_seed_capacity) return;
    host_seed_len = len;
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    const copy_len = @min(host_seed_len, seed.len);
    @memcpy(seed[0..copy_len], host_seed[0..copy_len]);
    csprng = std.Random.DefaultCsprng.init(seed);
}

/// Fill `buffer` with CSPRNG bytes. Hooks the comptime entropy lookup used by
/// field.zig / scalar.zig. Returns zeros if frost_seed has not been called.
pub export fn frost_random_bytes(buffer: [*]u8, len: usize) void {
    if (csprng) |*c| {
        c.random().bytes(buffer[0..len]);
    } else {
        @memset(buffer[0..len], 0);
    }
}

// Memory management exports: JS allocates input buffers with frost_alloc,
// writes bytes into linear memory, then frees them with frost_dealloc.
export fn frost_alloc(len: usize) ?[*]u8 {
    const slice = wasm_allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// Free a buffer previously returned by frost_alloc (same len required).
export fn frost_dealloc(ptr: [*]u8, len: usize) void {
    wasm_allocator.free(ptr[0..len]);
}

// Result accessors: read the last operation's out-slot.
export fn frost_out_ptr() [*]const u8 {
    return out_data.ptr;
}
export fn frost_out_len() u32 {
    return @intCast(out_data.len);
}
export fn frost_out_err() i32 {
    return out_err;
}

/// Module protocol version string (null-terminated C string).
export fn frost_version() [*:0]const u8 {
    return "0.1.0-wasm1";
}

// DKG package cleanup helpers. dkg.zig allocates heap fields with
// wasm_allocator directly, so the wasm layer frees them here.
fn freeRound1Secret(s: *const dkg.round1.SecretPackage) void {
    wasm_allocator.free(@constCast(s.coefficients));
    wasm_allocator.free(@constCast(s.commitment.coefficients));
}
fn freeRound2Secret(s: *const dkg.round2.SecretPackage) void {
    wasm_allocator.free(@constCast(s.commitment.coefficients));
}
fn freeRound1Package(p: *const dkg.round1.Package) void {
    wasm_allocator.free(@constCast(p.commitment.coefficients));
}

// Helpers: little/big-endian appenders and bounds-checked slice copies used
// when building wire-format blobs for the out-slot.
fn listAppendU16(buf: *std.ArrayList(u8), value: u16) !void {
    var tmp: [2]u8 = undefined;
    std.mem.writeInt(u16, &tmp, value, .big);
    try buf.appendSlice(wasm_allocator, &tmp);
}
fn listAppendU32(buf: *std.ArrayList(u8), value: u32) !void {
    var tmp: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp, value, .big);
    try buf.appendSlice(wasm_allocator, &tmp);
}

/// Copy 33 bytes starting at `off`; DeserializationFailed if out of range.
fn as33(bytes: []const u8, off: usize) ![33]u8 {
    if (bytes.len < off + 33) return FrostError.DeserializationFailed;
    var tmp: [33]u8 = undefined;
    @memcpy(tmp[0..33], bytes[off..off+33]);
    return tmp;
}
/// Copy 32 bytes starting at `off`; DeserializationFailed if out of range.
fn as32(bytes: []const u8, off: usize) ![32]u8 {
    if (bytes.len < off + 32) return FrostError.DeserializationFailed;
    var tmp: [32]u8 = undefined;
    @memcpy(tmp[0..32], bytes[off..off+32]);
    return tmp;
}

// Protocol operations (see each export for wire formats).

/// trusted dealer keygen: out = [count u16 = n][count x SecretShare][PublicKeyPackage]
export fn frost_keygen(t: u16, n: u16) i32 {
    if (t < 2 or n < 2 or t > n) {
        out_set(&.{}, @intFromEnum(WasmError.invalid_min_signers));
        return @intFromEnum(WasmError.invalid_min_signers);
    }
    const ids = keys.defaultIdentifiers(n) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(ids);

    const result = keys.generateWithDealer(n, t, ids) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const shares = result[0];
    var pubkey = result[1];
    // shares and pubkey are allocated by wasm_allocator internally and are
    // intentionally not freed here (avoid cross-allocator issues); wasm memory
    // is reclaimed when the module is unloaded.

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(wasm_allocator);
    listAppendU16(&buf, n) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    for (shares) |share| {
        const serialized = share.serialize(wasm_allocator) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        defer wasm_allocator.free(serialized);
        buf.appendSlice(wasm_allocator, serialized) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
    }
    const pk_bytes = pubkey.serialize(wasm_allocator) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(pk_bytes);
    buf.appendSlice(wasm_allocator, pk_bytes) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };

    const owned = buf.toOwnedSlice(wasm_allocator) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    out_set(owned, 0);
    return 0;
}

/// KeyPackage from SecretShare: in = SecretShare wire bytes → out = KeyPackage(132)
export fn frost_keypackage_from_share(ptr: [*]const u8, len: usize) i32 {
    const bytes = ptr[0..len];
    const share = keys.SecretShare.deserialize(wasm_allocator, bytes) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(share.commitment.coefficients);
    const kp = keys.KeyPackage.fromSecretShare(share) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const serialized = kp.serialize() catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    out_set(serialized[0..], 0);
    return 0;
}

/// Round 1: in = KeyPackage(132) → out = SigningNonces(64) + SigningCommitments(66) = 130B
export fn frost_round1_commit(ptr: [*]const u8, len: usize) i32 {
    if (len != 132) {
        out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
        return @intFromEnum(WasmError.deserialization_failed);
    }
    const kp = keys.KeyPackage.deserialize(ptr[0..132].*) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const nonces = round1.SigningNonces.new(&kp.signing_share);
    const nonces_bytes = nonces.serialize();
    const comm_bytes = nonces.commitments.serialize() catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    var out: [130]u8 = undefined;
    @memcpy(out[0..64], &nonces_bytes);
    @memcpy(out[64..130], &comm_bytes);
    out_set(out[0..], 0);
    return 0;
}

/// Round 2: in = SigningPackage(blob) + SigningNonces(64) + KeyPackage(132) → out = SignatureShare(32)
export fn frost_round2_sign(
    sp_ptr: [*]const u8, sp_len: usize,
    nonces_ptr: [*]const u8, nonces_len: usize,
    kp_ptr: [*]const u8, kp_len: usize,
) i32 {
    if (nonces_len != 64 or kp_len != 132) {
        out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
        return @intFromEnum(WasmError.deserialization_failed);
    }
    var sp = round2.SigningPackage.deserialize(wasm_allocator, sp_ptr[0..sp_len]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer sp.deinit();
    const nonces = round1.SigningNonces.deserialize(nonces_ptr[0..64].*) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const kp = keys.KeyPackage.deserialize(kp_ptr[0..132].*) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const share = round2.sign(&sp, &nonces, &kp) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const serialized = share.serialize();
    out_set(serialized[0..], 0);
    return 0;
}

/// Aggregate: in = SigningPackage(blob) + shares blob + PublicKeyPackage(blob) + mode → out = Signature(65)
/// shares blob: [count u16][count x (id32 | share32)]; mode: 0=disabled, 1=first_cheater, 2=all
export fn frost_aggregate(
    sp_ptr: [*]const u8, sp_len: usize,
    shares_ptr: [*]const u8, shares_len: usize,
    pk_ptr: [*]const u8, pk_len: usize,
    mode: u8,
) i32 {
    var sp = round2.SigningPackage.deserialize(wasm_allocator, sp_ptr[0..sp_len]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer sp.deinit();
    var pk = keys.PublicKeyPackage.deserialize(wasm_allocator, pk_ptr[0..pk_len]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer pk.deinit();

    if (shares_len < 2) {
        out_set(&.{}, @intFromEnum(WasmError.incorrect_number_of_shares));
        return @intFromEnum(WasmError.incorrect_number_of_shares);
    }
    const count = std.mem.readInt(u16, shares_ptr[0..2], .big);
    if (shares_len < 2 + count * 64) {
        out_set(&.{}, @intFromEnum(WasmError.incorrect_number_of_shares));
        return @intFromEnum(WasmError.incorrect_number_of_shares);
    }
    var sig_shares = std.AutoHashMap(Identifier, round2.SignatureShare).init(wasm_allocator);
    defer sig_shares.deinit();
    var off: usize = 2;
    for (0..count) |_| {
        var id_tmp: [32]u8 = undefined;
        @memcpy(id_tmp[0..], shares_ptr[off .. off + 32]);
        const id = Identifier.deserialize(id_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        off += 32;
        var share_tmp: [32]u8 = undefined;
        @memcpy(share_tmp[0..], shares_ptr[off .. off + 32]);
        const share = round2.SignatureShare.deserialize(share_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        off += 32;
        sig_shares.put(id, share) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
    }

    const cheater_mode = switch (mode) {
        0 => aggregate.CheaterDetection.disabled,
        1 => aggregate.CheaterDetection.first_cheater,
        2 => aggregate.CheaterDetection.all_cheaters,
        else => aggregate.CheaterDetection.disabled,
    };
    const sig = aggregate.aggregate(&sp, sig_shares, &pk, cheater_mode) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const serialized = sig.serialize() catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    out_set(serialized[0..], 0);
    return 0;
}

/// Verify: in = VerifyingKey(33) + message + Signature(65) → 0=valid, <0=error
export fn frost_verify(
    vk_ptr: [*]const u8, vk_len: usize,
    msg_ptr: [*]const u8, msg_len: usize,
    sig_ptr: [*]const u8, sig_len: usize,
) i32 {
    if (vk_len != 33 or sig_len != 65) {
        out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
        return @intFromEnum(WasmError.deserialization_failed);
    }
    const vk = keys.VerifyingKey.deserialize(vk_ptr[0..33].*) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const sig = Signature.deserialize(sig_ptr[0..65].*) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const message = msg_ptr[0..msg_len];
    vk.verify(message, sig) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    out_set(&.{}, 0);
    return 0;
}

/// Reconstruct: in = [count u16][count x KeyPackage(132)] → out = SigningKey(32)
export fn frost_reconstruct(kps_ptr: [*]const u8, kps_len: usize) i32 {
    if (kps_len < 2) {
        out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
        return @intFromEnum(WasmError.deserialization_failed);
    }
    const count = std.mem.readInt(u16, kps_ptr[0..2], .big);
    if (kps_len < 2 + count * 132) {
        out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
        return @intFromEnum(WasmError.deserialization_failed);
    }
    const kps = wasm_allocator.alloc(keys.KeyPackage, count) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(kps);
    var off: usize = 2;
    for (kps) |*kp| {
        var kp_tmp: [132]u8 = undefined;
        @memcpy(kp_tmp[0..], kps_ptr[off .. off + 132]);
        kp.* = keys.KeyPackage.deserialize(kp_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        off += 132;
    }
    const reconstructed = keys.reconstruct(kps[0..count]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const serialized = reconstructed.serialize();
    out_set(serialized[0..], 0);
    return 0;
}

// DKG package serializers: (de)serialize dkg.zig internal packages to/from
// wire blobs. dkg.zig uses wasm_allocator directly, so heap fields are freed
// with freeRound1Secret / freeRound2Secret / freeRound1Package.

/// Serialize a round-1 secret package: [id32][min u16][max u16][coeff_count u16][coeff_count x scalar32].
fn serializeRound1Secret(s: *const dkg.round1.SecretPackage) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(wasm_allocator);
    try buf.appendSlice(wasm_allocator, &s.identifier.serialize());
    try listAppendU16(&buf, s.min_signers);
    try listAppendU16(&buf, s.max_signers);
    try listAppendU16(&buf, @intCast(s.coefficients.len));
    for (s.coefficients) |c| {
        try buf.appendSlice(wasm_allocator, &field.scalarSerialize(c));
    }
    return buf.toOwnedSlice(wasm_allocator);
}

/// Deserialize a round-1 secret package from the layout produced by
/// serializeRound1Secret; reconstructs the coefficient commitments from the
/// private coefficients.
fn deserializeRound1Secret(bytes: []const u8) !dkg.round1.SecretPackage {
    if (bytes.len < 38) return FrostError.DeserializationFailed;
    const id = try Identifier.deserialize(bytes[0..32].*);
    const min = std.mem.readInt(u16, bytes[32..34], .big);
    const max = std.mem.readInt(u16, bytes[34..36], .big);
    const coeff_count = std.mem.readInt(u16, bytes[36..38], .big);
    if (bytes.len < 38 + coeff_count * 32) return FrostError.DeserializationFailed;
    const coeffs = try wasm_allocator.alloc(field.Scalar, coeff_count);
    errdefer wasm_allocator.free(coeffs);
    var off: usize = 38;
    for (coeffs) |*c| {
        var tmp: [32]u8 = undefined;
        @memcpy(tmp[0..], bytes.ptr[off .. off + 32]);
        c.* = try field.scalarDeserialize(tmp);
        off += 32;
    }
    const comm_coeffs = try wasm_allocator.alloc(keys.CoefficientCommitment, coeff_count);
    errdefer wasm_allocator.free(comm_coeffs);
    for (coeffs, comm_coeffs) |c, *cc| {
        cc.* = keys.CoefficientCommitment.fromElement(group.elementScalarBaseMul(c));
    }
    return dkg.round1.SecretPackage{
        .identifier = id,
        .coefficients = coeffs,
        .commitment = keys.VerifiableSecretSharingCommitment.init(comm_coeffs),
        .min_signers = min,
        .max_signers = max,
    };
}

/// Serialize a round-1 broadcast package: [coeff_count u16][count x 33][proof 65].
fn serializeRound1Package(p: *const dkg.round1.Package) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(wasm_allocator);
    try listAppendU16(&buf, @intCast(p.commitment.coefficients.len));
    for (p.commitment.coefficients) |c| {
        try buf.appendSlice(wasm_allocator, &(try c.serialize()));
    }
    try buf.appendSlice(wasm_allocator, &(try p.proof_of_knowledge.serialize()));
    return buf.toOwnedSlice(wasm_allocator);
}

/// Deserialize a round-1 broadcast package (inverse of serializeRound1Package).
fn deserializeRound1Package(bytes: []const u8) !dkg.round1.Package {
    if (bytes.len < 2) return FrostError.DeserializationFailed;
    const coeff_count = std.mem.readInt(u16, bytes[0..2], .big);
    if (bytes.len < 2 + coeff_count * 33 + 65) return FrostError.DeserializationFailed;
    const coeffs = try wasm_allocator.alloc(keys.CoefficientCommitment, coeff_count);
    errdefer wasm_allocator.free(coeffs);
    var off: usize = 2;
    for (coeffs) |*c| {
        c.* = try keys.CoefficientCommitment.deserialize(try as33(bytes, off));
        off += 33;
    }
    var proof_tmp: [65]u8 = undefined;
    @memcpy(proof_tmp[0..], bytes.ptr[off .. off + 65]);
    const proof = try Signature.deserialize(proof_tmp);
    return dkg.round1.Package{
        .commitment = keys.VerifiableSecretSharingCommitment.init(coeffs),
        .proof_of_knowledge = proof,
    };
}

/// Serialize a round-2 secret package: [id32][min u16][max u16][secret32][coeff_count u16][count x 33].
fn serializeRound2Secret(s: *const dkg.round2.SecretPackage) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(wasm_allocator);
    try buf.appendSlice(wasm_allocator, &s.identifier.serialize());
    try listAppendU16(&buf, s.min_signers);
    try listAppendU16(&buf, s.max_signers);
    try buf.appendSlice(wasm_allocator, &field.scalarSerialize(s.secret_share));
    try listAppendU16(&buf, @intCast(s.commitment.coefficients.len));
    for (s.commitment.coefficients) |c| {
        try buf.appendSlice(wasm_allocator, &(try c.serialize()));
    }
    return buf.toOwnedSlice(wasm_allocator);
}

/// Deserialize a round-2 secret package (inverse of serializeRound2Secret).
fn deserializeRound2Secret(bytes: []const u8) !dkg.round2.SecretPackage {
    if (bytes.len < 70) return FrostError.DeserializationFailed;
    const id = try Identifier.deserialize(bytes[0..32].*);
    const min = std.mem.readInt(u16, bytes[32..34], .big);
    const max = std.mem.readInt(u16, bytes[34..36], .big);
    const coeff_count = std.mem.readInt(u16, bytes[68..70], .big);
    if (bytes.len < 70 + coeff_count * 33) return FrostError.DeserializationFailed;
    const coeffs = try wasm_allocator.alloc(keys.CoefficientCommitment, coeff_count);
    errdefer wasm_allocator.free(coeffs);
    var off: usize = 70;
    for (coeffs) |*c| {
        c.* = try keys.CoefficientCommitment.deserialize(try as33(bytes, off));
        off += 33;
    }
    return dkg.round2.SecretPackage{
        .identifier = id,
        .commitment = keys.VerifiableSecretSharingCommitment.init(coeffs),
        .secret_share = try field.scalarDeserialize(bytes[36..68].*),
        .min_signers = min,
        .max_signers = max,
    };
}

/// DKG Part 1: sample a polynomial, commitment, and proof of knowledge for
/// participant `id` (must be >= 1). Out-slot:
///   [secret_len u16 BE][secret blob][broadcast blob]
/// The secret blob is kept private; the broadcast blob is sent to all others.
export fn frost_dkg_part1(id: u16, t: u16, n: u16) i32 {
    if (t < 2 or n < 2 or t > n) {
        out_set(&.{}, @intFromEnum(WasmError.invalid_min_signers));
        return @intFromEnum(WasmError.invalid_min_signers);
    }
    const identifier = Identifier.fromU16(id) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const r1_secret, const r1_pkg = dkg.part1(identifier, n, t) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer {
        freeRound1Secret(&r1_secret);
        freeRound1Package(&r1_pkg);
    }
    const secret_bytes = serializeRound1Secret(&r1_secret) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(secret_bytes);
    const bc_bytes = serializeRound1Package(&r1_pkg) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer wasm_allocator.free(bc_bytes);

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(wasm_allocator);
    listAppendU16(&buf, @intCast(secret_bytes.len)) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    buf.appendSlice(wasm_allocator, secret_bytes) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    buf.appendSlice(wasm_allocator, bc_bytes) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    const owned = buf.toOwnedSlice(wasm_allocator) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    out_set(owned, 0);
    return 0;
}

/// DKG Part 2: verify all n-1 received round-1 broadcasts (excluding self),
/// then compute the share for each other participant. Inputs:
///   secret      — own part1 secret blob
///   broadcasts  — [count u16][count x (id32 | round1_package)]
///                  (n-1 entries, self excluded)
/// On success (rc=0) the out-slot is:
///   [secret2_len u16][secret2][count u16][count x (id32 | share32)]
/// On identifiable abort (rc>0): [count u16][count x id32] of cheaters.
export fn frost_dkg_part2(
    secret_ptr: [*]const u8, secret_len: usize,
    broadcasts_ptr: [*]const u8, broadcasts_len: usize,
) i32 {
    const r1_secret = deserializeRound1Secret(secret_ptr[0..secret_len]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer freeRound1Secret(&r1_secret);

    if (broadcasts_len < 2) {
        out_set(&.{}, @intFromEnum(WasmError.incorrect_number_of_packages));
        return @intFromEnum(WasmError.incorrect_number_of_packages);
    }
    const bc_count = std.mem.readInt(u16, broadcasts_ptr[0..2], .big);
    var round1_packages = std.AutoHashMap(Identifier, dkg.round1.Package).init(wasm_allocator);
    defer {
        var it = round1_packages.valueIterator();
        while (it.next()) |pkg| freeRound1Package(pkg);
        round1_packages.deinit();
    }
    var off: usize = 2;
    const t = r1_secret.min_signers;
    for (0..bc_count) |_| {
        if (broadcasts_len < off + 32) {
            out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
            return @intFromEnum(WasmError.deserialization_failed);
        }
        var id_tmp: [32]u8 = undefined;
        @memcpy(id_tmp[0..], broadcasts_ptr[off .. off + 32]);
        const id = Identifier.deserialize(id_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        off += 32;
        const entry_len = 2 + @as(usize, t) * 33 + 65;
        if (broadcasts_len < off + entry_len) {
            out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
            return @intFromEnum(WasmError.deserialization_failed);
        }
        const pkg = deserializeRound1Package(broadcasts_ptr[off..off+entry_len]) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        off += entry_len;
        round1_packages.put(id, pkg) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
    }

    const result = dkg.part2(&r1_secret, &round1_packages, wasm_allocator) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    switch (result) {
        .ok => |ok| {
            defer freeRound2Secret(&ok.secret_package);
            const secret2_bytes = serializeRound2Secret(&ok.secret_package) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            defer wasm_allocator.free(secret2_bytes);
            var out = std.ArrayList(u8).empty;
            errdefer out.deinit(wasm_allocator);
            listAppendU16(&out, @intCast(secret2_bytes.len)) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            out.appendSlice(wasm_allocator, secret2_bytes) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            listAppendU16(&out, @intCast(ok.outgoing.count())) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            var it = ok.outgoing.keyIterator();
            while (it.next()) |id| {
                const pkg = ok.outgoing.get(id.*).?;
                out.appendSlice(wasm_allocator, &id.*.serialize()) catch |err| {
                    out_set(&.{}, toWasm(err));
                    return toWasm(err);
                };
                const share_bytes = pkg.signing_share.serialize();
                out.appendSlice(wasm_allocator, &share_bytes) catch |err| {
                    out_set(&.{}, toWasm(err));
                    return toWasm(err);
                };
            }
            const owned = out.toOwnedSlice(wasm_allocator) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            out_set(owned, 0);
            return 0;
        },
        .cheaters => |ids| {
            var buf = std.ArrayList(u8).empty;
            errdefer buf.deinit(wasm_allocator);
            listAppendU16(&buf, @intCast(ids.len)) catch |err| {
                wasm_allocator.free(ids);
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            for (ids) |id| {
                buf.appendSlice(wasm_allocator, &id.serialize()) catch |err| {
                    wasm_allocator.free(ids);
                    out_set(&.{}, toWasm(err));
                    return toWasm(err);
                };
            }
            const owned = buf.toOwnedSlice(wasm_allocator) catch {
                wasm_allocator.free(ids);
                out_set(&.{}, @intFromEnum(WasmError.randomness_error));
                return @intFromEnum(WasmError.randomness_error);
            };
            wasm_allocator.free(ids);
            out_set(owned, @intCast(ids.len));
            return @intCast(ids.len);
        },
    }
}

/// DKG Part 3: verify received round-2 shares against senders' round-1
/// commitments, sum them into the long-lived signing share, and derive the
/// group public key. Inputs:
///   secret2 — own part2 secret blob
///   r1      — [count u16][count x (id32 | round1_package)]  (self excluded)
///   r2      — [count u16][count x (id32 | share32)] keyed by SENDER id
///             (self excluded; each entry is the share you RECEIVED)
/// On success (rc=0) the out-slot is: KeyPackage(132) ‖ PublicKeyPackage.
/// On identifiable abort (rc>0): [count u16][count x id32] of cheaters.
export fn frost_dkg_part3(
    secret2_ptr: [*]const u8, secret2_len: usize,
    r1_ptr: [*]const u8, r1_len: usize,
    r2_ptr: [*]const u8, r2_len: usize,
) i32 {
    const r2_secret = deserializeRound2Secret(secret2_ptr[0..secret2_len]) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    defer freeRound2Secret(&r2_secret);

    if (r1_len < 2) {
        out_set(&.{}, @intFromEnum(WasmError.incorrect_number_of_packages));
        return @intFromEnum(WasmError.incorrect_number_of_packages);
    }
    const r1_count = std.mem.readInt(u16, r1_ptr[0..2], .big);
    var r1_packages = std.AutoHashMap(Identifier, dkg.round1.Package).init(wasm_allocator);
    defer {
        var it = r1_packages.valueIterator();
        while (it.next()) |pkg| freeRound1Package(pkg);
        r1_packages.deinit();
    }
    var r1_off: usize = 2;
    const t = r2_secret.min_signers;
    for (0..r1_count) |_| {
        if (r1_len < r1_off + 32) {
            out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
            return @intFromEnum(WasmError.deserialization_failed);
        }
        var id_tmp: [32]u8 = undefined;
        @memcpy(id_tmp[0..], r1_ptr[r1_off .. r1_off + 32]);
        const id = Identifier.deserialize(id_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        r1_off += 32;
        const entry_len = 2 + @as(usize, t) * 33 + 65;
        if (r1_len < r1_off + entry_len) {
            out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
            return @intFromEnum(WasmError.deserialization_failed);
        }
        const pkg = deserializeRound1Package(r1_ptr[r1_off..r1_off+entry_len]) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        r1_off += entry_len;
        r1_packages.put(id, pkg) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
    }

    if (r2_len < 2) {
        out_set(&.{}, @intFromEnum(WasmError.incorrect_number_of_packages));
        return @intFromEnum(WasmError.incorrect_number_of_packages);
    }
    const r2_count = std.mem.readInt(u16, r2_ptr[0..2], .big);
    var r2_packages = std.AutoHashMap(Identifier, dkg.round2.Package).init(wasm_allocator);
    defer r2_packages.deinit();
    var r2_off: usize = 2;
    for (0..r2_count) |_| {
        if (r2_len < r2_off + 64) {
            out_set(&.{}, @intFromEnum(WasmError.deserialization_failed));
            return @intFromEnum(WasmError.deserialization_failed);
        }
        var id_tmp: [32]u8 = undefined;
        @memcpy(id_tmp[0..], r2_ptr[r2_off .. r2_off + 32]);
        const id = Identifier.deserialize(id_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        r2_off += 32;
        var share_tmp: [32]u8 = undefined;
        @memcpy(share_tmp[0..], r2_ptr[r2_off .. r2_off + 32]);
        const share = keys.SigningShare.deserialize(share_tmp) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
        r2_off += 32;
        r2_packages.put(id, dkg.round2.Package{ .signing_share = share }) catch |err| {
            out_set(&.{}, toWasm(err));
            return toWasm(err);
        };
    }

    const result = dkg.part3(&r2_secret, &r1_packages, &r2_packages, wasm_allocator) catch |err| {
        out_set(&.{}, toWasm(err));
        return toWasm(err);
    };
    switch (result) {
        .ok => |ok| {
            const kp_bytes = ok.key_package.serialize() catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            const pk_bytes = ok.public_key_package.serialize(wasm_allocator) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            defer wasm_allocator.free(pk_bytes);
            var buf = std.ArrayList(u8).empty;
            errdefer buf.deinit(wasm_allocator);
            buf.appendSlice(wasm_allocator, &kp_bytes) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            buf.appendSlice(wasm_allocator, pk_bytes) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            const owned = buf.toOwnedSlice(wasm_allocator) catch |err| {
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            out_set(owned, 0);
            return 0;
        },
        .cheaters => |ids| {
            var buf = std.ArrayList(u8).empty;
            errdefer buf.deinit(wasm_allocator);
            listAppendU16(&buf, @intCast(ids.len)) catch |err| {
                wasm_allocator.free(ids);
                out_set(&.{}, toWasm(err));
                return toWasm(err);
            };
            for (ids) |id| {
                buf.appendSlice(wasm_allocator, &id.serialize()) catch |err| {
                    wasm_allocator.free(ids);
                    out_set(&.{}, toWasm(err));
                    return toWasm(err);
                };
            }
            const owned = buf.toOwnedSlice(wasm_allocator) catch {
                wasm_allocator.free(ids);
                out_set(&.{}, @intFromEnum(WasmError.randomness_error));
                return @intFromEnum(WasmError.randomness_error);
            };
            wasm_allocator.free(ids);
            out_set(owned, @intCast(ids.len));
            return @intCast(ids.len);
        },
    }
}

