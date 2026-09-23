//! FROST participant identifier.
//!
//! An identifier is a non-zero scalar mod the curve order, serialized as 32
//! big-endian bytes. Identifiers must be distinct across the signing set;
//! zero is invalid (fromU16 rejects id == 0 with InvalidMinSigners for
//! historical error-code reasons).
const std = @import("std");
const FrostError = @import("error.zig").FrostError;
const Ciphersuite = @import("ciphersuite.zig");

/// A FROST participant identifier.
/// Represented as a non-zero scalar modulo the curve order.
pub const Identifier = struct {
    /// 32-byte big-endian scalar encoding.
    bytes: [32]u8,

    /// Build an identifier from a u16; the value is placed in bytes 30-31
    /// (big-endian) with the rest zero. Rejects id == 0.
    pub fn fromU16(id: u16) !Identifier {
        if (id == 0) return FrostError.InvalidMinSigners;
        var bytes = @as([32]u8, @splat(0));
        bytes[30] = @truncate(id >> 8);
        bytes[31] = @truncate(id);
        return Identifier{ .bytes = bytes };
    }

    /// Derive an Identifier from an arbitrary byte string.
    /// Maps each byte string to a uniformly random non-zero identifier via HID.
    /// Not part of the FROST specification; a convenience for creating
    /// identifiers. Fails with negligible probability if the hash is zero.
    pub fn derive(msg: []const u8) !Identifier {
        const scalar = Ciphersuite.HID(msg);
        const bytes = scalar.toBytes(.big);
        var all_zero = true;
        for (bytes) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return FrostError.InvalidZeroScalar;
        return Identifier{ .bytes = bytes };
    }

    /// Read the low 16 bits (bytes 30-31). Only meaningful for identifiers
    /// created via fromU16; derived identifiers will truncate.
    pub fn toU16(self: Identifier) u16 {
        return (@as(u16, self.bytes[30]) << 8) | self.bytes[31];
    }

    /// Serialize to 32 big-endian bytes.
    pub fn serialize(self: Identifier) [32]u8 {
        return self.bytes;
    }

    /// Parse 32 bytes; rejects the all-zero identifier.
    pub fn deserialize(bytes: [32]u8) !Identifier {
        var all_zero = true;
        for (bytes) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return FrostError.InvalidMinSigners;
        return Identifier{ .bytes = bytes };
    }

    /// Byte-wise equality.
    pub fn eql(self: Identifier, other: Identifier) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Lexicographic ordering on the 32-byte encoding (used to sort the
    /// commitment list deterministically).
    pub fn lessThan(self: Identifier, other: Identifier) bool {
        return std.mem.order(u8, &self.bytes, &other.bytes) == .lt;
    }
};
