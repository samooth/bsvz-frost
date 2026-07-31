//! FROST participant identifier
const std = @import("std");
const FrostError = @import("error.zig").FrostError;

/// A FROST participant identifier.
/// Represented as a non-zero scalar modulo the curve order.
pub const Identifier = struct {
    bytes: [32]u8,

    pub fn fromU16(id: u16) !Identifier {
        if (id == 0) return FrostError.InvalidMinSigners;
        var bytes = [_]u8{0} ** 32;
        bytes[30] = @truncate(id >> 8);
        bytes[31] = @truncate(id);
        return Identifier{ .bytes = bytes };
    }

    pub fn toU16(self: Identifier) u16 {
        return (@as(u16, self.bytes[30]) << 8) | self.bytes[31];
    }

    pub fn serialize(self: Identifier) [32]u8 {
        return self.bytes;
    }

    pub fn deserialize(bytes: [32]u8) !Identifier {
        // Check non-zero
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

    pub fn eql(self: Identifier, other: Identifier) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn lessThan(self: Identifier, other: Identifier) bool {
        return std.mem.order(u8, &self.bytes, &other.bytes) == .lt;
    }
};
