//! Root re-exports for the bsvz-frost package (legacy convenience aliases).
//! Prefer importing the top-level `bsvz-frost` module via lib.zig, which
//! exposes the full public API.
pub const shamir = @import("shamir.zig");
pub const naive = @import("naive.zig");
pub const frost = @import("frost.zig");

/// A Shamir secret share (index + value).
pub const Share = shamir.Share;
/// A single participant's partial Schnorr response (naive scheme only).
pub const PartialSignature = naive.PartialSignature;
/// An aggregated naive Schnorr signature (naive scheme only).
pub const Signature = naive.Signature;
/// High-level FROST signer state machine (RFC 9591).
pub const FrostParticipant = frost.FrostParticipant;
