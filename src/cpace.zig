// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! CPace, the balanced password-authenticated key exchange the CFRG
//! recommends (draft-irtf-cfrg-cpace), in its CPACE-X25519-SHA512 suite and
//! initiator-responder mode, with the draft's explicit key confirmation.
//!
//! Two parties who share a low-entropy secret -- a PIN, say -- each send the
//! other one 32-byte share and end with the same 64-byte intermediate session
//! key, `isk`, if and only if their secrets matched. An active attacker gets
//! one guess at the secret per run and learns nothing an offline search could
//! use. The confirmation round is where a wrong guess shows: each side sends
//! `tag` and checks the other's with `verify`.
//!
//! ```zig
//! var a = try CPace.start(.initiator, pin, "", sid, "server", random);
//! var b = try CPace.start(.responder, pin, "", sid, "client", random);
//! try a.derive(b.share, "client");
//! try b.derive(a.share, "server");
//! // a.isk == b.isk, and each accepts the other's tag.
//! ```
//!
//! A run is a plain value that keeps copies of what it is given, so it can
//! be moved and returned freely.
//!
//! The session id `sid` has to be unique to the run and known to both sides
//! -- a protocol that runs CPace inside another handshake uses that
//! handshake's hash. The channel identifier `ci` and each side's associated
//! data `ad` bind whatever else both sides must agree on; a mismatch in any of
//! them is indistinguishable from a wrong password.
//!
//! The generator is the password hashed onto the curve with Elligator2, and
//! a share is that point times a random scalar, so both the map and the
//! multiplication are constant time: they are `std.crypto`'s. A share that
//! is a low-order point, whoever sent it, is refused.
//!
//! What the draft leaves to the application is the MAC in the confirmation
//! round. This uses HMAC-SHA512, 64-byte tags, as the Python `cpace` package
//! does, so that each can confirm the other.

const std = @import("std");
const Curve25519 = std.crypto.ecc.Curve25519;
const X25519 = std.crypto.dh.X25519;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

pub const CPace = struct {
    role: Role,
    /// This side's share, to send to the other.
    share: [share_length]u8,
    /// The intermediate session key, once `derive` has run: the same on both
    /// sides if their passwords matched. Feed it to a KDF before using it.
    isk: [isk_length]u8 = undefined,
    /// The session id and this side's associated data, copied: a run is a
    /// value that can be moved and returned, so it keeps no pointers.
    sid_buf: [max_input_length]u8,
    sid_len: usize,
    ad_buf: [max_input_length]u8,
    ad_len: usize,
    scalar: [32]u8,
    state: enum { started, derived } = .started,
    own_tag: [tag_length]u8 = undefined,
    peer_tag: [tag_length]u8 = undefined,
    /// Whether the peer's share and associated data were this side's own:
    /// a reflected run, whose tags would verify each other.
    reflected: bool = false,
    sid_output: [64]u8 = undefined,

    pub const share_length = 32;
    /// The longest session id and associated data a run keeps. The draft
    /// sets no limit; real ones are a few dozen bytes.
    pub const max_input_length = 256;
    pub const isk_length = Sha512.digest_length;
    pub const tag_length = HmacSha512.mac_length;

    /// Which side of the run: the initiator's share and associated data
    /// come first in everything both sides hash.
    pub const Role = enum { initiator, responder };

    pub const Error = error{
        /// The generator, or a share, is a point of low order: the one the
        /// password hashed to (vanishingly unlikely), or one the peer sent
        /// (an attack, or a broken peer).
        IdentityElement,
        /// `derive` called twice.
        AlreadyDerived,
        /// A session id or associated data longer than `max_input_length`.
        InputTooLong,
    };

    /// Begin a run: hash the password onto the curve and make this side's
    /// share from a scalar drawn from `random`. `sid` and `ad` are copied.
    pub fn start(role: Role, prs: []const u8, ci: []const u8, sid: []const u8, ad: []const u8, random: std.Random) Error!CPace {
        var scalar: [32]u8 = undefined;
        random.bytes(&scalar);
        return startWithScalar(role, prs, ci, sid, ad, scalar);
    }

    /// `start`, with the scalar given rather than drawn: for test vectors.
    pub fn startWithScalar(role: Role, prs: []const u8, ci: []const u8, sid: []const u8, ad: []const u8, scalar: [32]u8) Error!CPace {
        if (sid.len > max_input_length or ad.len > max_input_length) return error.InputTooLong;
        const g = calculateGenerator(prs, ci, sid);
        var self: CPace = .{
            .role = role,
            .share = try scalarMultVfy(scalar, g),
            .sid_buf = undefined,
            .sid_len = sid.len,
            .ad_buf = undefined,
            .ad_len = ad.len,
            .scalar = scalar,
        };
        @memcpy(self.sid_buf[0..sid.len], sid);
        @memcpy(self.ad_buf[0..ad.len], ad);
        return self;
    }

    /// Take the peer's share and associated data, and derive `isk` and both
    /// confirmation tags. A share that is a low-order point is refused.
    pub fn derive(self: *CPace, peer_share: [share_length]u8, peer_ad: []const u8) Error!void {
        if (self.state != .started) return error.AlreadyDerived;
        // Spent whatever happens next.
        defer std.crypto.secureZero(u8, &self.scalar);
        self.state = .derived;
        var k = try scalarMultVfy(self.scalar, peer_share);
        defer std.crypto.secureZero(u8, &k);
        const sid = self.sid_buf[0..self.sid_len];
        const ad = self.ad_buf[0..self.ad_len];

        const a_share, const a_ad, const b_share, const b_ad = switch (self.role) {
            .initiator => .{ &self.share, ad, &peer_share, peer_ad },
            .responder => .{ &peer_share, peer_ad, &self.share, ad },
        };

        var h = Sha512.init(.{});
        lv(&h, dsi_isk);
        lv(&h, sid);
        lv(&h, &k);
        transcript(&h, a_share, a_ad, b_share, b_ad);
        h.final(&self.isk);

        var mac_key: [Sha512.digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &mac_key);
        h = Sha512.init(.{});
        h.update("CPaceMac");
        h.update(sid);
        h.update(&self.isk);
        h.final(&mac_key);

        const ta = macOf(&mac_key, a_share, a_ad);
        const tb = macOf(&mac_key, b_share, b_ad);
        self.own_tag, self.peer_tag = switch (self.role) {
            .initiator => .{ ta, tb },
            .responder => .{ tb, ta },
        };
        self.reflected = std.mem.eql(u8, a_share, b_share) and std.mem.eql(u8, a_ad, b_ad);

        h = Sha512.init(.{});
        h.update("CPaceSidOutput");
        transcript(&h, a_share, a_ad, b_share, b_ad);
        h.final(&self.sid_output);
    }

    /// This side's confirmation tag, to send to the other: Ta from the
    /// initiator, Tb from the responder. Only after `derive`.
    pub fn tag(self: *const CPace) [tag_length]u8 {
        std.debug.assert(self.state == .derived);
        return self.own_tag;
    }

    /// Whether `peer_tag` proves the peer used the same password -- and the
    /// same session id, channel identifier and associated data. In constant
    /// time. A run whose peer only sent this side's own share back is never
    /// confirmed, since its tags would match. Only after `derive`.
    pub fn verify(self: *const CPace, peer_tag: []const u8) bool {
        std.debug.assert(self.state == .derived);
        if (peer_tag.len != tag_length) return false;
        const same = std.crypto.timing_safe.eql([tag_length]u8, peer_tag[0..tag_length].*, self.peer_tag);
        return same and !self.reflected;
    }
};

const dsi = "CPace255";
const dsi_isk = "CPace255_ISK";
/// SHA-512's block, which the generator string is padded out to.
const sha512_block = 128;

/// The generator the password maps to: the generator string hashed, its
/// first 32 bytes taken as a field element, and that mapped onto the curve
/// with Elligator2.
pub fn calculateGenerator(prs: []const u8, ci: []const u8, sid: []const u8) [32]u8 {
    var h = Sha512.init(.{});
    // lv_cat(DSI, PRS, zero padding, CI, sid), the padding filling the
    // first block of the hash, after DSI and PRS with their length prefixes,
    // to one byte short of the block: len_zpad = max(0, s_in_bytes - 1 -
    // len(prepend_len(PRS)) - len(prepend_len(DSI))).
    lv(&h, dsi);
    lv(&h, prs);
    const pad_len = @as(usize, sha512_block - 1) -| (lebLength(prs.len) + prs.len + lebLength(dsi.len) + dsi.len);
    const zeros: [sha512_block]u8 = @splat(0);
    lv(&h, zeros[0..pad_len]);
    lv(&h, ci);
    lv(&h, sid);
    var digest: [Sha512.digest_length]u8 = undefined;
    h.final(&digest);
    var u = digest[0..32].*;
    // A 255-bit field: the top bit is not part of the value (RFC 7748).
    u[31] &= 0x7f;
    return Curve25519.elligator2(Curve25519.Fe.fromBytes(u)).toBytes();
}

/// The draft's scalar_mult_vfy for X25519: the scalar clamped and the u
/// coordinate's bit 255 cleared, as RFC 7748 has it, and a result that is
/// the neutral element refused -- which a point of low order, on the curve
/// or its twist, always gives.
pub fn scalarMultVfy(scalar: [32]u8, u: [32]u8) CPace.Error![32]u8 {
    return X25519.scalarmult(scalar, u);
}

/// lv_cat of the two shares and their associated data, the initiator's
/// first: the transcript both the ISK and the session id output hash.
fn transcript(h: *Sha512, a_share: *const [32]u8, a_ad: []const u8, b_share: *const [32]u8, b_ad: []const u8) void {
    lv(h, a_share);
    lv(h, a_ad);
    lv(h, b_share);
    lv(h, b_ad);
}

fn macOf(key: *const [Sha512.digest_length]u8, share: *const [32]u8, ad: []const u8) [CPace.tag_length]u8 {
    var m = HmacSha512.init(key);
    var prefix: [10]u8 = undefined;
    m.update(leb128(&prefix, share.len));
    m.update(share);
    m.update(leb128(&prefix, ad.len));
    m.update(ad);
    var out: [CPace.tag_length]u8 = undefined;
    m.final(&out);
    return out;
}

/// prepend_len: `data` after its length in LEB128.
fn lv(h: *Sha512, data: []const u8) void {
    var prefix: [10]u8 = undefined;
    h.update(leb128(&prefix, data.len));
    h.update(data);
}

/// `n` in LEB128: seven bits a byte, least significant first, the top bit
/// set on every byte but the last.
fn leb128(buf: *[10]u8, n: usize) []const u8 {
    var v = n;
    var i: usize = 0;
    while (true) {
        buf[i] = @as(u8, @truncate(v)) & 0x7f;
        v >>= 7;
        if (v == 0) return buf[0 .. i + 1];
        buf[i] |= 0x80;
        i += 1;
    }
}

fn lebLength(n: usize) usize {
    var buf: [10]u8 = undefined;
    return leb128(&buf, n).len;
}

const testing = std.testing;

test "LEB128 as the draft's prepend_len has it" {
    var buf: [10]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x00}, leb128(&buf, 0));
    try testing.expectEqualSlices(u8, &.{0x04}, leb128(&buf, 4));
    try testing.expectEqualSlices(u8, &.{0x7f}, leb128(&buf, 127));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, leb128(&buf, 128));
    try testing.expectEqualSlices(u8, &.{ 0xe5, 0x8e, 0x26 }, leb128(&buf, 624485));
}

test "two sides with the same password agree, and one with another does not" {
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();
    const sid = "a session id both sides know";
    var a = try CPace.start(.initiator, "123456", "", sid, "server", random);
    var b = try CPace.start(.responder, "123456", "", sid, "client", random);
    try a.derive(b.share, "client");
    try b.derive(a.share, "server");
    try testing.expectEqualSlices(u8, &a.isk, &b.isk);
    try testing.expect(a.verify(&b.tag()));
    try testing.expect(b.verify(&a.tag()));
    try testing.expectEqualSlices(u8, &a.sid_output, &b.sid_output);

    var c = try CPace.start(.responder, "123457", "", sid, "client", random);
    var d = try CPace.start(.initiator, "123456", "", sid, "server", random);
    try c.derive(d.share, "server");
    try d.derive(c.share, "client");
    try testing.expect(!d.verify(&c.tag()));
    try testing.expect(!c.verify(&d.tag()));
    try testing.expectError(error.AlreadyDerived, c.derive(d.share, "server"));
}

test "a peer that sends back this side's own share is not confirmed" {
    var prng: std.Random.DefaultPrng = .init(2);
    var a = try CPace.start(.initiator, "pin", "", "sid", "", prng.random());
    const own = a.share;
    try a.derive(own, "");
    try testing.expect(!a.verify(&a.tag()));
}

test "a run is a value: moved or returned, it still agrees" {
    const Start = struct {
        fn run(role: CPace.Role, random: std.Random) !CPace {
            // The session id and associated data here are gone once this
            // returns, which a run that kept pointers to them would not
            // survive.
            var sid: [16]u8 = @splat(7);
            var ad: [6]u8 = "client".*;
            if (role == .initiator) ad = "server".*;
            const c = try CPace.start(role, "4321", "", &sid, &ad, random);
            @memset(&sid, 0xaa);
            @memset(&ad, 0xaa);
            return c;
        }
    };
    var prng: std.Random.DefaultPrng = .init(5);
    var a = try Start.run(.initiator, prng.random());
    var b = try Start.run(.responder, prng.random());
    try a.derive(b.share, "client");
    try b.derive(a.share, "server");
    try testing.expect(a.verify(&b.tag()) and b.verify(&a.tag()));
    const long: [CPace.max_input_length + 1]u8 = @splat(0);
    try testing.expectError(error.InputTooLong, CPace.start(.initiator, "", "", &long, "", prng.random()));
}
