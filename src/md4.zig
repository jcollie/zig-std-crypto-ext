// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! MD4, RFC 1320: the hash `std.crypto` does not have.
//!
//! **MD4 is broken, far more thoroughly than MD5.** A collision takes fewer
//! operations than computing the hash twice, and a second preimage is within
//! reach. Nothing new should use it for anything.
//!
//! What keeps it alive is Windows. The NT password hash is MD4 over the
//! password in UTF-16LE. It is stored in every Active Directory and SAM
//! database, and it is still what NTLM authenticates with. The domain cached
//! credentials (`msdcc` and `msdcc2`) are MD4 again, over the NT hash and the
//! user name. Reading or checking any of those needs MD4.
//!
//! The shape is `std.crypto.hash.Md5`'s: `init`, `update`, `final`, `hash`,
//! `block_length` and `digest_length`. That is what lets generic code, such as
//! `std.crypto.auth.hmac.Hmac`, take it without knowing what it is.

const std = @import("std");
const mem = std.mem;
const math = std.math;
const testing = std.testing;

pub const Md4 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 16;
    pub const Options = struct {};

    s: [4]u32,
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn init(options: Options) Self {
        _ = options;
        return .{
            .s = .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Self.init(options);
        d.update(data);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Top up a partial block from an earlier update first.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
            d.round(&d.buf);
            d.buf_len = 0;
        }

        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        const rest = b[off..];
        @memcpy(d.buf[d.buf_len..][0..rest.len], rest);
        d.buf_len += @intCast(rest.len);

        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The same padding as MD5: a one bit, zeros to 56 bytes mod 64, then
        // the length in bits as a little-endian 64-bit number.
        @memset(d.buf[d.buf_len..], 0);
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        if (64 - d.buf_len < 8) {
            d.round(&d.buf);
            @memset(&d.buf, 0);
        }

        mem.writeInt(u64, d.buf[56..64], d.total_len *% 8, .little);
        d.round(&d.buf);

        for (d.s, 0..) |s, j| {
            mem.writeInt(u32, out[4 * j ..][0..4], s, .little);
        }
    }

    /// The order in which each of the three rounds reads the sixteen words of
    /// the block, and the rotation distances, as RFC 1320 section 3.4 gives
    /// them.
    const order = [3][16]u4{
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 },
        .{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 },
    };
    const shifts = [3][4]u5{
        .{ 3, 7, 11, 19 },
        .{ 3, 5, 9, 13 },
        .{ 3, 9, 11, 15 },
    };
    /// The round constants: zero, then the square roots of 2 and of 3 as
    /// fractions of 2^30.
    const constants = [3]u32{ 0, 0x5a827999, 0x6ed9eba1 };

    fn round(d: *Self, b: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (&x, 0..) |*w, i| w.* = mem.readInt(u32, b[i * 4 ..][0..4], .little);

        var v = d.s;
        inline for (0..3) |r| {
            inline for (0..16) |i| {
                // Each step updates a, then d, then c, then b, over and over:
                // the register being written walks backwards round the four.
                const a = (4 - i % 4) % 4;
                const bb = (a + 1) % 4;
                const c = (a + 2) % 4;
                const dd = (a + 3) % 4;
                const f = switch (r) {
                    0 => (v[bb] & v[c]) | (~v[bb] & v[dd]),
                    1 => (v[bb] & v[c]) | (v[bb] & v[dd]) | (v[c] & v[dd]),
                    else => v[bb] ^ v[c] ^ v[dd],
                };
                v[a] = math.rotl(u32, v[a] +% f +% x[order[r][i]] +% constants[r], shifts[r][i % 4]);
            }
        }

        for (&d.s, v) |*s, n| s.* +%= n;
    }
};

fn expectHash(expected_hex: []const u8, input: []const u8) !void {
    var out: [Md4.digest_length]u8 = undefined;
    Md4.hash(input, &out, .{});
    var expected: [Md4.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "the RFC 1320 A.5 test suite" {
    try expectHash("31d6cfe0d16ae931b73c59d7e0c089c0", "");
    try expectHash("bde52cb31de33e46245e05fbdbd6fb24", "a");
    try expectHash("a448017aaf21d8525fc10ae87aa6729d", "abc");
    try expectHash("d9130a8164549fe818874806e1c7014b", "message digest");
    try expectHash("d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz");
    try expectHash("043f8582f241db351ce627e153e7f0e4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    try expectHash("e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

test "the NT hash of \"password\"" {
    // MD4 over UTF-16LE, which is the reason this file exists. The answer is
    // the one every NTLM tool prints for it.
    try expectHash("8846f7eaee8fb117ad06bdd830b7586c", "p\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00");
}

test "streaming matches one shot at every split" {
    const input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    var whole: [Md4.digest_length]u8 = undefined;
    Md4.hash(input, &whole, .{});
    for (0..input.len + 1) |split| {
        var h = Md4.init(.{});
        h.update(input[0..split]);
        h.update(input[split..]);
        var out: [Md4.digest_length]u8 = undefined;
        h.final(&out);
        try testing.expectEqualSlices(u8, &whole, &out);
    }
}

test "padding at the block boundaries" {
    // 55 bytes fit the length in the same block; 56 do not and need a second.
    // Answers from OpenSSL's legacy provider: `openssl dgst -md4`.
    try expectHash("c889c81dd86c4d2e025778944ea02881", "a" ** 55);
    try expectHash("d5f9a9e9257077a5f08b0b92f348b0ad", "a" ** 56);
    try expectHash("52f5076fabd22680234a3fa9f9dc5732", "a" ** 64);
}

test "HMAC takes it" {
    // RFC 2104's first HMAC-MD5 test case, recomputed with MD4 by OpenSSL:
    // `openssl mac -digest md4 -macopt hexkey:0b...0b HMAC`.
    const Hmac = std.crypto.auth.hmac.Hmac(Md4);
    var out: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&out, "Hi There", &([_]u8{0x0b} ** 16));
    var expected: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "90a79458f58f437e21f169cdba283da6");
    try testing.expectEqualSlices(u8, &expected, &out);
}
