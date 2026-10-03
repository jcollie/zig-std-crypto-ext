// SPDX-FileCopyrightText: © Zig contributors
// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT
//
// Vendored from Zig 0.16.0's `lib/std/crypto/argon2.zig`: the key derivation
// only, without the PHC string hasher, and with the version as a parameter.

//! Argon2 at either of its two versions, 1.0 (`0x10`) and 1.3 (`0x13`).
//!
//! `std.crypto.pwhash.argon2` computes only 1.3, and that is the right choice
//! for anything new. This is for the hashes already written by version 1.0:
//! the reference implementation produced it until 2016, and libraries built on
//! it wrote `$argon2i$m=...` strings with no `v=` field at all, which means
//! 1.0. A password database that has been through a few years of upgrades can
//! still hold some, and a verifier that cannot compute 1.0 fails every one of
//! them.
//!
//! The two versions differ in two places:
//!
//! * The version number is hashed into H0, so the same inputs give unrelated
//!   outputs even where the computation is otherwise the same.
//! * On the second and later passes over memory, 1.3 XORs each new block into
//!   the one it replaces, and 1.0 overwrites it. That is the change the 1.3
//!   revision made, to defeat a time-memory tradeoff that applied to 1.0.
//!
//! On the first pass the two agree, because the memory starts at zero and
//! XOR into zero is an overwrite. So a version 1.0 computation with one pass
//! differs from version 1.3 only by the H0 input.
//!
//! The parameter and mode types are `std`'s own, so the same `Params` drives
//! either implementation, and the tests use that to check this one against
//! `std` at version 1.3.

// https://datatracker.ietf.org/doc/rfc9106
// https://github.com/golang/crypto/tree/master/argon2
// https://github.com/P-H-C/phc-winner-argon2

const builtin = @import("builtin");

const std = @import("std");
const blake2 = crypto.hash.blake2;
const crypto = std.crypto;
const Io = std.Io;
const math = std.math;
const mem = std.mem;
const pwhash = crypto.pwhash;
const Blake2b512 = blake2.Blake2b512;
const Blocks = std.array_list.AlignedManaged([block_length]u64, .@"16");
const H0 = [Blake2b512.digest_length + 8]u8;

const KdfError = pwhash.KdfError;

const block_length = 128;
const sync_points = 4;
const max_int = 0xffff_ffff;

/// Which revision of Argon2 to compute.
pub const Version = enum(u32) {
    /// Version 1.0. Every pass overwrites the blocks it computes.
    v0x10 = 0x10,
    /// Version 1.3, RFC 9106's, and what `std` computes. Passes after the
    /// first XOR into the blocks they replace.
    v0x13 = 0x13,
};

/// Argon2d, Argon2i or Argon2id: `std`'s own type.
pub const Mode = pwhash.argon2.Mode;

/// Time, memory and parallelism, and the optional secret and associated
/// data: `std`'s own type.
pub const Params = pwhash.argon2.Params;

fn initHash(
    password: []const u8,
    salt: []const u8,
    params: Params,
    dk_len: usize,
    mode: Mode,
    version: Version,
) H0 {
    var h0: H0 = undefined;
    var parameters: [24]u8 = undefined;
    var tmp: [4]u8 = undefined;
    var b2 = Blake2b512.init(.{});
    mem.writeInt(u32, parameters[0..4], params.p, .little);
    mem.writeInt(u32, parameters[4..8], @as(u32, @intCast(dk_len)), .little);
    mem.writeInt(u32, parameters[8..12], params.m, .little);
    mem.writeInt(u32, parameters[12..16], params.t, .little);
    mem.writeInt(u32, parameters[16..20], @backingInt(version), .little);
    mem.writeInt(u32, parameters[20..24], @backingInt(mode), .little);
    b2.update(&parameters);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(password.len)), .little);
    b2.update(&tmp);
    b2.update(password);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(salt.len)), .little);
    b2.update(&tmp);
    b2.update(salt);
    const secret = params.secret orelse "";
    std.debug.assert(secret.len <= max_int);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(secret.len)), .little);
    b2.update(&tmp);
    b2.update(secret);
    const ad = params.ad orelse "";
    std.debug.assert(ad.len <= max_int);
    mem.writeInt(u32, &tmp, @as(u32, @intCast(ad.len)), .little);
    b2.update(&tmp);
    b2.update(ad);
    b2.final(h0[0..Blake2b512.digest_length]);
    return h0;
}

fn blake2bLong(out: []u8, in: []const u8) void {
    const H = Blake2b512;
    var outlen_bytes: [4]u8 = undefined;
    mem.writeInt(u32, &outlen_bytes, @as(u32, @intCast(out.len)), .little);

    var out_buf: [H.digest_length]u8 = undefined;

    if (out.len <= H.digest_length) {
        var h = H.init(.{ .expected_out_bits = out.len * 8 });
        h.update(&outlen_bytes);
        h.update(in);
        h.final(&out_buf);
        @memcpy(out, out_buf[0..out.len]);
        return;
    }

    var h = H.init(.{});
    h.update(&outlen_bytes);
    h.update(in);
    h.final(&out_buf);
    var out_slice = out;
    out_slice[0 .. H.digest_length / 2].* = out_buf[0 .. H.digest_length / 2].*;
    out_slice = out_slice[H.digest_length / 2 ..];

    var in_buf: [H.digest_length]u8 = undefined;
    while (out_slice.len > H.digest_length) {
        in_buf = out_buf;
        H.hash(&in_buf, &out_buf, .{});
        out_slice[0 .. H.digest_length / 2].* = out_buf[0 .. H.digest_length / 2].*;
        out_slice = out_slice[H.digest_length / 2 ..];
    }
    in_buf = out_buf;
    H.hash(&in_buf, &out_buf, .{ .expected_out_bits = out_slice.len * 8 });
    @memcpy(out_slice, out_buf[0..out_slice.len]);
}

fn initBlocks(
    blocks: *Blocks,
    h0: *H0,
    memory: u32,
    threads: u24,
) void {
    var block0: [1024]u8 = undefined;
    var lane: u24 = 0;
    while (lane < threads) : (lane += 1) {
        const j = lane * (memory / threads);
        mem.writeInt(u32, h0[Blake2b512.digest_length + 4 ..][0..4], lane, .little);

        mem.writeInt(u32, h0[Blake2b512.digest_length..][0..4], 0, .little);
        blake2bLong(&block0, h0);
        for (&blocks.items[j + 0], 0..) |*v, i| {
            v.* = mem.readInt(u64, block0[i * 8 ..][0..8], .little);
        }

        mem.writeInt(u32, h0[Blake2b512.digest_length..][0..4], 1, .little);
        blake2bLong(&block0, h0);
        for (&blocks.items[j + 1], 0..) |*v, i| {
            v.* = mem.readInt(u64, block0[i * 8 ..][0..8], .little);
        }
    }
}

fn processBlocks(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    version: Version,
    io: Io,
) Io.Cancelable!void {
    const lanes = memory / threads;
    const segments = lanes / sync_points;

    if (builtin.single_threaded or threads == 1) {
        processBlocksSync(blocks, time, memory, threads, mode, version, lanes, segments);
    } else {
        try processBlocksAsync(blocks, time, memory, threads, mode, version, lanes, segments, io);
    }
}

fn processBlocksSync(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    version: Version,
    lanes: u32,
    segments: u32,
) void {
    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u24 = 0;
            while (lane < threads) : (lane += 1) {
                processSegment(blocks, time, memory, threads, mode, version, lanes, segments, n, slice, lane);
            }
        }
    }
}

fn processBlocksAsync(
    blocks: *Blocks,
    time: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    version: Version,
    lanes: u32,
    segments: u32,
    io: Io,
) Io.Cancelable!void {
    var n: u32 = 0;
    while (n < time) : (n += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var group: Io.Group = .init;
            defer group.cancel(io);
            var lane: u24 = 0;
            while (lane < threads) : (lane += 1) {
                group.async(io, processSegment, .{
                    blocks, time, memory, threads, mode, version, lanes, segments, n, slice, lane,
                });
            }
            try group.await(io);
        }
    }
}

fn processSegment(
    blocks: *Blocks,
    passes: u32,
    memory: u32,
    threads: u24,
    mode: Mode,
    version: Version,
    lanes: u32,
    segments: u32,
    n: u32,
    slice: u32,
    lane: u24,
) void {
    var addresses: [block_length]u64 align(16) = @splat(0);
    var in: [block_length]u64 align(16) = @splat(0);
    const zero: [block_length]u64 align(16) = @splat(0);
    if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
        in[0] = n;
        in[1] = lane;
        in[2] = slice;
        in[3] = memory;
        in[4] = passes;
        in[5] = @backingInt(mode);
    }
    var index: u32 = 0;
    if (n == 0 and slice == 0) {
        index = 2;
        if (mode == .argon2i or mode == .argon2id) {
            in[6] += 1;
            processBlock(&addresses, &in, &zero);
            processBlock(&addresses, &addresses, &zero);
        }
    }
    var offset = lane * lanes + slice * segments + index;
    var random: u64 = 0;
    while (index < segments) : ({
        index += 1;
        offset += 1;
    }) {
        var prev = offset -% 1;
        if (index == 0 and slice == 0) {
            prev +%= lanes;
        }
        if (mode == .argon2i or (mode == .argon2id and n == 0 and slice < sync_points / 2)) {
            if (index % block_length == 0) {
                in[6] += 1;
                processBlock(&addresses, &in, &zero);
                processBlock(&addresses, &addresses, &zero);
            }
            random = addresses[index % block_length];
        } else {
            random = blocks.items[prev][0];
        }
        const new_offset = indexAlpha(random, lanes, segments, threads, n, slice, lane, index);
        // Memory starts at zero, so on the first pass XOR and overwrite are
        // the same thing and only the later passes tell the versions apart.
        switch (version) {
            .v0x13 => processBlockXor(&blocks.items[offset], &blocks.items[prev], &blocks.items[new_offset]),
            .v0x10 => processBlockGeneric(&blocks.items[offset], &blocks.items[prev], &blocks.items[new_offset], false),
        }
    }
}

fn processBlock(
    out: *align(16) [block_length]u64,
    in1: *align(16) const [block_length]u64,
    in2: *align(16) const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, false);
}

fn processBlockXor(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
) void {
    processBlockGeneric(out, in1, in2, true);
}

fn processBlockGeneric(
    out: *[block_length]u64,
    in1: *const [block_length]u64,
    in2: *const [block_length]u64,
    comptime xor: bool,
) void {
    var t: [block_length]u64 = undefined;
    for (&t, 0..) |*v, i| {
        v.* = in1[i] ^ in2[i];
    }
    var i: usize = 0;
    while (i < block_length) : (i += 16) {
        blamkaGeneric(t[i..][0..16]);
    }
    i = 0;
    var buffer: [16]u64 = undefined;
    while (i < block_length / 8) : (i += 2) {
        var j: usize = 0;
        while (j < block_length / 8) : (j += 2) {
            buffer[j] = t[j * 8 + i];
            buffer[j + 1] = t[j * 8 + i + 1];
        }
        blamkaGeneric(&buffer);
        j = 0;
        while (j < block_length / 8) : (j += 2) {
            t[j * 8 + i] = buffer[j];
            t[j * 8 + i + 1] = buffer[j + 1];
        }
    }
    if (xor) {
        for (t, 0..) |v, j| {
            out[j] ^= in1[j] ^ in2[j] ^ v;
        }
    } else {
        for (t, 0..) |v, j| {
            out[j] = in1[j] ^ in2[j] ^ v;
        }
    }
}

const QuarterRound = struct { a: usize, b: usize, c: usize, d: usize };

fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
    return .{ .a = a, .b = b, .c = c, .d = d };
}

fn fBlaMka(x: u64, y: u64) u64 {
    const xy = @as(u64, @as(u32, @truncate(x))) * @as(u64, @as(u32, @truncate(y)));
    return x +% y +% 2 *% xy;
}

fn blamkaGeneric(x: *[16]u64) void {
    const rounds = comptime [_]QuarterRound{
        Rp(0, 4, 8, 12),
        Rp(1, 5, 9, 13),
        Rp(2, 6, 10, 14),
        Rp(3, 7, 11, 15),
        Rp(0, 5, 10, 15),
        Rp(1, 6, 11, 12),
        Rp(2, 7, 8, 13),
        Rp(3, 4, 9, 14),
    };
    inline for (rounds) |r| {
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 32);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 24);
        x[r.a] = fBlaMka(x[r.a], x[r.b]);
        x[r.d] = math.rotr(u64, x[r.d] ^ x[r.a], 16);
        x[r.c] = fBlaMka(x[r.c], x[r.d]);
        x[r.b] = math.rotr(u64, x[r.b] ^ x[r.c], 63);
    }
}

fn finalize(
    blocks: *Blocks,
    memory: u32,
    threads: u24,
    out: []u8,
) void {
    const lanes = memory / threads;
    var lane: u24 = 0;
    while (lane < threads - 1) : (lane += 1) {
        for (blocks.items[(lane * lanes) + lanes - 1], 0..) |v, i| {
            blocks.items[memory - 1][i] ^= v;
        }
    }
    var block: [1024]u8 = undefined;
    for (blocks.items[memory - 1], 0..) |v, i| {
        mem.writeInt(u64, block[i * 8 ..][0..8], v, .little);
    }
    blake2bLong(out, &block);
}

fn indexAlpha(
    rand: u64,
    lanes: u32,
    segments: u32,
    threads: u24,
    n: u32,
    slice: u32,
    lane: u24,
    index: u32,
) u32 {
    var ref_lane = @as(u32, @intCast(rand >> 32)) % threads;
    if (n == 0 and slice == 0) {
        ref_lane = lane;
    }
    var m = 3 * segments;
    var s = ((slice + 1) % sync_points) * segments;
    if (lane == ref_lane) {
        m += index;
    }
    if (n == 0) {
        m = slice * segments;
        s = 0;
        if (slice == 0 or lane == ref_lane) {
            m += index;
        }
    }
    if (index == 0 or lane == ref_lane) {
        m -= 1;
    }
    var p = @as(u64, @as(u32, @truncate(rand)));
    p = (p * p) >> 32;
    p = (p * m) >> 32;
    return ref_lane * lanes + @as(u32, @intCast(((s + m - (p + 1)) % lanes)));
}

/// Derives a key from the password, salt, and argon2 parameters, at the
/// given version.
///
/// Derived key has to be at least 4 bytes length.
///
/// Salt has to be at least 8 bytes length.
pub fn kdf(
    allocator: mem.Allocator,
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    params: Params,
    mode: Mode,
    version: Version,
    io: Io,
) KdfError!void {
    if (derived_key.len < 4) return KdfError.WeakParameters;
    if (derived_key.len > max_int) return KdfError.OutputTooLong;

    if (password.len > max_int) return KdfError.WeakParameters;
    if (salt.len < 8 or salt.len > max_int) return KdfError.WeakParameters;
    if (params.t < 1 or params.p < 1) return KdfError.WeakParameters;
    if (params.m / 8 < params.p) return KdfError.WeakParameters;

    var h0 = initHash(password, salt, params, derived_key.len, mode, version);
    const memory = @max(
        params.m / (sync_points * params.p) * (sync_points * params.p),
        2 * sync_points * params.p,
    );

    var blocks = try Blocks.initCapacity(allocator, memory);
    defer blocks.deinit();

    blocks.appendNTimesAssumeCapacity(@splat(0), memory);

    initBlocks(&blocks, &h0, memory, params.p);
    try processBlocks(&blocks, params.t, memory, params.p, mode, version, io);
    finalize(&blocks, memory, params.p, derived_key);
}

const testing = std.testing;

const Vector = struct { version: Version, mode: Mode, t: u32, m: u32, p: u24, hex: []const u8 };

/// Every mode at both versions, with one pass (where the versions differ only
/// in H0), two passes (where the overwrite and the XOR part company) and four
/// lanes. The answers are the reference implementation's, through argon2-cffi
/// 25.1.0: `hash_secret_raw(b"password", b"somesalt", t, m, p, 32, type,
/// version=...)`.
const vectors = [_]Vector{
    .{ .version = .v0x10, .mode = .argon2d, .t = 1, .m = 16, .p = 1, .hex = "75a0f7bd70543d4352aa24b7a7f0ba48cb73d2f9c1713f6be43ba1bd81b3004e" },
    .{ .version = .v0x10, .mode = .argon2d, .t = 2, .m = 16, .p = 1, .hex = "b8b832ae3d1b16c5eb921f0bd43aa6ad18c15eb02cb8f6ba9a9d493bb6df76fe" },
    .{ .version = .v0x10, .mode = .argon2d, .t = 3, .m = 32, .p = 4, .hex = "c03e6ea388e8b206ee787353eebf6225f4a487546952f0fca2a76efb0ab3d8ae" },
    .{ .version = .v0x10, .mode = .argon2i, .t = 1, .m = 16, .p = 1, .hex = "cbcbbdbfe8f7a9964e975a2ada1685c83cd90419c7d5e8ae290762b0d34a1670" },
    .{ .version = .v0x10, .mode = .argon2i, .t = 2, .m = 16, .p = 1, .hex = "3ccd1ed72a485b1e698a39f39af777289f0ae5add88f991f3fb5ed476f451d43" },
    .{ .version = .v0x10, .mode = .argon2i, .t = 3, .m = 32, .p = 4, .hex = "a5742f9e3bf59936648fffc596029c224361c5efe42ccc704d4b2f7bf4ac0403" },
    .{ .version = .v0x10, .mode = .argon2id, .t = 1, .m = 16, .p = 1, .hex = "68460a22b31541f4fae652c5abbcdbf1075961659152760dfdee8db3800eecee" },
    .{ .version = .v0x10, .mode = .argon2id, .t = 2, .m = 16, .p = 1, .hex = "c1d493b7cc3b978c29662bd4ca58e8db0fdc52a31b040000dfa9789f91d6826d" },
    .{ .version = .v0x10, .mode = .argon2id, .t = 3, .m = 32, .p = 4, .hex = "4ed472a832960d0fd677459f7926f9b4bf72df7ec7e55436d578dd5f24e85fd1" },
    .{ .version = .v0x13, .mode = .argon2d, .t = 1, .m = 16, .p = 1, .hex = "321a42ea4f4df827355f94bbd4f4fda59e3ef6b07e3aa920a4a1ebda2546b168" },
    .{ .version = .v0x13, .mode = .argon2d, .t = 2, .m = 16, .p = 1, .hex = "e742c05880c44c4df5fe79937be77897a6e41ca758affc42301f1e4040e35bd2" },
    .{ .version = .v0x13, .mode = .argon2d, .t = 3, .m = 32, .p = 4, .hex = "d8c54d6283ca2dc14842a8509d7c84b9189b76293560d7c4775b2d1f0d69a968" },
    .{ .version = .v0x13, .mode = .argon2i, .t = 1, .m = 16, .p = 1, .hex = "1fca5e33c7734e5351da8dec4d24b6b317912733d9df7d4f8c7da50a0d6fff78" },
    .{ .version = .v0x13, .mode = .argon2i, .t = 2, .m = 16, .p = 1, .hex = "03df1d13e10203bcc663405e31ab1687939730c9152459bca28fd10c23e38f50" },
    .{ .version = .v0x13, .mode = .argon2i, .t = 3, .m = 32, .p = 4, .hex = "bd7549197d330319954b40c5f4fa0ffe798ca071331cecb282ec202086850ca8" },
    .{ .version = .v0x13, .mode = .argon2id, .t = 1, .m = 16, .p = 1, .hex = "3fd1f4fd38592d783450391972abe3cc1c2f2b58f8d8cbfda86a857d81d25f8d" },
    .{ .version = .v0x13, .mode = .argon2id, .t = 2, .m = 16, .p = 1, .hex = "058202c0723cd88c24408ccac1cbf828dee63bcf3843a150ea364a1e0b4e1ff8" },
    .{ .version = .v0x13, .mode = .argon2id, .t = 3, .m = 32, .p = 4, .hex = "bb0cc80a3e671149526915418c6eefe761bb19d5d2d567a017703e0cea6ab05c" },
};

test "both versions against the reference implementation" {
    for (vectors) |v| {
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, v.hex);
        var out: [32]u8 = undefined;
        try kdf(testing.allocator, &out, "password", "somesalt", .{ .t = v.t, .m = v.m, .p = v.p }, v.mode, v.version, testing.io);
        try testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "version 1.3 agrees with std, secret and associated data included" {
    // The RFC 9106 section 5 inputs, which exercise every field of H0.
    const password: [32]u8 = @splat(0x01);
    const salt: [16]u8 = @splat(0x02);
    const params: Params = .{ .t = 3, .m = 32, .p = 4, .secret = &@as([8]u8, @splat(0x03)), .ad = &@as([12]u8, @splat(0x04)) };
    for ([_]Mode{ .argon2d, .argon2i, .argon2id }) |mode| {
        var ours: [32]u8 = undefined;
        var theirs: [32]u8 = undefined;
        try kdf(testing.allocator, &ours, &password, &salt, params, mode, .v0x13, testing.io);
        try pwhash.argon2.kdf(testing.allocator, &theirs, &password, &salt, params, mode, testing.io);
        try testing.expectEqualSlices(u8, &theirs, &ours);
    }
}
