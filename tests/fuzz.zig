// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! What the ciphers and modes must do with keys and data nobody chose.
//!
//! A block cipher is an odd thing to fuzz: it takes fixed-size input and has
//! no parser to confuse, so there is no malformed input to find. What these
//! properties are actually for is the *modes*, where there is real room to be
//! wrong -- an off-by-one on the last partial block, a chaining value read
//! after it has been overwritten by an in-place operation, a length that is
//! not a whole number of blocks reaching a mode that cannot take one.
//!
//! So the properties are round trips, and the thing they are looking for is
//! any (key, iv, length) where encrypting and decrypting do not compose to
//! the identity. That is the bug a fixed test vector cannot find, because a
//! vector only ever exercises the one length it was written for.
//!
//! Each target is an ordinary test as well as a fuzz target, so `zig build
//! test` runs the same properties on the seeds checked in beside them.

const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Smith = std.testing.Smith;

const des = @import("std_crypto_ext");
const Des = des.Des;
const Des3 = des.Des3;
const modes = des.modes;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes192 = des.Aes192;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;

/// Unused here -- nothing in this library allocates -- but the standalone
/// driver sets it, so it has to exist.
pub var backing: Allocator = if (builtin.is_test) testing.allocator else undefined;

/// The lengths most likely to be where a mode goes wrong: nothing, one byte,
/// either side of a block for both block sizes, and a couple of whole blocks.
const interesting_lengths = [_]usize{ 0, 1, 7, 8, 9, 15, 16, 17, 23, 24, 31, 32, 33, 64, 65 };

// -- CBC --------------------------------------------------------------------

/// CBC over DES: encrypt then decrypt is the identity, for every whole number
/// of blocks. Also that it works in place, which is how a datagram is
/// decrypted where it landed.
fn cbcProperty(input: []const u8) !void {
    if (input.len < Des.key_length + Des.block_length) return;
    const key = input[0..Des.key_length].*;
    const iv = input[Des.key_length..][0..Des.block_length].*;
    const body = input[Des.key_length + Des.block_length ..];

    // CBC cannot encrypt a partial block, so round down. A caller who passes
    // one trips an assertion in a safe build and undefined behaviour in a
    // fast one, which is why the contract is theirs to check first.
    const len = body.len - body.len % Des.block_length;
    if (len == 0) return;
    const plaintext = body[0..len];

    var buffer: [4096]u8 = undefined;
    if (len > buffer.len) return;

    modes.cbcEncrypt(Des.EncryptCtx, Des.initEnc(key), buffer[0..len], plaintext, iv);
    var back: [4096]u8 = undefined;
    modes.cbcDecrypt(Des.DecryptCtx, Des.initDec(key), back[0..len], buffer[0..len], iv);
    try testing.expectEqualSlices(u8, plaintext, back[0..len]);

    // And in place, both ways.
    var scratch: [4096]u8 = undefined;
    @memcpy(scratch[0..len], plaintext);
    modes.cbcEncrypt(Des.EncryptCtx, Des.initEnc(key), scratch[0..len], scratch[0..len], iv);
    try testing.expectEqualSlices(u8, buffer[0..len], scratch[0..len]);
    modes.cbcDecrypt(Des.DecryptCtx, Des.initDec(key), scratch[0..len], scratch[0..len], iv);
    try testing.expectEqualSlices(u8, plaintext, scratch[0..len]);
}

test "fuzz cbc" {
    for (cipher_seeds) |seed| try cbcProperty(seed);
    try testing.fuzz({}, fuzzCbc, .{});
}

fn fuzzCbc(_: void, smith: *Smith) !void {
    var buffer: [2048]u8 = undefined;
    const len = smith.slice(&buffer);
    try cbcProperty(buffer[0..len]);
}

// -- CFB --------------------------------------------------------------------

/// CFB over AES-128, which is what SNMPv3 privacy actually uses. Being a
/// stream mode it takes any length, so every length is fair game -- and the
/// partial final block is exactly where a mode like this goes wrong.
fn cfbProperty(input: []const u8) !void {
    const key_length = 16;
    const block_length = 16;
    if (input.len < key_length + block_length) return;
    const key = input[0..key_length].*;
    const iv = input[key_length..][0..block_length].*;
    const plaintext = input[key_length + block_length ..];

    var buffer: [4096]u8 = undefined;
    if (plaintext.len > buffer.len) return;
    const len = plaintext.len;

    modes.cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), buffer[0..len], plaintext, iv);
    var back: [4096]u8 = undefined;
    // Decrypting takes an *encryption* context: CFB only runs the cipher
    // forwards. Handing it a decryption context is the mistake this asserts
    // against by simply not having one to hand.
    modes.cfbDecrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), back[0..len], buffer[0..len], iv);
    try testing.expectEqualSlices(u8, plaintext, back[0..len]);

    // In place.
    var scratch: [4096]u8 = undefined;
    @memcpy(scratch[0..len], plaintext);
    modes.cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), scratch[0..len], scratch[0..len], iv);
    try testing.expectEqualSlices(u8, buffer[0..len], scratch[0..len]);
    modes.cfbDecrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), scratch[0..len], scratch[0..len], iv);
    try testing.expectEqualSlices(u8, plaintext, scratch[0..len]);

    // AES-192 through the same mode, because it is this library's own cipher
    // rather than std's and so has nobody else's test suite behind it.
    if (input.len >= 24 + block_length) {
        const key192 = input[0..24].*;
        const iv192 = input[24..][0..block_length].*;
        const body = input[24 + block_length ..];
        if (body.len <= buffer.len) {
            var enc: [4096]u8 = undefined;
            modes.cfbEncrypt(Aes192.EncryptCtx, Aes192.initEnc(key192), enc[0..body.len], body, iv192);
            var dec: [4096]u8 = undefined;
            modes.cfbDecrypt(Aes192.EncryptCtx, Aes192.initEnc(key192), dec[0..body.len], enc[0..body.len], iv192);
            try testing.expectEqualSlices(u8, body, dec[0..body.len]);
        }
    }

    // A prefix of the plaintext must encrypt to a prefix of the ciphertext:
    // CFB is a stream mode, so the keystream cannot depend on how much comes
    // after. This is what catches a final-block special case that fires when
    // it should not.
    if (len > 1) {
        const shorter = len - 1;
        var partial: [4096]u8 = undefined;
        modes.cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), partial[0..shorter], plaintext[0..shorter], iv);
        try testing.expectEqualSlices(u8, buffer[0..shorter], partial[0..shorter]);
    }
}

test "fuzz cfb" {
    for (cipher_seeds) |seed| try cfbProperty(seed);
    try testing.fuzz({}, fuzzCfb, .{});
}

fn fuzzCfb(_: void, smith: *Smith) !void {
    var buffer: [2048]u8 = undefined;
    const len = smith.slice(&buffer);
    try cfbProperty(buffer[0..len]);
}

// -- the ciphers themselves -------------------------------------------------

/// DES and 3DES: a single block through encrypt and back through decrypt is
/// the identity, for any key. And the parity bits really are ignored, which
/// is a property of the key schedule rather than of any one vector.
fn cipherProperty(input: []const u8) !void {
    if (input.len < 24 + 8) return;
    const key1 = input[0..8].*;
    const key3 = input[0..24].*;
    const block = input[24..32].*;

    var c: [8]u8 = undefined;
    var back: [8]u8 = undefined;

    Des.initEnc(key1).encrypt(&c, &block);
    Des.initDec(key1).decrypt(&back, &c);
    try testing.expectEqualSlices(u8, &block, &back);

    // Flipping the parity bits cannot change the ciphertext: PC-1 discards
    // them. This holds for every key, which is why it belongs here rather
    // than in a single test.
    var flipped = key1;
    for (&flipped) |*byte| byte.* ^= 1;
    var c2: [8]u8 = undefined;
    Des.initEnc(flipped).encrypt(&c2, &block);
    try testing.expectEqualSlices(u8, &c, &c2);

    Des3.initEnc(key3).encrypt(&c, &block);
    Des3.initDec(key3).decrypt(&back, &c);
    try testing.expectEqualSlices(u8, &block, &back);

    // Three equal keys make 3DES into single DES, for every key and block.
    var same: [24]u8 = undefined;
    @memcpy(same[0..8], &key1);
    @memcpy(same[8..16], &key1);
    @memcpy(same[16..24], &key1);
    var triple: [8]u8 = undefined;
    var single: [8]u8 = undefined;
    Des3.initEnc(same).encrypt(&triple, &block);
    Des.initEnc(key1).encrypt(&single, &block);
    try testing.expectEqualSlices(u8, &single, &triple);

    // A weak key is an involution, and that is a claim about the cipher on
    // any block.
    for (des.weak_keys) |weak| {
        var once: [8]u8 = undefined;
        var twice: [8]u8 = undefined;
        const enc = Des.initEnc(weak);
        enc.encrypt(&once, &block);
        enc.encrypt(&twice, &once);
        try testing.expectEqualSlices(u8, &block, &twice);
    }
}

test "fuzz cipher" {
    for (cipher_seeds) |seed| try cipherProperty(seed);
    try testing.fuzz({}, fuzzCipher, .{});
}

fn fuzzCipher(_: void, smith: *Smith) !void {
    var buffer: [64]u8 = undefined;
    const len = smith.slice(&buffer);
    try cipherProperty(buffer[0..len]);
}

// -- seeds ------------------------------------------------------------------

const cipher_seeds = [_][]const u8{
    // Too short to do anything with, which every property must survive.
    "",
    "\x00",
    "short",
    // The FIPS key and block, then enough tail for the modes to chew on.
    "\x13\x34\x57\x79\x9b\xbc\xdf\xf1" ++ "\x01\x23\x45\x67\x89\xab\xcd\xef" ++
        "Now is the time for all ",
    // The weak keys, which are the ones a password-derived key might hit.
    "\x01\x01\x01\x01\x01\x01\x01\x01" ++ "\x00" ** 16 ++ "\xff" ** 16,
    "\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe" ++ "\x00" ** 16 ++ "\x00" ** 16,
    // All zeroes and all ones, both of which are real keys.
    "\x00" ** 64,
    "\xff" ** 64,
    // A length that is one short of a block, for both block sizes.
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6" ++ "\xab\xf7\x15\x88\x09\xcf\x4f\x3c" ++ "\xa5" ** 15,
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6" ++ "\xab\xf7\x15\x88\x09\xcf\x4f\x3c" ++ "\xa5" ** 17,
};

// Every interesting length, at one fixed key, so `zig build test` covers the
// boundaries deterministically rather than waiting for the fuzzer to find
// them.
test "the mode boundaries, at every interesting length" {
    const prefix = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6" ++ "\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    var input: [prefix.len + 128]u8 = undefined;
    @memcpy(input[0..prefix.len], prefix);
    for (input[prefix.len..], 0..) |*byte, i| byte.* = @truncate(i *% 7 +% 1);
    for (interesting_lengths) |len| {
        try cbcProperty(input[0 .. prefix.len + len]);
        try cfbProperty(input[0 .. prefix.len + len]);
    }
}

// -- the table the standalone driver reads ----------------------------------

pub const Target = struct {
    name: []const u8,
    run: *const fn (input: []const u8) anyerror!void,
    corpus: []const []const u8,
    /// The buffer this target reads its input into.
    ///
    /// `Smith.slice` yields an *empty* slice for a length larger than the
    /// buffer rather than a truncated one, so a generator that does not know
    /// this number hands the target nothing at all most of the time.
    content_max: usize,
};

fn Driven(comptime one: fn (void, *Smith) anyerror!void) type {
    return struct {
        fn run(input: []const u8) anyerror!void {
            var smith: Smith = .{ .in = input };
            return one({}, &smith);
        }
    };
}

pub const all = [_]Target{
    .{
        .name = "cbc",
        .run = Driven(fuzzCbc).run,
        .corpus = &cipher_seeds,
        .content_max = 2048,
    },
    .{
        .name = "cfb",
        .run = Driven(fuzzCfb).run,
        .corpus = &cipher_seeds,
        .content_max = 2048,
    },
    .{
        .name = "cipher",
        .run = Driven(fuzzCipher).run,
        .corpus = &cipher_seeds,
        .content_max = 64,
    },
};
