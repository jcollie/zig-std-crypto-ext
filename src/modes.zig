// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! The block cipher modes `std.crypto.modes` does not have.
//!
//! `std` ships `ctr` and nothing else, on the reasonable grounds that new code
//! should be using an AEAD. These are here for the protocols that specify
//! something older: SNMPv3 privacy is DES-CBC (RFC 3414) or AES-128-CFB with a
//! full-block feedback (RFC 3826), and neither is expressible with counter
//! mode.
//!
//! Everything here is generic over the block cipher: `comptime BlockCipher:
//! anytype`, using only `BlockCipher.block_length` and the context's
//! `encrypt`/`decrypt`. So these work on `std.crypto.core.aes.Aes128` and on
//! this library's `Des` and `Des3` without knowing the difference, and that is
//! the reason CFB lives here rather than in an SNMP library: SNMP needs CFB
//! for AES, which has nothing to do with DES.
//!
//! Worth knowing that `std.crypto.modes.ctr` is *not* generic in this sense,
//! despite its signature -- it reads
//! `BlockCipher.block.parallel.optimal_parallel_blocks` to batch blocks, which
//! only the AES implementations define. Depending on only the two things above
//! is deliberate.
//!
//! **None of these authenticate anything.** CBC and CFB hide content and do
//! not detect modification, and CBC in particular has a long history of
//! padding oracles. Use them where a specification requires them and pair them
//! with a MAC -- which is what SNMPv3 does, computing an HMAC over the whole
//! message.
//!
//! ## The contracts
//!
//! Every function here asserts what it needs of its lengths: `dst.len >=
//! src.len` always, and `src.len` a whole number of blocks for CBC and ECB.
//! An assertion is a check in a Debug or ReleaseSafe build and nothing at all
//! in ReleaseFast or ReleaseSmall, where a violation reads past the end of
//! `src` and writes past the end of `dst`. The length of a ciphertext comes
//! off the wire in the protocols these are for, so a caller checks it before
//! calling rather than relying on this to. `std.crypto.modes.ctr` and the
//! AEADs in `std` behave the same way.
//!
//! `dst` may be the very same slice as `src` -- decrypting a datagram where it
//! landed is the normal thing to do -- or one that does not overlap it. A
//! partial overlap overwrites blocks that have not been read yet and is not
//! detected. Working in place also asks the block cipher to tolerate `dst ==
//! src` over a single block, which `Des`, `Des3` and `std.crypto.core.aes`
//! all do by reading the whole block before writing any of it.
//!
//! The mode's own temporaries -- a keystream block, a block of plaintext
//! about to be encrypted -- are zeroed before returning. The contexts are the
//! caller's, and `Des` says what to do with those.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const des = @import("des.zig");

/// Cipher Block Chaining, encrypting.
///
/// Each plaintext block is XORed with the previous ciphertext block before
/// being encrypted, so an identical block does not encrypt identically twice
/// and a single bit of the IV changes everything after it.
///
/// `src.len` must be a whole number of blocks: this mode cannot encrypt a
/// partial one, and choosing a padding is the caller's business because the
/// padding is part of whatever specification sent them here. SNMPv3 pads with
/// whatever is convenient and relies on the BER length inside the plaintext to
/// say where the real data stops. That, and `dst.len >= src.len`, are
/// asserted only: see the contracts above.
pub fn cbcEncrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    iv: [BlockCipher.block_length]u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(src.len % block_length == 0);
    assert(dst.len >= src.len);

    var previous = iv;
    var block: [block_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &block);
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        for (&block, src[i..][0..block_length], previous) |*out, plain, chain| {
            out.* = plain ^ chain;
        }
        block_cipher.encrypt(dst[i..][0..block_length], &block);
        previous = dst[i..][0..block_length].*;
    }
}

/// Cipher Block Chaining, decrypting. Needs a *decryption* context, unlike
/// CFB and CTR.
///
/// `src.len` must be a whole number of blocks and `dst.len >= src.len`, and
/// both are asserted only: a ciphertext length that came off the wire is
/// checked before it gets here. See the contracts above.
pub fn cbcDecrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    iv: [BlockCipher.block_length]u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(src.len % block_length == 0);
    assert(dst.len >= src.len);

    var previous = iv;
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        // Saved before writing, because `dst` and `src` may be the same
        // slice -- decrypting in place is the normal thing to do with a
        // datagram that has just arrived.
        const chain = src[i..][0..block_length].*;
        block_cipher.decrypt(dst[i..][0..block_length], src[i..][0..block_length]);
        for (dst[i..][0..block_length], previous) |*out, c| out.* ^= c;
        previous = chain;
    }
}

/// Cipher Feedback with full-block feedback, which is what "CFB128" means for
/// a 128-bit cipher and what RFC 3826 specifies for SNMPv3.
///
/// The cipher is only ever run forwards, even to decrypt: it generates a
/// keystream from the previous ciphertext block. So this takes an *encryption*
/// context in both directions, and `cfbDecrypt` differs from `cfbEncrypt` only
/// in which of the two it feeds back.
///
/// Being a stream mode, it needs no padding and `src.len` need not be a whole
/// number of blocks -- the last partial block simply uses as much of the
/// keystream as it needs. `dst.len >= src.len` is asserted only: see the
/// contracts above.
pub fn cfbEncrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    iv: [BlockCipher.block_length]u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(dst.len >= src.len);

    var feedback = iv;
    var keystream: [block_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &keystream);
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        block_cipher.encrypt(&keystream, &feedback);
        const n = @min(block_length, src.len - i);
        for (dst[i..][0..n], src[i..][0..n], keystream[0..n]) |*out, plain, k| {
            out.* = plain ^ k;
        }
        // The ciphertext just produced is the next input. A final partial
        // block ends the message, so there is nothing to feed back.
        if (n == block_length) feedback = dst[i..][0..block_length].*;
    }
}

/// CFB, decrypting. Takes an **encryption** context: see `cfbEncrypt`.
/// `dst.len >= src.len` is asserted only: see the contracts above.
pub fn cfbDecrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    iv: [BlockCipher.block_length]u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(dst.len >= src.len);

    var feedback = iv;
    var keystream: [block_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &keystream);
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        block_cipher.encrypt(&keystream, &feedback);
        const n = @min(block_length, src.len - i);
        // Saved first, so that decrypting in place works.
        const chain: [block_length]u8 = if (n == block_length) src[i..][0..block_length].* else undefined;
        for (dst[i..][0..n], src[i..][0..n], keystream[0..n]) |*out, cipher, k| {
            out.* = cipher ^ k;
        }
        if (n == block_length) feedback = chain;
    }
}

/// Electronic Codebook: each block encrypted on its own, with no chaining.
///
/// This leaks which plaintext blocks are equal and must not be used to
/// encrypt a message. It is here because key-wrapping constructions and test
/// vectors are stated in terms of it, and because writing it out is better
/// than a caller reaching for the raw context and getting the loop wrong.
///
/// `src.len` must be a whole number of blocks and `dst.len >= src.len`, both
/// asserted only: see the contracts above.
pub fn ecbEncrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(src.len % block_length == 0);
    assert(dst.len >= src.len);
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        block_cipher.encrypt(dst[i..][0..block_length], src[i..][0..block_length]);
    }
}

/// ECB, decrypting. The same contracts as `ecbEncrypt`.
pub fn ecbDecrypt(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
) void {
    const block_length = BlockCipher.block_length;
    assert(src.len % block_length == 0);
    assert(dst.len >= src.len);
    var i: usize = 0;
    while (i < src.len) : (i += block_length) {
        block_cipher.decrypt(dst[i..][0..block_length], src[i..][0..block_length]);
    }
}

// -- tests ------------------------------------------------------------------

const Des = des.Des;
const Aes128 = std.crypto.core.aes.Aes128;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;
const Aes192 = @import("aes192.zig").Aes192;

test "DES-CBC against the NIST SP 800-38A style vector" {
    // Key and IV from the classic DES-CBC sample; three blocks of plaintext.
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const iv = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    const plaintext = "Now is the time for all ";

    var ciphertext: [24]u8 = undefined;
    cbcEncrypt(Des.EncryptCtx, Des.initEnc(key), &ciphertext, plaintext, iv);
    try testing.expectEqualSlices(u8, &.{
        0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c,
        0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38, 0x9c, 0x0f,
        0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6,
    }, &ciphertext);

    var back: [24]u8 = undefined;
    cbcDecrypt(Des.DecryptCtx, Des.initDec(key), &back, &ciphertext, iv);
    try testing.expectEqualSlices(u8, plaintext, &back);
}

test "DES-CFB against OpenSSL" {
    // The CBC vector's key, IV and plaintext through `openssl enc -des-cfb
    // -nopad`: the one DES-CFB answer in the tree, so that the mode is pinned
    // over this cipher and not only over AES.
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const iv = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    const plaintext = "Now is the time for all ";

    var ciphertext: [24]u8 = undefined;
    cfbEncrypt(Des.EncryptCtx, Des.initEnc(key), &ciphertext, plaintext, iv);
    try testing.expectEqualSlices(u8, &.{
        0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51,
        0xa6, 0x9e, 0x83, 0x9b, 0x1a, 0x92, 0xf7, 0x84,
        0x03, 0x46, 0x71, 0x33, 0x89, 0x8e, 0xa6, 0x22,
    }, &ciphertext);

    var back: [24]u8 = undefined;
    cfbDecrypt(Des.EncryptCtx, Des.initEnc(key), &back, &ciphertext, iv);
    try testing.expectEqualSlices(u8, plaintext, &back);
}

test "CBC decrypts in place" {
    // `dst` and `src` the same slice, which is what decrypting a datagram
    // where it landed looks like. The saved chaining block is what makes this
    // work.
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const iv = [_]u8{0x00} ** 8;
    var buffer = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } ** 3;
    const original = buffer;

    cbcEncrypt(Des.EncryptCtx, Des.initEnc(key), &buffer, &buffer, iv);
    try testing.expect(!std.mem.eql(u8, &original, &buffer));
    cbcDecrypt(Des.DecryptCtx, Des.initDec(key), &buffer, &buffer, iv);
    try testing.expectEqualSlices(u8, &original, &buffer);
}

test "AES-128-CFB against NIST SP 800-38A F.3.13" {
    // The CFB128 vector, which is the mode RFC 3826 specifies for SNMPv3.
    // This is the reason the modes here are generic over the cipher.
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const iv = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const plaintext = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const expected = [_]u8{
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
        0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
        0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
    };

    var ciphertext: [32]u8 = undefined;
    cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), &ciphertext, &plaintext, iv);
    try testing.expectEqualSlices(u8, &expected, &ciphertext);

    // Decryption runs the cipher forwards too, so it takes the same context.
    var back: [32]u8 = undefined;
    cfbDecrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), &back, &ciphertext, iv);
    try testing.expectEqualSlices(u8, &plaintext, &back);
}

test "CFB needs no padding" {
    // A stream mode, so a length that is not a whole number of blocks is
    // fine -- which is one fewer thing for a caller to get wrong.
    const key = [_]u8{0x2b} ** 16;
    const iv = [_]u8{0x11} ** 16;
    for ([_]usize{ 1, 15, 16, 17, 31, 33 }) |len| {
        const plaintext = ([_]u8{0xa5} ** 33)[0..len];
        var ciphertext: [33]u8 = undefined;
        cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), ciphertext[0..len], plaintext, iv);
        var back: [33]u8 = undefined;
        cfbDecrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), back[0..len], ciphertext[0..len], iv);
        try testing.expectEqualSlices(u8, plaintext, back[0..len]);
    }
}

test "CFB decrypts in place" {
    const key = [_]u8{0x2b} ** 16;
    const iv = [_]u8{0x11} ** 16;
    var buffer = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } ** 6;
    const original = buffer;
    cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), &buffer, &buffer, iv);
    try testing.expect(!std.mem.eql(u8, &original, &buffer));
    cfbDecrypt(AesEncryptCtx(Aes128), Aes128.initEnc(key), &buffer, &buffer, iv);
    try testing.expectEqualSlices(u8, &original, &buffer);
}

test "ECB is the raw cipher" {
    const key = [_]u8{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    var p: [8]u8 = undefined;
    std.mem.writeInt(u64, &p, 0x0123456789abcdef, .big);
    var c: [8]u8 = undefined;
    ecbEncrypt(Des.EncryptCtx, Des.initEnc(key), &c, &p);
    try testing.expectEqual(@as(u64, 0x85e813540f0ab405), std.mem.readInt(u64, &c, .big));
    var back: [8]u8 = undefined;
    ecbDecrypt(Des.DecryptCtx, Des.initDec(key), &back, &c);
    try testing.expectEqualSlices(u8, &p, &back);

    // ECB leaks equality between blocks, which is the whole reason not to use
    // it: the same plaintext block twice gives the same ciphertext twice.
    // Asserting it makes the hazard visible rather than implied.
    var repeated: [16]u8 = undefined;
    @memcpy(repeated[0..8], &p);
    @memcpy(repeated[8..16], &p);
    var out: [16]u8 = undefined;
    ecbEncrypt(Des.EncryptCtx, Des.initEnc(key), &out, &repeated);
    try testing.expectEqualSlices(u8, out[0..8], out[8..16]);

    // CBC over the same input does not, because the chaining value differs.
    var chained: [16]u8 = undefined;
    cbcEncrypt(Des.EncryptCtx, Des.initEnc(key), &chained, &repeated, [_]u8{0} ** 8);
    try testing.expect(!std.mem.eql(u8, chained[0..8], chained[8..16]));
}

test "AES-192-CFB against NIST SP 800-38A F.3.15" {
    // The key size `std.crypto` omits, driven through the same generic mode
    // as the other two -- which is the whole argument for the mode being
    // generic rather than tied to a cipher. Cisco's SNMPv3 privacy at 192
    // bits is what wants it.
    const key = [_]u8{
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    };
    const iv = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const plaintext = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const expected = [_]u8{
        0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab,
        0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
        0x67, 0xce, 0x7f, 0x7f, 0x81, 0x17, 0x36, 0x21,
        0x96, 0x1a, 0x2b, 0x70, 0x17, 0x1d, 0x3d, 0x7a,
    };

    var ciphertext: [32]u8 = undefined;
    cfbEncrypt(Aes192.EncryptCtx, Aes192.initEnc(key), &ciphertext, &plaintext, iv);
    try testing.expectEqualSlices(u8, &expected, &ciphertext);

    // And back, with an *encryption* context -- there is no AES-192
    // decryption context in this library, and CFB needs none.
    var back: [32]u8 = undefined;
    cfbDecrypt(Aes192.EncryptCtx, Aes192.initEnc(key), &back, &ciphertext, iv);
    try testing.expectEqualSlices(u8, &plaintext, &back);
}

test "AES-192-CFB at every length, and in place" {
    const key = [_]u8{0x3c} ** 24;
    const iv = [_]u8{0x9e} ** 16;
    for ([_]usize{ 1, 15, 16, 17, 31, 33, 64 }) |len| {
        const plaintext = ([_]u8{0x5a} ** 64)[0..len];
        var ciphertext: [64]u8 = undefined;
        cfbEncrypt(Aes192.EncryptCtx, Aes192.initEnc(key), ciphertext[0..len], plaintext, iv);
        var back: [64]u8 = undefined;
        cfbDecrypt(Aes192.EncryptCtx, Aes192.initEnc(key), back[0..len], ciphertext[0..len], iv);
        try testing.expectEqualSlices(u8, plaintext, back[0..len]);

        // In place, which is how a datagram is decrypted where it landed.
        var scratch: [64]u8 = undefined;
        @memcpy(scratch[0..len], plaintext);
        cfbEncrypt(Aes192.EncryptCtx, Aes192.initEnc(key), scratch[0..len], scratch[0..len], iv);
        try testing.expectEqualSlices(u8, ciphertext[0..len], scratch[0..len]);
    }
}

test "the three AES key sizes give three different ciphertexts" {
    // A mode that silently used the wrong key schedule would still
    // round-trip, so this pins that the key length actually selects the
    // cipher -- which is exactly the mistake that would make an AES-256
    // SNMPv3 session appear to work against a permissive agent.
    const iv = [_]u8{0x11} ** 16;
    const plaintext = [_]u8{0xa5} ** 16;
    var out128: [16]u8 = undefined;
    var out192: [16]u8 = undefined;
    var out256: [16]u8 = undefined;
    cfbEncrypt(AesEncryptCtx(Aes128), Aes128.initEnc(@splat(0x2b)), &out128, &plaintext, iv);
    cfbEncrypt(Aes192.EncryptCtx, Aes192.initEnc(@splat(0x2b)), &out192, &plaintext, iv);
    cfbEncrypt(
        AesEncryptCtx(std.crypto.core.aes.Aes256),
        std.crypto.core.aes.Aes256.initEnc(@splat(0x2b)),
        &out256,
        &plaintext,
        iv,
    );
    try testing.expect(!std.mem.eql(u8, &out128, &out192));
    try testing.expect(!std.mem.eql(u8, &out192, &out256));
    try testing.expect(!std.mem.eql(u8, &out128, &out256));
}
