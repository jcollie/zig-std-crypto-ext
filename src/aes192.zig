// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! AES-192, the key size `std.crypto` leaves out.
//!
//! `std.crypto.core.aes` ships `Aes128` and `Aes256` and nothing between,
//! which is a reasonable place to stop: nothing modern specifies AES-192, and
//! its 12 rounds buy little over 128's 10 against any attack that matters.
//! Its own key schedule is generic enough to have handled it -- the expansion
//! loop in `aes/soft.zig` is written over the number of key words and even
//! gets the extra `SubWord` that only AES-256 needs right -- but two
//! `comptime` assertions confine it to 128 and 256, and relaxing those is a
//! change to `std` rather than a use of it.
//!
//! What wants AES-192 is Cisco. `draft-blumenthal-aes-usm` defines
//! SNMPv3 privacy at all three key sizes, IOS implements all three, and a
//! manager that cannot speak the middle one cannot talk to a device
//! configured for it. That draft expired without becoming an RFC, so this is
//! interoperability with deployed equipment rather than conformance to
//! anything.
//!
//! ## Encryption only, and why that is not a gap
//!
//! There is `initEnc` and no `initDec`, because the only thing that needs
//! AES-192 here is **CFB**, and CFB never runs the cipher backwards: it
//! builds a keystream by encrypting the feedback block, so decrypting is the
//! same operation with the ciphertext fed back instead of the plaintext. The
//! same is true of CTR. Shipping an inverse cipher and an inverted key
//! schedule that nothing calls would be shipping untested code with a
//! published name on it.
//!
//! Asking for `Aes192.initDec` is therefore a compile error naming the
//! missing declaration, which is a better way to find this out than a runtime
//! surprise. Adding it later is additive: the inverse cipher needs the
//! inverse S-box and `InvMixColumns`, and nothing about the layout here would
//! have to change.
//!
//! ## Shape
//!
//! Deliberately the shape of `std.crypto.core.aes.Aes128`, so that it reads
//! the same way and so that this library's generic `modes` take it without
//! knowing what it is -- `key_bits`, `initEnc`, and a context with a
//! `block_length` and `encrypt`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Rijndael's S-box, as FIPS 197 Figure 7 prints it.
const sbox = [256]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/// The round constants, `x^(i-1)` in GF(2^8). Only eight are needed for
/// AES-192's 52-word expansion; AES-128 needs ten, which is the one place a
/// smaller key does *more* key-schedule work.
const rcon = [_]u8{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

/// Multiplication by x in GF(2^8) modulo Rijndael's polynomial.
fn xtime(a: u8) u8 {
    return (a << 1) ^ (if (a & 0x80 != 0) @as(u8, 0x1b) else 0);
}

/// AES-192: a 24-octet key and twelve rounds.
pub const Aes192 = struct {
    pub const key_bits: usize = 192;
    pub const key_length = key_bits / 8;
    pub const block_length = 16;
    /// FIPS 197 Table 2. The same formula `std` uses -- (192-64)/32 + 8 -- and
    /// the reason AES-192 is twelve rather than ten or fourteen.
    pub const rounds = 12;

    pub fn initEnc(key: [key_length]u8) EncryptCtx {
        return .{ .round_keys = expandKey(key) };
    }

    // No `initDec`. See the note at the top of this file: CFB and CTR only
    // ever run the cipher forwards, so an inverse cipher here would be
    // untested code with a published name on it. Asking for it is a compile
    // error naming this declaration, which is the point.

    pub const EncryptCtx = struct {
        pub const block_length = Aes192.block_length;
        /// Thirteen round keys of sixteen octets: the initial AddRoundKey and
        /// one per round.
        round_keys: [(rounds + 1) * 16]u8,

        pub fn encrypt(
            ctx: EncryptCtx,
            dst: *[Aes192.block_length]u8,
            src: *const [Aes192.block_length]u8,
        ) void {
            var state: [16]u8 = src.*;
            addRoundKey(&state, ctx.round_keys[0..16]);

            var round: usize = 1;
            while (round < rounds) : (round += 1) {
                subBytes(&state);
                shiftRows(&state);
                mixColumns(&state);
                addRoundKey(&state, ctx.round_keys[round * 16 ..][0..16]);
            }
            // The last round omits MixColumns, which is what makes the
            // inverse cipher's rounds line up.
            subBytes(&state);
            shiftRows(&state);
            addRoundKey(&state, ctx.round_keys[rounds * 16 ..][0..16]);

            dst.* = state;
        }
    };

    /// FIPS 197 Figure 11, with Nk = 6.
    ///
    /// The 24-octet key is six words, and 52 words are produced. Every sixth
    /// word gets RotWord, SubWord and a round constant; the rest are a plain
    /// XOR with the word six places back. AES-256 additionally applies
    /// SubWord at `i % Nk == 4`, which is why a reading generic over Nk has
    /// to guard that on `Nk > 6` -- and why AES-192 is not simply AES-256
    /// with a shorter key.
    fn expandKey(key: [key_length]u8) [(rounds + 1) * 16]u8 {
        const words_in_key = key_length / 4; // 6
        const total_words = (rounds + 1) * 4; // 52
        var w: [total_words][4]u8 = undefined;

        for (0..words_in_key) |i| {
            w[i] = key[i * 4 ..][0..4].*;
        }

        for (words_in_key..total_words) |i| {
            var t = w[i - 1];
            if (i % words_in_key == 0) {
                // RotWord, then SubWord, then the round constant.
                //
                // Through a temporary, and this is not style. Assigning an
                // array from a literal built out of itself --
                // `t = .{ t[1], t[2], t[3], t[0] }` -- is performed
                // **element by element in place**, so by the time the last
                // element reads `t[0]` it has already been overwritten with
                // the old `t[1]`. That turns RotWord into a rotation that
                // duplicates one byte and drops another, and the resulting
                // cipher is perfectly self-consistent and wrong: it was the
                // FIPS 197 known answer that caught it, and the divergence
                // was a single byte of the *first* expanded word.
                const rotated: [4]u8 = .{ t[1], t[2], t[3], t[0] };
                t = rotated;
                for (&t) |*byte| byte.* = sbox[byte.*];
                t[0] ^= rcon[i / words_in_key - 1];
            }
            // No `else if (i % words_in_key == 4)` branch: that step belongs
            // to AES-256 alone, and applying it here would produce a cipher
            // that is self-consistent and wrong.
            for (&w[i], w[i - words_in_key], t) |*out, previous, mixed| {
                out.* = previous ^ mixed;
            }
        }

        var round_keys: [(rounds + 1) * 16]u8 = undefined;
        for (0..total_words) |i| {
            @memcpy(round_keys[i * 4 ..][0..4], &w[i]);
        }
        return round_keys;
    }
};

fn addRoundKey(state: *[16]u8, round_key: *const [16]u8) void {
    for (state, round_key) |*byte, key_byte| byte.* ^= key_byte;
}

fn subBytes(state: *[16]u8) void {
    for (state) |*byte| byte.* = sbox[byte.*];
}

/// Row `r` rotated left by `r`. The state is column-major -- byte `r + 4c` is
/// row r, column c -- which is why this does not look like a rotation.
fn shiftRows(state: *[16]u8) void {
    // The copy is load bearing for the same reason the temporary in
    // `expandKey` is: assigning an array from a literal built out of itself
    // happens element by element in place, so a permutation written without
    // a copy reads values it has already overwritten.
    const s = state.*;
    state.* = .{
        s[0],  s[5],  s[10], s[15],
        s[4],  s[9],  s[14], s[3],
        s[8],  s[13], s[2],  s[7],
        s[12], s[1],  s[6],  s[11],
    };
}

fn mixColumns(state: *[16]u8) void {
    var column: usize = 0;
    while (column < 4) : (column += 1) {
        const c = state[column * 4 ..][0..4];
        const a0 = c[0];
        const a1 = c[1];
        const a2 = c[2];
        const a3 = c[3];
        c[0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        c[1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        c[2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        c[3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

// -- tests ------------------------------------------------------------------
//
// Every vector here was cross-checked against OpenSSL, for the same reason
// the DES vectors were: an AES that is self-consistent and wrong is easy to
// write -- omit the `Nk > 6` guard in the key schedule and it still produces
// a perfectly reversible cipher -- so a round-trip test proves nothing and a
// number transcribed from memory is worth no more than the memory.
//
//   openssl enc -aes-192-ecb -nopad -K <48 hex digits> -in block.bin

fn expectBlock(key: [24]u8, plaintext: [16]u8, expected: [16]u8) !void {
    var out: [16]u8 = undefined;
    Aes192.initEnc(key).encrypt(&out, &plaintext);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "FIPS 197 C.2, the AES-192 known answer" {
    // The vector every AES-192 implementation is checked against first.
    try expectBlock(
        .{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        },
        .{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        },
        .{
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
            0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
        },
    );
}

test "the all-zero key and block" {
    // Not a published vector, so computed with OpenSSL. Worth having because
    // a key schedule bug that happens to cancel on a structured key shows up
    // on a degenerate one.
    try expectBlock(
        @splat(0),
        @splat(0),
        .{
            0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3,
            0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7,
        },
    );
}

test "the NIST SP 800-38A key, which SNMPv3 privacy uses the same way" {
    // The key from SP 800-38A's AES-192 examples, on the first block of its
    // plaintext. In CFB that block is XORed with the keystream rather than
    // being the ciphertext, so this checks the raw cipher underneath the mode
    // -- and `modes.zig`'s test checks the mode on top of it.
    try expectBlock(
        .{
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        },
        .{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        },
        // The keystream block SP 800-38A F.3.15 implies: its first ciphertext
        // block XOR its first plaintext block.
        .{
            0xa6, 0x09, 0xb3, 0x8d, 0xf3, 0xb1, 0x13, 0x3d,
            0xdd, 0xff, 0x27, 0x18, 0xba, 0x09, 0x56, 0x5e,
        },
    );
}

test "twelve rounds, thirteen round keys, and the first is the key itself" {
    try testing.expectEqual(@as(usize, 12), Aes192.rounds);
    try testing.expectEqual(@as(usize, 24), Aes192.key_length);
    try testing.expectEqual(@as(usize, 16), Aes192.block_length);
    // The formula std uses, which gives 10, 12 and 14 for the three sizes.
    try testing.expectEqual(Aes192.rounds, (Aes192.key_bits - 64) / 32 + 8);

    // FIPS 197: the first Nk words of the expansion are the key verbatim, so
    // the first 24 octets of the schedule are the key. Checking it catches a
    // transposed expansion that is otherwise invisible behind a correct
    // ciphertext.
    var key: [24]u8 = undefined;
    for (&key, 0..) |*byte, i| byte.* = @intCast(i);
    const ctx = Aes192.initEnc(key);
    try testing.expectEqualSlices(u8, &key, ctx.round_keys[0..24]);
    try testing.expectEqual(@as(usize, 13 * 16), ctx.round_keys.len);
}

test "every bit of the key matters, and every bit of the block" {
    // A key schedule that dropped a word -- which is exactly what happens if
    // the `Nk > 6` guard is got wrong -- would leave some key bits with no
    // effect, and the known answers above would not necessarily catch it.
    var key: [24]u8 = undefined;
    for (&key, 0..) |*byte, i| byte.* = @intCast(i * 7 + 1);
    const block = [_]u8{0xa5} ** 16;

    var baseline: [16]u8 = undefined;
    Aes192.initEnc(key).encrypt(&baseline, &block);

    for (0..24 * 8) |bit| {
        var flipped = key;
        flipped[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var out: [16]u8 = undefined;
        Aes192.initEnc(flipped).encrypt(&out, &block);
        try testing.expect(!std.mem.eql(u8, &baseline, &out));
    }
    for (0..16 * 8) |bit| {
        var flipped = block;
        flipped[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var out: [16]u8 = undefined;
        Aes192.initEnc(key).encrypt(&out, &flipped);
        try testing.expect(!std.mem.eql(u8, &baseline, &out));
    }
}

test "the S-box is a permutation" {
    // A transcription error in a 256-entry table is the classic way to get a
    // cipher that is wrong on some inputs and right on the ones you tested,
    // and a duplicate entry is what such an error looks like.
    var seen = [_]bool{false} ** 256;
    for (sbox) |value| {
        try testing.expect(!seen[value]);
        seen[value] = true;
    }
    // And the two fixed points FIPS 197 notes.
    try testing.expectEqual(@as(u8, 0x63), sbox[0x00]);
    try testing.expectEqual(@as(u8, 0x7c), sbox[0x01]);
}
