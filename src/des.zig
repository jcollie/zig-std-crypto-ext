// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! DES and Triple DES, the block ciphers `std.crypto` does not have.
//!
//! **These are obsolete and are here for the protocols that will not let them
//! go.** Single DES has a 56-bit key and has been brute-forceable since 1998;
//! two-key Triple DES has a meet-in-the-middle attack at 2^57 work given
//! enough known plaintext, and the 64-bit block means a birthday bound at 32
//! GiB under one key whatever the key length. Nothing new should choose either.
//! What keeps them alive is that SNMPv3's `usmDESPrivProtocol` is DES-CBC and
//! is still the default privacy protocol on a great deal of network equipment,
//! so a manager that cannot speak it cannot talk to those devices at all.
//! Kerberos 4, PKCS#12, MS-CHAP and a good deal of banking hardware are in the
//! same position.
//!
//! The shape here is deliberately the shape of `std.crypto.core.aes.Aes128`:
//! `initEnc` and `initDec` return contexts with a `block_length` and an
//! `encrypt`/`decrypt` over a single block. That is what lets `std`'s own
//! `crypto.modes.ctr` take one of these without knowing what it is, and it is
//! why `modes.cbc` and `modes.cfb` in this library are written the same
//! generic way rather than being DES-specific.
//!
//! ## What DES actually is
//!
//! Sixteen rounds of a Feistel network over a 64-bit block. Each round splits
//! the block in half, expands the right half from 32 to 48 bits, mixes in a
//! 48-bit round key, puts the result through eight S-boxes that take 6 bits to
//! 4, permutes those 32 bits, and XORs them into the left half before swapping
//! the halves. The initial and final permutations either side of that are
//! pure bit shuffling with no cryptographic effect -- they exist because the
//! 1970s hardware they were designed for got them for free -- and the key
//! schedule is a third shuffle plus a rotating split.
//!
//! It is all fixed tables, so it is all in this file, and each table says
//! which one it is in FIPS 46-3's numbering.
//!
//! ## Timing
//!
//! Every operation here takes the same time whatever the key and the block.
//! The permutation tables are only ever read at constant indices, every loop
//! runs a fixed number of times, and the S-boxes -- the one place a DES
//! implementation normally reads memory at a key-dependent address, which is
//! the cache-timing attack of Tsunoo et al. (2003) -- are evaluated by `sbox`
//! with masks and a shift rather than a lookup. What that rests on is that
//! integer compare, mask and variable-distance shift are constant-time, which
//! they are on x86-64 and AArch64 and which is the same assumption
//! `std.crypto` makes; and that the compiler does not turn a mask into a
//! branch, which nothing forbids it to do, so like every constant-time claim
//! made in a language without constant-time semantics this one is
//! best-effort. It is not bitsliced. The key helpers `hasOddParity`,
//! `setOddParity` and `isWeak` are written the same way, since the key is what
//! they are given.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

// -- the tables -------------------------------------------------------------
//
// Every one of these is 1-based and numbered from the most significant bit,
// which is how FIPS 46-3 prints them; the code subtracts one and counts from
// the top when it uses them. Transcribing them the other way round is the
// classic way to get a DES that is self-consistent and wrong, so they are
// left exactly as published and the conversion happens in `permute`.
//
// Each is checked at compile time, at the end of this section, for the
// property it is supposed to have: a transcription error that repeats or
// omits a bit produces a cipher that still round-trips, and an entry outside
// the input width would make `permute` shift by more than there is, which is
// a panic in a safe build and undefined behaviour in a fast one.

/// IP, the initial permutation. 64 bits to 64.
const initial_permutation = [64]u8{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

/// IP^-1, the final permutation, which undoes IP.
const final_permutation = [64]u8{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25,
};

/// E, the expansion. 32 bits of the right half to the 48 the round key is.
/// Every fourth bit appears twice, which is what makes the halves diffuse
/// into each other.
const expansion = [48]u8{
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
};

/// P, the permutation applied to the S-box output inside the round function.
const round_permutation = [32]u8{
    16, 7,  20, 21, 29, 12, 28, 17,
    1,  15, 23, 26, 5,  18, 31, 10,
    2,  8,  24, 14, 32, 27, 3,  9,
    19, 13, 30, 6,  22, 11, 4,  25,
};

/// PC-1, the permuted choice that drops the eight parity bits: 64 key bits to
/// 56. This is where the "56-bit key" comes from -- bits 8, 16, ... 64 of the
/// key are never used for anything, so two keys differing only in those are
/// the same key.
const key_permutation_1 = [56]u8{
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4,
};

/// PC-2, the permuted choice that picks each round's 48-bit subkey out of the
/// 56-bit rotating register. The eight bits it leaves out are 9, 18, 22, 25,
/// 35, 38, 43 and 54.
const key_permutation_2 = [48]u8{
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

/// How far the key register rotates before each round. They sum to 28, which
/// is why the register returns to its starting position after sixteen rounds.
const key_rotations = [16]u3{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

/// The eight S-boxes as FIPS 46-3 prints them: 4 rows of 16, where the row is
/// the **outer** two bits of the six-bit input and the column the **inner**
/// four.
///
/// That indexing is not the input itself, and treating it as though it were is
/// the single most common way to write a DES that round-trips perfectly and
/// produces the wrong ciphertext -- which is exactly what happened here, and
/// what the known-answer tests caught. `s_boxes` below does the shuffle once
/// at compile time so that the rest of the file can index by the input value
/// directly.
const s_boxes_published = [8][64]u8{
    .{
        14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
        0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
        4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
        15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13,
    },
    .{
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
        3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
        0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
        13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9,
    },
    .{
        10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
        13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
        13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
        1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12,
    },
    .{
        7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
        13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
        10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
        3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14,
    },
    .{
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3,
    },
    .{
        12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
        10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
        9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
        4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13,
    },
    .{
        4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
        13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
        1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
        6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12,
    },
    .{
        13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
        1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
        7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
        2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11,
    },
};

/// The same eight boxes, re-indexed by the six-bit input.
///
/// The published row is `(b1 b6)` and the column `(b2 b3 b4 b5)`, so for an
/// input `b1..b6` the published entry lives at `row * 16 + column`. Doing that
/// arithmetic here keeps the tables above verbatim as printed, which is what
/// makes them checkable against the standard. The round function does not
/// read this table -- see `s_boxes_packed` for why -- but it is what that
/// table is built from and what the tests check it against.
const s_boxes = blk: {
    var boxes: [8][64]u8 = undefined;
    for (s_boxes_published, 0..) |published, box| {
        for (0..64) |six| {
            const row = ((six >> 5) & 1) * 2 + (six & 1);
            const column = (six >> 1) & 0xf;
            boxes[box][six] = published[row * 16 + column];
        }
    }
    break :blk boxes;
};

/// The same eight boxes once more, packed sixteen nibbles to a word, so that
/// the round function can pick an entry without reading memory at an address
/// that depends on the key.
///
/// Word `w` of a box holds the entries for inputs `16w` to `16w + 15`, and
/// within it input `j` sits in bits `4j` to `4j + 3`. `sbox` selects the word
/// with masks and the nibble with a shift, which is the whole of the
/// constant-time claim made at the top of this file.
const s_boxes_packed = blk: {
    var boxes: [8][4]u64 = @splat(@splat(0));
    for (s_boxes, 0..) |box, b| {
        for (box, 0..) |entry, six| {
            boxes[b][six / 16] |= @as(u64, entry) << ((six % 16) * 4);
        }
    }
    break :blk boxes;
};

// The checks. Each is a `@compileError` naming the table, so that a slip in
// transcription is a build failure that says where rather than a wrong
// ciphertext that says nothing.

/// `table` names distinct bits of an `in_bits` wide value, and the bits it
/// leaves out are exactly `omitted`. With nothing omitted it is a permutation.
fn checkSelection(comptime name: []const u8, comptime table: []const u8, comptime in_bits: usize, comptime omitted: []const u8) void {
    var seen = [_]bool{false} ** (in_bits + 1);
    for (table) |bit| {
        if (bit < 1 or bit > in_bits) @compileError(name ++ ": entry out of range");
        if (seen[bit]) @compileError(name ++ ": repeats a bit");
        seen[bit] = true;
    }
    for (1..in_bits + 1) |bit| {
        var is_omitted = false;
        for (omitted) |o| is_omitted = is_omitted or o == bit;
        if (seen[bit] == is_omitted) @compileError(name ++ ": omits the wrong bits");
    }
}

comptime {
    // The checks are a few thousand simple steps, which is over the default.
    @setEvalBranchQuota(20_000);
    checkSelection("IP", &initial_permutation, 64, &.{});
    checkSelection("IP^-1", &final_permutation, 64, &.{});
    checkSelection("P", &round_permutation, 32, &.{});
    checkSelection("PC-1", &key_permutation_1, 64, &.{ 8, 16, 24, 32, 40, 48, 56, 64 });
    checkSelection("PC-2", &key_permutation_2, 56, &.{ 9, 18, 22, 25, 35, 38, 43, 54 });

    // E names every bit of the 32, and doubles exactly the ones either side of
    // each four-bit group: bit 4n and bit 4n+1.
    var times = [_]u8{0} ** 33;
    for (expansion) |bit| {
        if (bit < 1 or bit > 32) @compileError("E: entry out of range");
        times[bit] += 1;
    }
    for (1..33) |bit| {
        const expected: u8 = if (bit % 4 == 0 or bit % 4 == 1) 2 else 1;
        if (times[bit] != expected) @compileError("E: wrong bit doubled");
    }

    // IP^-1 undoes IP.
    for (initial_permutation, 1..) |from, to| {
        if (final_permutation[from - 1] != to) @compileError("IP^-1 does not undo IP");
    }

    // The register comes back round after sixteen rounds.
    var total = 0;
    for (key_rotations) |r| total += r;
    if (total != 28) @compileError("key rotations do not sum to 28");

    // Each S-box row is a permutation of 0..15, as printed.
    for (s_boxes_published) |box| {
        for (0..4) |row| {
            var seen = [_]bool{false} ** 16;
            for (box[row * 16 ..][0..16]) |v| {
                if (v > 15) @compileError("S-box entry out of range");
                if (seen[v]) @compileError("S-box row repeats a value");
                seen[v] = true;
            }
        }
    }

    // And the weak keys are written with odd parity, which `isWeak` relies on.
    for (weak_keys) |key| {
        if (!hasOddParity(&key)) @compileError("a weak key is written without odd parity");
    }
}

// -- the machinery ----------------------------------------------------------

/// Applies one of the tables above, reading `in_bits` from `in` and producing
/// `table.len` bits, both numbered from the most significant.
fn permute(comptime out_bits: usize, comptime in_bits: usize, table: *const [out_bits]u8, in: u64) u64 {
    var out: u64 = 0;
    for (table) |from| {
        // The tables are 1-based from the top, so bit `from` of an `in_bits`
        // wide value lives at shift `in_bits - from`.
        const bit = (in >> @intCast(in_bits - from)) & 1;
        out = (out << 1) | bit;
    }
    return out;
}

/// The sixteen 48-bit round keys, in encryption order.
fn schedule(key: [8]u8) [16]u48 {
    const key64 = std.mem.readInt(u64, &key, .big);
    const permuted = permute(56, 64, &key_permutation_1, key64);
    // Two 28-bit halves that rotate independently.
    var c: u28 = @truncate(permuted >> 28);
    var d: u28 = @truncate(permuted);
    var keys: [16]u48 = undefined;
    for (&keys, key_rotations) |*out, rotation| {
        c = std.math.rotl(u28, c, rotation);
        d = std.math.rotl(u28, d, rotation);
        const combined = (@as(u64, c) << 28) | @as(u64, d);
        out.* = @truncate(permute(48, 56, &key_permutation_2, combined));
    }
    return keys;
}

/// S-box `box` applied to the six-bit `six`, without a data-dependent memory
/// access: the word that holds the entry is chosen by ANDing each of the four
/// against a mask that is all ones for exactly one of them, and the entry is
/// shifted out of that.
inline fn sbox(comptime box: usize, six: u6) u4 {
    const hi: u2 = @intCast(six >> 4);
    var word: u64 = 0;
    inline for (s_boxes_packed[box], 0..) |candidate, w| {
        const mask: u64 = 0 -% @as(u64, @intFromBool(hi == w));
        word |= candidate & mask;
    }
    const shift: u6 = @as(u6, @as(u4, @truncate(six))) * 4;
    return @truncate(word >> shift);
}

/// The Feistel round function: expand, mix in the key, substitute, permute.
fn feistel(right: u32, round_key: u48) u32 {
    const expanded = permute(48, 32, &expansion, right) ^ @as(u64, round_key);
    var substituted: u32 = 0;
    inline for (0..8) |box| {
        // Six bits at a time, most significant group first.
        const six: u6 = @truncate(expanded >> @intCast(42 - box * 6));
        substituted = (substituted << 4) | sbox(box, six);
    }
    return @truncate(permute(32, 32, &round_permutation, substituted));
}

/// One block, sixteen rounds, with the round keys in whatever order was
/// given -- which is the whole of the difference between encrypting and
/// decrypting a Feistel cipher.
fn crypt(keys: *const [16]u48, block: u64) u64 {
    const permuted = permute(64, 64, &initial_permutation, block);
    var left: u32 = @truncate(permuted >> 32);
    var right: u32 = @truncate(permuted);
    for (keys) |round_key| {
        const next = left ^ feistel(right, round_key);
        left = right;
        right = next;
    }
    // The halves are swapped once more at the end, which is what makes the
    // same routine run backwards with the keys reversed.
    const combined = (@as(u64, right) << 32) | @as(u64, left);
    return permute(64, 64, &final_permutation, combined);
}

// -- DES --------------------------------------------------------------------

/// Single DES: a 64-bit key of which 56 bits matter, and a 64-bit block.
///
/// A context holds the sixteen expanded round keys and has no `deinit`. A
/// caller who wants them gone when finished zeroes the context with
/// `std.crypto.secureZero`, as with `std.crypto.core.aes`.
pub const Des = struct {
    pub const key_length = 8;
    pub const block_length = 8;
    /// Eight of the key's 64 bits are parity and are ignored, which is why
    /// this is not 64.
    pub const key_bits = 56;

    pub fn initEnc(key: [key_length]u8) EncryptCtx {
        return .{ .keys = schedule(key) };
    }

    pub fn initDec(key: [key_length]u8) DecryptCtx {
        var keys = schedule(key);
        std.mem.reverse(u48, &keys);
        return .{ .keys = keys };
    }

    pub const EncryptCtx = struct {
        pub const block_length = Des.block_length;
        keys: [16]u48,

        pub fn encrypt(ctx: EncryptCtx, dst: *[Des.block_length]u8, src: *const [Des.block_length]u8) void {
            std.mem.writeInt(u64, dst, crypt(&ctx.keys, std.mem.readInt(u64, src, .big)), .big);
        }
    };

    /// Deliberately has no `encrypt`: CFB and CTR run the cipher forwards to
    /// decrypt and so take an `EncryptCtx`, and a decryption context that
    /// answered to `encrypt` would let them compile with the schedule
    /// reversed -- producing ciphertext that round-trips with itself and that
    /// nothing else can read.
    pub const DecryptCtx = struct {
        pub const block_length = Des.block_length;
        keys: [16]u48,

        pub fn decrypt(ctx: DecryptCtx, dst: *[Des.block_length]u8, src: *const [Des.block_length]u8) void {
            std.mem.writeInt(u64, dst, crypt(&ctx.keys, std.mem.readInt(u64, src, .big)), .big);
        }
    };
};

/// Triple DES in EDE order: encrypt with the first key, *decrypt* with the
/// second, encrypt with the third.
///
/// The middle decryption is not a mistake and is not for security -- it is so
/// that setting all three keys equal makes this identical to single DES, which
/// is how the hardware of the day stayed compatible. Two-key 3DES is this with
/// the third key equal to the first.
///
/// As with `Des`, a context holds the expanded round keys -- forty-eight of
/// them here -- and a caller who wants them gone zeroes it with
/// `std.crypto.secureZero`.
pub const Des3 = struct {
    pub const key_length = 24;
    pub const block_length = 8;
    pub const key_bits = 168;

    pub fn initEnc(key: [key_length]u8) EncryptCtx {
        return .{
            .k1 = schedule(key[0..8].*),
            .k2 = reversed(schedule(key[8..16].*)),
            .k3 = schedule(key[16..24].*),
        };
    }

    pub fn initDec(key: [key_length]u8) DecryptCtx {
        // Backwards: undo the third, redo the second, undo the first.
        return .{
            .k1 = reversed(schedule(key[16..24].*)),
            .k2 = schedule(key[8..16].*),
            .k3 = reversed(schedule(key[0..8].*)),
        };
    }

    /// Two-key 3DES, where the third key is the first again. Common in
    /// older protocols and weaker than it looks.
    pub fn initEnc2(key: [16]u8) EncryptCtx {
        var full: [key_length]u8 = undefined;
        @memcpy(full[0..16], &key);
        @memcpy(full[16..24], key[0..8]);
        return initEnc(full);
    }

    pub fn initDec2(key: [16]u8) DecryptCtx {
        var full: [key_length]u8 = undefined;
        @memcpy(full[0..16], &key);
        @memcpy(full[16..24], key[0..8]);
        return initDec(full);
    }

    fn reversed(keys: [16]u48) [16]u48 {
        var out = keys;
        std.mem.reverse(u48, &out);
        return out;
    }

    fn triple(k1: *const [16]u48, k2: *const [16]u48, k3: *const [16]u48, block: u64) u64 {
        return crypt(k3, crypt(k2, crypt(k1, block)));
    }

    pub const EncryptCtx = struct {
        pub const block_length = Des3.block_length;
        k1: [16]u48,
        k2: [16]u48,
        k3: [16]u48,

        pub fn encrypt(ctx: EncryptCtx, dst: *[Des3.block_length]u8, src: *const [Des3.block_length]u8) void {
            const out = triple(&ctx.k1, &ctx.k2, &ctx.k3, std.mem.readInt(u64, src, .big));
            std.mem.writeInt(u64, dst, out, .big);
        }
    };

    pub const DecryptCtx = struct {
        pub const block_length = Des3.block_length;
        k1: [16]u48,
        k2: [16]u48,
        k3: [16]u48,

        pub fn decrypt(ctx: DecryptCtx, dst: *[Des3.block_length]u8, src: *const [Des3.block_length]u8) void {
            const out = triple(&ctx.k1, &ctx.k2, &ctx.k3, std.mem.readInt(u64, src, .big));
            std.mem.writeInt(u64, dst, out, .big);
        }
    };
};

/// Whether every byte of `key` has odd parity, which is the convention DES
/// keys are distributed under.
///
/// Nothing in the cipher cares -- the parity bits are discarded by PC-1 -- so
/// this is for a caller that wants to check a key it was given, or to fix one
/// up before handing it to hardware that does care. It looks at every byte
/// rather than stopping at the first even one, so that how long it takes says
/// nothing about the key.
pub fn hasOddParity(key: []const u8) bool {
    var all_odd: u8 = 1;
    for (key) |byte| all_odd &= @popCount(byte) & 1;
    return all_odd == 1;
}

/// `key` with each byte's low bit set so that the byte has odd parity.
///
/// The parity of the other seven bits is key material, so this is done with
/// arithmetic rather than a branch on it.
pub fn setOddParity(key: []u8) void {
    for (key) |*byte| {
        const parity: u8 = @popCount(byte.* & 0xfe) & 1;
        byte.* = (byte.* & 0xfe) | (parity ^ 1);
    }
}

/// The four keys for which DES is an involution -- encrypting twice returns
/// the plaintext -- because their key schedule is the same in every round.
///
/// A protocol deriving a key from a password can produce one of these by
/// accident, and `usmDESPrivProtocol` derives its key from a password.
pub const weak_keys = [4][8]u8{
    .{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    .{ 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
    .{ 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },
    .{ 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
};

/// Whether `key` is one of `weak_keys`, ignoring parity bits.
///
/// Only the four weak keys: not the twelve semi-weak ones, which pair up into
/// keys that undo each other and which OpenSSL's `DES_set_key_checked` also
/// refuses. The comparison is constant-time and looks at all four, since the
/// key is a secret and this is the function called on it while it is fresh.
pub fn isWeak(key: [8]u8) bool {
    var normalized = key;
    setOddParity(&normalized);
    var hit: u8 = 0;
    for (weak_keys) |weak| {
        hit |= @intFromBool(std.crypto.timing_safe.eql([8]u8, normalized, weak));
    }
    return hit != 0;
}

// -- tests ------------------------------------------------------------------
//
// Every vector here was cross-checked against OpenSSL's legacy provider:
//
//   openssl enc -provider legacy -provider default -des-ecb -nopad -K <key>
//
// That is not belt-and-braces. A DES that is self-consistent and wrong is easy
// to write -- index the S-boxes with the raw six bits instead of the published
// row and column and it still round-trips perfectly, which is precisely the
// bug these tests caught here -- so a round-trip test proves almost nothing,
// and a vector transcribed from memory is worth no more than the memory. One
// of the four NBS values below was wrong when first written, and OpenSSL is
// what settled which of us was.

fn expectBlock(comptime T: type, key: []const u8, plaintext: u64, expected: u64) !void {
    var p: [8]u8 = undefined;
    std.mem.writeInt(u64, &p, plaintext, .big);

    var c: [8]u8 = undefined;
    const enc = T.initEnc(key[0..T.key_length].*);
    enc.encrypt(&c, &p);
    try testing.expectEqual(expected, std.mem.readInt(u64, &c, .big));

    var back: [8]u8 = undefined;
    const dec = T.initDec(key[0..T.key_length].*);
    dec.decrypt(&back, &c);
    try testing.expectEqualSlices(u8, &p, &back);
}

test "the FIPS 46-3 known answer" {
    // The vector every DES implementation is checked against first.
    try expectBlock(Des, &.{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 }, 0x0123456789abcdef, 0x85e813540f0ab405);
}

test "Ron Rivest's cycle, first step" {
    // From "Testing Implementations of DES": the all-zero key on the all-zero
    // block, and the all-ones key on the all-ones block.
    try expectBlock(Des, &([_]u8{0x00} ** 8), 0x0000000000000000, 0x8ca64de9c1b123a7);
    try expectBlock(Des, &([_]u8{0xff} ** 8), 0xffffffffffffffff, 0x7359b2163e4edc58);
}

test "the NBS sample round trip" {
    try expectBlock(Des, "\x01\x23\x45\x67\x89\xab\xcd\xef", 0x1111111111111111, 0x17668dfc7292532d);
    try expectBlock(Des, "\x01\x23\x45\x67\x89\xab\xcd\xef", 0x0123456789abcdef, 0x56cc09e7cfdc4cef);
    // A weak key, and still a perfectly ordinary encryption: weak means the
    // key schedule is the same every round, not that the output is special.
    // Confirmed against OpenSSL's legacy provider, which is also what caught
    // the value originally written here being wrong.
    try expectBlock(Des, "\x1f\x1f\x1f\x1f\x0e\x0e\x0e\x0e", 0x0123456789abcdef, 0xdb958605f8c8c606);
    try expectBlock(Des, "\xfe\xdc\xba\x98\x76\x54\x32\x10", 0x0123456789abcdef, 0xed39d950fa74bcc4);
}

test "triple DES with three equal keys is single DES" {
    // The whole reason for the middle decryption. Same key three times, same
    // answer as single DES on the FIPS vector.
    const key = [_]u8{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    try expectBlock(Des3, &(key ++ key ++ key), 0x0123456789abcdef, 0x85e813540f0ab405);
}

test "the NIST SP 800-67 known answer" {
    // Appendix B of SP 800-67: three distinct keys over three blocks of
    // plaintext, whose misspelling is the standard's own. A round trip would
    // pass with k1 and k3 swapped in both directions; this does not.
    // Confirmed against OpenSSL: -des-ede3 -nopad.
    const key3 = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
    };
    const plaintext = "The qufck brown fox jump";
    const expected = [3]u64{ 0xa826fd8ce53b855f, 0xcce21c8112256fe6, 0x68d5c05dd9b6b900 };
    for (expected, 0..) |c, i| {
        try expectBlock(Des3, &key3, std.mem.readInt(u64, plaintext[i * 8 ..][0..8], .big), c);
    }
}

test "two-key triple DES" {
    // OpenSSL -des-ede -nopad, with the first two keys of the SP 800-67
    // vector. The three-key form with k3 = k1 gives the same answer there, and
    // the two spellings must agree here too.
    const key2 = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
    };
    var p: [8]u8 = undefined;
    std.mem.writeInt(u64, &p, 0x0123456789abcdef, .big);
    var c2: [8]u8 = undefined;
    Des3.initEnc2(key2).encrypt(&c2, &p);
    try testing.expectEqual(@as(u64, 0xa6bb373e196b375e), std.mem.readInt(u64, &c2, .big));

    var back: [8]u8 = undefined;
    Des3.initDec2(key2).decrypt(&back, &c2);
    try testing.expectEqualSlices(u8, &p, &back);

    var expanded: [24]u8 = undefined;
    @memcpy(expanded[0..16], &key2);
    @memcpy(expanded[16..24], key2[0..8]);
    try expectBlock(Des3, &expanded, 0x0123456789abcdef, 0xa6bb373e196b375e);
}

test "the parity bits are not part of the key" {
    // PC-1 discards every eighth bit, so flipping them all cannot change the
    // ciphertext. This is what "56-bit key" means, made visible.
    var key = [_]u8{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    var p: [8]u8 = undefined;
    std.mem.writeInt(u64, &p, 0x0123456789abcdef, .big);
    var a: [8]u8 = undefined;
    Des.initEnc(key).encrypt(&a, &p);

    for (&key) |*byte| byte.* ^= 1;
    var b: [8]u8 = undefined;
    Des.initEnc(key).encrypt(&b, &p);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "parity helpers" {
    try testing.expect(Des.key_bits == 56);
    // The FIPS key is distributed with odd parity, as DES keys conventionally
    // are.
    try testing.expect(hasOddParity(&.{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 }));
    try testing.expect(!hasOddParity(&([_]u8{0x00} ** 8)));
    // An even byte anywhere, not only first.
    try testing.expect(!hasOddParity(&.{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf0 }));

    var key = [_]u8{0x00} ** 8;
    setOddParity(&key);
    try testing.expect(hasOddParity(&key));
    try testing.expectEqualSlices(u8, &([_]u8{0x01} ** 8), &key);
    // And every byte value, both ways round.
    for (0..256) |v| {
        var byte = [1]u8{@intCast(v)};
        setOddParity(&byte);
        try testing.expect(hasOddParity(&byte));
        try testing.expectEqual(@as(u8, @intCast(v & 0xfe)), byte[0] & 0xfe);
    }
}

test "the weak keys are involutions" {
    // Encrypting twice under a weak key returns the plaintext, because every
    // round key is the same. A password-derived key could be one of these.
    var p: [8]u8 = undefined;
    std.mem.writeInt(u64, &p, 0x0123456789abcdef, .big);
    for (weak_keys) |key| {
        try testing.expect(isWeak(key));
        var once: [8]u8 = undefined;
        var twice: [8]u8 = undefined;
        const enc = Des.initEnc(key);
        enc.encrypt(&once, &p);
        enc.encrypt(&twice, &once);
        try testing.expectEqualSlices(u8, &p, &twice);
    }
    try testing.expect(!isWeak(.{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 }));
    // Parity is ignored when deciding, so the all-zero key is the all-ones
    // parity spelling of the first weak key, and each of the others has an
    // even-parity spelling too.
    try testing.expect(isWeak([_]u8{0x00} ** 8));
    for (weak_keys) |key| {
        var respelled = key;
        for (&respelled) |*byte| byte.* ^= 1;
        try testing.expect(isWeak(respelled));
    }
    // A key one bit off a weak key, in a bit that matters, is not weak.
    try testing.expect(!isWeak(.{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03 }));
}

test "the packed S-boxes are the S-boxes" {
    // `sbox` must agree with the plain re-indexed table for every input;
    // the known-answer tests then cover everything downstream of it.
    inline for (0..8) |box| {
        for (0..64) |six| {
            try testing.expectEqual(s_boxes[box][six], sbox(box, @intCast(six)));
        }
    }
}

test "IP^-1 undoes IP on live data" {
    // The tables are checked against each other at compile time; this checks
    // `permute` applies them the way the check assumed.
    for (0..64) |i| {
        const block = @as(u64, 1) << @intCast(i);
        const there = permute(64, 64, &initial_permutation, block);
        try testing.expectEqual(block, permute(64, 64, &final_permutation, there));
    }
}
