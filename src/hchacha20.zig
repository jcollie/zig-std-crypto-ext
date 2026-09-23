// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! HChaCha20, the key derivation `std.crypto` has and does not hand over.
//!
//! Every other file here supplies something `std` omits. This one supplies
//! something `std` implements, uses, and keeps to itself: `XChaCha20Poly1305`
//! turns its 24-byte nonce into a subkey and a 12-byte nonce by calling an
//! `hchacha20` that is a private function inside `ChaChaImpl`
//! (`std/crypto/chacha20.zig:309`), and nothing reaches it from outside.
//!
//! ## Who wants it on its own
//!
//! Anything that follows libsodium's `crypto_box_curve25519xchacha20poly1305`.
//! There, HChaCha20 appears *twice*: once inside the AEAD, which `std` does
//! for you, and once before it, to turn the X25519 shared point into the key
//! the box is opened with -- `crypto_core_hchacha20(k, zero, scalarmult, NULL)`,
//! which libsodium calls `beforenm`. The second one is the caller's, and a
//! caller that has no HChaCha20 cannot compute the key at all.
//!
//! The motivating one is DNSCrypt. Its es-version 2 is
//! X25519-XChaCha20-Poly1305 and its shared key is exactly that derivation, so
//! a DNS client that speaks it needs this function and nothing else from
//! outside `std`. (es-version 1 is the XSalsa20 box, and for that `std` already
//! hands over the whole thing: `std.crypto.nacl.Box.createSharedSecret` is
//! `beforenm` with HSalsa20 inside it. The asymmetry is `std`'s, not the
//! protocol's.)
//!
//! ## Written out rather than borrowed
//!
//! `aes192.zig` could build on `std.crypto.core.aes.Block` because `std`
//! exports the AES round. There is no exported ChaCha round, no quarter-round
//! and no state type, so there is nothing to borrow and this is forty lines of
//! ARX written down: the constants of RFC 8439 §2.3, twenty rounds, and the
//! two halves of the final state that §2.2 of the XChaCha draft asks for.
//!
//! The one place to be careful is the end. ChaCha20's block function *adds*
//! the initial state back before serialising; HChaCha20 does not. It takes
//! words 0..3 and 12..15 of the final state as they stand, which is why a
//! subkey derived with a ChaCha20 block function is wrong in a way that still
//! looks random.
//!
//! ## Timing
//!
//! Constant-time by construction, and so not measured. The whole function is
//! addition, rotation and exclusive-or over fixed indices: no table, no
//! branch, and no memory access that depends on the key. There is nothing for
//! `zig build timing` to compare against, which is why -- unlike `Des` and
//! `Aes192` -- it has no entry in `tools/timing.zig`.

const std = @import("std");
const testing = std.testing;

/// RFC 8439 §2.3: the first four words of a ChaCha state, "expand 32-byte k".
const constants = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

/// libsodium's `crypto_core_hchacha20`: a 32-byte key and a 16-byte input to a
/// 32-byte subkey.
///
/// The argument order is Zig's own private function's rather than libsodium's,
/// so that the day `std` makes that one public this file becomes a deletion
/// and its callers do not move.
pub fn hChaCha20(input: [16]u8, key: [32]u8) [32]u8 {
    var x: [16]u32 = undefined;
    x[0..4].* = constants;
    for (0..8) |i| x[4 + i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
    for (0..4) |i| x[12 + i] = std.mem.readInt(u32, input[i * 4 ..][0..4], .little);

    // Twenty rounds, as ten double rounds: four columns, then four diagonals.
    for (0..10) |_| {
        quarter(&x, 0, 4, 8, 12);
        quarter(&x, 1, 5, 9, 13);
        quarter(&x, 2, 6, 10, 14);
        quarter(&x, 3, 7, 11, 15);
        quarter(&x, 0, 5, 10, 15);
        quarter(&x, 1, 6, 11, 12);
        quarter(&x, 2, 7, 8, 13);
        quarter(&x, 3, 4, 9, 14);
    }

    // §2.2 of the XChaCha draft: "the first 128 bits and last 128 bits of the
    // ChaCha state (both little-endian) are concatenated". The state as it
    // stands -- ChaCha20's block function would add the initial state back
    // here, and doing so is the classic way to get a subkey that is wrong and
    // looks right.
    var out: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], x[i], .little);
    for (0..4) |i| std.mem.writeInt(u32, out[16 + i * 4 ..][0..4], x[12 + i], .little);
    return out;
}

/// RFC 8439 §2.1's quarter round, in place.
inline fn quarter(x: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    x[a] +%= x[b];
    x[d] = std.math.rotl(u32, x[d] ^ x[a], 16);
    x[c] +%= x[d];
    x[b] = std.math.rotl(u32, x[b] ^ x[c], 12);
    x[a] +%= x[b];
    x[d] = std.math.rotl(u32, x[d] ^ x[a], 8);
    x[c] +%= x[d];
    x[b] = std.math.rotl(u32, x[b] ^ x[c], 7);
}

// -- tests ------------------------------------------------------------------
//
// The published vector is one 32-byte answer, which is enough to catch a
// transposed index and not enough to be sure this is the *same* HChaCha20 the
// AEAD next door uses. So the second test derives a key with this function,
// hands it to `ChaCha20Poly1305`, and requires the result to equal what
// `XChaCha20Poly1305` produced from the long nonce -- which is a differential
// test against `std`'s own copy of the function, on inputs of our choosing.

test "draft-irtf-cfrg-xchacha-03 2.2.1, the HChaCha20 subkey" {
    // The only published vector for this function, from §2.2.1 of Scott
    // Arciszewski's XChaCha draft.
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const input = [16]u8{
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
    };
    const expected = [32]u8{
        0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
        0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
        0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
        0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc,
    };

    try testing.expectEqualSlices(u8, &expected, &hChaCha20(input, key));
}

test "the subkey std's XChaCha20 derives from a long nonce" {
    // §2.3 of the draft, as `std/crypto/chacha20.zig:522`'s `extend` reads it:
    // the subkey is HChaCha20 over the nonce's first sixteen bytes, and what
    // is left is four zero bytes and the nonce's last eight. If this file and
    // that one disagree by so much as a byte order, these two ciphertexts
    // differ.
    const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
    const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    const message = "one query, padded to a multiple of sixty-four bytes";
    const ad = "";

    for (0..8) |i| {
        var key: [32]u8 = @splat(@intCast(0x20 + i));
        key[0] = @intCast(i);
        var nonce: [24]u8 = @splat(@intCast(0xa0 - i));
        nonce[23] = @intCast(i * 7);

        var long_out: [message.len]u8 = undefined;
        var long_tag: [XChaCha.tag_length]u8 = undefined;
        XChaCha.encrypt(&long_out, &long_tag, message, ad, nonce, key);

        var short_nonce: [ChaCha.nonce_length]u8 = @splat(0);
        short_nonce[4..].* = nonce[16..24].*;
        var short_out: [message.len]u8 = undefined;
        var short_tag: [ChaCha.tag_length]u8 = undefined;
        ChaCha.encrypt(
            &short_out,
            &short_tag,
            message,
            ad,
            short_nonce,
            hChaCha20(nonce[0..16].*, key),
        );

        try testing.expectEqualSlices(u8, &long_out, &short_out);
        try testing.expectEqualSlices(u8, &long_tag, &short_tag);
    }
}

test "every bit of the key and of the input matters" {
    // Not a published vector: a cheap check that no word was dropped from the
    // state. Flipping one bit anywhere in either argument has to change the
    // subkey, and a function that ignored, say, x[7] would pass the vector
    // above only if the vector happened to have a zero there.
    const key: [32]u8 = @splat(0x5a);
    const input: [16]u8 = @splat(0xa5);
    const base = hChaCha20(input, key);

    for (0..32) |i| {
        var altered = key;
        altered[i] ^= 0x01;
        try testing.expect(!std.mem.eql(u8, &base, &hChaCha20(input, altered)));
    }
    for (0..16) |i| {
        var altered = input;
        altered[i] ^= 0x01;
        try testing.expect(!std.mem.eql(u8, &base, &hChaCha20(altered, key)));
    }
}
