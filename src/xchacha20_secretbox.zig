// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! libsodium's XChaCha20 secretbox and box, which `std.crypto` does not have
//! in this shape.
//!
//! `std.crypto` ships two things that look like what this is and are not it.
//! `std.crypto.aead.chacha_poly.XChaCha20Poly1305` is the AEAD of RFC 8439:
//! the Poly1305 key comes from a separate keystream block, the message starts
//! at block 1, and the authenticated data and the two lengths are part of what
//! the tag covers. `std.crypto.nacl.SecretBox` is the construction wanted here
//! but over XSalsa20, which is a different cipher.
//!
//! What this file is, is the third combination: the NaCl `secretbox`
//! construction with XChaCha20 in it -- libsodium's
//! `crypto_secretbox_xchacha20poly1305` and, on top of it,
//! `crypto_box_curve25519xchacha20poly1305`. The Poly1305 key is the first 32
//! bytes of the keystream, the first 32 bytes of the message ride in the rest
//! of that same block, the remainder is encrypted from block 1, and the tag
//! covers the ciphertext and nothing else. The tag goes *before* the
//! ciphertext, as NaCl has always put it.
//!
//! **The two are not interchangeable and produce different bytes**, which is
//! the trap: both are "XChaCha20-Poly1305", both take a 32-byte key and a
//! 24-byte nonce, and a program that reaches for the one `std` exports gets a
//! box no libsodium peer will open. There is a test below that says so in
//! bytes.
//!
//! ## Who wants it
//!
//! DNSCrypt. Its es-version 2 is `X25519-XChaCha20Poly1305`, and the draft
//! that is becoming the RFC spells out which construction that is: "the
//! `XChaCha20_DJB-Poly1305` construction ... whose output is the 16-byte
//! authentication tag followed by the ciphertext. This is the NaCl `secretbox`
//! layout ... it is not the AEAD of RFC 8439, and the two are not
//! interchangeable." dnscrypt-proxy reaches it through jedisct1's
//! `xsecretbox`, which is this file in Go.
//!
//! Anything else following libsodium's XChaCha20 box is in the same position:
//! `crypto_box_curve25519xchacha20poly1305_easy` is `Box.seal` here.
//!
//! ## The DJB nonce
//!
//! libsodium derives the subkey with HChaCha20 over the nonce's first sixteen
//! bytes and uses the remaining eight as the nonce of the *original* ChaCha20,
//! the one with a 64-bit nonce and a 64-bit counter -- hence the draft's
//! "DJB". `std.crypto.stream.chacha.ChaCha20With64BitNonce` is exactly that
//! cipher, so no keystream is written here.
//!
//! ## Timing
//!
//! Constant-time on whatever `std`'s ChaCha20 and Poly1305 are, which is what
//! this is made of; the tag is compared with `crypto.timing_safe.eql`. There
//! is nothing of our own to measure, which is why -- unlike `Des` and
//! `Aes192` -- it has no entry in `tools/timing.zig`.

const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const testing = std.testing;

const ChaCha20 = crypto.stream.chacha.ChaCha20With64BitNonce;
const Poly1305 = crypto.onetimeauth.Poly1305;
const X25519 = crypto.dh.X25519;

const AuthenticationError = crypto.errors.AuthenticationError;
const IdentityElementError = crypto.errors.IdentityElementError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

const hChaCha20 = @import("hchacha20.zig").hChaCha20;

/// libsodium's `crypto_secretbox_xchacha20poly1305`: authenticated encryption
/// under a key both ends already have.
///
/// Shaped like `std.crypto.nacl.SecretBox`, whose documentation applies word
/// for word except that the cipher inside is XChaCha20 rather than XSalsa20.
pub const SecretBox = struct {
    /// Key length in bytes.
    pub const key_length = 32;
    /// Nonce length in bytes.
    pub const nonce_length = 24;
    /// Authentication tag length in bytes.
    pub const tag_length = Poly1305.mac_length;

    /// Encrypt and authenticate `m` under the nonce `npub` and the key `k`.
    ///
    /// `c` must be exactly `tag_length` longer than `m`: it holds the tag and
    /// then the ciphertext, which is the layout every NaCl peer expects and
    /// means nothing has to be moved afterwards.
    pub fn seal(c: []u8, m: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        debug.assert(c.len == tag_length + m.len);
        sealDetached(c[tag_length..], c[0..tag_length], m, npub, k);
    }

    /// Verify and decrypt `c`, which holds the tag and then the ciphertext.
    ///
    /// `m` must be exactly `tag_length` shorter than `c`. Its contents are
    /// undefined if the tag does not verify, so a caller must not look at it
    /// before this returns.
    pub fn open(m: []u8, c: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        if (c.len < tag_length) return error.AuthenticationFailed;
        debug.assert(m.len == c.len - tag_length);
        return openDetached(m, c[0..tag_length].*, c[tag_length..], npub, k);
    }

    /// As `seal`, with the tag written somewhere of its own.
    pub fn sealDetached(
        c: []u8,
        tag: *[tag_length]u8,
        m: []const u8,
        npub: [nonce_length]u8,
        k: [key_length]u8,
    ) void {
        debug.assert(c.len == m.len);
        const subkey = hChaCha20(npub[0..16].*, k);
        const suffix = npub[16..24].*;

        // The first keystream block does double duty, which is the whole of
        // what makes this construction not the RFC 8439 one: its first 32
        // bytes are the Poly1305 key and its last 32 encrypt the start of the
        // message. Everything after that comes from block 1.
        var block0: [64]u8 = @splat(0);
        defer crypto.secureZero(u8, &block0);
        const mlen0 = @min(32, m.len);
        @memcpy(block0[32..][0..mlen0], m[0..mlen0]);
        ChaCha20.xor(&block0, &block0, 0, subkey, suffix);
        @memcpy(c[0..mlen0], block0[32..][0..mlen0]);
        ChaCha20.xor(c[mlen0..], m[mlen0..], 1, subkey, suffix);

        // The ciphertext and nothing else: no associated data, no lengths, no
        // padding block. A tag computed the RFC 8439 way over these same bytes
        // is a different tag.
        var mac = Poly1305.init(block0[0..32]);
        mac.update(c);
        mac.final(tag);
    }

    /// As `open`, with the tag held separately.
    pub fn openDetached(
        m: []u8,
        tag: [tag_length]u8,
        c: []const u8,
        npub: [nonce_length]u8,
        k: [key_length]u8,
    ) AuthenticationError!void {
        debug.assert(m.len == c.len);
        const subkey = hChaCha20(npub[0..16].*, k);
        const suffix = npub[16..24].*;

        var block0: [64]u8 = @splat(0);
        defer crypto.secureZero(u8, &block0);
        const mlen0 = @min(32, c.len);
        @memcpy(block0[32..][0..mlen0], c[0..mlen0]);
        ChaCha20.xor(&block0, &block0, 0, subkey, suffix);

        var mac = Poly1305.init(block0[0..32]);
        mac.update(c);
        var computed: [tag_length]u8 = undefined;
        mac.final(&computed);
        if (!crypto.timing_safe.eql([tag_length]u8, computed, tag)) {
            crypto.secureZero(u8, &computed);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }

        @memcpy(m[0..mlen0], block0[32..][0..mlen0]);
        ChaCha20.xor(m[mlen0..], c[mlen0..], 1, subkey, suffix);
    }
};

/// libsodium's `crypto_box_curve25519xchacha20poly1305`: `SecretBox` under a
/// key derived from an X25519 exchange.
///
/// Shaped like `std.crypto.nacl.Box`. The derivation is the part a caller
/// cannot write for itself out of `std`, because it needs HChaCha20 -- see
/// `hchacha20.zig` for why that is not available there.
pub const Box = struct {
    /// Public key length in bytes.
    pub const public_length = X25519.public_length;
    /// Secret key length in bytes.
    pub const secret_length = X25519.secret_length;
    /// Shared key length in bytes.
    pub const shared_length = SecretBox.key_length;
    /// Seed length in bytes.
    pub const seed_length = X25519.seed_length;
    /// Nonce length in bytes.
    pub const nonce_length = SecretBox.nonce_length;
    /// Authentication tag length in bytes.
    pub const tag_length = SecretBox.tag_length;

    /// A key pair, which is an X25519 one: the box is the only thing that
    /// differs from `std.crypto.nacl.Box`.
    pub const KeyPair = X25519.KeyPair;

    /// libsodium's `crypto_box_curve25519xchacha20poly1305_beforenm`: the
    /// X25519 shared point put through HChaCha20 with a zero input.
    ///
    /// Worth computing once and keeping when many boxes go to the same peer,
    /// which is what a DNSCrypt client does with the resolver's short-term key.
    pub fn createSharedSecret(
        public_key: [public_length]u8,
        secret_key: [secret_length]u8,
    ) (IdentityElementError || WeakPublicKeyError)![shared_length]u8 {
        const p = try X25519.scalarmult(secret_key, public_key);
        const zero: [16]u8 = @splat(0);
        return hChaCha20(zero, p);
    }

    /// Encrypt and authenticate `m` for the holder of `public_key`.
    pub fn seal(
        c: []u8,
        m: []const u8,
        npub: [nonce_length]u8,
        public_key: [public_length]u8,
        secret_key: [secret_length]u8,
    ) (IdentityElementError || WeakPublicKeyError)!void {
        const shared = try createSharedSecret(public_key, secret_key);
        return SecretBox.seal(c, m, npub, shared);
    }

    /// Verify and decrypt a box from the holder of `public_key`.
    pub fn open(
        m: []u8,
        c: []const u8,
        npub: [nonce_length]u8,
        public_key: [public_length]u8,
        secret_key: [secret_length]u8,
    ) (IdentityElementError || WeakPublicKeyError || AuthenticationError)!void {
        const shared = try createSharedSecret(public_key, secret_key);
        return SecretBox.open(m, c, npub, shared);
    }
};

// -- tests ------------------------------------------------------------------
//
// There is no vector for this construction in any specification, and nothing
// in `std` computes it to compare against, so every number below came out of
// libsodium 1.0.22 itself -- `crypto_secretbox_xchacha20poly1305_easy`,
// `crypto_box_curve25519xchacha20poly1305_beforenm` and
// `crypto_scalarmult_curve25519_base`, called through `ctypes`. The inputs are
// counting patterns chosen here; the outputs are libsodium's answers. That is
// the only kind of test worth having for this file, since the whole point of it
// is to agree with that library byte for byte.

const test_key: [32]u8 = .{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

const test_nonce: [24]u8 = .{
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
};

test "libsodium's crypto_secretbox_xchacha20poly1305_easy, 64 bytes" {
    // A padded DNSCrypt query, which is what this is for: the message is 64
    // bytes, so it spans the block that also holds the Poly1305 key and one
    // whole block after it.
    const message = "a DNSCrypt query, padded to sixty-four bytes\x80" ++ "\x00" ** 19;
    try testing.expectEqual(@as(usize, 64), message.len);

    const expected: [80]u8 = .{
        0x93, 0x6f, 0x28, 0x08, 0xa7, 0xd7, 0x59, 0x74,
        0xf8, 0x91, 0x99, 0x9a, 0x93, 0x74, 0xd0, 0x20,
        0xc0, 0xeb, 0x63, 0x76, 0x08, 0x43, 0x40, 0xe6,
        0x0d, 0xa8, 0x32, 0x01, 0x2c, 0xb3, 0xfa, 0x5c,
        0x7d, 0x81, 0x50, 0x86, 0x07, 0x77, 0x37, 0x8d,
        0x90, 0x4c, 0x7a, 0x52, 0x9a, 0x39, 0x6d, 0x2e,
        0x88, 0x21, 0x15, 0x9b, 0x2e, 0x82, 0xd4, 0x38,
        0x82, 0x66, 0x12, 0xa0, 0x76, 0xae, 0x9d, 0x55,
        0x32, 0x47, 0x72, 0x6e, 0x05, 0x44, 0x9c, 0xec,
        0xca, 0xba, 0xf5, 0x0c, 0x42, 0x55, 0x0d, 0xc8,
    };

    var box: [80]u8 = undefined;
    SecretBox.seal(&box, message, test_nonce, test_key);
    try testing.expectEqualSlices(u8, &expected, &box);

    var back: [64]u8 = undefined;
    try SecretBox.open(&back, &box, test_nonce, test_key);
    try testing.expectEqualStrings(message, &back);
}

test "libsodium's answer for a message shorter than the first block" {
    // Twelve bytes, so the whole message is encrypted inside the block that
    // also carries the Poly1305 key and the cipher's counter never reaches 1.
    // A version of this that started the message at block 1 would pass the
    // test above and fail this one.
    const message = "twelve bytes";
    const expected: [28]u8 = .{
        0xf7, 0xea, 0x02, 0x62, 0x62, 0x2b, 0x72, 0xc4,
        0xe8, 0x45, 0x84, 0x1c, 0x27, 0x8d, 0x9a, 0xaf,
        0xd5, 0xbc, 0x42, 0x54, 0x2d, 0x65, 0x12, 0xfd,
        0x04, 0xa8, 0x77, 0x03,
    };

    var box: [28]u8 = undefined;
    SecretBox.seal(&box, message, test_nonce, test_key);
    try testing.expectEqualSlices(u8, &expected, &box);

    var back: [12]u8 = undefined;
    try SecretBox.open(&back, &box, test_nonce, test_key);
    try testing.expectEqualStrings(message, &back);
}

test "libsodium's answer for an empty message, which is a tag on its own" {
    const expected: [16]u8 = .{
        0x47, 0xcc, 0x68, 0x73, 0xa8, 0xf2, 0xb1, 0x90,
        0xdd, 0x73, 0x80, 0x71, 0x83, 0xf9, 0x07, 0xd5,
    };

    var box: [16]u8 = undefined;
    SecretBox.seal(&box, "", test_nonce, test_key);
    try testing.expectEqualSlices(u8, &expected, &box);

    try SecretBox.open(&.{}, &box, test_nonce, test_key);
}

test "this is not the RFC 8439 AEAD that std exports" {
    // The claim in the doc comment, in bytes. Same key, same nonce, same
    // message, two constructions, and a program that picks the wrong one
    // produces something no libsodium peer will open -- with no error to
    // notice, because both encrypt perfectly well.
    const message = "a DNSCrypt query, padded to sixty-four bytes\x80" ++ "\x00" ** 19;
    const Ietf = crypto.aead.chacha_poly.XChaCha20Poly1305;

    var ours: [80]u8 = undefined;
    SecretBox.seal(&ours, message, test_nonce, test_key);

    var theirs: [80]u8 = undefined;
    Ietf.encrypt(theirs[16..], theirs[0..16], message, "", test_nonce, test_key);

    try testing.expect(!std.mem.eql(u8, &ours, &theirs));
    // Not merely a different tag: the keystream differs too, because one of
    // them spends its first block on the Poly1305 key and the other does not.
    try testing.expect(!std.mem.eql(u8, ours[16..], theirs[16..]));
}

test "libsodium's crypto_box_curve25519xchacha20poly1305_beforenm" {
    // The DNSCrypt es-version 2 shared key: X25519 and then HChaCha20 with a
    // zero input. Both key pairs and the answer are libsodium's, and the two
    // directions must agree or no exchange works at all.
    const client_sk: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const client_pk: [32]u8 = .{
        0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8,
        0xb7, 0x55, 0xdc, 0x1b, 0x10, 0xe8, 0x6c, 0xb4,
        0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed,
        0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
    };
    const resolver_sk: [32]u8 = .{
        0x5b, 0x58, 0x59, 0x5e, 0x5f, 0x5c, 0x5d, 0x52,
        0x53, 0x50, 0x51, 0x56, 0x57, 0x54, 0x55, 0x4a,
        0x4b, 0x48, 0x49, 0x4e, 0x4f, 0x4c, 0x4d, 0x42,
        0x43, 0x40, 0x41, 0x46, 0x47, 0x44, 0x45, 0x7a,
    };
    const resolver_pk: [32]u8 = .{
        0x69, 0x96, 0xb5, 0xa7, 0x8b, 0x4f, 0xb0, 0x3a,
        0xb0, 0x0d, 0x79, 0x65, 0x0c, 0xc3, 0x1c, 0xcd,
        0xb0, 0x2d, 0x3f, 0x0e, 0xab, 0x7e, 0x7a, 0x1b,
        0x0a, 0x10, 0xfd, 0xa4, 0xb0, 0x5b, 0x87, 0x34,
    };
    const expected: [32]u8 = .{
        0xfa, 0xf7, 0x93, 0x86, 0x88, 0xd2, 0xbb, 0xb1,
        0xc4, 0x57, 0x54, 0x25, 0x93, 0x91, 0xfd, 0x0d,
        0x20, 0xe8, 0x9b, 0xa3, 0x7f, 0xca, 0x96, 0xe4,
        0x0a, 0xa3, 0x43, 0x5a, 0x91, 0x56, 0x0e, 0xeb,
    };

    // The public keys are libsodium's too, so this also checks that `std`'s
    // X25519 base point multiplication agrees with `crypto_scalarmult_base`.
    try testing.expectEqualSlices(u8, &client_pk, &(try X25519.recoverPublicKey(client_sk)));
    try testing.expectEqualSlices(u8, &resolver_pk, &(try X25519.recoverPublicKey(resolver_sk)));

    const from_client = try Box.createSharedSecret(resolver_pk, client_sk);
    const from_resolver = try Box.createSharedSecret(client_pk, resolver_sk);
    try testing.expectEqualSlices(u8, &expected, &from_client);
    try testing.expectEqualSlices(u8, &expected, &from_resolver);

    // And the box itself goes both ways under those keys.
    const message = "one query";
    var box: [message.len + Box.tag_length]u8 = undefined;
    try Box.seal(&box, message, test_nonce, resolver_pk, client_sk);
    var back: [message.len]u8 = undefined;
    try Box.open(&back, &box, test_nonce, client_pk, resolver_sk);
    try testing.expectEqualStrings(message, &back);
}

test "a box round-trips at every length across the block boundaries" {
    // 0 to 200 bytes covers a message that fits inside the first block, one
    // that exactly fills the 32 bytes of it that are usable, and one that
    // spans three blocks. The lengths either side of 32 and 96 are the ones
    // that catch an off-by-one in which bytes come from which block.
    var message: [200]u8 = undefined;
    for (&message, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);

    var box: [200 + SecretBox.tag_length]u8 = undefined;
    var back: [200]u8 = undefined;
    for (0..message.len + 1) |len| {
        SecretBox.seal(box[0 .. len + SecretBox.tag_length], message[0..len], test_nonce, test_key);
        try SecretBox.open(back[0..len], box[0 .. len + SecretBox.tag_length], test_nonce, test_key);
        try testing.expectEqualSlices(u8, message[0..len], back[0..len]);
    }
}

test "every byte of a box is authenticated, and so are the key and the nonce" {
    const message = "sixty-four bytes of padded DNS query, more or less" ++ "\x80" ** 15;
    var box: [message.len + SecretBox.tag_length]u8 = undefined;
    SecretBox.seal(&box, message, test_nonce, test_key);

    var back: [message.len]u8 = undefined;
    for (0..box.len) |i| {
        var altered = box;
        altered[i] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            SecretBox.open(&back, &altered, test_nonce, test_key),
        );
    }

    var other_key = test_key;
    other_key[31] ^= 0x01;
    try testing.expectError(
        error.AuthenticationFailed,
        SecretBox.open(&back, &box, test_nonce, other_key),
    );

    // Byte 16 of the nonce is the first one that is *not* part of the
    // HChaCha20 input, so it reaches the cipher by the other of the two paths
    // a subkeyed construction has.
    for ([_]usize{ 0, 15, 16, 23 }) |i| {
        var other_nonce = test_nonce;
        other_nonce[i] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            SecretBox.open(&back, &box, other_nonce, test_key),
        );
    }
}

test "a box shorter than the tag is a failure rather than an assertion" {
    // Reachable from the wire: a resolver's answer is whatever arrived, and
    // `open` is the first thing that looks at it.
    var back: [0]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, SecretBox.open(&back, "short", test_nonce, test_key));
}
