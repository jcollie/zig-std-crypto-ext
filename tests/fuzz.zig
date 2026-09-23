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
const rsa = des.rsa;
const Sha256 = std.crypto.hash.sha2.Sha256;
const SecretBox = des.XChaCha20SecretBox;
const hChaCha20 = des.hChaCha20;

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

// -- the XChaCha20 box ------------------------------------------------------

/// Three properties over a key, a nonce and a message the fuzzer chose.
///
/// The published vectors beside `xchacha20_secretbox.zig` pin three lengths
/// against libsodium, which is the only thing that can say this construction is
/// the right one. What they cannot do is cover every length, and this is a
/// construction with a seam in the middle of it: the first 32 bytes of the
/// message ride in the block that also carries the Poly1305 key, and everything
/// after them comes from block 1. So the lengths either side of 32 are where an
/// off-by-one lives, and a fuzzer walks all of them.
///
/// The third property is the one worth the most, and it is a differential test
/// against `std`'s own copy of a function it will not export: `XChaCha20Poly1305`
/// derives its subkey with the private `hchacha20` inside `ChaChaImpl`, so if
/// this library's `hChaCha20` and that one ever disagree by a byte order or an
/// index, the two ciphertexts below stop matching. No vector is needed for it,
/// which is what lets it run on arbitrary input.
fn xboxProperty(input: []const u8) !void {
    const overhead = SecretBox.key_length + SecretBox.nonce_length;
    if (input.len < overhead) return;
    const key = input[0..SecretBox.key_length].*;
    const nonce = input[SecretBox.key_length..][0..SecretBox.nonce_length].*;
    const message = input[overhead..];

    var box: [2048 + SecretBox.tag_length]u8 = undefined;
    if (message.len > 2048) return;
    const sealed = box[0 .. message.len + SecretBox.tag_length];

    SecretBox.seal(sealed, message, nonce, key);

    var back: [2048]u8 = undefined;
    try SecretBox.open(back[0..message.len], sealed, nonce, key);
    try testing.expectEqualSlices(u8, message, back[0..message.len]);

    // The detached form writes the same bytes in two pieces, which is what a
    // caller with a tag of its own gets.
    var detached: [2048]u8 = undefined;
    var tag: [SecretBox.tag_length]u8 = undefined;
    SecretBox.sealDetached(detached[0..message.len], &tag, message, nonce, key);
    try testing.expectEqualSlices(u8, sealed[0..SecretBox.tag_length], &tag);
    try testing.expectEqualSlices(u8, sealed[SecretBox.tag_length..], detached[0..message.len]);

    // Authentication, at the places a break would show: the first and last
    // bytes of the tag, the two either side of the tag-ciphertext boundary, the
    // last byte of the ciphertext, and one byte chosen by the input itself so
    // that the middle is covered over many runs.
    const positions = [_]usize{
        0,
        SecretBox.tag_length - 1,
        SecretBox.tag_length,
        sealed.len - 1,
        SecretBox.tag_length + message.len / 2,
        SecretBox.tag_length + (@as(usize, key[0]) *% 31) % @max(1, message.len),
    };
    for (positions) |i| {
        if (i >= sealed.len) continue;
        var altered: [2048 + SecretBox.tag_length]u8 = undefined;
        @memcpy(altered[0..sealed.len], sealed);
        altered[i] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            SecretBox.open(back[0..message.len], altered[0..sealed.len], nonce, key),
        );
    }

    // And the differential test against `std`'s private HChaCha20: our subkey,
    // handed to the 12-byte-nonce AEAD, must produce exactly what the 24-byte
    // one produces from the whole nonce.
    const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
    const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    var long: [2048]u8 = undefined;
    var long_tag: [XChaCha.tag_length]u8 = undefined;
    XChaCha.encrypt(long[0..message.len], &long_tag, message, "", nonce, key);

    var short_nonce: [ChaCha.nonce_length]u8 = @splat(0);
    short_nonce[4..].* = nonce[16..24].*;
    var short: [2048]u8 = undefined;
    var short_tag: [ChaCha.tag_length]u8 = undefined;
    ChaCha.encrypt(
        short[0..message.len],
        &short_tag,
        message,
        "",
        short_nonce,
        hChaCha20(nonce[0..16].*, key),
    );
    try testing.expectEqualSlices(u8, long[0..message.len], short[0..message.len]);
    try testing.expectEqualSlices(u8, &long_tag, &short_tag);

    // The trap the file exists to name: that AEAD is *not* this box, and the two
    // never agree on the bytes they produce.
    //
    // The claim is about the whole box rather than about the ciphertext alone,
    // and the difference matters. The two ciphertexts come from different parts
    // of the keystream, so for a short message they coincide by chance -- one
    // time in 256 for a single byte, which this fuzzer duly found within four
    // minutes on a one-byte message whose two ciphertexts were both `06`.
    // Comparing tag and ciphertext together makes it a claim about 128 bits of
    // Poly1305 output, which holds at every length including the empty one.
    var long_box: [2048 + XChaCha.tag_length]u8 = undefined;
    long_box[0..XChaCha.tag_length].* = long_tag;
    @memcpy(long_box[XChaCha.tag_length..][0..message.len], long[0..message.len]);
    try testing.expect(!std.mem.eql(u8, sealed, long_box[0..sealed.len]));
}

test "fuzz the XChaCha20 box" {
    for (xbox_seeds) |seed| try xboxProperty(seed);
    try testing.fuzz({}, fuzzXbox, .{});
}

fn fuzzXbox(_: void, smith: *Smith) !void {
    var buffer: [512]u8 = undefined;
    const len = smith.slice(&buffer);
    try xboxProperty(buffer[0..len]);
}

/// A key and a nonce, and then the lengths that matter: nothing, one byte,
/// either side of the 32 bytes that ride in the first block, and either side of
/// a whole further block.
const xbox_seeds = blk: {
    const head = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f" ++
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f" ++
        "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b" ++
        "\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57";
    break :blk [_][]const u8{
        // Too short to be a key and a nonce at all, which the property must
        // survive rather than index past.
        "",
        "\x00" ** 55,
        head,
        head ++ "q",
        head ++ "q" ** 31,
        head ++ "q" ** 32,
        head ++ "q" ** 33,
        head ++ "q" ** 63,
        head ++ "q" ** 64,
        head ++ "q" ** 65,
        // A padded DNSCrypt query, which is what this is for.
        head ++ "a DNSCrypt query, padded to sixty-four bytes\x80" ++ "\x00" ** 19,
        // All zeroes and all ones, both of which are real keys and nonces.
        "\x00" ** 128,
        "\xff" ** 128,
    };
};

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

// -- RSA key parsing ---------------------------------------------------------

/// A real 1024-bit PKCS#8 private key, as DER. The seed that matters: a
/// mutation of something structurally valid reaches far deeper into the
/// parser than any amount of random noise ever will.
const key_1024_der_hex = "30820276020100300d06092a864886f70d0101010500048202603082025c0201" ++
    "0002818100cb5c30a3ab5fa4d04eeef43f18e45324be186bfe2368e03d8a80f9" ++
    "c4620ccefb193425710b394f2b5c748c90921ba046d37f966cc242f08b77aa09" ++
    "8f1a7e6333e33da553f288471904064f13c97d7898a81ee32e45aa3e8ce3b3ae" ++
    "c115a51d38808f130c4cd1c85d19d45a675b07df8fb3006b4cbdf8587bdabea0" ++
    "a1621b037902030100010281804b846ba78bcf53b3eb6bff15a357beac694f46" ++
    "6334a1108ca9ef6551111c328cba7a4be123cadf6479cbea1b11b6e2990a9759" ++
    "b3ff9bbe19fc910f45ae0ffb24331f6b4f3cd228c7d7a0b1ac358fff6097f950" ++
    "724cd675e62bd570a4b5812910d5688febd650af29c39f1eb80512d9a5764fc1" ++
    "908fe3cdba981571bd1d771451024100e9aaee3bade98320d69d8f28d21fad67" ++
    "fc9d058f6586bef7be0962774fc9c3276f0475781a20c3b8cabccb8a63f0bd67" ++
    "5491bb22fe84515ae3c836fdf4ecd02d024100decbbbe5224d9afa1e7cd67603" ++
    "93a4130b7bb7dc90f706e704df06486cc5eb2fb48cb74312c2ccf883f8d98115" ++
    "90aed874ee1dbc5b3c37de94dcbf8d27dbc3fd024100a2fc9079de4000301aa3" ++
    "02257613946ff11b51b2891da8fcc378664f54bf2639ce4d2ce6de4ab65aa247" ++
    "782e0ab1f45b2bf90eb04519e4696272d830e1f380ed02407cf799f4f440c364" ++
    "f824ddc6644b3404dab412754d7ac20c62d7161719ac0a373ff68df4b9593acf" ++
    "4a7712c92ce772ab472b28d2b5fa18fc685349be4b5521a102403a584eb1e387" ++
    "b09fc70935011e28b0e25d7f9f5e7276b61627a0b27eb350ba5d31504277925d" ++
    "8e5c25a3192ccbfd67094bd02c4f8e6cc62e8b41a5b6c7c2d187";

/// Its public half, as a SubjectPublicKeyInfo.
const pub_1024_der_hex = "30819f300d06092a864886f70d010101050003818d0030818902818100cb5c30" ++
    "a3ab5fa4d04eeef43f18e45324be186bfe2368e03d8a80f9c4620ccefb193425" ++
    "710b394f2b5c748c90921ba046d37f966cc242f08b77aa098f1a7e6333e33da5" ++
    "53f288471904064f13c97d7898a81ee32e45aa3e8ce3b3aec115a51d38808f13" ++
    "0c4cd1c85d19d45a675b07df8fb3006b4cbdf8587bdabea0a1621b0379020301" ++
    "0001";

/// Decodes one of the hex constants above at run time.
fn unhexAlloc(out: []u8, hex: []const u8) []const u8 {
    return std.fmt.hexToBytes(out, hex) catch unreachable;
}

/// The key parsers, which are the only part of this library that reads
/// anything an attacker wrote.
///
/// A cipher has no parser to confuse; a DER reader is nothing but. The
/// property is the weak one on purpose -- return a key or return an error,
/// but do not read outside the buffer, do not recurse without bound, and do
/// not spin. Anything stronger would be asserting what *should* come back
/// from bytes that are not a key, and for almost all of them nothing should.
///
/// The one real assertion is at the end: whatever a parsed key claims about
/// its own size has to be a size this library can actually work with, because
/// everything downstream indexes buffers by it.
fn keyParseProperty(input: []const u8) !void {
    var der_buf: [rsa.max_secret_key_der]u8 = undefined;

    if (rsa.SecretKey.fromDer(input)) |sk| {
        try checkSize(sk.n.bits(), sk.modulusLength());
        try checkSize(sk.publicKey().n.bits(), sk.publicKey().modulusLength());
    } else |_| {}

    if (rsa.PublicKey.fromDer(input)) |pk| {
        try checkSize(pk.n.bits(), pk.modulusLength());
    } else |_| {}

    // The PEM readers get the same bytes as text. Mostly they will not find a
    // marker at all, which is the point: the search for one runs over
    // arbitrary input.
    if (rsa.SecretKey.fromPem(&der_buf, input)) |sk| {
        try checkSize(sk.n.bits(), sk.modulusLength());
    } else |_| {}
    if (rsa.PublicKey.fromPem(&der_buf, input)) |pk| {
        try checkSize(pk.n.bits(), pk.modulusLength());
    } else |_| {}

    // And into a buffer far too small for any key, since  is
    // a path of its own and one a caller can easily reach.
    var tiny: [16]u8 = undefined;
    if (rsa.SecretKey.fromPem(&tiny, input)) |_| {} else |_| {}
}

fn checkSize(bits: usize, len: usize) !void {
    try testing.expect(bits >= 512 and bits <= rsa.max_modulus_bits);
    try testing.expect(len <= rsa.max_modulus_len);
    try testing.expectEqual((bits + 7) / 8, len);
}

test "fuzz rsa key parsing" {
    var scratch: [1024]u8 = undefined;
    try keyParseProperty(unhexAlloc(&scratch, key_1024_der_hex));
    try keyParseProperty(unhexAlloc(&scratch, pub_1024_der_hex));
    for (key_seeds) |seed| try keyParseProperty(seed);
    try testing.fuzz({}, fuzzKeyParse, .{});
}

fn fuzzKeyParse(_: void, smith: *Smith) !void {
    var buffer: [2048]u8 = undefined;
    const len = smith.slice(&buffer);
    try keyParseProperty(buffer[0..len]);
}

/// Verification against bytes nobody signed, which must always be refused.
///
/// This is the property worth having: a verifier that accepts something is a
/// catastrophe, where a verifier that rejects something is at worst a bug
/// report. The chance of the fuzzer stumbling on a valid signature is nil, so
/// every input here is a forgery attempt and every one of them has to fail.
fn verifyForgeryProperty(input: []const u8) !void {
    var scratch: [1024]u8 = undefined;
    const pk = rsa.PublicKey.fromDer(unhexAlloc(&scratch, pub_1024_der_hex)) catch unreachable;

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(input, &digest, .{});

    // A signature of the right length is the interesting case -- the wrong
    // length is refused before any arithmetic happens -- so pad or truncate
    // the input to the modulus rather than testing the easy rejection.
    var sig: [rsa.max_modulus_len]u8 = @splat(0);
    const k = pk.modulusLength();
    const n = @min(input.len, k);
    @memcpy(sig[k - n ..][0..n], input[0..n]);

    try testing.expectError(
        error.InvalidSignature,
        rsa.pkcs1v1_5.Signer(Sha256).verifyDigest(sig[0..k], digest, pk),
    );
    // ...and the lengths that are not the modulus, which must also fail and
    // must not index off the end of anything while doing it.
    for ([_]usize{ 0, 1, k - 1, k + 1, rsa.max_modulus_len }) |len| {
        try testing.expectError(
            error.InvalidSignature,
            rsa.pkcs1v1_5.Signer(Sha256).verifyDigest(sig[0..len], digest, pk),
        );
    }
}

test "fuzz rsa verify" {
    for (key_seeds) |seed| try verifyForgeryProperty(seed);
    try testing.fuzz({}, fuzzVerify, .{});
}

fn fuzzVerify(_: void, smith: *Smith) !void {
    var buffer: [256]u8 = undefined;
    const len = smith.slice(&buffer);
    try verifyForgeryProperty(buffer[0..len]);
}

/// A well-formed PKCS#1 `RSAPublicKey` whose modulus is `modulus_len` bytes
/// with the top bit set, built at compile time.
///
/// It exists for the seed below. The upper bound on the modulus is the
/// check `checkSize` exists to enforce, and a fuzzer mutating 1024-bit keys
/// never produces a 4104-bit one on its own -- which is how a missing upper
/// bound stayed missing through half a million iterations. A seed sitting
/// just past the ceiling, and its mutations sitting either side of it, is
/// what makes that property reachable.
fn publicKeyDerOfSize(comptime modulus_len: usize) [4 + 4 + 1 + modulus_len + 5]u8 {
    @setEvalBranchQuota(10_000);
    const n_len = modulus_len + 1; // a sign byte, since the top bit is set
    const e = [_]u8{ 0x02, 0x03, 0x01, 0x00, 0x01 };
    const body_len = 4 + n_len + e.len;
    var out: [4 + body_len]u8 = undefined;
    out[0..4].* = .{ 0x30, 0x82, body_len >> 8, body_len & 0xff };
    out[4..9].* = .{ 0x02, 0x82, n_len >> 8, n_len & 0xff, 0x00 };
    out[9] = 0xc0;
    @memset(out[10 .. 9 + modulus_len - 1], 0x11);
    out[9 + modulus_len - 1] = 0x01;
    out[9 + modulus_len ..][0..e.len].* = e;
    return out;
}

/// Eight bits past `max_modulus_bits`: accepted by `std.crypto.ff`'s field,
/// which is sized in 63-bit limbs and so reaches 4158 bits, and exactly what
/// the parser has to refuse.
const oversized_public_key_der = publicKeyDerOfSize(513);

/// Seeds for both: the shapes a parser gets wrong before it gets anything
/// else wrong -- empty, a bare tag, a length with no content, a length that
/// claims more than there is, and the two PEM markers with nothing between.
/// And one key that is too large by a byte, for the reason given on it.
const key_seeds = [_][]const u8{
    "",
    "\x30",
    "\x30\x00",
    "\x30\x82\xff\xff",
    "\x30\x80\x02\x01\x00",
    "\x02\x01\x00",
    "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
    "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n",
    "-----BEGIN PRIVATE KEY-----",
    &oversized_public_key_der,
};

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
    .{
        .name = "key-parse",
        .run = Driven(fuzzKeyParse).run,
        .corpus = &key_seeds,
        .content_max = 2048,
    },
    .{
        .name = "verify",
        .run = Driven(fuzzVerify).run,
        .corpus = &key_seeds,
        .content_max = 256,
    },
    .{
        .name = "xbox",
        .run = Driven(fuzzXbox).run,
        .corpus = &xbox_seeds,
        .content_max = 512,
    },
};
