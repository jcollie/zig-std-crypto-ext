// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! The ciphers and modes `std.crypto` leaves out.
//!
//! `std.crypto` is aimed at code being written now, and stops in sensible
//! places: no DES, no Triple DES, no AES-192, and of the block cipher modes
//! only counter mode. Every one of those omissions is defensible on its own
//! terms -- nothing new should choose any of them.
//!
//! This is the other case: a protocol specified decades ago that is still
//! deployed and still has to be spoken. The motivating one is SNMPv3 privacy.
//! RFC 3414's `usmDESPrivProtocol` is DES-CBC and remains the default on a
//! great deal of network equipment; RFC 3826's `usmAesCfb128PrivProtocol` is
//! AES-128 in full-block CFB; and `draft-blumenthal-aes-usm`, which Cisco
//! implements, adds AES-192 and AES-256 in the same mode. So one library has
//! to supply two ciphers `std` omits and a mode `std` omits, across four key
//! sizes -- which is why the modes here are generic over the cipher rather
//! than tied to any of them.
//!
//! Named for what it is rather than for its first occupant: it started as
//! `zig-des` and DES is now the smaller half of it.
//!
//! ```zig
//! const des = @import("std_crypto_ext");
//!
//! // DES-CBC, as SNMPv3 privacy uses it.
//! var ciphertext: [24]u8 = undefined;
//! des.modes.cbcEncrypt(
//!     des.Des.EncryptCtx, des.Des.initEnc(key), &ciphertext, plaintext, iv,
//! );
//!
//! // And the same mode machinery over AES, because it is generic over the
//! // cipher rather than tied to this library's.
//! const aes = std.crypto.core.aes;
//! des.modes.cfbEncrypt(
//!     aes.AesEncryptCtx(aes.Aes128), aes.Aes128.initEnc(aes_key),
//!     &out, plaintext, aes_iv,
//! );
//! ```
//!
//! The contexts are shaped like `std.crypto.core.aes`'s -- `initEnc`,
//! `initDec`, a `block_length`, and `encrypt`/`decrypt` over one block -- so
//! that they read the same way as the cipher next door. That is a familiarity
//! argument and not an interoperability one: `std.crypto.modes.ctr` reaches
//! into `BlockCipher.block.parallel.optimal_parallel_blocks` to decide how
//! many blocks to do at once, which only AES has, so it cannot take a cipher
//! from here. The modes in this library are generic in the way that one only
//! looks generic.
//!
//! **Read the warnings on `Des` and on `modes` before choosing any of this.**
//! Single DES is brute-forceable and has been since 1998, Triple DES has a
//! 64-bit block and so a birthday bound at 32 GiB, and CBC and CFB
//! authenticate nothing. Everything here is for talking to something that
//! already exists. What it does promise is spelled out in the same two
//! places: the cipher is constant-time in the key and the data, on the
//! assumptions `Des` names -- and `Aes192`, built on `std`'s hardware
//! rounds, has whatever timing `std`'s own AES has on the same build -- and
//! the modes' length checks are assertions, which `modes` says the
//! consequences of.

const std = @import("std");
const testing = std.testing;

/// The ciphers. Named `cipher` rather than `des` so that a caller who imports
/// this module as `des` does not have to write `des.des.Des`.
pub const cipher = @import("des.zig");
pub const modes = @import("modes.zig");
/// AES-192, which `std.crypto` omits: it ships Aes128 and Aes256 and nothing
/// between. Encryption only, because CFB and CTR never run a cipher
/// backwards -- the file says more.
pub const aes192 = @import("aes192.zig");
/// RSA signing, which `std.crypto` leaves out: it ships a verifier, buried in
/// the certificate parser, and no private key type at all. The file says what
/// that costs and what this does and does not promise.
pub const rsa = @import("rsa.zig");

/// The pieces a caller reaches for most often, spelled without the layer in
/// between.
pub const Des = cipher.Des;
pub const Des3 = cipher.Des3;
pub const Aes192 = aes192.Aes192;
pub const weak_keys = cipher.weak_keys;
pub const isWeak = cipher.isWeak;
pub const hasOddParity = cipher.hasOddParity;
pub const setOddParity = cipher.setOddParity;

test {
    testing.refAllDecls(@This());
    // Without these the tests in each file would never be analysed, let alone
    // run: a test executable covers the module it is given and reaches a file
    // only through a reference to it.
    _ = cipher;
    _ = modes;
    _ = aes192;
    _ = rsa;
}
