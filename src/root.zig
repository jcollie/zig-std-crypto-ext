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
//! And a third case, which is neither: a construction `std` has in one shape
//! and not in another. `XChaCha20Poly1305` in `std` is the RFC 8439 AEAD;
//! libsodium's XChaCha20 box is the NaCl secretbox construction with the same
//! cipher in it, and the two are not interchangeable. DNSCrypt's es-version 2
//! is the second one, so it is here, along with the HChaCha20 both of them are
//! built on.
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
/// HChaCha20, which `std.crypto` has and does not hand over: it is a private
/// function inside the ChaCha implementation, reached only by
/// `XChaCha20Poly1305`. libsodium's XChaCha20 box needs it a second time, to
/// turn an X25519 shared point into the key -- which is what DNSCrypt's
/// es-version 2 is -- so a caller outside `std` has to have it.
pub const hchacha20 = @import("hchacha20.zig");
/// libsodium's XChaCha20 secretbox and box, which `std.crypto` does not have
/// in this shape: it ships the RFC 8439 AEAD of the same name and the NaCl
/// secretbox over XSalsa20, and not the third combination -- the NaCl
/// construction with XChaCha20 in it. DNSCrypt's es-version 2 is that one, and
/// the two are not interchangeable. The file says how they differ.
pub const xchacha20_secretbox = @import("xchacha20_secretbox.zig");

/// `std.crypto.ff` with one function put right.
///
/// The only thing here that is not an addition to the standard library but a
/// correction to it: `Modulus.pow` sized its exponent buffer by the type's
/// maximum width rather than the modulus's, and the ladder spends four
/// squarings on every nibble it is given -- so a 2048-bit key under the
/// `Modulus(4096)` an RSA implementation needs for 4096-bit keys did twice
/// the work, all of it on leading zeros. See the note at the top of `ff.zig`.
///
/// A carried patch rather than a fork. The intent is that it goes upstream
/// and this goes away.
pub const ff = @import("ff.zig");

/// The pieces a caller reaches for most often, spelled without the layer in
/// between.
pub const Des = cipher.Des;
pub const Des3 = cipher.Des3;
pub const Aes192 = aes192.Aes192;
pub const hChaCha20 = hchacha20.hChaCha20;
pub const XChaCha20SecretBox = xchacha20_secretbox.SecretBox;
pub const XChaCha20Box = xchacha20_secretbox.Box;
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
    _ = hchacha20;
    _ = xchacha20_secretbox;
}
