// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! DES, Triple DES, and the block cipher modes `std.crypto` leaves out.
//!
//! `std.crypto` has no DES at all and `std.crypto.modes` has only counter
//! mode, which is the right call for a standard library aimed at new code.
//! This is for the other case: a protocol specified decades ago that is still
//! deployed and still has to be spoken. The motivating one is SNMPv3 privacy,
//! where RFC 3414's `usmDESPrivProtocol` is DES-CBC and remains the default on
//! a great deal of network equipment, and RFC 3826's `usmAesCfb128PrivProtocol`
//! is AES-128 in full-block CFB -- so one library has to supply a cipher `std`
//! omits and a mode `std` omits, for two different ciphers.
//!
//! ```zig
//! const des = @import("des");
//!
//! // DES-CBC, as SNMPv3 privacy uses it.
//! var ciphertext: [24]u8 = undefined;
//! des.modes.cbcEncrypt(
//!     des.Des.EncryptCtx, des.Des.initEnc(key), &ciphertext, plaintext, iv,
//! );
//!
//! // And the same mode machinery over AES, because it is generic over the
//! // cipher rather than tied to this library's.
//! const Aes128 = std.crypto.core.aes.Aes128;
//! des.modes.cfbEncrypt(
//!     Aes128.EncryptCtx, Aes128.initEnc(aes_key), &out, plaintext, aes_iv,
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
//! already exists.

const std = @import("std");
const testing = std.testing;

/// The ciphers. Named `cipher` rather than `des` so that a caller who imports
/// this module as `des` does not have to write `des.des.Des`.
pub const cipher = @import("des.zig");
pub const modes = @import("modes.zig");

/// The pieces a caller reaches for most often, spelled without the layer in
/// between.
pub const Des = cipher.Des;
pub const Des3 = cipher.Des3;
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
}
