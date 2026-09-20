// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! `src/ff.zig` against the `std.crypto.ff` it was taken from.
//!
//! A carried patch has one obligation that an addition does not: it must
//! compute what the thing it replaces computes. So this is differential
//! rather than exemplary -- the same exponentiations through both, at the
//! widths where the patch changes the work and at the widths where it must
//! not change anything.

const std = @import("std");
const testing = std.testing;

const ours = @import("std_crypto_ext").ff;
const theirs = std.crypto.ff;

/// Random moduli, bases and exponents at one width, through both.
fn agrees(comptime max_bits: usize, comptime bits: usize, rounds: usize, seed: u64) !void {
    const Theirs = theirs.Modulus(max_bits);
    const Ours = ours.Modulus(max_bits);
    const bytes = bits / 8;

    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    for (0..rounds) |_| {
        var n_buf: [max_bits / 8]u8 = undefined;
        var e_buf: [max_bits / 8]u8 = undefined;
        var m_buf: [max_bits / 8]u8 = undefined;
        rand.bytes(n_buf[0..bytes]);
        rand.bytes(e_buf[0..bytes]);
        rand.bytes(m_buf[0..bytes]);
        // A modulus of the full width, odd, with a base and an exponent below
        // it -- which is what `Fe.fromBytes` will insist on.
        n_buf[0] |= 0x80;
        n_buf[bytes - 1] |= 1;
        m_buf[0] &= 0x7f;
        e_buf[0] &= 0x7f;

        const t_m = try Theirs.fromBytes(n_buf[0..bytes], .big);
        const o_m = try Ours.fromBytes(n_buf[0..bytes], .big);

        const t_out = try t_m.pow(
            try Theirs.Fe.fromBytes(t_m, m_buf[0..bytes], .big),
            try Theirs.Fe.fromBytes(t_m, e_buf[0..bytes], .big),
        );
        const o_out = try o_m.pow(
            try Ours.Fe.fromBytes(o_m, m_buf[0..bytes], .big),
            try Ours.Fe.fromBytes(o_m, e_buf[0..bytes], .big),
        );

        var t_bytes: [max_bits / 8]u8 = undefined;
        var o_bytes: [max_bits / 8]u8 = undefined;
        try t_out.toBytes(t_bytes[0..bytes], .big);
        try o_out.toBytes(o_bytes[0..bytes], .big);
        try testing.expectEqualSlices(u8, t_bytes[0..bytes], o_bytes[0..bytes]);
    }
}

test "a modulus narrower than its type: where the patch does its work" {
    // The case the patch is for, and the case an RSA implementation is always
    // in: 4096-bit keys force `Modulus(4096)`, and then every 2048-bit key
    // runs under it.
    try agrees(4096, 2048, 8, 0xff01);
    try agrees(4096, 1024, 12, 0xff02);
    try agrees(2048, 1024, 12, 0xff03);
}

test "a modulus as wide as its type: where the patch must change nothing" {
    // And the edge the first version of the patch got wrong. Sizing the
    // exponent by the limb count rather than the bit length asks for more
    // bytes than the buffer has when the modulus fills the type, because a
    // limb holds `t_bits` and not eight.
    try agrees(4096, 4096, 4, 0xff04);
    try agrees(2048, 2048, 8, 0xff05);
    try agrees(1024, 1024, 12, 0xff06);
    try agrees(512, 512, 16, 0xff07);
}

test "the public path is untouched" {
    // `powPublic` is not patched, and trims further than the secret path may.
    // It is here so that a change to the file that broke it would be caught
    // by this file rather than by whatever uses it next.
    const Theirs = theirs.Modulus(2048);
    const Ours = ours.Modulus(2048);

    var n_buf: [256]u8 = undefined;
    var m_buf: [256]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xff08);
    prng.random().bytes(&n_buf);
    prng.random().bytes(&m_buf);
    n_buf[0] |= 0x80;
    n_buf[255] |= 1;
    m_buf[0] &= 0x7f;

    const t_m = try Theirs.fromBytes(&n_buf, .big);
    const o_m = try Ours.fromBytes(&n_buf, .big);

    // 65537, the exponent every RSA certificate in the world verifies with.
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    const t_out = try t_m.powPublic(
        try Theirs.Fe.fromBytes(t_m, &m_buf, .big),
        try Theirs.Fe.fromBytes(t_m, &e, .big),
    );
    const o_out = try o_m.powPublic(
        try Ours.Fe.fromBytes(o_m, &m_buf, .big),
        try Ours.Fe.fromBytes(o_m, &e, .big),
    );

    var t_bytes: [256]u8 = undefined;
    var o_bytes: [256]u8 = undefined;
    try t_out.toBytes(&t_bytes, .big);
    try o_out.toBytes(&o_bytes, .big);
    try testing.expectEqualSlices(u8, &t_bytes, &o_bytes);
}
