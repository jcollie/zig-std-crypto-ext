// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! CPace against the draft's own test vectors: `testvectors.json` from the
//! CFRG's repository for draft-irtf-cfrg-cpace, fetched as a lazy dependency
//! only when these tests are built.
//!
//! The draft gives no vectors for the confirmation tags, whose MAC it leaves
//! to the application; the two below are what the Python `cpace` package
//! 0.1.0 computes for the draft's inputs, the package aiosendspin pairs
//! with -- which is the implementation this one has to agree with.

const std = @import("std");
const testing = std.testing;
const CPace = @import("std_crypto_ext").CPace;
const calculateGenerator = @import("std_crypto_ext").cpace.calculateGenerator;

const vectors_json = @embedFile("cpace_vectors");

const ta_hex = "214B05FED53D47D1AC815B42EAE64CC68F93F2013DB81DB04CC9A4F12A1A5CA513CB2458C9071BBECF720556872DE984260FDC2B576C8F5331C455DE81BD22DD";
const tb_hex = "B792827DC20F93390415CBA5F17CBDBB00556053CE74D334E16FFD52258C132036F933ECE5527CA39CCD6D25AC7030C15B15AE6EE45B7665E5DF9DC651AD9362";

fn hex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn field(a: std.mem.Allocator, o: std.json.ObjectMap, name: []const u8) ![]u8 {
    return hex(a, (o.get(name) orelse return error.MissingVector).string);
}

test "G_25519: the generator, both shares, the ISK and the session id output" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(std.json.Value, a, vectors_json, .{});
    const v = root.object.get("G_25519").?.object;

    const prs = try field(a, v, "PRS");
    const ci = try field(a, v, "CI");
    const sid = try field(a, v, "sid");
    const ad_a = try field(a, v, "ADa");
    const ad_b = try field(a, v, "ADb");

    try testing.expectEqualSlices(u8, try field(a, v, "g"), &calculateGenerator(prs, ci, sid));

    var initiator = try CPace.startWithScalar(.initiator, prs, ci, sid, ad_a, (try field(a, v, "ya"))[0..32].*);
    var responder = try CPace.startWithScalar(.responder, prs, ci, sid, ad_b, (try field(a, v, "yb"))[0..32].*);
    try testing.expectEqualSlices(u8, try field(a, v, "Ya"), &initiator.share);
    try testing.expectEqualSlices(u8, try field(a, v, "Yb"), &responder.share);

    try initiator.derive(responder.share, ad_b);
    try responder.derive(initiator.share, ad_a);
    const isk = try field(a, v, "ISK_IR");
    try testing.expectEqualSlices(u8, isk, &initiator.isk);
    try testing.expectEqualSlices(u8, isk, &responder.isk);
    try testing.expectEqualSlices(u8, try field(a, v, "sid_output_ir"), &initiator.sid_output);

    try testing.expectEqualSlices(u8, try hex(a, ta_hex), &initiator.tag());
    try testing.expectEqualSlices(u8, try hex(a, tb_hex), &responder.tag());
    try testing.expect(initiator.verify(&responder.tag()));
    try testing.expect(responder.verify(&initiator.tag()));
}

// The draft's scalar_mult_vfy vectors for X25519, from `testvectors.md`,
// which has the scalar and the results the JSON leaves out: `s = ...`,
// then `uN: ...` and `qN: ...` lines.
test "scalar_mult_vfy: low-order points abort, and bit 255 is cleared" {
    const md = @embedFile("cpace_vectors_md");
    const start = std.mem.indexOf(u8, md, "### Test vectors for G\\_X25519.scalar\\_mult\\_vfy") orelse return error.MissingVectors;
    const rest = md[start + 3 ..];
    const section = rest[0 .. std.mem.indexOf(u8, rest, "###") orelse rest.len];

    var u: [12][32]u8 = undefined;
    var q: [12][32]u8 = undefined;
    var s: [32]u8 = undefined;
    var have_s = false;
    var n_u: usize = 0;
    var n_q: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, section, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (std.mem.startsWith(u8, line, "s = ")) {
            _ = try std.fmt.hexToBytes(&s, line[4..]);
            have_s = true;
        } else if (line.len == 4 + 64 and line[2] == ':' and (line[0] == 'u' or line[0] == 'q')) {
            const index = std.fmt.parseInt(usize, line[1..2], 16) catch continue;
            const dest = if (line[0] == 'u') &u else &q;
            _ = try std.fmt.hexToBytes(&dest[index], line[4..]);
            if (line[0] == 'u') n_u += 1 else n_q += 1;
        }
    }
    try testing.expect(have_s and n_u == 12 and n_q == 12);

    const zero: [32]u8 = @splat(0);
    for (u, q, 0..) |point, expected, i| {
        errdefer std.debug.print("u{x}\n", .{i});
        if (std.mem.eql(u8, &expected, &zero)) {
            // The abort case, whichever side sends it.
            try testing.expectError(error.IdentityElement, @import("std_crypto_ext").cpace.scalarMultVfy(s, point));
            var prng: std.Random.DefaultPrng = .init(i);
            var c = try CPace.start(.responder, "Password", "", "sid", "", prng.random());
            try testing.expectError(error.IdentityElement, c.derive(point, ""));
        } else {
            try testing.expectEqualSlices(u8, &expected, &try @import("std_crypto_ext").cpace.scalarMultVfy(s, point));
        }
    }
}
