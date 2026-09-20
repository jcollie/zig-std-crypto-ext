// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! Measure the constant-time claim rather than trust it.
//!
//! `Des` says the cipher and the key helpers take the same time whatever the
//! key and the data, on the assumption that the compiler keeps a mask a mask
//! and a shift a shift. Nothing forbids a compiler from turning either into a
//! branch, and a disassembly is the only proof that a particular build did
//! not -- but a disassembly is read once, and this runs every time. `Aes192`
//! makes the same claim by a different route, resting on `std`'s hardware
//! round, and the modes make it by construction, so all of those are on the
//! list too rather than taken on trust:
//!
//! ```console
//! $ zig build timing
//! $ zig build timing -- --samples 1000000 --seed 7
//! ```
//!
//! It is the test from dudect (Reparaz, Balasch and Verbauwhede, 2017). Each
//! function is timed on two classes of input, one fixed and one random, many
//! times in a random order, and Welch's t-test asks whether the two timing
//! distributions have the same mean. The tail of a timing distribution is
//! interrupts and page faults, so the test is repeated on the samples below
//! several percentiles as well as on all of them, and the worst t across those
//! is what is reported. A |t| above 10 is a leak: at these sample counts that
//! is a difference of a cycle or so, held consistently. A constant-time
//! function sits within a few units of zero however many samples are taken.
//!
//! A function whose running time *is* its input runs first, so that the
//! harness is seen to find a leak before it is believed about not finding one;
//! a run in which that control is not detected fails for that reason.
//!
//! Every input is prepared before any is timed. Generating the random class's
//! input just before starting the timer leaves different pipeline and cache
//! state behind than the fixed class's copy does, and at four hundred thousand
//! samples that alone reads as a leak of twenty-odd units on code that has
//! none. That is the mistake this file was first written with.
//!
//! What it cannot tell: that another compiler, or this one at another
//! version, emits the same thing. It reads the machine it runs on, and the
//! cycle counter it needs exists on x86-64 and AArch64.

const std = @import("std");
const builtin = @import("builtin");
const des = @import("des");
const ext = des;

/// Cycles, from a counter that costs nothing to read and cannot be reordered
/// with the code around it.
inline fn cycles() u64 {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var lo: u32 = undefined;
            var hi: u32 = undefined;
            asm volatile ("rdtscp"
                : [lo] "={eax}" (lo),
                  [hi] "={edx}" (hi),
                :
                : .{ .rcx = true, .memory = true });
            return (@as(u64, hi) << 32) | lo;
        },
        .aarch64 => {
            return asm volatile (
                \\isb
                \\mrs %[out], cntvct_el0
                : [out] "=r" (-> u64),
                :
                : .{ .memory = true });
        },
        else => @compileError("no cycle counter is known for this target"),
    }
}

/// Above this, dudect calls it a leak. Between `suspicious` and this it is
/// worth a second run with more samples.
const leak_threshold = 10.0;
const suspicious_threshold = 4.5;

/// Enough key and data for the largest thing measured: Triple DES and AES-192
/// take 24 bytes of key, and the modes are run over three DES blocks, which
/// is also one and a half AES blocks -- so the partial-block path of CFB is
/// on the clock too. Each operation takes the prefix it needs.
const Input = struct { key: [24]u8, block: [24]u8 };

/// Mean and variance in one pass, Welford's way, so that a million cycle
/// counts need not be held as floats.
const Stats = struct {
    n: f64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,

    fn push(s: *Stats, x: f64) void {
        s.n += 1;
        const d = x - s.mean;
        s.mean += d / s.n;
        s.m2 += d * (x - s.mean);
    }

    fn variance(s: Stats) f64 {
        return s.m2 / (s.n - 1);
    }
};

/// Welch's t: how many standard errors apart the two means are.
fn welch(a: Stats, b: Stats) f64 {
    return (a.mean - b.mean) / @sqrt(a.variance() / a.n + b.variance() / b.n);
}

const Verdict = enum { ok, suspicious, leak };

fn verdict(t: f64) Verdict {
    if (@abs(t) > leak_threshold) return .leak;
    if (@abs(t) > suspicious_threshold) return .suspicious;
    return .ok;
}

const Measurement = struct {
    name: []const u8,
    /// Fills an input for a class: `false` is the fixed input, `true` a
    /// random one.
    prepare: *const fn (bool, std.Random, *Input) void,
    /// Runs the operation on one input and returns the cycles it took,
    /// starting and stopping the counter as close to the operation as it can.
    op: *const fn (*const Input) u64,
    /// The positive control is expected to leak, and the run fails if it
    /// does not, because then nothing else can be believed either.
    must_leak: bool = false,
};

fn measure(m: Measurement, samples_per_class: usize, random: std.Random, gpa: std.mem.Allocator) !Verdict {
    const total = 2 * samples_per_class;
    const classes = try gpa.alloc(bool, total);
    defer gpa.free(classes);
    const inputs = try gpa.alloc(Input, total);
    defer gpa.free(inputs);
    // Exactly half in each class, in a random order -- rather than a coin
    // per sample, which gives the same thing on average and leaves the
    // percentile arithmetic below assuming neither class came up empty.
    for (classes, 0..) |*class, i| class.* = i % 2 == 1;
    random.shuffle(bool, classes);
    for (classes, inputs) |class, *input| m.prepare(class, random, input);

    var t0 = try std.ArrayList(u64).initCapacity(gpa, total);
    defer t0.deinit(gpa);
    var t1 = try std.ArrayList(u64).initCapacity(gpa, total);
    defer t1.deinit(gpa);
    for (0..@min(10_000, total)) |i| _ = m.op(&inputs[i]);
    for (classes, inputs) |class, *input| {
        const took = m.op(input);
        (if (class) &t1 else &t0).appendAssumeCapacity(took);
    }

    std.mem.sort(u64, t0.items, {}, std.sort.asc(u64));
    std.mem.sort(u64, t1.items, {}, std.sort.asc(u64));
    var worst: f64 = 0;
    var worst_at: usize = 100;
    var whole: f64 = 0;
    inline for (.{ 100, 99, 95, 90, 75, 50 }) |percent| {
        // One crop threshold from the larger of the two classes' percentiles,
        // so that both are cut at the same value.
        const cut = @max(t0.items[t0.items.len * percent / 100 - 1], t1.items[t1.items.len * percent / 100 - 1]);
        var a: Stats = .{};
        var b: Stats = .{};
        for (t0.items) |x| if (x <= cut) a.push(@floatFromInt(x));
        for (t1.items) |x| if (x <= cut) b.push(@floatFromInt(x));
        const t = welch(a, b);
        if (percent == 100) whole = t;
        if (@abs(t) > @abs(worst)) {
            worst = t;
            worst_at = percent;
        }
        if (percent == 100 or percent == 90) {
            std.debug.print("  {s:<30} crop {d:>3}%  fixed {d:>7.1} +- {d:>6.1}  random {d:>7.1} +- {d:>6.1}  t = {d:>7.2}\n", .{
                m.name, percent, a.mean, @sqrt(a.variance()), b.mean, @sqrt(b.variance()), t,
            });
        }
    }
    const v = verdict(worst);
    const word = if (m.must_leak)
        (if (v == .leak) "leaks, as it must" else "NOT DETECTED: the harness cannot see a leak on this machine")
    else switch (v) {
        .ok => "ok",
        .suspicious => "SUSPICIOUS: run again with more samples",
        .leak => "LEAK",
    };
    std.debug.print("  {s:<30} worst |t| = {d:.2} at crop {d}%: {s}\n\n", .{ m.name, @abs(worst), worst_at, word });
    return v;
}

// -- the inputs -------------------------------------------------------------

fn zerosOrRandom(class: bool, random: std.Random, input: *Input) void {
    input.* = .{ .key = @splat(0), .block = @splat(0) };
    if (class) {
        random.bytes(&input.key);
        random.bytes(&input.block);
    }
}

fn weakOrRandom(class: bool, random: std.Random, input: *Input) void {
    // Fixed: a weak key, which a comparison that stops early matches in full
    // on its first candidate. Random: a key that matches none of them.
    input.* = .{ .key = @splat(0), .block = @splat(0) };
    input.key[0..8].* = des.weak_keys[0];
    if (class) random.bytes(input.key[0..8]);
}

// -- the operations ---------------------------------------------------------

fn encryptOp(input: *const Input) u64 {
    var out: [8]u8 = undefined;
    const start = cycles();
    des.Des.initEnc(input.key[0..8].*).encrypt(&out, input.block[0..8]);
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

fn decryptOp(input: *const Input) u64 {
    var out: [8]u8 = undefined;
    const start = cycles();
    des.Des.initDec(input.key[0..8].*).decrypt(&out, input.block[0..8]);
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

fn des3EncryptOp(input: *const Input) u64 {
    var out: [8]u8 = undefined;
    const start = cycles();
    des.Des3.initEnc(input.key).encrypt(&out, input.block[0..8]);
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

fn aes192EncryptOp(input: *const Input) u64 {
    var out: [16]u8 = undefined;
    const start = cycles();
    des.Aes192.initEnc(input.key).encrypt(&out, input.block[0..16]);
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

/// DES-CBC over three blocks: the mode's own loop and XORs on top of the
/// cipher, which is what SNMPv3 privacy actually runs.
fn cbcOp(input: *const Input) u64 {
    var out: [24]u8 = undefined;
    const start = cycles();
    des.modes.cbcEncrypt(des.Des.EncryptCtx, des.Des.initEnc(input.key[0..8].*), &out, &input.block, @splat(0));
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

/// AES-192-CFB over twenty-four bytes: one whole block and a partial one,
/// so the final-block path is timed along with the rest.
fn cfbOp(input: *const Input) u64 {
    var out: [24]u8 = undefined;
    const start = cycles();
    des.modes.cfbEncrypt(des.Aes192.EncryptCtx, des.Aes192.initEnc(input.key), &out, &input.block, @splat(0));
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

fn isWeakOp(input: *const Input) u64 {
    const start = cycles();
    const weak = des.isWeak(input.key[0..8].*);
    const end = cycles();
    std.mem.doNotOptimizeAway(weak);
    return end - start;
}

fn parityOp(input: *const Input) u64 {
    var key = input.key[0..8].*;
    const start = cycles();
    des.setOddParity(&key);
    const odd = des.hasOddParity(&key);
    const end = cycles();
    std.mem.doNotOptimizeAway(key);
    std.mem.doNotOptimizeAway(odd);
    return end - start;
}

/// A three-byte *secret* exponent through `ff.powWithEncodedExponent`.
///
/// `std.crypto.ff` chooses between a constant-time table walk and a short
/// exponent loop with a data-dependent branch, and in 0.16.0 the test that
/// makes that choice reads
///
/// ```zig
/// if (public and e.len < 3 or (e.len == 3 and e[0] <= 0b1111))
/// ```
///
/// which `and` binding tighter than `or` turns into `(public and short) or
/// (three bytes and small)`. The second half never asks whether the exponent
/// is public, so a three-byte secret exponent with a small top nibble goes
/// down the branchy path and its bits show up in the timing. `src/ff.zig`
/// parenthesises it; this is what says so.
///
/// Fixed class: an exponent of three zero-ish bytes. Random class: three
/// random bytes under the same top-nibble bound, so both classes take the
/// same branch in the *patched* code and differ only in bits the loop would
/// branch on in the unpatched one.
fn shortSecretExponentOp(input: *const Input) u64 {
    const M = ext.ff.Modulus(2048);
    const m = M.fromBytes(&exponent_modulus, .big) catch unreachable;
    const x = M.Fe.fromBytes(m, input.block[0..16], .big) catch unreachable;
    const start = cycles();
    const out = m.powWithEncodedExponent(x, input.key[0..3], .big) catch unreachable;
    const end = cycles();
    std.mem.doNotOptimizeAway(out);
    return end - start;
}

/// A fixed 2048-bit modulus for the exponent timing, odd and full width.
const exponent_modulus: [256]u8 = blk: {
    var m: [256]u8 = @splat(0x5a);
    m[0] = 0xd3;
    m[255] = 0x8f;
    break :blk m;
};

fn shortExponent(class: bool, random: std.Random, input: *Input) void {
    input.* = .{ .key = @splat(0), .block = @splat(0x42) };
    if (class) random.bytes(input.key[0..3]);
    // Both classes keep the top nibble small, which is the condition that
    // sends a three-byte exponent down the short path: the classes must
    // differ in the exponent's *bits*, not in which branch is taken, or the
    // test measures the branch rather than the leak.
    input.key[0] &= 0x0f;
    // And a non-zero exponent, which `powWithEncodedExponent` insists on.
    input.key[2] |= 1;
}

/// The positive control: a loop whose count is the first key byte, doing
/// something the compiler cannot fold into a closed form.
fn leakyOp(input: *const Input) u64 {
    const start = cycles();
    var x: u32 = 1;
    var i: usize = 0;
    while (i < input.key[0]) : (i += 1) x = x *% 0x9e3779b1 +% @as(u32, @intCast(i));
    const end = cycles();
    std.mem.doNotOptimizeAway(x);
    return end - start;
}

const measurements = [_]Measurement{
    .{ .name = "loop bound from data (control)", .prepare = zerosOrRandom, .op = leakyOp, .must_leak = true },
    .{ .name = "Des encrypt", .prepare = zerosOrRandom, .op = encryptOp },
    .{ .name = "Des decrypt", .prepare = zerosOrRandom, .op = decryptOp },
    .{ .name = "Des3 encrypt", .prepare = zerosOrRandom, .op = des3EncryptOp },
    .{ .name = "Aes192 encrypt", .prepare = zerosOrRandom, .op = aes192EncryptOp },
    .{ .name = "DES-CBC, three blocks", .prepare = zerosOrRandom, .op = cbcOp },
    .{ .name = "AES-192-CFB, 24 bytes", .prepare = zerosOrRandom, .op = cfbOp },
    .{ .name = "isWeak", .prepare = weakOrRandom, .op = isWeakOp },
    .{ .name = "setOddParity + hasOddParity", .prepare = zerosOrRandom, .op = parityOp },
    .{ .name = "ff: three-byte secret exponent", .prepare = shortExponent, .op = shortSecretExponentOp },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var samples_per_class: usize = 400_000;
    var seed: u64 = 0x5eed;
    var args: std.process.Args.Iterator = .init(init.minimal.args);
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--samples")) {
            samples_per_class = std.fmt.parseInt(usize, args.next() orelse "", 10) catch samples_per_class;
        } else if (std.mem.eql(u8, arg, "--seed")) {
            seed = std.fmt.parseInt(u64, args.next() orelse "", 10) catch seed;
        } else {
            std.debug.print("usage: timing [--samples N] [--seed S]\n", .{});
            std.process.exit(2);
        }
    }
    if (samples_per_class < 100) {
        std.debug.print("--samples must be at least 100\n", .{});
        std.process.exit(2);
    }

    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    std.debug.print("{d} samples per class, seed {d}, cycles per call; |t| > {d} is a leak\n\n", .{
        samples_per_class, seed, leak_threshold,
    });

    var failed = false;
    for (measurements) |m| {
        const v = try measure(m, samples_per_class, random, gpa);
        if (m.must_leak) {
            if (v != .leak) failed = true;
        } else if (v == .leak) {
            failed = true;
        }
    }
    if (failed) {
        std.debug.print("timing: FAILED\n", .{});
        std.process.exit(1);
    }
    std.debug.print("timing: every function measured constant-time on this machine\n", .{});
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

test "Welch's t on the same distribution is about zero" {
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();
    var a: Stats = .{};
    var b: Stats = .{};
    for (0..100_000) |_| {
        a.push(@floatFromInt(random.uintLessThan(u32, 100)));
        b.push(@floatFromInt(random.uintLessThan(u32, 100)));
    }
    try testing.expect(@abs(welch(a, b)) < suspicious_threshold);
    try testing.expectEqual(Verdict.ok, verdict(welch(a, b)));
}

test "Welch's t sees a shift of one cycle at these sample counts" {
    // Which is the resolution the whole exercise depends on.
    var prng: std.Random.DefaultPrng = .init(2);
    const random = prng.random();
    var a: Stats = .{};
    var b: Stats = .{};
    for (0..400_000) |_| {
        a.push(@floatFromInt(random.uintLessThan(u32, 40)));
        b.push(@floatFromInt(random.uintLessThan(u32, 40) + 1));
    }
    try testing.expectEqual(Verdict.leak, verdict(welch(a, b)));
}

test "Welford agrees with the textbook" {
    var s: Stats = .{};
    for ([_]f64{ 2, 4, 4, 4, 5, 5, 7, 9 }) |x| s.push(x);
    try testing.expectApproxEqAbs(@as(f64, 5), s.mean, 1e-12);
    // Sample variance, n - 1 in the denominator.
    try testing.expectApproxEqAbs(@as(f64, 32.0 / 7.0), s.variance(), 1e-12);
}
