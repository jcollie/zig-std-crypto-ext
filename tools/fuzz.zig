// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! Run the fuzz targets in `tests/fuzz.zig` against input this makes up.
//!
//! Zig has a fuzzer of its own and those targets are written for it, so the
//! obvious thing to run is `zig build fuzz --fuzz`. With the devshell's
//! patched Zig that now *compiles* -- `flake.nix` says what the patch is --
//! and then ends with
//!
//! ```
//! error: step 'run test': corrupted coverage file: pcs_len was zero
//! ```
//!
//! because nothing in 0.16.0 populates the table of program counters, however
//! the modules are built. A fuzzer with no coverage is a random number
//! generator, so this is one written down honestly: it makes an input, hands
//! it to a target, and says so when one comes back with an error.
//!
//! ```console
//! $ zig build fuzz-run                                # a minute of each
//! $ zig build fuzz-run -- --seconds 300 --target messages
//! $ zig build fuzz-run -- --seed 12345                # exactly again
//! $ zig build fuzz-run -- --input fuzz-findings/x.bin --target messages
//! ```
//!
//! # What an input is
//!
//! Not a file: a `std.testing.Smith` reads it as a stream of answers, and the
//! encoding is worth knowing before writing a generator for it.
//!
//! * `smith.slice(buf)` reads **four** bytes as a little-endian `u32` length,
//!   then that many bytes of content. A length larger than `buf.len` is not
//!   reduced into range -- it yields an *empty* slice. So a string of random
//!   bytes gives almost every target nothing at all to parse, and a generator
//!   that does not write a plausible length is fuzzing nothing.
//! * `smith.value(T)` reads **eight** bytes as a little-endian `u64` and, if
//!   that value is outside the asked-for range, returns the range's minimum
//!   rather than reducing it. For an `i64` every value is in range; for a
//!   `bool` only 0 and 1 are, so random bytes make it false every time.
//!
//! Every target here begins with a `slice`, so `makeInput` writes two
//! length-prefixed chunks -- two because a target may ask for two slices, and
//! the second would otherwise only ever see the random tail -- and each chunk
//! is a mutation of one of the target's own seeds. That corpus is the whole of
//! what stands in for coverage feedback.
//!
//! The length is capped at the target's own buffer size, which `Target` has to
//! carry for the reason above: a length larger than the buffer yields nothing
//! rather than a truncation, and getting it wrong is silent -- the target
//! runs, reports no failure, and was handed the empty string every time.
//!
//! # Two kinds of input
//!
//! LDAP has both, which is why `Target` says which it is. A filter, a
//! distinguished name and a URL are text, and mutate best towards the
//! punctuation their grammars are made of. A message is BER, and mutates best
//! towards tag and length bytes: a run of random bytes is not a message and
//! never becomes one, whereas a real message with one length byte changed is
//! exactly the input worth trying.
//!
//! # The watchdog
//!
//! Nothing here should be able to loop -- every parser walks a bounded input
//! once, and the two that recurse have a depth limit -- but "should" is what a
//! fuzzer is for. A thread watches the clock, and an iteration that outlasts
//! `--timeout` seconds is reported as a hang with the input that caused it.
//! There is no way to unwind out of it, so that ends the run.

const std = @import("std");
const targets = @import("fuzz_targets");

const Smith = std.testing.Smith;

/// Milliseconds on a clock that only goes forwards while the machine is up.
fn nowMs(io: std.Io) i64 {
    return @intCast(@divFloor(std.Io.Timestamp.now(io, .awake).nanoseconds, std.time.ns_per_ms));
}

/// What the watchdog needs to see, written before each iteration begins.
const Watch = struct {
    /// When the running iteration started, or zero between iterations.
    started_ms: std.atomic.Value(i64) = .init(0),
    /// The input it is running, which is what a hang has to report.
    input: []const u8 = &.{},
    target: []const u8 = "",
    timeout_s: u32 = 10,
    dir: []const u8 = "",
};

var watch: Watch = .{};

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Two allocators, and they have to be two. The targets are written to run
    // against the testing allocator, which cannot be named outside a test
    // build; this is the same thing by another route, a debug allocator whose
    // outstanding allocations are counted after every input, since a leak is
    // one of the things being fuzzed for. Nothing else may allocate from it --
    // the loop's own buffer would be indistinguishable from a target's leak --
    // so everything here uses the process allocator instead.
    var checked: std.heap.DebugAllocator(.{}) = .init;
    defer _ = checked.deinit();
    targets.backing = checked.allocator();
    const gpa = init.gpa;

    var seconds: u32 = 60;
    var iterations: ?u64 = null;
    var seed: u64 = @bitCast(@as(i64, @truncate(std.Io.Timestamp.now(io, .real).nanoseconds)));
    var only: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var dir: []const u8 = "fuzz-findings";
    var timeout_s: u32 = 10;

    var args: std.process.Args.Iterator = .init(init.minimal.args);
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--seconds")) {
            seconds = std.fmt.parseInt(u32, args.next() orelse "60", 10) catch 60;
        } else if (std.mem.eql(u8, arg, "--iterations")) {
            iterations = std.fmt.parseInt(u64, args.next() orelse "0", 10) catch null;
        } else if (std.mem.eql(u8, arg, "--seed")) {
            seed = std.fmt.parseInt(u64, args.next() orelse "0", 10) catch seed;
        } else if (std.mem.eql(u8, arg, "--target")) {
            only = args.next();
        } else if (std.mem.eql(u8, arg, "--input")) {
            input_path = args.next();
        } else if (std.mem.eql(u8, arg, "--findings")) {
            dir = args.next() orelse dir;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            timeout_s = std.fmt.parseInt(u32, args.next() orelse "10", 10) catch 10;
        } else {
            std.debug.print(
                \\usage: fuzz [--target NAME] [--seconds N | --iterations N] [--seed S]
                \\            [--timeout S] [--findings DIR] [--input FILE]
                \\
                \\Targets: {s}
                \\
            , .{targetNames()});
            std.process.exit(2);
        }
    }

    watch.timeout_s = timeout_s;
    watch.dir = dir;

    const thread = try std.Thread.spawn(.{}, watchdog, .{io});
    thread.detach();

    // One input, from a file, and nothing else: this is how a finding is
    // looked at again after it has been fixed.
    if (input_path) |path| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
        defer gpa.free(bytes);
        const name = only orelse targets.all[0].name;
        const target = find(name) orelse {
            std.debug.print("no target called {s}; there are: {s}\n", .{ name, targetNames() });
            std.process.exit(2);
        };
        watch.input = bytes;
        watch.target = target.name;
        watch.started_ms.store(nowMs(io), .release);
        target.run(bytes) catch |err| {
            std.debug.print("{s}: {t}\n", .{ target.name, err });
            show(bytes);
            std.process.exit(1);
        };
        std.debug.print("{s}: that input is fine now\n", .{target.name});
        return;
    }

    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(gpa);

    std.debug.print("seed {d}\n", .{seed});
    var failures: usize = 0;
    for (targets.all) |target| {
        if (only) |name| if (!std.mem.eql(u8, name, target.name)) continue;

        var runs: u64 = 0;
        const deadline = nowMs(io) + @as(i64, seconds) * 1000;
        while (if (iterations) |n| runs < n else nowMs(io) < deadline) : (runs += 1) {
            try makeInput(gpa, &buffer, random, target);
            watch.input = buffer.items;
            watch.target = target.name;
            watch.started_ms.store(nowMs(io), .release);
            const result = target.run(buffer.items);
            watch.started_ms.store(0, .release);
            if (checked.detectLeaks() != 0) {
                std.debug.print("\n{s}: leaked\n", .{target.name});
                try report(io, dir, target.name, buffer.items);
                std.process.exit(1);
            }
            result catch |err| {
                failures += 1;
                std.debug.print("\n{s}: {t}\n", .{ target.name, err });
                try report(io, dir, target.name, buffer.items);
                // Keep going: one shape of failure is usually many inputs, and
                // stopping at the first says less than a handful does.
                if (failures >= 10) {
                    std.debug.print("ten failures; stopping\n", .{});
                    std.process.exit(1);
                }
            };
        }
        std.debug.print("{s}: {d} runs\n", .{ target.name, runs });
    }
    if (failures != 0) std.process.exit(1);
}

fn find(name: []const u8) ?targets.Target {
    for (targets.all) |t| if (std.mem.eql(u8, t.name, name)) return t;
    return null;
}

fn targetNames() []const u8 {
    comptime var names: []const u8 = "";
    inline for (targets.all, 0..) |t, i| {
        names = names ++ (if (i == 0) "" else ", ") ++ t.name;
    }
    return names;
}

/// Make the next input: two length-prefixed chunks and a random tail.
///
/// Two, because a target may ask for two slices -- `paths` wants a working
/// directory and then an argument -- and the second would otherwise only ever
/// see whatever random bytes happened to follow. A target that asks for one
/// slice reads the first chunk and leaves the rest for its `value` calls.
///
/// The length is capped at `target.content_max` rather than at some number
/// chosen here, because `Smith.slice` answers a length larger than its buffer
/// with an *empty* slice rather than a truncated one. Getting that wrong is
/// silent: the target runs, reports no failure, and has been handed nothing.
fn makeInput(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    random: std.Random,
    target: targets.Target,
) !void {
    out.clearRetainingCapacity();

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);

    for (0..2) |_| {
        content.clearRetainingCapacity();
        if (target.corpus.len == 0 or random.uintLessThan(u8, 8) == 0) {
            // Sometimes nothing but noise, so that the shapes nobody thought
            // of are reachable at all.
            const len = random.uintLessThan(usize, target.content_max);
            try content.ensureUnusedCapacity(gpa, len);
            for (0..len) |_| content.appendAssumeCapacity(random.int(u8));
        } else {
            const seed = target.corpus[random.uintLessThan(usize, target.corpus.len)];
            try content.appendSlice(gpa, seed);
            // Splicing, which is what the stream-shaped targets want: two of
            // them read a series of messages rather than one, and a second
            // seed stuck on the end -- often cut short, so that the join
            // lands in the middle of a message -- is how the boundary between
            // one message and the next gets tested at all. A single mutated
            // seed never produces a truncated message followed by a good one.
            if (random.uintLessThan(u8, 4) == 0) {
                const other = target.corpus[random.uintLessThan(usize, target.corpus.len)];
                const take = if (other.len == 0) 0 else random.uintLessThan(usize, other.len) + 1;
                try content.appendSlice(gpa, other[0..take]);
            }
            const rounds = 1 + random.uintLessThan(usize, 8);
            for (0..rounds) |_| try mutate(gpa, &content, random, interestingFor(target));
        }
        if (content.items.len > target.content_max) {
            content.shrinkRetainingCapacity(target.content_max);
        }

        var length: [4]u8 = undefined;
        std.mem.writeInt(u32, &length, @intCast(content.items.len), .little);
        try out.appendSlice(gpa, &length);
        try out.appendSlice(gpa, content.items);
    }

    // And a tail, for whatever a target asks after its slices: an `i64` reads
    // eight bytes from here.
    const tail = 16 + random.uintLessThan(usize, 48);
    try out.ensureUnusedCapacity(gpa, tail);
    for (0..tail) |_| out.appendAssumeCapacity(random.int(u8));
}

fn mutate(gpa: std.mem.Allocator, content: *std.ArrayList(u8), random: std.Random, interesting: []const u8) !void {
    if (content.items.len == 0) {
        try content.append(gpa, random.int(u8));
        return;
    }
    switch (random.uintLessThan(u8, 8)) {
        // A byte, replaced. The commonest useful mutation, and the one that
        // turns a length into a nearly-right length.
        0, 1 => content.items[random.uintLessThan(usize, content.items.len)] = random.int(u8),
        // A byte, replaced by one of the ones this protocol is made of.
        2, 3 => content.items[random.uintLessThan(usize, content.items.len)] =
            interesting[random.uintLessThan(usize, interesting.len)],
        4 => try content.insert(gpa, random.uintLessThan(usize, content.items.len), random.int(u8)),
        5 => try content.insert(
            gpa,
            random.uintLessThan(usize, content.items.len),
            interesting[random.uintLessThan(usize, interesting.len)],
        ),
        // A run on the end, which is how an input grows another element.
        6 => for (0..1 + random.uintLessThan(usize, 16)) |_| {
            try content.append(gpa, interesting[random.uintLessThan(usize, interesting.len)]);
        },
        else => _ = content.orderedRemove(random.uintLessThan(usize, content.items.len)),
    }
}

/// The bytes each kind of input is mostly made of.
///
/// For text, the alphabet a dotted-decimal OID is written in, and the
/// punctuation most likely to be mistaken for part of one.
const interesting_text = blk: {
    var set: []const u8 = "0123456789";
    set = set ++ "..........";
    set = set ++ " -+,;:/\\";
    set = set ++ &[_]u8{ 0x00, 0x7f, 0x80, 0xff };
    break :blk set;
};

/// And for BER: the identifier octets these encodings are built from, the
/// lengths that start the long form, and the boundaries a length check is most
/// likely to have got wrong.
const interesting_binary = blk: {
    // SEQUENCE, SET, INTEGER, OCTET STRING, BOOLEAN, ENUMERATED, NULL,
    // OBJECT IDENTIFIER, BIT STRING.
    var set: []const u8 = &[_]u8{ 0x30, 0x31, 0x02, 0x04, 0x01, 0x0a, 0x05, 0x06, 0x03 };
    // The high tag number form, and the application and context classes that
    // carry a protocol's own types -- SNMP's Counter32 through Counter64 and
    // its three exception markers, and the PDU tags above them.
    set = set ++ &[_]u8{ 0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xdf, 0xff };
    set = set ++ &[_]u8{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x46, 0x80, 0x81, 0x82 };
    set = set ++ &[_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    // The base-128 continuation bit, which is what a sub-identifier and a
    // high tag number are made of, and the non-minimal leading value both
    // must reject.
    set = set ++ &[_]u8{ 0x80, 0x81, 0x8f, 0x90, 0x2b, 0x28, 0x50, 0x4f };
    // Lengths: nothing, one, the short form's last value, the long form's
    // first, and the ones that claim more than anybody has.
    set = set ++ &[_]u8{ 0x00, 0x01, 0x7f, 0x81, 0x82, 0x84, 0x88, 0xff };
    break :blk set;
};

fn interestingFor(target: targets.Target) []const u8 {
    return switch (target.flavor) {
        .text => interesting_text,
        .binary => interesting_binary,
    };
}

/// Print a failing input and write it where it can be fed back.
fn report(io: std.Io, dir: []const u8, target: []const u8, input: []const u8) !void {
    show(input);

    var name: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&name, "{s}/{s}-{x:0>16}.bin", .{
        dir,
        target,
        std.hash.Wyhash.hash(0, input),
    }) catch return;

    std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    var file = std.Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
        std.debug.print("(could not write {s}: {t})\n", .{ path, err });
        return;
    };
    defer file.close(io);
    file.writeStreamingAll(io, input) catch {};
    std.debug.print(
        "written to {s}, and `--input {s} --target {s}` runs it again\n",
        .{ path, path, target },
    );
}

/// The input, in hex, and then what a target actually reads out of it.
///
/// The second half earns its lines: an input is a stream of answers rather
/// than a file, so the bytes alone do not say what the parser was given, and
/// that is the first thing anybody wants to see.
fn show(input: []const u8) void {
    std.debug.print("input, {d} bytes:\n ", .{input.len});
    for (input, 0..) |b, i| {
        if (i != 0 and i % 32 == 0) std.debug.print("\n ", .{});
        std.debug.print(" {x:0>2}", .{b});
    }
    std.debug.print("\n", .{});

    var smith: Smith = .{ .in = input };
    var buffer: [4096]u8 = undefined;
    const text = buffer[0..smith.slice(&buffer)];
    std.debug.print("which reads as {d} bytes:\n", .{text.len});
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        std.debug.print("  |{f}\n", .{std.ascii.hexEscape(line, .lower)});
    }
}

/// Watch for an iteration that never ends.
fn watchdog(io: std.Io) void {
    while (true) {
        std.Io.sleep(io, .fromMilliseconds(500), .awake) catch return;
        const started = watch.started_ms.load(.acquire);
        if (started == 0) continue;
        const elapsed = nowMs(io) - started;
        if (elapsed < @as(i64, watch.timeout_s) * 1000) continue;

        std.debug.print(
            "\n{s}: no answer after {d} seconds, which is a hang\n",
            .{ watch.target, @divTrunc(elapsed, 1000) },
        );
        show(watch.input);
        var name: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&name, "{s}/{s}-hang-{x:0>16}.bin", .{
            watch.dir,
            watch.target,
            std.hash.Wyhash.hash(0, watch.input),
        }) catch std.process.exit(3);
        std.Io.Dir.cwd().createDirPath(io, watch.dir) catch {};
        if (std.Io.Dir.cwd().createFile(io, path, .{})) |file| {
            defer file.close(io);
            file.writeStreamingAll(io, watch.input) catch {};
            std.debug.print("written to {s}\n", .{path});
        } else |_| {}
        std.process.exit(3);
    }
}
