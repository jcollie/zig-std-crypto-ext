// SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! RSA signing, which `std.crypto` leaves out.
//!
//! Zig 0.16 does ship RSA, but only half of it, and only as an implementation
//! detail of something else: `std.crypto.Certificate.rsa` has a `PublicKey`, a
//! PKCS#1 v1.5 verifier and a PSS verifier, because that is what checking a
//! certificate chain needs. There is no private key type anywhere in the
//! standard library and nothing that can produce a signature. A protocol that
//! has to *sign* -- DKIM, JWT, a CSR, anything with an RSA key at the bottom
//! of it -- has nowhere to go.
//!
//! This is that missing half, plus the key parsing that has to come with it,
//! because a private key arrives as PKCS#1 or PKCS#8 DER inside PEM and none
//! of those are things `std` will decode for you either.
//!
//! ```zig
//! const rsa = @import("std_crypto_ext").rsa;
//! const Sha256 = std.crypto.hash.sha2.Sha256;
//!
//! var der_buf: [rsa.max_secret_key_der]u8 = undefined;
//! const sk = try rsa.SecretKey.fromPem(&der_buf, pem_text);
//!
//! var sig: [rsa.max_modulus_len]u8 = undefined;
//! const signature = try rsa.pkcs1v1_5.Signer(Sha256).sign(&sig, message, sk);
//! ```
//!
//! ## What it promises
//!
//! The private exponentiation goes through `std.crypto.ff`'s
//! `powWithEncodedExponent`, which is constant time with respect to both the
//! base and the exponent -- the same Montgomery arithmetic the standard
//! library verifies certificate signatures with. That is the defence that
//! matters against a remote timing attack, and it is why this does not
//! reimplement bignum arithmetic of its own.
//!
//! The Chinese Remainder Theorem is used when the key carries the
//! parameters for it, which every PKCS#1 and PKCS#8 key does: two
//! exponentiations modulo numbers half the width of `n` instead of one
//! modulo `n`, which is a quarter of the work because the cost goes as the
//! cube of the size. Measured on a 2026 x86-64 laptop, in ReleaseFast:
//!
//! | key      | sign    | sign, whole `d` | verify  |
//! |----------|---------|-----------------|---------|
//! | 2048-bit | 3.9 ms  | 13 ms           | 0.20 ms |
//! | 4096-bit | 27 ms   | 101 ms          | 0.55 ms |
//!
//! Both columns include the check described below. A key built from `n`, `d`
//! and `e` alone takes the second.
//!
//! **Every signature is verified before it is released**, and with the CRT
//! that is not belt and braces but what makes it safe to use. A signer that
//! gets one of its two halves wrong -- through a fault induced in the
//! hardware, or a key whose components disagree -- emits a signature from
//! which `gcd(s^e - m, n)` is one of the primes. That is the Bellcore
//! attack, and it recovers the whole private key from a *single* bad
//! signature. Recomputing `s^e mod n` with the public exponent costs about a
//! fiftieth of what the signature cost, and a mismatch returns
//! `error.SigningFailed` with the output buffer wiped.
//!
//! What it does **not** do is blind the input. Base blinding -- signing
//! `m * r^e` and dividing the result by `r` -- additionally defends against
//! side channels in the surrounding code, and it needs a modular inverse,
//! which `ff` exposes no way to compute. The CRT needs none, because the key
//! carries `qinv` already.
//!
//! **So: this is appropriate for signing with a key you hold on a machine you
//! trust. It is not hardened against an attacker who can induce faults in the
//! hardware, and it is not a replacement for an HSM.**
//!
//! ## Sizes
//!
//! The modulus ceiling is 4096 bits, which is `std.crypto.Certificate.rsa`'s
//! ceiling too, and deliberately the same one: the field arithmetic is sized
//! at compile time, so a key type that admitted more would cost every caller
//! the memory for a key nobody uses. RFC 8017 has no upper bound and RFC 3766
//! puts 4096 bits at about 140 bits of symmetric strength, which is past
//! anything else in the stack. Raising it is the one constant below.

const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
/// This library's `ff` and not `std.crypto.ff`, which is the same file with
/// two things put right: a secret exponent of exactly three bytes taking a
/// branchy path, and `pow` sizing its exponent buffer by the type's width
/// rather than the modulus's. Neither is reachable from the code here --
/// which is why they were only found by measuring something else -- but a
/// library that carries the fix should be the first to use it.
const ff = @import("ff.zig");
const testing = std.testing;

/// The largest modulus this implementation will accept, in bits.
///
/// The same ceiling `std.crypto.Certificate.rsa` uses, so that a public key
/// parsed here and one parsed from a certificate are the same field type.
pub const max_modulus_bits = 4096;

/// The largest modulus, and so the largest signature, in bytes.
pub const max_modulus_len = max_modulus_bits / 8;

/// The smallest modulus this implementation will accept, in bits.
///
/// 512-bit RSA was factored in 1999 and 768-bit in 2009, so this rejects only
/// what is already broken rather than what is merely unwise; `std` draws the
/// line in the same place and says so in the same tone. Anything new should be
/// at 2048 at the very least -- RFC 8301 requires it of DKIM signers.
pub const min_modulus_bits = 512;

const Modulus = ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;

/// Enough room for the DER of any secret key this module will accept.
///
/// A PKCS#1 `RSAPrivateKey` carries the modulus, two exponents, two primes,
/// two reduced exponents and a coefficient: five halves and two wholes of the
/// modulus, so about four times the modulus, plus tags and lengths. PKCS#8
/// wraps that in about another 40 bytes. Doubling the modulus length five
/// times over is comfortably clear of both: a 4096-bit PKCS#8 key is 2373
/// bytes of DER against the 2816 here.
///
/// It is sized for the DER and only the DER. `fromPem` decodes the base64
/// straight out of the PEM text into this buffer, so the buffer never has
/// to hold the base64 as well -- which is a third longer, and was how an
/// earlier version of `pemDecode` turned a 4096-bit key into
/// `error.BufferTooSmall` with a buffer of exactly this size.
pub const max_secret_key_der = 5 * max_modulus_len + 256;

/// What can go wrong reading a key out of bytes somebody else wrote.
pub const ParseError = error{
    /// The bytes are not well-formed DER, or not the structure expected.
    MalformedDer,
    /// Well-formed DER describing a key this module cannot use: a modulus
    /// outside `min_modulus_bits`...`max_modulus_bits`, an even modulus, an
    /// exponent that is not a usable one, or a component that is not less
    /// than the modulus.
    InvalidKey,
    /// A key algorithm other than `rsaEncryption`, or a PKCS#8 version this
    /// does not know.
    UnsupportedKeyType,
};

/// What can go wrong turning PEM text into DER.
pub const PemError = ParseError || error{
    /// No `-----BEGIN ...-----` and `-----END ...-----` pair was found, or
    /// they do not agree, or the label is not one this module knows.
    MalformedPem,
    /// The base64 between the markers is not valid base64.
    InvalidBase64,
    /// The decoded DER is larger than the buffer given.
    BufferTooSmall,
};

// -- DER ---------------------------------------------------------------------
//
// `std.crypto.Certificate.der` exists and is public, but everything it returns
// is shaped for certificates: its errors are named `CertificateFieldHas...`,
// which is a strange thing for a private key file to tell you about, and its
// `Element` model hands back indices into the original buffer rather than
// slices. What is needed here is small enough that a reader of its own is
// clearer than a translation layer.
//
// This is a *strict* DER reader and not a BER one. Definite lengths only, the
// shortest possible length encoding only, and INTEGERs in the minimal form.
// Being strict is free -- every key this will ever see was written by OpenSSL
// or something imitating it -- and it means malformed input is rejected at the
// door rather than somewhere further in.

const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_octet_string: u8 = 0x04;
const tag_null: u8 = 0x05;
const tag_oid: u8 = 0x06;
const tag_sequence: u8 = 0x30;

/// `1.2.840.113549.1.1.1`, PKCS#1's `rsaEncryption`, as its DER contents.
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

const Der = struct {
    buf: []const u8,
    i: usize = 0,

    fn atEnd(self: Der) bool {
        return self.i >= self.buf.len;
    }

    /// The contents of the next element, which must carry `tag`.
    fn take(self: *Der, tag: u8) ParseError![]const u8 {
        if (self.i >= self.buf.len) return error.MalformedDer;
        if (self.buf[self.i] != tag) return error.MalformedDer;
        self.i += 1;
        const len = try self.takeLength();
        if (self.buf.len - self.i < len) return error.MalformedDer;
        defer self.i += len;
        return self.buf[self.i..][0..len];
    }

    /// A whole element as a nested reader, for a SEQUENCE whose contents are
    /// then read in turn.
    fn takeSeq(self: *Der) ParseError!Der {
        return .{ .buf = try self.take(tag_sequence) };
    }

    fn takeLength(self: *Der) ParseError!usize {
        if (self.i >= self.buf.len) return error.MalformedDer;
        const first = self.buf[self.i];
        self.i += 1;
        if (first < 0x80) return first;
        const n = first & 0x7f;
        // 0x80 is BER's indefinite length, which DER forbids; and a length
        // needing more bytes than a `usize` has is not a key, it is an attack
        // on this parser.
        if (n == 0 or n > @sizeOf(usize)) return error.MalformedDer;
        if (self.buf.len - self.i < n) return error.MalformedDer;
        const bytes = self.buf[self.i..][0..n];
        self.i += n;
        // DER requires the shortest encoding: no leading zero byte, and
        // nothing below 0x80 that could have been written in one byte.
        if (bytes[0] == 0) return error.MalformedDer;
        var len: usize = 0;
        for (bytes) |b| len = (len << 8) | b;
        if (len < 0x80) return error.MalformedDer;
        return len;
    }

    /// A non-negative INTEGER's value, with the sign byte removed.
    ///
    /// DER writes integers two's-complement and big-endian, so a value whose
    /// top bit is set gains a leading zero to keep it positive. Every RSA
    /// component is positive, so that byte is noise here and is stripped --
    /// but only where it is legitimately there, since a leading zero in front
    /// of a byte that did not need one is a non-minimal encoding.
    fn takeInteger(self: *Der) ParseError![]const u8 {
        const raw = try self.take(tag_integer);
        if (raw.len == 0) return error.MalformedDer;
        if (raw[0] & 0x80 != 0) return error.MalformedDer; // negative
        if (raw.len == 1) return raw; // possibly zero; the caller will reject it
        if (raw[0] == 0 and raw[1] & 0x80 == 0) return error.MalformedDer;
        return if (raw[0] == 0) raw[1..] else raw;
    }

    /// Checks for the `AlgorithmIdentifier` of an RSA key: the
    /// `rsaEncryption` OID, and the explicit NULL that PKCS#1 requires after
    /// it. Some writers omit the NULL, so it is accepted either way.
    fn takeRsaAlgorithmIdentifier(self: *Der) ParseError!void {
        var alg = try self.takeSeq();
        const oid = try alg.take(tag_oid);
        if (!std.mem.eql(u8, oid, &oid_rsa_encryption)) return error.UnsupportedKeyType;
        if (!alg.atEnd()) _ = try alg.take(tag_null);
        if (!alg.atEnd()) return error.MalformedDer;
    }
};

// -- keys --------------------------------------------------------------------

/// An RSA public key: a modulus and a public exponent.
pub const PublicKey = struct {
    /// The modulus, as the field it defines.
    n: Modulus,
    /// The public exponent, as an element of that field.
    e: Fe,

    /// A public key from its two components, each big-endian with any leading
    /// zeroes already removed or not -- both are accepted.
    ///
    /// The argument order is modulus first, which is the order they are
    /// written in every specification and in the DER.
    /// (`std.crypto.Certificate.rsa.PublicKey.fromBytes` takes them the other
    /// way round; this is the one place the two deliberately differ.)
    pub fn fromBytes(modulus: []const u8, exponent: []const u8) ParseError!PublicKey {
        const n = Modulus.fromBytes(modulus, .big) catch return error.InvalidKey;
        // Both bounds, and the upper one is not decoration. The field type
        // is sized in 63-bit limbs, so `Modulus.fromBytes` accepts up to 4158
        // bits without complaint, and everything downstream slices arrays of
        // `max_modulus_len` bytes by `modulusLength()`. A modulus between the
        // two ceilings would pass here and walk off the end of those.
        if (n.bits() < min_modulus_bits or n.bits() > max_modulus_bits) return error.InvalidKey;

        // An exponent above 2^32 is refused for the same reason `std` refuses
        // it: no real key has one, Windows' CryptoAPI cannot represent one,
        // and a large public exponent is purely a way to make a verifier do
        // work. It must also be odd and at least 3 -- an even exponent is not
        // coprime with a modulus that is a product of odd primes, and e = 1
        // would make the signature the message.
        if (exponent.len > 4) return error.InvalidKey;
        const e = Fe.fromBytes(n, exponent, .big) catch return error.InvalidKey;
        if (!e.isOdd()) return error.InvalidKey;
        const e_value = e.toPrimitive(u32) catch return error.InvalidKey;
        if (e_value < 3) return error.InvalidKey;

        return .{ .n = n, .e = e };
    }

    /// A public key from a PKCS#1 `RSAPublicKey`: `SEQUENCE { modulus
    /// INTEGER, publicExponent INTEGER }`.
    pub fn fromPkcs1Der(bytes: []const u8) ParseError!PublicKey {
        var outer: Der = .{ .buf = bytes };
        var seq = try outer.takeSeq();
        const modulus = try seq.takeInteger();
        const exponent = try seq.takeInteger();
        if (!seq.atEnd() or !outer.atEnd()) return error.MalformedDer;
        return fromBytes(modulus, exponent);
    }

    /// A public key from an X.509 `SubjectPublicKeyInfo`, which is what
    /// `-----BEGIN PUBLIC KEY-----` holds and what most protocols carry.
    pub fn fromSpkiDer(bytes: []const u8) ParseError!PublicKey {
        var outer: Der = .{ .buf = bytes };
        var seq = try outer.takeSeq();
        try seq.takeRsaAlgorithmIdentifier();
        const bit_string = try seq.take(tag_bit_string);
        if (!seq.atEnd() or !outer.atEnd()) return error.MalformedDer;
        // A BIT STRING's first content byte counts the unused bits in its last
        // byte. Anything DER-wrapped in one is a whole number of bytes.
        if (bit_string.len < 1 or bit_string[0] != 0) return error.MalformedDer;
        return fromPkcs1Der(bit_string[1..]);
    }

    /// A public key from DER in either shape, chosen by looking at it.
    ///
    /// The two are told apart by what follows the outer SEQUENCE: an
    /// `RSAPublicKey` starts with an INTEGER, a `SubjectPublicKeyInfo` with
    /// the SEQUENCE of the algorithm identifier. This exists because formats
    /// that carry an RSA public key as bytes are inconsistent about which one
    /// they mean -- DKIM's DNS records are specified as
    /// `SubjectPublicKeyInfo` but bare `RSAPublicKey` is found in the wild --
    /// so a reader usually has to accept both.
    pub fn fromDer(bytes: []const u8) ParseError!PublicKey {
        var probe: Der = .{ .buf = bytes };
        const seq = try probe.takeSeq();
        if (seq.buf.len == 0) return error.MalformedDer;
        return switch (seq.buf[0]) {
            tag_integer => fromPkcs1Der(bytes),
            tag_sequence => fromSpkiDer(bytes),
            else => error.MalformedDer,
        };
    }

    /// A public key from PEM text, in either DER shape.
    ///
    /// `der_buf` receives the decoded DER and must outlive nothing: a
    /// `PublicKey` copies the values it needs, so the buffer may be reused as
    /// soon as this returns.
    pub fn fromPem(der_buf: []u8, text: []const u8) PemError!PublicKey {
        const der_bytes = try pemDecode(der_buf, text, &.{ "PUBLIC KEY", "RSA PUBLIC KEY" });
        return fromDer(der_bytes);
    }

    /// The modulus length in bytes, which is also the length of every
    /// signature made with the matching secret key.
    pub fn modulusLength(self: PublicKey) usize {
        return std.math.divCeil(usize, self.n.bits(), 8) catch unreachable;
    }
};

/// An RSA secret key.
///
/// Held by value, with the components copied in rather than pointed at, so
/// that the DER it was parsed from can be overwritten -- which a caller
/// holding a private key ought to be doing -- without invalidating the key.
/// It has no `deinit`, for the same reason `Des`'s contexts have none: there
/// is nothing to free. A caller who wants the private exponent gone when
/// finished zeroes the whole value, which is plain bytes and nothing else:
///
/// ```zig
/// defer std.crypto.secureZero(u8, std.mem.asBytes(&secret_key));
/// ```
///
/// The Chinese Remainder Theorem parameters are deliberately not kept: this
/// implementation does not use them, and a secret not stored is a secret not
/// leaked. See the note at the top of the file about what that costs.
pub const SecretKey = struct {
    /// The modulus, as the field it defines.
    n: Modulus,
    /// The private exponent, as an element of that field.
    d: Fe,
    /// The public exponent, kept so that `publicKey` can hand back the other
    /// half of the pair without the caller having to carry it separately.
    e: Fe,
    /// The Chinese remainder components, when the key carried them.
    ///
    /// Null for a key built from `n`, `d` and `e` alone, which then signs the
    /// slow way. Every PKCS#1 and PKCS#8 key has them.
    crt: ?Crt = null,

    /// What RFC 8017 §3.2 calls the second representation of a private key:
    /// the two primes and the three values derived from them, which turn one
    /// exponentiation modulo `n` into two modulo numbers half its size.
    ///
    /// Held as the fields they define and the elements of those fields,
    /// because that is what the arithmetic wants; the bytes they were parsed
    /// from are not kept.
    pub const Crt = struct {
        /// The primes, as the fields they define.
        p: Modulus,
        q: Modulus,
        /// `d mod (p-1)` and `d mod (q-1)`.
        dp: Fe,
        dq: Fe,
        /// `q^-1 mod p`, which is what makes the recombination a
        /// multiplication rather than an inversion -- the reason this needs
        /// nothing `std.crypto.ff` does not have.
        qinv: Fe,
    };

    /// A secret key from a PKCS#1 `RSAPrivateKey`, which is what
    /// `-----BEGIN RSA PRIVATE KEY-----` holds.
    ///
    /// The CRT components are kept, which is what makes signing with this
    /// key four times cheaper than signing with one built from `n`, `d` and
    /// `e` alone.
    pub fn fromPkcs1Der(bytes: []const u8) ParseError!SecretKey {
        var outer: Der = .{ .buf = bytes };
        var seq = try outer.takeSeq();

        // Version: 0 for a two-prime key, 1 for a multi-prime one. Multi-prime
        // keys are rejected rather than ignored -- the extra primes change
        // nothing about n, d and e, so this *could* sign with one, but a key
        // shape this has never been tested against is not one to guess at.
        const version = try seq.takeInteger();
        if (version.len != 1 or version[0] != 0) return error.UnsupportedKeyType;

        const modulus = try seq.takeInteger();
        const public_exponent = try seq.takeInteger();
        const private_exponent = try seq.takeInteger();
        // prime1, prime2, exponent1, exponent2, coefficient -- the second
        // representation of §3.2, which is what makes signing four times
        // cheaper. A truncated key fails here rather than being used as if
        // whole, which is why they were read even when they were dropped.
        const prime1 = try seq.takeInteger();
        const prime2 = try seq.takeInteger();
        const exponent1 = try seq.takeInteger();
        const exponent2 = try seq.takeInteger();
        const coefficient = try seq.takeInteger();
        // And nothing after them. A version-0 key has exactly nine fields,
        // so anything more is either a multi-prime key that lied about its
        // version or bytes that are not part of the key at all.
        if (!seq.atEnd() or !outer.atEnd()) return error.MalformedDer;

        var key = try fromComponents(modulus, public_exponent, private_exponent);
        key.crt = try crtFromComponents(prime1, prime2, exponent1, exponent2, coefficient);
        return key;
    }

    /// The second representation, from the five integers that carry it.
    ///
    /// Everything here is checked only for being a usable field element:
    /// that the primes really are the factors of `n`, and that the exponents
    /// really are `d` reduced, is not checked at parse time because it does
    /// not have to be. Every signature made with them is verified before it
    /// is released, and a key whose components disagree with each other
    /// fails that check on its first use -- which is also the defence
    /// against a fault, and is therefore machinery this has to have anyway.
    fn crtFromComponents(
        prime1: []const u8,
        prime2: []const u8,
        exponent1: []const u8,
        exponent2: []const u8,
        coefficient: []const u8,
    ) ParseError!Crt {
        const p = Modulus.fromBytes(prime1, .big) catch return error.InvalidKey;
        const q = Modulus.fromBytes(prime2, .big) catch return error.InvalidKey;
        // A prime of one limb is not a key, and a prime wider than the
        // modulus ceiling cannot be a factor of a modulus under it.
        if (p.bits() < 2 or q.bits() < 2) return error.InvalidKey;
        if (p.bits() > max_modulus_bits or q.bits() > max_modulus_bits) return error.InvalidKey;

        // `Fe.fromBytes` rejects anything not already reduced, which is the
        // check that each exponent is below the prime it belongs to and that
        // the coefficient is below `p`.
        const dp = Fe.fromBytes(p, exponent1, .big) catch return error.InvalidKey;
        const dq = Fe.fromBytes(q, exponent2, .big) catch return error.InvalidKey;
        const qinv = Fe.fromBytes(p, coefficient, .big) catch return error.InvalidKey;
        if (dp.isZero() or dq.isZero() or qinv.isZero()) return error.InvalidKey;

        return .{ .p = p, .q = q, .dp = dp, .dq = dq, .qinv = qinv };
    }

    /// A secret key from a PKCS#8 `PrivateKeyInfo`, which is what
    /// `-----BEGIN PRIVATE KEY-----` holds and what OpenSSL has written by
    /// default since 3.0.
    pub fn fromPkcs8Der(bytes: []const u8) ParseError!SecretKey {
        var outer: Der = .{ .buf = bytes };
        var seq = try outer.takeSeq();

        const version = try seq.takeInteger();
        if (version.len != 1 or version[0] != 0) return error.UnsupportedKeyType;

        try seq.takeRsaAlgorithmIdentifier();
        const inner = try seq.take(tag_octet_string);
        // The `PrivateKeyInfo` may go on -- optional attributes, and in
        // version 1 the public key -- so the inner sequence is not required
        // to end here. The outer one is: bytes after it belong to nothing.
        if (!outer.atEnd()) return error.MalformedDer;
        return fromPkcs1Der(inner);
    }

    /// A secret key from DER in either shape, chosen by looking at it.
    ///
    /// A PKCS#1 `RSAPrivateKey` and a PKCS#8 `PrivateKeyInfo` both begin
    /// SEQUENCE, INTEGER 0, so the version does not separate them. What does
    /// is what comes next: PKCS#1 has the modulus, another INTEGER, where
    /// PKCS#8 has the algorithm identifier, a SEQUENCE.
    pub fn fromDer(bytes: []const u8) ParseError!SecretKey {
        var probe: Der = .{ .buf = bytes };
        var seq = try probe.takeSeq();
        _ = try seq.takeInteger();
        if (seq.atEnd()) return error.MalformedDer;
        return switch (seq.buf[seq.i]) {
            tag_integer => fromPkcs1Der(bytes),
            tag_sequence => fromPkcs8Der(bytes),
            else => error.MalformedDer,
        };
    }

    /// A secret key from PEM text, in either DER shape.
    ///
    /// `der_buf` must be at least as long as the DER inside the PEM;
    /// `max_secret_key_der` is always enough. It holds private key material
    /// on return and is worth wiping.
    pub fn fromPem(der_buf: []u8, text: []const u8) PemError!SecretKey {
        const der_bytes = try pemDecode(der_buf, text, &.{ "PRIVATE KEY", "RSA PRIVATE KEY" });
        return fromDer(der_bytes);
    }

    fn fromComponents(
        modulus: []const u8,
        public_exponent: []const u8,
        private_exponent: []const u8,
    ) ParseError!SecretKey {
        const public = try PublicKey.fromBytes(modulus, public_exponent);
        // `Fe.fromBytes` rejects anything not already reduced, so this is also
        // the check that d < n, which every valid key satisfies and a
        // corrupted one need not.
        const d = Fe.fromBytes(public.n, private_exponent, .big) catch return error.InvalidKey;
        if (d.isZero()) return error.InvalidKey;
        return .{ .n = public.n, .d = d, .e = public.e };
    }

    /// `m^d mod n`, by whichever route this key can take.
    ///
    /// With the second representation, two exponentiations modulo numbers
    /// half the width of `n` instead of one modulo `n`. The cost of a
    /// modular exponentiation goes as the cube of the operand size -- each
    /// multiplication is quadratic and there are linearly many -- so halving
    /// the width and doing it twice is a quarter of the work.
    ///
    /// §5.1.2 of RFC 8017 in the form that needs no inversion, because the
    /// key already carries `qinv`:
    ///
    ///     m1 = c^dp mod p
    ///     m2 = c^dq mod q
    ///     h  = qinv * (m1 - m2) mod p
    ///     m  = m2 + q*h
    ///
    /// The last line is arithmetic in `n` rather than plain integers: the
    /// true value of `m2 + q*h` is below `n`, so reducing it changes nothing
    /// and the field's `mul` and `add` can do the work.
    ///
    /// Constant time with respect to everything secret. The exponents go in
    /// serialized to the full width of their primes, for the same reason `d`
    /// does below; `reduce`, `mul`, `sub` and `add` are constant time for a
    /// given modulus; and the moduli here are `p` and `q`, whose *widths*
    /// are public -- half the key size -- even though their values are not.
    fn exponentiate(self: SecretKey, m: Fe) Fe {
        const crt = self.crt orelse return self.exponentiateWhole(m);

        const p_len = std.math.divCeil(usize, crt.p.bits(), 8) catch unreachable;
        const q_len = std.math.divCeil(usize, crt.q.bits(), 8) catch unreachable;

        var dp_bytes: [max_modulus_len]u8 = undefined;
        var dq_bytes: [max_modulus_len]u8 = undefined;
        defer crypto.secureZero(u8, dp_bytes[0..p_len]);
        defer crypto.secureZero(u8, dq_bytes[0..q_len]);
        crt.dp.toBytes(dp_bytes[0..p_len], .big) catch unreachable;
        crt.dq.toBytes(dq_bytes[0..q_len], .big) catch unreachable;

        // The message taken into each prime's field. `reduce` is what makes
        // this possible at all: `Fe.fromBytes` would refuse, since `m` is
        // larger than either prime.
        const m1 = crt.p.powWithEncodedExponent(
            crt.p.reduce(m.v),
            dp_bytes[0..p_len],
            .big,
        ) catch unreachable;
        const m2 = crt.q.powWithEncodedExponent(
            crt.q.reduce(m.v),
            dq_bytes[0..q_len],
            .big,
        ) catch unreachable;

        // h = qinv * (m1 - m2) mod p. `m2` belongs to q's field and has to
        // be carried into p's before the subtraction; `sub` is modular, so
        // the case where m2 > m1 needs no separate handling.
        const m2_in_p = crt.p.reduce(m2.v);
        const h = crt.p.mul(crt.p.sub(m1, m2_in_p), crt.qinv);

        // m = m2 + q*h, in n's field.
        //
        // Through bytes rather than through `reduce`, which only goes the
        // other way: it takes a value wider than the modulus and brings it
        // down, and handed a narrower one it runs off the bottom of its own
        // index. What is needed here is the opposite -- three values already
        // smaller than `n`, carried into its field unchanged -- and
        // `Fe.fromBytes` is that, since it accepts exactly what is already
        // reduced.
        const k = self.modulusLength();
        var wide: [max_modulus_len]u8 = @splat(0);
        crt.q.toBytes(wide[0..k], .big) catch unreachable;
        const q_in_n = Fe.fromBytes(self.n, wide[0..k], .big) catch unreachable;
        h.toBytes(wide[0..k], .big) catch unreachable;
        const h_in_n = Fe.fromBytes(self.n, wide[0..k], .big) catch unreachable;
        m2.toBytes(wide[0..k], .big) catch unreachable;
        const m2_in_n = Fe.fromBytes(self.n, wide[0..k], .big) catch unreachable;

        return self.n.add(m2_in_n, self.n.mul(q_in_n, h_in_n));
    }

    /// `m^d mod n` the direct way, for a key with no second representation.
    fn exponentiateWhole(self: SecretKey, m: Fe) Fe {
        const k = self.modulusLength();
        // `powWithEncodedExponent` is the constant-time one; `powPublic`
        // next to it is not, and using it here would leak `d` through
        // timing.
        //
        // The exponent is written into exactly `k` bytes rather than the
        // field element's full width. d < n, so it always fits, and the
        // exponentiation walks every bit it is given: at the full 4096-bit
        // width a 2048-bit key would pay for 2048 leading zero bits it does
        // not have.
        //
        // Exactly `k`, and not any shorter. `std.crypto.ff` decides between
        // its constant-time table walk and a short-exponent loop with a
        // data-dependent branch by looking at the exponent's *length*, and
        // upstream's test for that has a precedence slip which sends a
        // three-byte secret exponent down the branchy path. `src/ff.zig`
        // fixes it; `k` being at least 64 here is what made it unreachable
        // before that, and an optimisation that serialized `d` at its
        // minimal length would not have had that guarantee.
        var d_bytes: [max_modulus_len]u8 = undefined;
        defer crypto.secureZero(u8, d_bytes[0..k]);
        self.d.toBytes(d_bytes[0..k], .big) catch unreachable;
        return self.n.powWithEncodedExponent(m, d_bytes[0..k], .big) catch unreachable;
    }

    /// The matching public key.
    pub fn publicKey(self: SecretKey) PublicKey {
        return .{ .n = self.n, .e = self.e };
    }

    /// The modulus length in bytes, which is also the length of every
    /// signature this key makes.
    pub fn modulusLength(self: SecretKey) usize {
        return std.math.divCeil(usize, self.n.bits(), 8) catch unreachable;
    }
};

// -- PEM ---------------------------------------------------------------------

/// Decodes the base64 body of a PEM block into `out`, returning the DER.
///
/// `labels` is the set of labels accepted after `BEGIN`; the `END` marker must
/// carry the same one. Anything before the `BEGIN` line is ignored, which is
/// what lets this read a file OpenSSL has written a human-readable dump of the
/// key into above the block.
fn pemDecode(out: []u8, text: []const u8, labels: []const []const u8) PemError![]u8 {
    const begin_prefix = "-----BEGIN ";
    const end_prefix = "-----END ";
    const marker_suffix = "-----";

    const begin = std.mem.indexOf(u8, text, begin_prefix) orelse return error.MalformedPem;
    const label_start = begin + begin_prefix.len;
    const label_end = std.mem.indexOfPos(u8, text, label_start, marker_suffix) orelse
        return error.MalformedPem;
    const label = text[label_start..label_end];

    for (labels) |candidate| {
        if (std.mem.eql(u8, label, candidate)) break;
    } else return error.MalformedPem;

    const body_start = label_end + marker_suffix.len;
    const end = std.mem.indexOfPos(u8, text, body_start, end_prefix) orelse
        return error.MalformedPem;
    // The END marker has to name the same thing the BEGIN marker did, and
    // then close, otherwise this is two overlapping blocks rather than one --
    // or a line that merely begins the way an END line does.
    const end_marker = end + end_prefix.len;
    if (end_marker + label.len + marker_suffix.len > text.len) return error.MalformedPem;
    if (!std.mem.eql(u8, text[end_marker..][0..label.len], label)) return error.MalformedPem;
    if (!std.mem.eql(u8, text[end_marker + label.len ..][0..marker_suffix.len], marker_suffix)) {
        return error.MalformedPem;
    }

    // The base64 is wrapped at 64 columns and the line endings may be CRLF,
    // since a key is as likely to have come through a mail message as off a
    // disk. The decoder is told to step over both rather than the text being
    // repacked first, and that is not a shortcut: repacking the base64 into
    // `out` before decoding it there means `out` has to hold the base64, a
    // third longer than the DER, and a buffer sized for the DER -- which is
    // what `max_secret_key_der` promises to be -- is then too small for a
    // 4096-bit key. Decoding straight from the text also means nothing is
    // ever decoded over itself.
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const der_len = decoder.decode(out, text[body_start..end]) catch |err| switch (err) {
        error.NoSpaceLeft => return error.BufferTooSmall,
        error.InvalidCharacter, error.InvalidPadding => return error.InvalidBase64,
    };
    return out[0..der_len];
}

// -- PKCS#1 v1.5 signatures --------------------------------------------------

/// RFC 8017 §8.2, RSASSA-PKCS1-v1_5.
///
/// The padding scheme every RSA signature in the wild uses that is not PSS:
/// TLS certificates, JWS `RS256`, DKIM, S/MIME. It is deterministic, which is
/// the property that makes a test vector possible, and its security proof is
/// weaker than PSS's -- but a protocol rarely gets to choose, and these all
/// specify it.
pub const pkcs1v1_5 = struct {
    /// What can go wrong producing a signature.
    pub const SignError = error{
        /// The output buffer is shorter than the modulus.
        BufferTooSmall,
        /// The modulus is too short to hold this hash's padded encoding: RFC
        /// 8017 requires at least 11 bytes of padding, so SHA-256 needs a
        /// 62-byte modulus and SHA-512 a 94-byte one. Any real key clears
        /// this; a 512-bit modulus with SHA-512 does not.
        ModulusTooShort,
        /// The signature this key produced did not verify against the
        /// message it was made over, so it was not released.
        ///
        /// Not reachable by ordinary means: it says that the arithmetic
        /// produced the wrong answer, which is either a key whose components
        /// contradict each other or a fault in the machine. It exists
        /// because the alternative to noticing is handing out a signature
        /// that reveals the private key -- see the note where it is
        /// returned.
        SigningFailed,
    };

    /// What can go wrong checking one.
    pub const VerifyError = error{
        /// The signature is not the length of the modulus, or is not less
        /// than it as a number.
        InvalidSignature,
        /// As `SignError.ModulusTooShort`.
        ModulusTooShort,
    };

    /// The signer and verifier for one hash function.
    ///
    /// `Hash` must be one of the five RFC 8017 assigns a DigestInfo prefix:
    /// SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512. Anything else is a
    /// compile error, because there is no way to encode it.
    pub fn Signer(comptime Hash: type) type {
        return struct {
            /// The DigestInfo prefix for this hash: the DER of `SEQUENCE {
            /// AlgorithmIdentifier, OCTET STRING }` up to but not including
            /// the digest itself. RFC 8017 §9.2 note 1 lists them, and they
            /// are constants precisely so that nobody has to build ASN.1 at
            /// signing time.
            pub const digest_info_prefix: []const u8 = switch (Hash) {
                crypto.hash.Sha1 => &.{
                    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
                },
                crypto.hash.sha2.Sha224 => &.{
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                    0x00, 0x04, 0x1c,
                },
                crypto.hash.sha2.Sha256 => &.{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                    0x00, 0x04, 0x20,
                },
                crypto.hash.sha2.Sha384 => &.{
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                    0x00, 0x04, 0x30,
                },
                crypto.hash.sha2.Sha512 => &.{
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                    0x00, 0x04, 0x40,
                },
                else => @compileError("RFC 8017 assigns no DigestInfo prefix to " ++
                    @typeName(Hash) ++ "; PKCS#1 v1.5 cannot encode it"),
            };

            /// The length of the DigestInfo: the prefix and the digest.
            pub const digest_info_len = digest_info_prefix.len + Hash.digest_length;

            /// Signs `msg`, writing the signature to the front of `out` and
            /// returning it. The signature is exactly as long as the modulus.
            pub fn sign(out: []u8, msg: []const u8, secret_key: SecretKey) SignError![]u8 {
                return signConcat(out, &.{msg}, secret_key);
            }

            /// As `sign`, over the concatenation of `parts` without joining
            /// them in memory first.
            pub fn signConcat(out: []u8, parts: []const []const u8, secret_key: SecretKey) SignError![]u8 {
                var digest: [Hash.digest_length]u8 = undefined;
                var hasher: Hash = .init(.{});
                for (parts) |part| hasher.update(part);
                hasher.final(&digest);
                return signDigest(out, digest, secret_key);
            }

            /// As `sign`, given the digest rather than the message.
            ///
            /// This is the entry point for a protocol that hashes something
            /// other than a contiguous message -- DKIM hashes a rewritten
            /// version of the headers that never exists as bytes anywhere --
            /// and for one that gets the digest from elsewhere entirely.
            pub fn signDigest(
                out: []u8,
                digest: [Hash.digest_length]u8,
                secret_key: SecretKey,
            ) SignError![]u8 {
                const k = secret_key.modulusLength();
                if (out.len < k) return error.BufferTooSmall;
                const em = out[0..k];
                try encode(em, digest);

                const m = Fe.fromBytes(secret_key.n, em, .big) catch unreachable;
                const sig = secret_key.exponentiate(m);

                // Every signature is checked before it is released, and with
                // the second representation that is not belt and braces but
                // the thing that makes it safe to use at all.
                //
                // A CRT signer that gets one of its two halves wrong --
                // through a fault induced in the hardware, a cosmic ray, or
                // a key whose components disagree -- emits a signature from
                // which `gcd(s^e - m, n)` is one of the primes. That is the
                // Bellcore attack, and it recovers the entire private key
                // from a *single* bad signature, so the faulty output must
                // never leave this function. Recomputing `s^e mod n` with
                // the public exponent costs about a fiftieth of what the
                // signature cost and closes it.
                //
                // `powPublic` is the right one here: `e` is public, and the
                // value being exponentiated is the signature, which is about
                // to be handed to the caller.
                const check = secret_key.n.powPublic(sig, secret_key.e) catch unreachable;
                // Both buffers zeroed in full and only their first `k` bytes
                // written, so the comparison is over whole arrays -- the same
                // shape the verifier next door uses, and for the same reason.
                var check_bytes: [max_modulus_len]u8 = @splat(0);
                var encoded: [max_modulus_len]u8 = @splat(0);
                check.toBytes(check_bytes[0..k], .big) catch unreachable;
                @memcpy(encoded[0..k], em);
                if (!crypto.timing_safe.eql([max_modulus_len]u8, check_bytes, encoded)) {
                    // The buffer holds a half-made signature, and a caller
                    // that ignored the error would otherwise release it.
                    crypto.secureZero(u8, em);
                    return error.SigningFailed;
                }

                sig.toBytes(em, .big) catch unreachable;
                return em;
            }

            /// Checks `sig` against `msg`. Returns without error only if the
            /// signature is valid.
            pub fn verify(sig: []const u8, msg: []const u8, public_key: PublicKey) VerifyError!void {
                return verifyConcat(sig, &.{msg}, public_key);
            }

            /// As `verify`, over the concatenation of `parts`.
            pub fn verifyConcat(
                sig: []const u8,
                parts: []const []const u8,
                public_key: PublicKey,
            ) VerifyError!void {
                var digest: [Hash.digest_length]u8 = undefined;
                var hasher: Hash = .init(.{});
                for (parts) |part| hasher.update(part);
                hasher.final(&digest);
                return verifyDigest(sig, digest, public_key);
            }

            /// As `verify`, given the digest rather than the message.
            pub fn verifyDigest(
                sig: []const u8,
                digest: [Hash.digest_length]u8,
                public_key: PublicKey,
            ) VerifyError!void {
                const k = public_key.modulusLength();
                if (sig.len != k) return error.InvalidSignature;

                // Both buffers are zeroed in full and only their first `k`
                // bytes written, so that the comparison below can be over the
                // whole fixed-size array -- comparing `undefined` tail bytes
                // would be a real bug and not merely an untidy one.
                var expected: [max_modulus_len]u8 = @splat(0);
                encode(expected[0..k], digest) catch |err| switch (err) {
                    error.ModulusTooShort => return error.ModulusTooShort,
                    error.BufferTooSmall => unreachable,
                };

                // A signature is only valid if it is already reduced; one that
                // is not is rejected rather than quietly reduced, which is
                // what makes a signature's encoding unique.
                const s = Fe.fromBytes(public_key.n, sig, .big) catch
                    return error.InvalidSignature;
                const m = public_key.n.powPublic(s, public_key.e) catch
                    return error.InvalidSignature;
                var actual: [max_modulus_len]u8 = @splat(0);
                m.toBytes(actual[0..k], .big) catch unreachable;

                // Nothing here is secret -- both sides are recoverable from
                // the signature and the public key -- but comparing in
                // constant time anyway costs nothing and means no future
                // reader has to work out whether it mattered.
                if (!crypto.timing_safe.eql([max_modulus_len]u8, expected, actual)) {
                    return error.InvalidSignature;
                }
            }

            /// EMSA-PKCS1-v1_5, RFC 8017 §9.2: fills `em` with
            /// `0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo`.
            /// Its own error set rather than `SignError`, which is wider than
            /// what padding a buffer can go wrong with and which the verifier
            /// also has to switch over.
            const EncodeError = error{ ModulusTooShort, BufferTooSmall };

            fn encode(em: []u8, digest: [Hash.digest_length]u8) EncodeError!void {
                // §9.2 step 3: at least eight 0xFF bytes, plus the two leading
                // bytes and the separator.
                if (em.len < digest_info_len + 11) return error.ModulusTooShort;
                em[0] = 0x00;
                em[1] = 0x01;
                const digest_info_start = em.len - digest_info_len;
                @memset(em[2 .. digest_info_start - 1], 0xff);
                em[digest_info_start - 1] = 0x00;
                @memcpy(em[digest_info_start..][0..digest_info_prefix.len], digest_info_prefix);
                @memcpy(em[em.len - digest.len ..], &digest);
            }
        };
    }
};

// -- tests -------------------------------------------------------------------
//
// The key material and the signatures below were made by OpenSSL 3.6, which is
// the point of them: a signature this library produces has to be byte-for-byte
// what the rest of the world produces, and a signature the rest of the world
// produced has to verify here. PKCS#1 v1.5 is deterministic, so "byte for
// byte" is a test that can actually be written -- with PSS it could not be.
//
//     openssl genrsa -out key.pem 2048
//     openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem
//     openssl rsa -in key.pem -pubout -out pub.spki.pem
//     openssl dgst -sha256 -sign key.pem -out sig.bin msg.txt

const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha512 = crypto.hash.sha2.Sha512;

const test_message = "The quick brown fox jumps over the lazy dog";

/// A 2048-bit key as PKCS#8, which is what `openssl genrsa` writes now.
const key_2048_pkcs8 =
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCs/p69dd+ZfZo0\n" ++
    "w1QSBizDeh4BxqQFMO4mJ4MXnqIdLS5eD7bcCpyJQhaq+8yldafXey6ghjnNzML0\n" ++
    "rzK8ZNtoxOluzd+lksZfDxhAP3fThp8UpAk2r63T+U4OfZcFp/sMv/BAYQxQ4Cez\n" ++
    "4S3nwpFixzFAoy7gXgK7vhIgkb0SWAdzgcaK2ZNKZTWbt40ibHzptBWwXSTpRo13\n" ++
    "KxkDr9kxobItqNSDI0m1rfz5SYVo8SXHKFf6HUAese7HDFxW4F79FcYf9ldnhacp\n" ++
    "ixZJke47qo7EHAH9ANGOgbSt2pbxaSiHnPNLNE449Hk8D9aRRYMq78RxNtRu/nLV\n" ++
    "KlQT3EcrAgMBAAECggEAMoWDz3nyrK1ZUSpwTXk/LnFl/QfJk/iHvF3Ss52w44tz\n" ++
    "3KWDNjzlHVLPMu0phXLYax4+7kN08yznDLVzwEBGMZE8SQ9Xzs+QHmfWocDHWl+Y\n" ++
    "6trDFBT3U44d5S55Yf3+W+lcHTkacy4bejV7hhE1C193+1QM1xqteq3WNmvJh2bx\n" ++
    "TCtJ3aUrNXoWT+CvOv61RS7lOCL5Ck6c/IehWNkUHh7MKBBmaUu8/Hgyeer2zNHX\n" ++
    "lmr1jzYhlzeH9q5LvoTe6eQJdoeVYZlHYsPuR0RbZRPFwZ8k+s1Y49mEcAr0BfBv\n" ++
    "ufxs3MGzbdHRK6xlNemfBA/87H7OEhetM1SEB24WKQKBgQDrM+rf4UBrJ9RlMsSl\n" ++
    "nVVkdBwup3i95e0CcANEZT1A9XNGj/DegBkY16oZqHyCmQrzEAKC+hSkBPuC0Zmi\n" ++
    "Ju8Wscusb9IN6zG5V+9UegrtAnnsQ8CpZoKhpxEh48BpCNsDTzQyEt94pEFqqZDF\n" ++
    "u+tSSpWzZb/8WTt1nhLzagKF4wKBgQC8SoyszRHP72aHxKhqNZSbhTvY18nKHW4O\n" ++
    "oJxkjzh8QDw4XPQqEsRyhlK124aBg6TJXCddI+JRg5x/Y/kUC9V4D6YbBJ0tA3VL\n" ++
    "WKLn2sSENdm+QcY2+5EqE49cIu4nLpb9tdDPtAieSwRu+C678tBlzrB/xh9oXiBc\n" ++
    "A4oRSZQ8GQKBgQCKB+z2OF4yxKwsO7AWNZBQpKeJZbVBVLdUL+Jq+DMLdUCSj5Tf\n" ++
    "LzQLVT25UxzHFAPOA35F2XfVjisAafuMoua7XdpWt0UB8B49VHLbE8hnsYVV96kQ\n" ++
    "gV12evJd/igEPDMz7P6HyHWnelX9v8d7k74VjDnwj20tLjzr2LnsajFS2wKBgBQz\n" ++
    "T0pOqeWMAoz4TTUv0GSq85O8+tojNCZ/lqe3MdEqtws49bz5zHeY75CxH4oPjINJ\n" ++
    "zrNQYTxriUOlfxhmeJ1r2F83rIEiyNevh7KmJsUkXdrqhZBqhtVjydKRsMklV2+a\n" ++
    "rO9Lmk0ZMT2ShLkHQNJbTVY39DCnQIN+obZfFXcpAoGBAJX+Poe47rrYb94m+vQq\n" ++
    "0kJcv2VzUEXc7VmmeIANC7qJutVXqlf35s9tpZmTH3cD3JtzeY5ApYe7mYSFg9T5\n" ++
    "dRHeqV3rXtrFQVk/1eg8j/JW6yVBrQKha5Vvt1T2VN272rFd8wicj/+n8rf90na5\n" ++
    "RPc0GyFcbwtdATby/62XgFES\n" ++
    "-----END PRIVATE KEY-----\n";

/// The same key as PKCS#1, which is what it wrote before 3.0 and what
/// `-traditional` still writes.
const key_2048_pkcs1 =
    "-----BEGIN RSA PRIVATE KEY-----\n" ++
    "MIIEpAIBAAKCAQEArP6evXXfmX2aNMNUEgYsw3oeAcakBTDuJieDF56iHS0uXg+2\n" ++
    "3AqciUIWqvvMpXWn13suoIY5zczC9K8yvGTbaMTpbs3fpZLGXw8YQD9304afFKQJ\n" ++
    "Nq+t0/lODn2XBaf7DL/wQGEMUOAns+Et58KRYscxQKMu4F4Cu74SIJG9ElgHc4HG\n" ++
    "itmTSmU1m7eNImx86bQVsF0k6UaNdysZA6/ZMaGyLajUgyNJta38+UmFaPElxyhX\n" ++
    "+h1AHrHuxwxcVuBe/RXGH/ZXZ4WnKYsWSZHuO6qOxBwB/QDRjoG0rdqW8Wkoh5zz\n" ++
    "SzROOPR5PA/WkUWDKu/EcTbUbv5y1SpUE9xHKwIDAQABAoIBADKFg8958qytWVEq\n" ++
    "cE15Py5xZf0HyZP4h7xd0rOdsOOLc9ylgzY85R1SzzLtKYVy2GsePu5DdPMs5wy1\n" ++
    "c8BARjGRPEkPV87PkB5n1qHAx1pfmOrawxQU91OOHeUueWH9/lvpXB05GnMuG3o1\n" ++
    "e4YRNQtfd/tUDNcarXqt1jZryYdm8UwrSd2lKzV6Fk/grzr+tUUu5Tgi+QpOnPyH\n" ++
    "oVjZFB4ezCgQZmlLvPx4Mnnq9szR15Zq9Y82IZc3h/auS76E3unkCXaHlWGZR2LD\n" ++
    "7kdEW2UTxcGfJPrNWOPZhHAK9AXwb7n8bNzBs23R0SusZTXpnwQP/Ox+zhIXrTNU\n" ++
    "hAduFikCgYEA6zPq3+FAayfUZTLEpZ1VZHQcLqd4veXtAnADRGU9QPVzRo/w3oAZ\n" ++
    "GNeqGah8gpkK8xACgvoUpAT7gtGZoibvFrHLrG/SDesxuVfvVHoK7QJ57EPAqWaC\n" ++
    "oacRIePAaQjbA080MhLfeKRBaqmQxbvrUkqVs2W//Fk7dZ4S82oCheMCgYEAvEqM\n" ++
    "rM0Rz+9mh8SoajWUm4U72NfJyh1uDqCcZI84fEA8OFz0KhLEcoZStduGgYOkyVwn\n" ++
    "XSPiUYOcf2P5FAvVeA+mGwSdLQN1S1ii59rEhDXZvkHGNvuRKhOPXCLuJy6W/bXQ\n" ++
    "z7QInksEbvguu/LQZc6wf8YfaF4gXAOKEUmUPBkCgYEAigfs9jheMsSsLDuwFjWQ\n" ++
    "UKSniWW1QVS3VC/iavgzC3VAko+U3y80C1U9uVMcxxQDzgN+Rdl31Y4rAGn7jKLm\n" ++
    "u13aVrdFAfAePVRy2xPIZ7GFVfepEIFddnryXf4oBDwzM+z+h8h1p3pV/b/He5O+\n" ++
    "FYw58I9tLS4869i57GoxUtsCgYAUM09KTqnljAKM+E01L9BkqvOTvPraIzQmf5an\n" ++
    "tzHRKrcLOPW8+cx3mO+QsR+KD4yDSc6zUGE8a4lDpX8YZnida9hfN6yBIsjXr4ey\n" ++
    "pibFJF3a6oWQaobVY8nSkbDJJVdvmqzvS5pNGTE9koS5B0DSW01WN/Qwp0CDfqG2\n" ++
    "XxV3KQKBgQCV/j6HuO662G/eJvr0KtJCXL9lc1BF3O1ZpniADQu6ibrVV6pX9+bP\n" ++
    "baWZkx93A9ybc3mOQKWHu5mEhYPU+XUR3qld617axUFZP9XoPI/yVuslQa0CoWuV\n" ++
    "b7dU9lTdu9qxXfMInI//p/K3/dJ2uUT3NBshXG8LXQE28v+tl4BREg==\n" ++
    "-----END RSA PRIVATE KEY-----\n";

/// Its public half as a SubjectPublicKeyInfo.
const pub_2048_spki =
    "-----BEGIN PUBLIC KEY-----\n" ++
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArP6evXXfmX2aNMNUEgYs\n" ++
    "w3oeAcakBTDuJieDF56iHS0uXg+23AqciUIWqvvMpXWn13suoIY5zczC9K8yvGTb\n" ++
    "aMTpbs3fpZLGXw8YQD9304afFKQJNq+t0/lODn2XBaf7DL/wQGEMUOAns+Et58KR\n" ++
    "YscxQKMu4F4Cu74SIJG9ElgHc4HGitmTSmU1m7eNImx86bQVsF0k6UaNdysZA6/Z\n" ++
    "MaGyLajUgyNJta38+UmFaPElxyhX+h1AHrHuxwxcVuBe/RXGH/ZXZ4WnKYsWSZHu\n" ++
    "O6qOxBwB/QDRjoG0rdqW8Wkoh5zzSzROOPR5PA/WkUWDKu/EcTbUbv5y1SpUE9xH\n" ++
    "KwIDAQAB\n" ++
    "-----END PUBLIC KEY-----\n";

/// ...and as a bare PKCS#1 RSAPublicKey.
const pub_2048_pkcs1 =
    "-----BEGIN RSA PUBLIC KEY-----\n" ++
    "MIIBCgKCAQEArP6evXXfmX2aNMNUEgYsw3oeAcakBTDuJieDF56iHS0uXg+23Aqc\n" ++
    "iUIWqvvMpXWn13suoIY5zczC9K8yvGTbaMTpbs3fpZLGXw8YQD9304afFKQJNq+t\n" ++
    "0/lODn2XBaf7DL/wQGEMUOAns+Et58KRYscxQKMu4F4Cu74SIJG9ElgHc4HGitmT\n" ++
    "SmU1m7eNImx86bQVsF0k6UaNdysZA6/ZMaGyLajUgyNJta38+UmFaPElxyhX+h1A\n" ++
    "HrHuxwxcVuBe/RXGH/ZXZ4WnKYsWSZHuO6qOxBwB/QDRjoG0rdqW8Wkoh5zzSzRO\n" ++
    "OPR5PA/WkUWDKu/EcTbUbv5y1SpUE9xHKwIDAQAB\n" ++
    "-----END RSA PUBLIC KEY-----\n";

/// A 1024-bit key, because DKIM records in the wild are still full of them.
const key_1024_pkcs1 =
    "-----BEGIN RSA PRIVATE KEY-----\n" ++
    "MIICXAIBAAKBgQDLXDCjq1+k0E7u9D8Y5FMkvhhr/iNo4D2KgPnEYgzO+xk0JXEL\n" ++
    "OU8rXHSMkJIboEbTf5ZswkLwi3eqCY8afmMz4z2lU/KIRxkEBk8TyX14mKge4y5F\n" ++
    "qj6M47OuwRWlHTiAjxMMTNHIXRnUWmdbB9+PswBrTL34WHvavqChYhsDeQIDAQAB\n" ++
    "AoGAS4Rrp4vPU7Pra/8Vo1e+rGlPRmM0oRCMqe9lUREcMoy6ekvhI8rfZHnL6hsR\n" ++
    "tuKZCpdZs/+bvhn8kQ9Frg/7JDMfa0880ijH16CxrDWP/2CX+VByTNZ15ivVcKS1\n" ++
    "gSkQ1WiP69ZQrynDnx64BRLZpXZPwZCP4826mBVxvR13FFECQQDpqu47remDINad\n" ++
    "jyjSH61n/J0Fj2WGvve+CWJ3T8nDJ28EdXgaIMO4yrzLimPwvWdUkbsi/oRRWuPI\n" ++
    "Nv307NAtAkEA3su75SJNmvoefNZ2A5OkEwt7t9yQ9wbnBN8GSGzF6y+0jLdDEsLM\n" ++
    "+IP42YEVkK7YdO4dvFs8N96U3L+NJ9vD/QJBAKL8kHneQAAwGqMCJXYTlG/xG1Gy\n" ++
    "iR2o/MN4Zk9UvyY5zk0s5t5KtlqiR3guCrH0Wyv5DrBFGeRpYnLYMOHzgO0CQHz3\n" ++
    "mfT0QMNk+CTdxmRLNATatBJ1TXrCDGLXFhcZrAo3P/aN9LlZOs9KdxLJLOdyq0cr\n" ++
    "KNK1+hj8aFNJvktVIaECQDpYTrHjh7Cfxwk1AR4osOJdf59ecna2Fiegsn6zULpd\n" ++
    "MVBCd5Jdjlwloxksy/1nCUvQLE+ObMYui0GltsfC0Yc=\n" ++
    "-----END RSA PRIVATE KEY-----\n";

/// A 4096-bit key, the largest this module accepts, as PKCS#8. It is here
/// because the top of the range is where the fixed-size buffers are fullest:
/// this is the key that found `fromPem` unable to fit into the buffer whose
/// size it documents.
const key_4096_pkcs8 =
    "-----BEGIN PRIVATE KEY-----\n" ++
    "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\n" ++
    "cQ/JnoXxkeTHe9m+dkC3U+MxHm7Y\n" ++
    "-----END PRIVATE KEY-----\n";

/// Its public half.
const pub_4096_spki =
    "-----BEGIN PUBLIC KEY-----\n" ++
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl3ozTENLJi0Xo22fLnWd\n" ++
    "C4ZH1EqW43L4xA6MafTTkWeTLupUd9OmFelkjUyXcl/fNv+Bp0KLJpAN/jdfDzPB\n" ++
    "8DHhNGZf7HnAO7jWXSlNWweZWoxUlEi6nldHjpAxr53jTx1ealyjTXiaJQWllp3n\n" ++
    "RY1w6es8Mqlv3ZpVzbicomKWQkZgfCHwnE/KHiRJoD10oAwHBo42ITTse37Qw+6k\n" ++
    "5soRyZWc7JvpQoHp4sDtwd8vSxTONQjggnW0rJaS/RN/ZPYF0JOUS1t1A5sKNq2T\n" ++
    "aA2y0o2Ats+7PsF2bFkLF8+n9y7k1TGDi2SHzrZ8S4F8fEJQTeFvsnYJqYUTdqij\n" ++
    "BTMU64Eqg1L3m+e96eSLnafs9UhcCR4xQUeLOzyKIj2DE42yc5RVzJF2wM23RjjQ\n" ++
    "Op2JJODa9y02qvETslWpeBkVXXM/1BETKFM1sBfe69/NypQFlW7V4fs3fkRgffMV\n" ++
    "LB3fhK8fxBiIe4d85MJwS8myK39aOAoWolHUip6CxUn0LlFwekcS4CRYlbTrGpcj\n" ++
    "dbRSSeAuq+DKSYDmxr28dt8TAnIfJkzfiEed69t1VjbVPCryM0jju4NFPnFspilU\n" ++
    "DP789ofzQ3ACc5UzTdt9tVzn48yekRX3NwmUgEG/Fkj3vq3n7EhSDuCWHNKWQz0E\n" ++
    "Tp6AYp67uknnJuFYw5ktqykCAwEAAQ==\n" ++
    "-----END PUBLIC KEY-----\n";

/// `openssl dgst -sha256 -sign key4096 msg.txt`, OpenSSL 3.6.3.
const sig_4096_sha256_hex = "361d413e3380b4bbdacd47eb706d29eea7b034c45e44b7f594378ab8ad2ec5fc" ++
    "c00bebe74c533b53edf68ec08fecafdcc2a61bcb9671f9567221ec1922b53ec8" ++
    "e0c1cc23e8225c048cc93327a62c989a204ac365a8fb9bf3415db4017426d68c" ++
    "c87c0cc94fd6957bee0e43a3ba8584d6ad6e0e2c7c0146d7f9919a4bd1a4e186" ++
    "d8a8d36efd496c60c2e888ecf272fc23c839bc30fd8fdf995ca945685b5b1ad5" ++
    "c24e1736fb17fa9048d5896c3329a41b8c13793057c8f1aa32b2698f3f128984" ++
    "50d7a87c81bba26149a1230a1c7f85f34818b5c215e2f895f522ec943cf9d650" ++
    "1ace666347477fe10fab912d1621a2a581ecb543b6dde304391b8596ec5d74d2" ++
    "c5b683659914685d42f3f8f39876bcc7034de880cd2c959e542637a6bf6fa7f2" ++
    "4b7a0aa76c977aa4f6149af4c4d0cb279ae495c990f27251ce6556444350aa76" ++
    "1f676cb520bc14427113aca54c8db0ebb78831fd379d32d6332a3fa228a4f9ca" ++
    "24c8bb1deb46220d15560a43eef3fb0aa722d09daa94265ac6d55a226e00371d" ++
    "8c07c700cc1da96f582190eab1be2a48b7d04606affa9fbf2ae8fc70c5de38a1" ++
    "49a0d5cf938827d07e03ada43550b1288e2358627055431143257a585378dc53" ++
    "6dc416647085551cf3a9492f4de8f0cf62a099a4e91adb00ef16ef4d474d3302" ++
    "0851baea21864a8b04283dce2db071c491c345cea950afe8422009da6c6ad4ad";

/// `openssl dgst -sha256 -sign key2048 msg.txt`.
const sig_2048_sha256_hex = "90c564cf0c0ff9d16bfe0ecd2630ea62a7c82d18b30f9f598a4f5896c567c7ab" ++
    "0fd52c13897cb7b8bbbd2a5b275fa4d597a8197178b2925f8d58634481b67f68" ++
    "013d4dbb2c0f803d528909af22b1a1e6f73e81f08cac9331f7c5606db4ed638f" ++
    "cb3be691a34f55f59e2d045373c189a0796c5c692b866bcb72b7c2ce71af9943" ++
    "e6355ad187a348879cc34e337c277db8679a6872906a88de473e28b46622089d" ++
    "cbea923cd602b044a8c520ac7de6981976cdbc1a5ea82615f7ce89485a891352" ++
    "9f4837c405c004c746594a7e3d5cde153b6418fb7f4715ddc58d8054f4185f87" ++
    "64a2bc50eeed83f40516ddc8dd6a44e1b899fc053524586cbb25a766fbf7ba06";

/// The same message under SHA-1.
const sig_2048_sha1_hex = "2e10c80f84ce72dd5fa7df923a0b6df42a4c6602d85ea4b4a84d8a846ac1cf68" ++
    "56710374330d921971607ac2238034e953e14abce6fd5e643e96bb4e14c96eb9" ++
    "a221dad6d27696fa72388fb1c26ecbb26f3ab3d4b3188a11a9a8eea9febc7e9b" ++
    "bb5af973c5b2c9a80a42ba303d1e0c977f17bf7c912bbc89e4a3c637b6af641e" ++
    "2d82f00c1ad1864726e99f0895d9b514318e583662da741c8e7a95118c824881" ++
    "51a9f27a27f8db3683dc936cf1369d863977e2db848a8a4ca57ca4ebbebd1de4" ++
    "76309037ce5082a5d6dd83f896ecf3278042482366e7563669517fb43ccf081b" ++
    "687f3e295073b13d528721fd73447cef26aff22d7c63194d098689da3d0be741";

/// ...and under the 1024-bit key.
const sig_1024_sha256_hex = "725aa5cecfc46019264c0cde0bde16ee420a94f41750585899ed1bf5795f0a56" ++
    "96afed23f88a4c0c4bd0a5b9fdc4b58c83d930e884f06af039bb9846eb30b1ca" ++
    "6e45cf010ba1ad1ecd66ca7d1612f73ae1dea08755c83e8e35598b1b9919a787" ++
    "3eb4d30dc08225c4ba2214d889856fb4a572f04905810426c75708559483e81f";

/// Decodes one of the hex constants above into a buffer.
fn unhex(out: []u8, hex: []const u8) []u8 {
    return std.fmt.hexToBytes(out, hex) catch unreachable;
}

test "PKCS#8 and PKCS#1 PEM describe the same key" {
    var der_a: [max_secret_key_der]u8 = undefined;
    var der_b: [max_secret_key_der]u8 = undefined;
    const from_pkcs8 = try SecretKey.fromPem(&der_a, key_2048_pkcs8);
    const from_pkcs1 = try SecretKey.fromPem(&der_b, key_2048_pkcs1);

    try testing.expectEqual(@as(usize, 256), from_pkcs8.modulusLength());
    try testing.expectEqual(@as(usize, 2048), from_pkcs8.n.bits());
    try testing.expect(from_pkcs8.d.eql(from_pkcs1.d));
    try testing.expect(from_pkcs8.e.eql(from_pkcs1.e));
}

test "SPKI and PKCS#1 public PEM describe the same key" {
    var der_a: [max_secret_key_der]u8 = undefined;
    var der_b: [max_secret_key_der]u8 = undefined;
    const spki = try PublicKey.fromPem(&der_a, pub_2048_spki);
    const pkcs1 = try PublicKey.fromPem(&der_b, pub_2048_pkcs1);

    try testing.expectEqual(@as(usize, 256), spki.modulusLength());
    try testing.expect(spki.e.eql(pkcs1.e));
    // The moduli are the same field, so an element made from one is
    // canonical in the other.
    var n_a: [256]u8 = undefined;
    var n_b: [256]u8 = undefined;
    try spki.n.toBytes(&n_a, .big);
    try pkcs1.n.toBytes(&n_b, .big);
    try testing.expectEqualSlices(u8, &n_a, &n_b);
}

test "the public key derived from a secret key is the published one" {
    var der_a: [max_secret_key_der]u8 = undefined;
    var der_b: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der_a, key_2048_pkcs8);
    const pk = try PublicKey.fromPem(&der_b, pub_2048_spki);

    const derived = sk.publicKey();
    try testing.expect(derived.e.eql(pk.e));
    var n_a: [256]u8 = undefined;
    var n_b: [256]u8 = undefined;
    try derived.n.toBytes(&n_a, .big);
    try pk.n.toBytes(&n_b, .big);
    try testing.expectEqualSlices(u8, &n_a, &n_b);
}

test "signatures match OpenSSL byte for byte" {
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_2048_pkcs8);

    var expected_buf: [max_modulus_len]u8 = undefined;
    var sig_buf: [max_modulus_len]u8 = undefined;

    {
        const expected = unhex(&expected_buf, sig_2048_sha256_hex);
        const sig = try pkcs1v1_5.Signer(Sha256).sign(&sig_buf, test_message, sk);
        try testing.expectEqualSlices(u8, expected, sig);
    }
    {
        const expected = unhex(&expected_buf, sig_2048_sha1_hex);
        const sig = try pkcs1v1_5.Signer(Sha1).sign(&sig_buf, test_message, sk);
        try testing.expectEqualSlices(u8, expected, sig);
    }
}

test "a 1024-bit key signs the same way a 2048-bit one does" {
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_1024_pkcs1);
    try testing.expectEqual(@as(usize, 128), sk.modulusLength());

    var expected_buf: [max_modulus_len]u8 = undefined;
    const expected = unhex(&expected_buf, sig_1024_sha256_hex);
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try pkcs1v1_5.Signer(Sha256).sign(&sig_buf, test_message, sk);
    try testing.expectEqualSlices(u8, expected, sig);
    try pkcs1v1_5.Signer(Sha256).verify(sig, test_message, sk.publicKey());
}

test "OpenSSL's signatures verify here" {
    var der: [max_secret_key_der]u8 = undefined;
    const pk = try PublicKey.fromPem(&der, pub_2048_spki);

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = unhex(&sig_buf, sig_2048_sha256_hex);
    try pkcs1v1_5.Signer(Sha256).verify(sig, test_message, pk);

    // The same signature under the wrong hash must not verify, which is the
    // check that the DigestInfo prefix is doing its job.
    try testing.expectError(
        error.InvalidSignature,
        pkcs1v1_5.Signer(Sha1).verify(sig, test_message, pk),
    );
}

test "the two representations sign identically" {
    // The second representation is an optimisation and nothing else: the
    // signature it produces is the signature the direct route produces, or
    // it is wrong. `signatures match OpenSSL byte for byte` already checks
    // the CRT path against a third party, so what this adds is the two
    // halves of this file checked against each other on the same key.
    var der_buf: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der_buf, key_2048_pkcs8);
    try testing.expect(sk.crt != null);

    var whole = sk;
    whole.crt = null;

    var a: [max_modulus_len]u8 = undefined;
    var b: [max_modulus_len]u8 = undefined;
    const with = try pkcs1v1_5.Signer(Sha256).sign(&a, test_message, sk);
    const without = try pkcs1v1_5.Signer(Sha256).sign(&b, test_message, whole);
    try testing.expectEqualSlices(u8, without, with);
}

test "a key whose components contradict each other signs nothing" {
    // The Bellcore attack in the form this library can be made to suffer it.
    // A CRT signer that gets one half wrong emits a signature from which
    // `gcd(s^e - m, n)` is one of the primes -- the whole private key, from
    // one bad signature. Inducing a hardware fault is not something a test
    // can do, but corrupting a component has the same effect on the
    // arithmetic, and what must happen is that nothing comes out.
    var der_buf: [max_secret_key_der]u8 = undefined;
    var sk = try SecretKey.fromPem(&der_buf, key_2048_pkcs8);

    // `qinv` off by one: still a perfectly good field element, so nothing
    // upstream of the signature rejects it.
    const crt = sk.crt.?;
    sk.crt.?.qinv = crt.p.add(crt.qinv, crt.p.one());

    var sig: [max_modulus_len]u8 = undefined;
    try testing.expectError(
        error.SigningFailed,
        pkcs1v1_5.Signer(Sha256).sign(&sig, test_message, sk),
    );

    // And the buffer does not hold the faulty signature: a caller that
    // ignored the error would otherwise publish exactly what must not be
    // published.
    var zeroed = true;
    for (sig[0..sk.modulusLength()]) |byte| {
        if (byte != 0) zeroed = false;
    }
    try testing.expect(zeroed);
}

test "a signature does not verify against a message it was not made over" {
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_2048_pkcs8);
    const pk = sk.publicKey();

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try pkcs1v1_5.Signer(Sha256).sign(&sig_buf, test_message, sk);
    try pkcs1v1_5.Signer(Sha256).verify(sig, test_message, pk);

    try testing.expectError(
        error.InvalidSignature,
        pkcs1v1_5.Signer(Sha256).verify(sig, test_message ++ "!", pk),
    );

    // Every single-bit change to the signature must be rejected. This is the
    // test that catches a comparison that stops early or a buffer that is
    // only partly compared -- a whole-array comparison over a partly written
    // buffer would pass the happy path above and fail here.
    for (0..sig.len) |i| {
        for ([_]u8{ 0x01, 0x80 }) |bit| {
            var damaged: [max_modulus_len]u8 = undefined;
            @memcpy(damaged[0..sig.len], sig);
            damaged[i] ^= bit;
            try testing.expectError(
                error.InvalidSignature,
                pkcs1v1_5.Signer(Sha256).verify(damaged[0..sig.len], test_message, pk),
            );
        }
    }
}

test "signing over parts is signing over the join of them" {
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_2048_pkcs8);

    var whole_buf: [max_modulus_len]u8 = undefined;
    var parts_buf: [max_modulus_len]u8 = undefined;
    const whole = try pkcs1v1_5.Signer(Sha256).sign(&whole_buf, "abcdef", sk);
    const parts = try pkcs1v1_5.Signer(Sha256).signConcat(
        &parts_buf,
        &.{ "ab", "", "cde", "f" },
        sk,
    );
    try testing.expectEqualSlices(u8, whole, parts);
}

test "signing a digest is signing the message that hashed to it" {
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_2048_pkcs8);

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(test_message, &digest, .{});

    var a_buf: [max_modulus_len]u8 = undefined;
    var b_buf: [max_modulus_len]u8 = undefined;
    const from_message = try pkcs1v1_5.Signer(Sha256).sign(&a_buf, test_message, sk);
    const from_digest = try pkcs1v1_5.Signer(Sha256).signDigest(&b_buf, digest, sk);
    try testing.expectEqualSlices(u8, from_message, from_digest);
}

test "a modulus too short for the hash is refused rather than truncated" {
    // SHA-512's DigestInfo is 83 bytes, so RFC 8017 needs a 94-byte modulus
    // for it and a 1024-bit key has 128 -- but a 512-bit one has 64.
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_1024_pkcs1);
    var sig_buf: [max_modulus_len]u8 = undefined;
    // 1024 bits is enough for SHA-512, so this one works...
    _ = try pkcs1v1_5.Signer(Sha512).sign(&sig_buf, test_message, sk);
    // ...and the buffer check is what a caller gets for being careless.
    try testing.expectError(
        error.BufferTooSmall,
        pkcs1v1_5.Signer(Sha512).sign(sig_buf[0..64], test_message, sk),
    );
}

test "the encoded message is what RFC 8017 section 9.2 describes" {
    // EM = 0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo, and the DigestInfo
    // is the prefix followed by the digest.
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(test_message, &digest, .{});

    const Signer = pkcs1v1_5.Signer(Sha256);
    var em: [256]u8 = undefined;
    try Signer.encode(&em, digest);

    try testing.expectEqual(@as(u8, 0x00), em[0]);
    try testing.expectEqual(@as(u8, 0x01), em[1]);
    const info_start = em.len - Signer.digest_info_len;
    for (em[2 .. info_start - 1]) |b| try testing.expectEqual(@as(u8, 0xff), b);
    try testing.expectEqual(@as(u8, 0x00), em[info_start - 1]);
    try testing.expectEqualSlices(
        u8,
        Signer.digest_info_prefix,
        em[info_start..][0..Signer.digest_info_prefix.len],
    );
    try testing.expectEqualSlices(u8, &digest, em[em.len - digest.len ..]);
    // At least eight 0xFF bytes, which is the whole of step 3.
    try testing.expect(info_start - 3 >= 8);
}

test "malformed keys are rejected rather than misread" {
    var der: [max_secret_key_der]u8 = undefined;

    // Not PEM at all.
    try testing.expectError(error.MalformedPem, SecretKey.fromPem(&der, "hello"));
    // A label this function does not accept.
    try testing.expectError(error.MalformedPem, SecretKey.fromPem(&der, pub_2048_spki));
    // Markers that disagree.
    try testing.expectError(error.MalformedPem, SecretKey.fromPem(&der,
        \\-----BEGIN PRIVATE KEY-----
        \\MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
        \\-----END PUBLIC KEY-----
        \\
    ));
    // Base64 that is not.
    try testing.expectError(error.InvalidBase64, SecretKey.fromPem(&der,
        \\-----BEGIN PRIVATE KEY-----
        \\!!!!
        \\-----END PRIVATE KEY-----
        \\
    ));
    // Valid base64, valid length, but not the DER of anything.
    try testing.expectError(error.MalformedDer, SecretKey.fromPem(&der,
        \\-----BEGIN PRIVATE KEY-----
        \\AAAAAAAAAAAA
        \\-----END PRIVATE KEY-----
        \\
    ));
}

test "a truncated key is rejected, not used as if whole" {
    // Cutting the DER short anywhere has to be an error: the components are
    // read in order, so a key missing its coefficient still has everything
    // this implementation *uses*, and accepting it would mean accepting a
    // file that is not a key.
    var full: [max_secret_key_der]u8 = undefined;
    const der_bytes = try pemDecode(&full, key_2048_pkcs8, &.{"PRIVATE KEY"});

    var i: usize = 1;
    while (i < der_bytes.len) : (i += 7) {
        try testing.expectError(error.MalformedDer, SecretKey.fromDer(der_bytes[0..i]));
    }
}

test "DER that is well-formed but describes an unusable key" {
    // A 256-bit modulus: real DER, real structure, a key nobody should be
    // allowed to use. Built by hand because OpenSSL will not generate one.
    //   SEQUENCE { INTEGER 0, INTEGER n, INTEGER 65537, INTEGER d,
    //              INTEGER 0 x5 }
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const n = [_]u8{0xc0} ++ [_]u8{0x01} ** 30 ++ [_]u8{0x01}; // 256 bits, odd
    const d = [_]u8{0x11} ++ [_]u8{0x22} ** 30 ++ [_]u8{0x33};

    var body: [512]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&body);
    try bw.writeAll(&.{ 0x02, 0x01, 0x00 }); // version 0
    try bw.writeAll(&.{ 0x02, @intCast(n.len + 1), 0x00 }); // n, with sign byte
    try bw.writeAll(&n);
    try bw.writeAll(&.{ 0x02, 0x03, 0x01, 0x00, 0x01 }); // e = 65537
    try bw.writeAll(&.{ 0x02, @intCast(d.len) }); // d
    try bw.writeAll(&d);
    for (0..5) |_| try bw.writeAll(&.{ 0x02, 0x01, 0x01 }); // the CRT values
    const body_bytes = bw.buffered();

    // The short form, because the body is under 0x80 bytes and this reader
    // insists on the shortest encoding -- writing `0x81, len` here would be
    // rejected as malformed before it ever got as far as looking at the key.
    try testing.expect(body_bytes.len < 0x80);
    try w.writeAll(&.{ 0x30, @intCast(body_bytes.len) });
    try w.writeAll(body_bytes);

    try testing.expectError(error.InvalidKey, SecretKey.fromDer(w.buffered()));
}

test "a public exponent that is not usable is refused" {
    // e must be odd and at least 3: an even one is not coprime with n, and
    // e = 1 would make the signature the message.
    const n = [_]u8{0xc0} ++ [_]u8{0xff} ** 126 ++ [_]u8{0x01}; // 1024 bits
    try testing.expectError(error.InvalidKey, PublicKey.fromBytes(&n, &.{0x01}));
    try testing.expectError(error.InvalidKey, PublicKey.fromBytes(&n, &.{0x02}));
    try testing.expectError(error.InvalidKey, PublicKey.fromBytes(&n, &.{ 0x01, 0x00, 0x00, 0x00, 0x01 }));
    _ = try PublicKey.fromBytes(&n, &.{0x03});
    _ = try PublicKey.fromBytes(&n, &.{ 0x01, 0x00, 0x01 });
}

test "a modulus below the floor is refused" {
    const short = [_]u8{0xc0} ++ [_]u8{0xff} ** 30 ++ [_]u8{0x01}; // 256 bits
    try testing.expectError(
        error.InvalidKey,
        PublicKey.fromBytes(&short, &.{ 0x01, 0x00, 0x01 }),
    );
}

test "PEM with CRLF line endings, and with noise above the block" {
    // A key that has been through a mail message has CRLF, and one dumped by
    // `openssl rsa -text` has its own description above the block.
    var crlf_buf: [4096]u8 = undefined;
    var len: usize = 0;
    const preamble = "Private-Key: (2048 bit, 2 primes)\nmodulus: ...\n";
    @memcpy(crlf_buf[0..preamble.len], preamble);
    len = preamble.len;
    for (key_2048_pkcs8) |c| {
        if (c == '\n') {
            crlf_buf[len] = '\r';
            len += 1;
        }
        crlf_buf[len] = c;
        len += 1;
    }

    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, crlf_buf[0..len]);
    try testing.expectEqual(@as(usize, 2048), sk.n.bits());
}

test "a 4096-bit key fits the buffer whose size it documents" {
    // The top of the accepted range, through `fromPem` into a buffer of
    // exactly `max_secret_key_der`. This is the case that used to fail: the
    // base64 was repacked into the same buffer before being decoded, and
    // base64 is a third longer than the DER the buffer is sized for.
    var der: [max_secret_key_der]u8 = undefined;
    const sk = try SecretKey.fromPem(&der, key_4096_pkcs8);
    try testing.expectEqual(@as(usize, 4096), sk.n.bits());
    try testing.expectEqual(@as(usize, max_modulus_len), sk.modulusLength());

    var pub_der: [max_secret_key_der]u8 = undefined;
    const pk = try PublicKey.fromPem(&pub_der, pub_4096_spki);

    // And the signature is what OpenSSL makes with it, byte for byte, and
    // fills the whole of a `max_modulus_len` buffer with nothing over.
    var expected_buf: [max_modulus_len]u8 = undefined;
    const expected = unhex(&expected_buf, sig_4096_sha256_hex);
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try pkcs1v1_5.Signer(Sha256).sign(&sig_buf, test_message, sk);
    try testing.expectEqualSlices(u8, expected, sig);
    try pkcs1v1_5.Signer(Sha256).verify(sig, test_message, pk);
}

/// A PKCS#1 `RSAPublicKey` with a modulus of `modulus_len` bytes, top bit
/// set and odd, and e = 65537: well-formed DER for a key of any size.
fn publicKeyDerOfSize(out: []u8, modulus_len: usize) []u8 {
    var w: std.Io.Writer = .fixed(out);
    const n_len = modulus_len + 1; // a sign byte, since the top bit is set
    const e = [_]u8{ 0x02, 0x03, 0x01, 0x00, 0x01 };
    const body_len = 4 + n_len + e.len;
    w.writeAll(&.{ 0x30, 0x82, @intCast(body_len >> 8), @intCast(body_len & 0xff) }) catch unreachable;
    w.writeAll(&.{ 0x02, 0x82, @intCast(n_len >> 8), @intCast(n_len & 0xff), 0x00 }) catch unreachable;
    w.writeByte(0xc0) catch unreachable;
    for (1..modulus_len - 1) |_| w.writeByte(0x11) catch unreachable;
    w.writeByte(0x01) catch unreachable;
    w.writeAll(&e) catch unreachable;
    return w.buffered();
}

test "a modulus above the ceiling is refused, not sliced past the buffers" {
    // `std.crypto.ff` sizes its field in 63-bit limbs, so a
    // `Modulus(4096)` quietly accepts anything up to 4158 bits. A key in
    // that gap used to parse, report a `modulusLength()` of 513 or more,
    // and then index `[max_modulus_len]u8` arrays with it -- a panic in a
    // safe build and a stack overrun in a fast one, reachable from any
    // public key an attacker hands to `verify`.
    var buf: [1024]u8 = undefined;
    for ([_]usize{ 513, 514, 519 }) |modulus_len| {
        const der = publicKeyDerOfSize(&buf, modulus_len);
        try testing.expectError(error.InvalidKey, PublicKey.fromDer(der));
    }
    // The ceiling itself is fine, and is exactly the buffer.
    const at_limit = try PublicKey.fromDer(publicKeyDerOfSize(&buf, 512));
    try testing.expectEqual(@as(usize, max_modulus_len), at_limit.modulusLength());
}

test "bytes after the key are rejected, for secret keys as for public" {
    // `PublicKey.fromPkcs1Der` always checked that the DER ended where the
    // key did; the secret key readers did not, so a key with anything
    // appended -- inside the sequence or after it -- was accepted. A strict
    // reader is strict about both.
    var full: [max_secret_key_der + 8]u8 = undefined;
    const der = try pemDecode(&full, key_2048_pkcs8, &.{"PRIVATE KEY"});
    _ = try SecretKey.fromDer(der);

    // After the outer sequence, for both shapes of key.
    @memcpy(full[der.len..][0..4], "JUNK");
    try testing.expectError(error.MalformedDer, SecretKey.fromDer(full[0 .. der.len + 4]));

    var pkcs1: [max_secret_key_der + 8]u8 = undefined;
    const der1 = try pemDecode(&pkcs1, key_2048_pkcs1, &.{"RSA PRIVATE KEY"});
    _ = try SecretKey.fromDer(der1);
    @memcpy(pkcs1[der1.len..][0..4], "JUNK");
    try testing.expectError(error.MalformedDer, SecretKey.fromDer(pkcs1[0 .. der1.len + 4]));

    // And inside the PKCS#1 sequence, after the coefficient: a tenth
    // INTEGER, with the lengths above it adjusted to cover it. Both are
    // long-form lengths of two bytes, at offsets 2 and 3 of the sequence.
    var grown: [max_secret_key_der + 8]u8 = undefined;
    @memcpy(grown[0..der1.len], der1);
    grown[der1.len..][0..3].* = .{ 0x02, 0x01, 0x07 };
    const inner_len = std.mem.readInt(u16, der1[2..4], .big) + 3;
    std.mem.writeInt(u16, grown[2..4], inner_len, .big);
    try testing.expectError(error.MalformedDer, SecretKey.fromDer(grown[0 .. der1.len + 3]));
}

test "an END line has to close" {
    // The label was compared and the dashes after it were not, so a line
    // that merely began the way an END line does was taken for one.
    var der: [max_secret_key_der]u8 = undefined;
    try testing.expectError(error.MalformedPem, SecretKey.fromPem(&der,
        \\-----BEGIN PRIVATE KEY-----
        \\MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
        \\-----END PRIVATE KEY
        \\
    ));
}
