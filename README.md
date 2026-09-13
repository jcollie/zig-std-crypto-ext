<!--
SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
SPDX-License-Identifier: MIT
-->

# zig-std-crypto-ext

The ciphers, modes and signatures `std.crypto` leaves out: **DES**, **Triple
DES**, **AES-192**, **CBC, CFB and ECB** generic over any block cipher, and
**RSA signing**.

Named for what it is rather than for its first occupant — it started as
`zig-des`, and DES is now the smaller half of it.

The API documentation is generated from the doc comments, which carry most of
the explanation, and is published at
**<https://jeff.jcollie.page/zig-std-crypto-ext/>**.

```console
$ git clone https://git.jcollie.dev/jeff/zig-std-crypto-ext.git
$ cd zig-std-crypto-ext
$ nix develop -c zig build test
```

## Where this lives

Four homes, with the same history in each.

* Forgejo, at <https://git.jcollie.dev/jeff/zig-std-crypto-ext>, which is where the
  workflow runs and where the documentation is published from.
* GitHub, at <https://github.com/jcollie/zig-std-crypto-ext>.
* [Tangled](https://tangled.org/), at
  <https://tangled.org/jcollie.dev/zig-std-crypto-ext>.
* [Radicle](https://radicle.xyz/), as `rad:z2UqY7wXCc4xUHRfeaDepK33Kch1Z`. A
  Radicle repository is only findable by its ID, so that string is the whole
  address:

  ```console
  $ rad clone rad:z2UqY7wXCc4xUHRfeaDepK33Kch1Z
  ```

## Why this exists

⚠️ **Everything here is obsolete, and that is the point.** Single DES has a
56-bit key and has been brute-forceable since 1998 [8]. Two-key Triple DES has
a meet-in-the-middle attack [9], and the 64-bit block gives a birthday bound
around 32 GiB under one key however long the key is [10]. CBC and CFB
authenticate nothing and CBC has a long history of padding oracles. **Nothing
new should choose any of it.**

What keeps it alive is equipment that already exists. SNMPv3's
`usmDESPrivProtocol` (RFC 3414 [6]) is DES-CBC and is still the default privacy
protocol on a great deal of network hardware, so a manager that cannot speak it
cannot talk to those devices at all. Kerberos 4, PKCS#12, MS-CHAP and a good
deal of banking hardware are in the same position. `std.crypto` quite reasonably
declines to ship any of this; this library is where it goes instead, clearly
labelled.

The modes are here for a second reason: `std.crypto.modes` has only counter
mode, and RFC 3826 [7] specifies **AES**-128 in full-block CFB for SNMPv3. So one
library has to supply a cipher `std` omits and a mode `std` omits, for two
different ciphers — which is why `modes` is generic over the cipher rather than
tied to DES.

**RSA is here for a different reason, and it is not obsolete.** Zig 0.16 does
ship RSA, but only half of it and only as an implementation detail of
something else: `std.crypto.Certificate.rsa` has a public key and a verifier
because checking a certificate chain needs them. There is no private key type
anywhere in the standard library and nothing that can produce a signature. A
protocol that has to *sign* — DKIM, JWS `RS256`, a certificate request — has
nowhere to go. So this library supplies the missing half, and the PKCS#1 and
PKCS#8 key parsing that has to come with it, since a private key arrives as
DER inside PEM and `std` will not decode that either.

## What it does promise

Obsolete is not the same as careless, and two things are deliberately true of
this code.

**The cipher is constant-time in the key and the data.** The tables are only
ever read at constant indices, every loop runs a fixed number of times, and
the S-boxes — the one place a DES implementation normally reads memory at a
key-dependent address, which is the cache-timing attack of Tsunoo et al. [11] — are
evaluated with masks and a shift rather than a lookup. The key helpers are
written the same way, since the key is what they are given. That rests on
integer compare, mask and variable shift being constant-time, which they are
on x86-64 and AArch64, and on the compiler not turning a mask back into a
branch, which nothing forbids, so like every such claim made in a language
without constant-time semantics it is best-effort. It is not bitsliced.
Because it is best-effort it is also measured: `zig build timing` runs the
test from dudect [12] against the release build on the machine at hand, and the
section on tests below says how to read it.

**AES-192 has exactly the timing `std`'s own AES has.** It is not written
out in software: the rounds are `std.crypto.core.aes.Block`'s `encrypt` and
`encryptLast`, which are single instructions on x86-64 with AES-NI and on
AArch64 with the crypto extension, and the key schedule's S-box goes through
the same instruction. Only the schedule's bookkeeping is this library's. So it
is constant-time wherever `std.crypto.core.aes.has_hardware_support` is true
and falls back to `std`'s software AES wherever it is not — which is decided
by the CPU the build was given, not the one it runs on, and `-Dcpu=baseline`
on x86-64 has no AES-NI. An earlier version indexed a 256-byte S-box by the
state, the cache-timing leak of Bernstein and of Osvik, Shamir and Tromer,
next door to a DES that goes to some lengths to avoid exactly that.

**The modes' length checks are assertions.** `dst.len >= src.len`, and a whole
number of blocks for CBC and ECB, are checked in a Debug or ReleaseSafe build
and not at all in ReleaseFast or ReleaseSmall, where a violation reads past
`src` and writes past `dst`. A ciphertext length that came off the wire is
checked by the caller before it gets here, which is how `std.crypto`'s own
modes behave too. The doc comment on `modes` spells out the rest: `dst` is the
same slice as `src` or does not overlap it, and the mode's temporaries are
zeroed on return while the contexts, being the caller's, are not.

**RSA's private exponentiation is constant-time, and it is neither blinded nor
CRT.** The exponentiation goes through `std.crypto.ff`, the same Montgomery
arithmetic `std` verifies certificates with, which is constant time in both
the base and the exponent — the defence that matters against a remote timing
attack. It does not blind the input, because blinding needs a modular inverse
and `std.crypto.ff` exposes none; and it does not use the Chinese Remainder
Theorem even when the key carries the parameters, which is what makes it an
order of magnitude slower than OpenSSL (13 ms for a 2048-bit signature
against roughly 1 ms) and also what means there is no faulty recombination to
leak the key through. It is appropriate for signing with a key on a machine
you trust, and it is not a replacement for an HSM. The doc comment on `rsa`
gives the numbers and the reasoning.

## What is here

| | |
| --- | --- |
| `Des` | Single DES. `initEnc`/`initDec` return contexts with a `block_length` and `encrypt`/`decrypt` over one block. |
| `Des3` | Triple DES in EDE order, three-key and two-key (`initEnc2`). Three equal keys make it identical to single DES, which is what the middle decryption is for. |
| `modes.cbcEncrypt`, `cbcDecrypt` | Cipher Block Chaining. Whole blocks only; choosing a padding is the caller's business, because the padding belongs to whatever specification sent them here. |
| `modes.cfbEncrypt`, `cfbDecrypt` | Cipher Feedback with full-block feedback — "CFB128" for a 128-bit cipher. A stream mode, so any length, and it runs the cipher *forwards* in both directions, so both take an encryption context. |
| `modes.ecbEncrypt`, `ecbDecrypt` | Each block alone. Leaks which plaintext blocks are equal; present because key-wrapping constructions and test vectors are stated in terms of it. |
| `Aes192` | AES-192, the key size `std.crypto` omits — it ships `Aes128` and `Aes256` and nothing between. Built from `std`'s own hardware rounds, so it has `std`'s timing; only the key schedule is written here. **Encryption only**, because CFB and CTR never run a cipher backwards; `initDec` is deliberately absent, so asking for it is a compile error rather than a surprise. |
| `weak_keys`, `isWeak` | The four keys for which DES is an involution. A password-derived key can be one by accident, and `usmDESPrivProtocol` derives its key from a password. |
| `hasOddParity`, `setOddParity` | The parity convention DES keys are distributed under. The cipher ignores the parity bits entirely — that is what "56-bit key" means. |
| `rsa.SecretKey` | An RSA private key, read from PKCS#1 or PKCS#8 DER or from the PEM around either — `fromPem` tells the two apart by looking. Held by value, so the DER it came from can be wiped. |
| `rsa.PublicKey` | An RSA public key, from a `SubjectPublicKeyInfo` or a bare PKCS#1 `RSAPublicKey`, DER or PEM. Both shapes are accepted because formats that carry one are inconsistent about which they mean. |
| `rsa.pkcs1v1_5.Signer(Hash)` | RFC 8017 RSASSA-PKCS1-v1_5, over SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512. `sign`/`verify` over a message, `signConcat`/`verifyConcat` over its pieces, and `signDigest`/`verifyDigest` for a protocol that hashes something which never exists as contiguous bytes. |

## Using it

```console
$ zig fetch --save git+https://git.jcollie.dev/jeff/zig-std-crypto-ext.git
```

```zig
const des = @import("std_crypto_ext");

// DES-CBC, as SNMPv3 privacy uses it.
var ciphertext: [24]u8 = undefined;
des.modes.cbcEncrypt(
    des.Des.EncryptCtx, des.Des.initEnc(key), &ciphertext, plaintext, iv,
);

// And the same mode machinery over AES, because it is generic over the
// cipher rather than tied to this library's.
const aes = std.crypto.core.aes;
des.modes.cfbEncrypt(
    aes.AesEncryptCtx(aes.Aes128), aes.Aes128.initEnc(aes_key),
    &out, plaintext, aes_iv,
);
```

```zig
const rsa = @import("std_crypto_ext").rsa;
const Sha256 = std.crypto.hash.sha2.Sha256;

var der: [rsa.max_secret_key_der]u8 = undefined;
const sk = try rsa.SecretKey.fromPem(&der, pem_text);

var buf: [rsa.max_modulus_len]u8 = undefined;
const sig = try rsa.pkcs1v1_5.Signer(Sha256).sign(&buf, message, sk);
try rsa.pkcs1v1_5.Signer(Sha256).verify(sig, message, sk.publicKey());
```

The contexts are shaped like `std.crypto.core.aes`'s so that they read the same
way as the cipher next door. That is a familiarity argument and not an
interoperability one: `std.crypto.modes.ctr` reaches into
`BlockCipher.block.parallel.optimal_parallel_blocks` to batch blocks, which only
AES defines, so it cannot take a cipher from here. The modes in this library
depend on nothing but `block_length` and `encrypt`/`decrypt`, which is what
makes them genuinely generic.

## Tests

```console
$ nix develop -c zig build test --summary all
$ nix develop -c zig build fuzz-run -- --seconds 60
$ nix develop -c zig build timing
```

**Every vector was cross-checked against OpenSSL's legacy provider** [13], not
transcribed and trusted:

```console
$ openssl enc -provider legacy -provider default -des-ecb -nopad -K <key> -in pt.bin
```

That is not belt-and-braces. A DES that is self-consistent and *wrong* is easy
to write — index the S-boxes with the raw six input bits rather than the
published row and column and it still round-trips perfectly — and that is
precisely the bug that occurred here. A round-trip test proves almost nothing,
so the known-answer tests are the real ones: FIPS 46-3 [1], the NBS samples
[2], Rivest's sixteen-step cycle [3], NIST SP 800-67's Appendix B for Triple
DES [4], and NIST SP 800-38A F.3.13 for AES-128-CFB [5], with the DES-CFB and
two-key Triple DES answers taken from OpenSSL. One of the four NBS values was
wrong when first written, and OpenSSL is what settled which of us was. Rivest's
cycle is the one that earns its place: sixteen encryptions and decryptions
chained through each other, which he showed detects every single-fault error
in an implementation with one comparison at the end.

**The RSA vectors were made by OpenSSL too, and for the same reason.** PKCS#1
v1.5 is deterministic, so "byte for byte identical to what OpenSSL signed" is
a test that can actually be written — with PSS it could not be — and the suite
asserts exactly that for 1024- and 2048-bit keys under SHA-1 and SHA-256, in
both directions: OpenSSL's signatures verify here, and this library's
signatures are bit-identical to OpenSSL's. Alongside those are the tests that
a vector cannot reach: that flipping *any single bit* of a signature is
rejected, which is what catches a comparison that stops early or only compares
part of the buffer; that truncating the key DER at any offset is an error
rather than a key missing its tail; that a key too small, an exponent that
is even or 1, and a modulus too short for the hash are each refused rather
than used; and that a modulus *too large* is refused too, which matters more
than it sounds: `std.crypto.ff`'s field is sized in 63-bit limbs and so
quietly accepts up to 4158 bits, and a key in the gap above 4096 used to parse
and then index the 512-byte signature buffers past their end. A 4096-bit key,
the top of the range, is in the suite alongside the 1024- and 2048-bit ones,
because that is the size at which `fromPem` used to run out of the buffer
whose size it documents.

The fuzz targets are round-trip properties over the *modes*, where there is
real room to be wrong — an off-by-one on a final partial block, a chaining
value read after being overwritten by an in-place operation, a keystream that
wrongly depends on how much plaintext follows. They also assert the properties
no single vector can: that the parity bits never change the ciphertext, that
three equal keys make 3DES into DES, and that a weak key is an involution, for
every key and block rather than for one. The key parsers get targets of
their own, since a DER reader is the one thing here that reads bytes somebody
else wrote: the property is the weak one — return a key or an error, but stay
inside the buffer and terminate — seeded with a real key so that mutations
reach past the first tag. The verifier gets the strong one: every input is a
forgery, and every one has to be refused.

`zig build timing` measures the constant-time claim instead of trusting it.
It is the test from dudect [12]: DES, Triple DES, AES-192, the key helpers,
and DES-CBC and AES-192-CFB over a few blocks are each timed on a fixed input
and on random ones, hundreds of thousands of times in a random order, and
Welch's t-test asks whether the two timing distributions can be told apart. A |t| above 10 is a leak, and at these sample counts that is a
difference of about one cycle held consistently. A function whose running time
*is* its input runs first, and the run fails if that control is not detected,
so that a clean result means something. It reads the machine it runs on and
the compiler that built it, which is exactly what the claim depends on and
exactly what a disassembly read once cannot keep checking. Before the S-boxes
were rewritten it reported the table lookup as a leak at |t| of 20; it now
reports every function within a few units of zero.

## The API documentation

```console
$ nix develop -c zig build docs         # into zig-out/docs
$ nix develop -c zig build docs-serve   # http://127.0.0.1:8000
```

## References cited

1. National Institute of Standards and Technology, *Data Encryption Standard
   (DES)*, FIPS PUB 46-3, 25 October 1999; withdrawn 19 May 2005.
   <https://csrc.nist.gov/pubs/fips/46-3/final>. The tables, and the first
   known answer.
2. Jason Gait, *Validating the Correctness of Hardware Implementations of the
   NBS Data Encryption Standard*, NBS Special Publication 500-20, National
   Bureau of Standards, 1977, revised 1980.
   <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nbsspecialpublication500-20e1980.pdf>.
   The NBS sample vectors.
3. Ronald L. Rivest, *Testing Implementations of DES*, 23 February 1985.
   <https://people.csail.mit.edu/rivest/pubs/Riv85.txt>. The sixteen-step
   cycle from `9474B8E8C73BCA7D` to `1B1A2DDB4C642438`.
4. Elaine Barker and Nicky Mouha, *Recommendation for the Triple Data
   Encryption Algorithm (TDEA) Block Cipher*, NIST Special Publication 800-67
   Revision 2, November 2017. <https://doi.org/10.6028/NIST.SP.800-67r2>.
   Appendix B, the Triple DES known answer.
5. Morris Dworkin, *Recommendation for Block Cipher Modes of Operation:
   Methods and Techniques*, NIST Special Publication 800-38A, December 2001.
   <https://doi.org/10.6028/NIST.SP.800-38A>. CBC, CFB and ECB as specified,
   and the AES-128-CFB128 vector in F.3.13.
6. Uri Blumenthal and Bert Wijnen, *User-based Security Model (USM) for
   version 3 of the Simple Network Management Protocol (SNMPv3)*, RFC 3414,
   December 2002. <https://www.rfc-editor.org/rfc/rfc3414>.
7. Uri Blumenthal, Fabio Maino and Keith McCloghrie, *The Advanced Encryption
   Standard (AES) Cipher Algorithm in the SNMP User-based Security Model*,
   RFC 3826, June 2004. <https://www.rfc-editor.org/rfc/rfc3826>.
8. Electronic Frontier Foundation, *Cracking DES: Secrets of Encryption
   Research, Wiretap Politics & Chip Design*, O'Reilly, May 1998,
   ISBN 1-56592-520-3. The machine that made 56 bits a matter of days.
9. Paul C. van Oorschot and Michael J. Wiener, "A Known-Plaintext Attack on
   Two-Key Triple Encryption", *Advances in Cryptology — EUROCRYPT '90*,
   Lecture Notes in Computer Science 473, pp. 318–325, 1991.
   <https://doi.org/10.1007/3-540-46877-3_29>.
10. Karthikeyan Bhargavan and Gaëtan Leurent, "On the Practical (In-)Security
    of 64-bit Block Ciphers", *Proceedings of the 2016 ACM SIGSAC Conference
    on Computer and Communications Security*, pp. 456–467, October 2016.
    <https://doi.org/10.1145/2976749.2978423>. The birthday bound, known as
    Sweet32.
11. Yukiyasu Tsunoo, Teruo Saito, Tomoyasu Suzaki, Maki Shigeri and Hiroshi
    Miyauchi, "Cryptanalysis of DES Implemented on Computers with Cache",
    *Cryptographic Hardware and Embedded Systems — CHES 2003*, Lecture Notes
    in Computer Science 2779, pp. 62–76, 2003.
    <https://doi.org/10.1007/978-3-540-45238-6_6>. Key recovery from the
    S-box lookups' cache behaviour, which is what the constant-time S-boxes
    are for.
12. Oscar Reparaz, Josep Balasch and Ingrid Verbauwhede, "Dude, is my code
    constant time?", *Design, Automation & Test in Europe (DATE) 2017*; IACR
    Cryptology ePrint Archive, Report 2016/1123.
    <https://eprint.iacr.org/2016/1123>. The test that `zig build timing`
    runs.
13. The OpenSSL Project, *OpenSSL* 3.6.3, `openssl enc` with the legacy
    provider. <https://www.openssl.org/>. The independent implementation
    every vector was checked against.

## Licence

MIT. See `LICENSES/MIT.txt`.
