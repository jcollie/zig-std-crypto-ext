<!--
SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
SPDX-License-Identifier: MIT
-->

# zig-des

DES, Triple DES, and the block cipher modes `std.crypto` leaves out — CBC, CFB
and ECB, generic over any block cipher.

The API documentation is generated from the doc comments, which carry most of
the explanation, and is published at
**<https://jeff.jcollie.page/zig-des/>**.

```console
$ git clone https://git.jcollie.dev/jeff/zig-des.git
$ cd zig-des
$ nix develop -c zig build test
```

## Where this lives

Two homes, with the same history in both.

* Forgejo, at <https://git.jcollie.dev/jeff/zig-des>, which is where the
  workflow runs and where the documentation is published from.
* [Tangled](https://tangled.org/), at
  <https://tangled.org/jcollie.dev/zig-des>.

## Why this exists

⚠️ **Everything here is obsolete, and that is the point.** Single DES has a
56-bit key and has been brute-forceable since 1998. Two-key Triple DES has a
meet-in-the-middle attack, and the 64-bit block gives a birthday bound around
32 GiB under one key however long the key is. CBC and CFB authenticate nothing
and CBC has a long history of padding oracles. **Nothing new should choose any
of it.**

What keeps it alive is equipment that already exists. SNMPv3's
`usmDESPrivProtocol` (RFC 3414) is DES-CBC and is still the default privacy
protocol on a great deal of network hardware, so a manager that cannot speak it
cannot talk to those devices at all. Kerberos 4, PKCS#12, MS-CHAP and a good
deal of banking hardware are in the same position. `std.crypto` quite reasonably
declines to ship any of this; this library is where it goes instead, clearly
labelled.

The modes are here for a second reason: `std.crypto.modes` has only counter
mode, and RFC 3826 specifies **AES**-128 in full-block CFB for SNMPv3. So one
library has to supply a cipher `std` omits and a mode `std` omits, for two
different ciphers — which is why `modes` is generic over the cipher rather than
tied to DES.

## What is here

| | |
| --- | --- |
| `Des` | Single DES. `initEnc`/`initDec` return contexts with a `block_length` and `encrypt`/`decrypt` over one block. |
| `Des3` | Triple DES in EDE order, three-key and two-key (`initEnc2`). Three equal keys make it identical to single DES, which is what the middle decryption is for. |
| `modes.cbcEncrypt`, `cbcDecrypt` | Cipher Block Chaining. Whole blocks only; choosing a padding is the caller's business, because the padding belongs to whatever specification sent them here. |
| `modes.cfbEncrypt`, `cfbDecrypt` | Cipher Feedback with full-block feedback — "CFB128" for a 128-bit cipher. A stream mode, so any length, and it runs the cipher *forwards* in both directions, so both take an encryption context. |
| `modes.ecbEncrypt`, `ecbDecrypt` | Each block alone. Leaks which plaintext blocks are equal; present because key-wrapping constructions and test vectors are stated in terms of it. |
| `weak_keys`, `isWeak` | The four keys for which DES is an involution. A password-derived key can be one by accident, and `usmDESPrivProtocol` derives its key from a password. |
| `hasOddParity`, `setOddParity` | The parity convention DES keys are distributed under. The cipher ignores the parity bits entirely — that is what "56-bit key" means. |

## Using it

```console
$ zig fetch --save git+https://git.jcollie.dev/jeff/zig-des.git
```

```zig
const des = @import("des");

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
```

**Every vector was cross-checked against OpenSSL's legacy provider**, not
transcribed and trusted:

```console
$ openssl enc -provider legacy -provider default -des-ecb -nopad -K <key> -in pt.bin
```

That is not belt-and-braces. A DES that is self-consistent and *wrong* is easy
to write — index the S-boxes with the raw six input bits rather than the
published row and column and it still round-trips perfectly — and that is
precisely the bug that occurred here. A round-trip test proves almost nothing,
so the known-answer tests are the real ones: FIPS 46-3, Rivest's cycle, the NBS
samples, and NIST SP 800-38A F.3.13 for AES-128-CFB. One of the four NBS values
was wrong when first written, and OpenSSL is what settled which of us was.

The fuzz targets are round-trip properties over the *modes*, where there is
real room to be wrong — an off-by-one on a final partial block, a chaining
value read after being overwritten by an in-place operation, a keystream that
wrongly depends on how much plaintext follows. They also assert the properties
no single vector can: that the parity bits never change the ciphertext, that
three equal keys make 3DES into DES, and that a weak key is an involution, for
every key and block rather than for one.

## The API documentation

```console
$ nix develop -c zig build docs         # into zig-out/docs
$ nix develop -c zig build docs-serve   # http://127.0.0.1:8000
```

## Licence

MIT. See `LICENSES/MIT.txt`.
