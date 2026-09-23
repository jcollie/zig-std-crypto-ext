# SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

{
  lib,
  stdenv,
  zig_0_16,
}:

stdenv.mkDerivation {
  pname = "zig-std-crypto-ext";
  version = "0.0.0";

  # Named rather than filtered, so that editing something outside this list --
  # the flake, a scratch file, a note -- does not rebuild.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./build.zig
      ./build.zig.zon
      ./src
      ./tests
      ./tools
      ./LICENSES
      ./README.md
      ./REUSE.toml
    ];
  };

  nativeBuildInputs = [ zig_0_16 ];

  # No `zigBuildFlags = [ "--system" ... ]` here, and none needed: the
  # manifest names no dependencies, so the build fetches nothing and the
  # sandbox has nothing to be denied.

  # This is the whole point of the derivation. A library installs no binary --
  # `$out` ends up holding only the documentation -- so what is being checked
  # is that every module compiles and every test passes.
  doCheck = true;

  # `zig build` here installs the API documentation and nothing else, since
  # there is no artifact to install. That makes the package useful for the
  # workflow's publish job as well as for `nix flake check`.
  buildPhase = ''
    runHook preBuild
    zig build docs --prefix "$out" --cache-dir "$TMPDIR/zig-cache" \
      --global-cache-dir "$TMPDIR/zig-global-cache"
    runHook postBuild
  '';

  checkPhase = ''
    runHook preCheck
    zig build test --summary all --cache-dir "$TMPDIR/zig-cache" \
      --global-cache-dir "$TMPDIR/zig-global-cache"
    zig build check --cache-dir "$TMPDIR/zig-cache" \
      --global-cache-dir "$TMPDIR/zig-global-cache"
    runHook postCheck
  '';

  # `zig build docs --prefix` has already put everything in place.
  installPhase = ''
    runHook preInstall
    runHook postInstall
  '';

  meta = {
    description = "The ciphers, modes and primitives std.crypto leaves out: DES, Triple DES, AES-192, CBC, CFB, ECB, RSA signing, HChaCha20";
    homepage = "https://git.jcollie.dev/jeff/zig-std-crypto-ext";
    license = lib.licenses.mit;
    platforms = lib.platforms.all;
  };
}
