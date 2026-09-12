# SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

{
  description = "zig-std-crypto-ext";

  inputs = {
    nixpkgs = {
      url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    };
  };

  # No `zon2nix` input, and no `build.zig.zon.nix`: this library has no
  # dependencies beyond `std`, so there is nothing for a sandboxed build to
  # fetch and nothing to generate. Add both back the day that changes.

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      makePackages =
        system:
        import nixpkgs {
          inherit system;
        };
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;

      # The devshell's Zig, with one line of its own standard library put
      # right, because without it `zig build fuzz --fuzz` cannot compile.
      #
      # Zig 0.16.0's `compiler/test_runner.zig` reports a failing fuzz input by
      # asking `std.debug.writeStackTrace` to print what `@errorReturnTrace()`
      # gave it. Those are two different types: an error return trace is a
      # `builtin.StackTrace`, a ring buffer with a write index, and that
      # function takes a `debug.StackTrace`, which is a plain slice and a count
      # of what was skipped. It is a type error, it is on the path taken only
      # under `-ffuzz`, and it stops *any* project with a fuzz test in it from
      # building one. The fix is the function next door: `writeErrorReturnTrace`
      # takes exactly the type in hand and is what the other three places in
      # the same file use.
      #
      # `--replace-fail` is the whole safety of this: the day Zig ships the fix
      # the pattern will not be found, the build will fail here rather than
      # patch something else, and this can go.
      #
      # It buys the fuzzer and not its coverage. Nothing in this release
      # populates the table of program counters, so a bounded run ends with
      # "corrupted coverage file: pcs_len was zero" and an unbounded one
      # panics in the build runner's coverage thread; neither is a finding,
      # and a finding says "input saved to" above the report. The properties in
      # `tests/fuzz.zig` run as ordinary tests either way, and `zig build
      # fuzz-run` drives them from a loop of our own.
      fuzzableZig =
        pkgs:
        let
          # A farm of symlinks rather than a copy: the library is 217 MB, and
          # exactly one file of it is being changed.
          library = pkgs.runCommand "zig-0.16.0-lib-fuzz-fix" { } ''
            cp -rs --no-preserve=mode ${pkgs.zig_0_16}/lib/zig $out
            chmod -R u+w $out
            rm $out/compiler/test_runner.zig
            cp --no-preserve=mode \
              ${pkgs.zig_0_16}/lib/zig/compiler/test_runner.zig \
              $out/compiler/test_runner.zig
            substituteInPlace $out/compiler/test_runner.zig \
              --replace-fail \
                'std.debug.writeStackTrace(trace, stderr)' \
                'std.debug.writeErrorReturnTrace(trace, stderr)'
          '';
        in
        pkgs.symlinkJoin {
          name = "zig-0.16.0-fuzzable";
          paths = [ pkgs.zig_0_16 ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postBuild = ''
            wrapProgram $out/bin/zig --set ZIG_LIB_DIR ${library}
          '';
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        rec {
          zig-std-crypto-ext = pkgs.callPackage ./package.nix { };
          default = zig-std-crypto-ext;
        }
      );

      # A Zig library is source, so the package exists to be *run* rather than
      # installed: it compiles every module and runs every test, which is the
      # only thing there is to check here. There are no virtual machine tests
      # -- nothing in this library does any I/O worth booting a guest for.
      checks = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        {
          zig-std-crypto-ext = pkgs.callPackage ./package.nix { };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        {
          default = pkgs.mkShell {
            name = "zig-std-crypto-ext";
            nativeBuildInputs = [
              (fuzzableZig pkgs)
              pkgs.git-pages-cli
              pkgs.pinact
              pkgs.reuse
            ];
          };
        }
      );
    };
}
