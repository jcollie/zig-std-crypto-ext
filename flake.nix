# SPDX-FileCopyrightText: © 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

{
  description = "zig-std-crypto-ext";

  inputs = {
    nixpkgs = {
      url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    };
    # The toolchain is the official 0.17.0 release binary, packaged by the
    # overlay; nixpkgs has no Zig 0.17.
    zig = {
      url = "git+https://git.jcollie.dev/jeff/zig-overlay.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The library still depends on nothing beyond `std`; the one entry in
    # build.zig.zon is CPace's test vectors, which the tests -- and so the
    # package's check phase -- need in a sandbox that cannot fetch them.
    zon2nix = {
      url = "github:jcollie/zon2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      zig,
      zon2nix,
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
      zigFor = pkgs: zig.packages.${pkgs.stdenv.hostPlatform.system}."0.17.0";

      # zon2nix shells out to `zig env`, and without a Zig on PATH it prints
      # "unable to execute zig, is it in your PATH?" and stops having written
      # nothing -- which leaves the previous build.zig.zon.nix in place looking
      # untouched rather than obviously broken. Wrap it so the Zig it finds is
      # this project's.
      wrappedZon2nix =
        pkgs:
        pkgs.symlinkJoin {
          name = "zon2nix";
          paths = [ zon2nix.packages.${pkgs.stdenv.hostPlatform.system}.zon2nix ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postBuild = ''
            wrapProgram $out/bin/zon2nix \
              --prefix PATH : ${lib.makeBinPath [ (zigFor pkgs) ]}
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
          zig-std-crypto-ext = pkgs.callPackage ./package.nix { zig = zigFor pkgs; };
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
          zig-std-crypto-ext = pkgs.callPackage ./package.nix { zig = zigFor pkgs; };
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
              (zigFor pkgs)
              (wrappedZon2nix pkgs)
              pkgs.git-pages-cli
              pkgs.pinact
              pkgs.reuse
            ];
          };
        }
      );
    };
}
