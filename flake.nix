{
  description = "sudokey - ssh-agent-authenticated root command broker";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # toolchain-with-extra-targets pattern, same as the HelpNLearn workspace
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # lets shell.nix reuse the flake's devShell via nix-shell
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    # Content-addressed compilation cache, wired as RUSTC_WRAPPER below.
    # `follows` so kache is built against this flake's nixpkgs rather than a
    # second copy of it.
    kache = {
      url = "github:sirati/nix-drv-kache";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    kache,
    ...
  }:
    flake-utils.lib.eachSystem ["x86_64-linux"] (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default kache.overlays.default];
      };

      # Stable toolchain from the nix store, carrying the musl target so the
      # binary can be built fully static (self-contained, no libc dependency).
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = ["clippy" "rust-src" "rustfmt"];
        targets = ["x86_64-unknown-linux-musl"];
      };

      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };
    in {
      # `withKache` adds the kache package, sets RUSTC_WRAPPER to it, and emits
      # a shellHook writing a gitignored .kache.toml. The store lands in
      # .kache-store at the root of this checkout, which keeps it on the same
      # filesystem as target/ -- a reflink cannot cross one, and a store on the
      # wrong filesystem turns every zero-copy restore into a full copy without
      # saying so.
      devShells.default = pkgs.mkShell (kache.lib.withKache
        {inherit (pkgs) kache;}
        {
          packages = [
            rustToolchain
            pkgs.rust-analyzer
            # cc is used as the linker driver; rust supplies the self-contained
            # musl startfiles for the static target.
            pkgs.stdenv.cc
          ];

          env = {
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            # Static musl link flags live in .cargo/config.toml so both the dev
            # shell and `nix build` pick them up.
          };
        });

      devShell = self.devShells.${system}.default;

      packages = {
        sudokey = rustPlatform.buildRustPackage {
          pname = "sudokey";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          target = "x86_64-unknown-linux-musl";
          doCheck = false;
        };
        default = self.packages.${system}.sudokey;
      };
    });
}
