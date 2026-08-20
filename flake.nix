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
  }: let
    systems = ["x86_64-linux"];

    perSystem = flake-utils.lib.eachSystem systems (system: let
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
        sudokey = pkgs.callPackage ./nix/package.nix {};
        # Dynamically linked against this system's glibc. Builds faster and is
        # what you want when the binary never leaves the machine that built it.
        sudokey-dynamic = pkgs.callPackage ./nix/package.nix {static = false;};
        default = self.packages.${system}.sudokey;
      };

      apps.default = flake-utils.lib.mkApp {
        drv = self.packages.${system}.sudokey;
        name = "sudokey";
      };

      checks = {
        static = self.packages.${system}.sudokey;
        dynamic = self.packages.${system}.sudokey-dynamic;

        # Derived from the package so it reuses the vendored dependency tree
        # rather than trying to reach the network from a sandboxed build.
        clippy = self.packages.${system}.sudokey-dynamic.overrideAttrs (old: {
          pname = "sudokey-clippy";
          nativeBuildInputs = (old.nativeBuildInputs or []) ++ [pkgs.clippy];
          buildPhase = "cargo clippy --release --all-targets -- -D warnings";
          installPhase = "touch $out";
          doCheck = false;
        });

        fmt =
          pkgs.runCommand "sudokey-fmt" {
            nativeBuildInputs = [pkgs.rustfmt];
          } ''
            rustfmt --check --edition 2021 ${self}/src/*.rs
            touch "$out"
          '';

        # Boots a real NixOS machine running the module and drives it as an
        # unprivileged user. Needs KVM, so it is the slow one.
        nixos = pkgs.callPackage ./nix/vm-test.nix {
          module = self.nixosModules.sudokey;
          package = self.packages.${system}.sudokey;
        };
      };

      formatter = pkgs.alejandra;
    });
  in
    perSystem
    // {
      overlays.default = final: prev: {
        sudokey = final.callPackage ./nix/package.nix {};
      };

      # Usable without the overlay: it pins `services.sudokey.package` to this
      # flake's build for the host system.
      nixosModules.sudokey = {
        pkgs,
        lib,
        ...
      }: {
        imports = [./nix/module.nix];
        services.sudokey.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.sudokey;
      };
      nixosModules.default = self.nixosModules.sudokey;
    };
}
