# sudokey, built as a fully static musl binary by default.
#
# Static matters here because the daemon is copied to servers that are not
# NixOS: a static binary runs unchanged on Debian 11 (glibc 2.31) with no
# runtime dependency to install. It is also why the code reads /etc/passwd
# directly instead of calling getpwuid — a static musl binary has no NSS.
{
  lib,
  stdenv,
  pkgsStatic,
  rustPlatform,
  static ? true,
}: let
  platform =
    if static
    then pkgsStatic.rustPlatform
    else rustPlatform;
in
  platform.buildRustPackage {
    pname = "sudokey";
    version = (lib.importTOML ../Cargo.toml).package.version;

    src = lib.cleanSourceWith {
      src = ../.;
      filter = path: type: let
        base = baseNameOf path;
      in
        !(builtins.elem base ["target" ".kache-store" ".git" "result"]);
    };

    cargoLock.lockFile = ../Cargo.lock;

    # There are no tests; saying so is quicker than discovering it per build.
    doCheck = false;

    meta = {
      description = "Minimal SSH-agent-authenticated root command broker over a unix socket";
      homepage = "https://github.com/sirati/sudokey";
      license = lib.licenses.mit;
      mainProgram = "sudokey";
      platforms = lib.platforms.linux;
      broken = static && !stdenv.hostPlatform.isLinux;
    };
  }
