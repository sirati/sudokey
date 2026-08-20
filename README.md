# sudokey

A minimal root "broker". You start it once as **root** on a server; it then lets
an **unprivileged** client run commands and open interactive shells **as root** —
but only after the client proves control of an authorized SSH private key via a
forwarded SSH agent. This removes the need for interactive `sudo` on remote
servers you control.

The gate is cryptographic: on every connection the server sends a random 32-byte
nonce, the client signs `"sudokey-auth-v1" || nonce` with each ed25519 identity
in its agent, and the server grants access only if one of those keys is in its
`authorized_keys` file **and** the signature verifies (`verify_strict`). The
per-connection random nonce prevents replay.

- Single **static** `x86_64-unknown-linux-musl` binary — no libc/OpenSSL runtime
  dependency, runs unchanged on Debian 11 (glibc 2.31) and NixOS.
- Pure-Rust crypto (`ed25519-dalek`), no OpenSSL, no `ring`.
- **No `unsafe` in this crate**: the pty is handled by `portable-pty`, terminal
  raw-mode/winsize/euid/signalling by `rustix`, signal handling by `signal-hook`.
- Ships a Nix package, a NixOS module with a systemd service, and a plain
  `sudokey.service` for everything else.

## Install

### NixOS (flake)

```nix
{
  inputs.sudokey.url = "github:sirati/sudokey";

  outputs = { nixpkgs, sudokey, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        sudokey.nixosModules.default
        {
          services.sudokey = {
            enable = true;
            # `sudokey list-keys` on the client prints these lines.
            authorizedKeys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... laptop"
            ];
          };
        }
      ];
    };
  };
}
```

That installs the binary, writes `/etc/sudokey/authorized_keys`, and starts a
`sudokey.service` listening on `/run/sudokey.sock` as `root:wheel` mode `0660`.
Changing `authorizedKeys` and rebuilding takes effect immediately — the daemon
re-reads the file, so adding or revoking a key never disturbs live sessions.

Options: `package`, `authorizedKeys`, `authorizedKeysFile`, `autoStart`, `socketPath`,
`socketMode`, `socketGroup`, `maxConnections`, `maxConnectionsPerUid`,
`authTimeout`, `commandPath`, `extraArgs`. See `nix/module.nix`.

There is also `sudokey.overlays.default` (giving `pkgs.sudokey`) and
`nix run github:sirati/sudokey -- list-keys`.

### Anywhere else

```sh
nix build github:sirati/sudokey        # or see "Build from source" below
install -m 755 result/bin/sudokey /usr/local/bin/sudokey
install -m 644 systemd/sudokey.service /etc/systemd/system/
groupadd -f sudokey && usermod -aG sudokey youruser
systemctl daemon-reload && systemctl enable --now sudokey
```

Set up the key file first (see below), or the service will refuse to start.

### Build from source

```sh
nix develop -c cargo build --release --target x86_64-unknown-linux-musl
```

Result: `target/x86_64-unknown-linux-musl/release/sudokey`, statically linked
and stripped. Static link flags live in `.cargo/config.toml`.

`nix flake check` builds both the static and dynamic packages, runs clippy and
rustfmt, and boots a NixOS VM that exercises the module end to end.

## Operator setup

1. **On the client**, list the ed25519 public keys held by your SSH agent in
   `authorized_keys` format:

   ```sh
   sudokey list-keys
   # ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... Personal Devices
   ```

2. **On the server**, save the line(s) you want to authorize. On NixOS use
   `services.sudokey.authorizedKeys`; otherwise:

   ```sh
   sudo install -d -m 700 /root/.config/sudokey
   sudo tee /root/.config/sudokey/authorized_keys > /dev/null <<'EOF'
   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... Personal Devices
   EOF
   sudo chmod 600 /root/.config/sudokey/authorized_keys
   ```

   Like OpenSSH's StrictModes, the server refuses to start unless the key file
   **and every directory above it** are owned by root (or the running user) and
   not writable by group or other. A group-writable directory is accepted only
   when it is sticky, since the sticky bit is what prevents a non-owner
   replacing the file — this is what allows key files provisioned through Nix,
   as `/nix/store` is mode `1775`.

3. **Start the daemon.** Under systemd use the unit; by hand:

   ```sh
   sudo sudokey serve
   # sudokey: loaded 1 authorized ed25519 key(s) from /root/.config/sudokey/authorized_keys
   # sudokey: listening on /run/sudokey.sock (mode 666) as uid 0; max 128 connections (32 per uid)
   ```

   `sudokey serve --help` lists every flag. Signals: `SIGHUP` re-reads the key
   file, `SIGINT`/`SIGTERM` remove the socket and exit.

## Client usage

With your SSH agent forwarded (`ssh -A`) and holding an authorized ed25519 key:

```sh
# Non-interactive, piped I/O. Streams stdout/stderr, forwards stdin,
# exits with the command's exit code. Primary mode for automation.
sudokey run -- id
sudokey run -- systemctl restart nginx
echo "data" | sudokey run -- tee /root/file

# Interactive shell / command over a pty. Window resizes are forwarded.
sudokey shell               # root login shell
sudokey shell -- top

# Both accept --socket PATH (default /run/sudokey.sock, or $SUDOKEY_SOCKET).
sudokey run --socket /run/sudokey.sock -- whoami
```

Commands run with a **reset environment** (`sudo`'s `env_reset`): a fixed
`PATH`, `HOME`/`SHELL`/`USER`/`LOGNAME` for root, locale variables from the
daemon's own environment, `TERM` for pty sessions, plus `SUDOKEY_UID` and
`SUDOKEY_KEY` naming the caller. Nothing from the client's environment is
carried across. The working directory is root's home, so **use absolute paths** —
the protocol carries no working directory.

Disconnecting terminates the remote command (`SIGTERM`, then `SIGKILL` after
five seconds) rather than orphaning a root process.

## Protocol (summary)

Unix socket, one connection per client. All integers big-endian; SSH-style
strings are `u32` length + bytes.

1. Server → client: 4-byte magic `SDKY`, 1 version byte, 32-byte nonce.
2. Client → server: `u32` count, then `(key_blob, sig_blob)` pairs. The client
   signs `CONTEXT || nonce` with every ed25519 identity in its agent.
3. Server → client: 1 status byte (1 = ok, 0 = deny). On deny it closes.
4. Client → server: mode byte (0 = exec, 1 = pty), `u32` argc + args; for pty
   also `u16` cols, `u16` rows, and a TERM string.
5. Multiplexed frames `[u8 channel][u32 len][payload]`:
   `0` stdin (c→s), `1` stdout (s→c), `2` stderr (s→c, exec),
   `3` i32 exit status (s→c), `4` winsize cols/rows (c→s, pty),
   `5` stdin-EOF (c→s). All lengths are bounded.
6. The client exits with the child's exit code.

Steps 1–4 run under a single deadline (`--auth-timeout`, default 10s) and tight
per-field size bounds; argv is carried as raw bytes, so non-UTF-8 arguments
reach the command unchanged.

The SSH agent is spoken directly over `$SSH_AUTH_SOCK`
(`REQUEST_IDENTITIES` / `SIGN_REQUEST`).

## Security notes

- Anyone whose public key is in `authorized_keys` gets a **full root shell** —
  treat that file exactly like `sudoers`. Equally, any process that can reach
  your ssh-agent can obtain root through this daemon, so forward your agent
  only to hosts you trust.
- The socket mode controls who can *connect*; the ed25519 challenge is the
  authorization gate. The NixOS module still restricts the socket to
  `root:wheel` `0660` by default, so unrelated local accounts cannot spend the
  daemon's connection budget at all. The bare CLI default remains `0666`; pass
  `--socket-group GROUP --socket-mode 0660` to tighten it.
- Only ed25519 keys are supported (RSA is intentionally skipped).
- Every granted and denied connection is logged with the peer's kernel-attested
  uid/gid/pid and the SHA256 fingerprint of the key that authorised it,
  alongside the command. Under systemd these carry syslog priorities, so
  `journalctl -u sudokey -p notice` shows the audit trail.
- Concurrent connections are capped in total and per peer uid, and the
  handshake runs under a deadline, so an unprivileged local user cannot exhaust
  the daemon's threads or descriptors and lock everyone else out.
- Commands are **not** sandboxed, and the systemd units deliberately set no
  `ProtectSystem`/`NoNewPrivileges`/`ProtectKernel*` directives: those are
  inherited by the root commands the broker exists to run, and a sandbox you
  must disable to do the job reads as protection that is not there. For the
  same reason, resource limits set on the unit apply to every command run
  through it.

## Changes in 0.2

- **Fixed: the daemon could be running, with its socket present, while every
  client hung or was refused.** Connections had no timeout and no cap, so a few
  hundred that never spoke exhausted the process's descriptor table; `accept()`
  then failed forever, and the accept loop retried it in a tight spin that
  pegged a CPU and flooded the journal. Connections are now capped in total and
  per uid, the handshake runs under a deadline, accept errors back off, and
  repeated failures are rate-limited in the log.
- A second `sudokey serve` no longer silently steals a running daemon's socket;
  it refuses to start. Stale sockets are still cleaned up.
- The socket is created unreachable and only opened up once its group and mode
  are set, then renamed into place — no window at the ambient umask.
- `authorized_keys` is re-read when it changes and on `SIGHUP`, so revoking a
  key no longer requires a restart. StrictModes now checks every parent
  directory, not just the file.
- Children get a reset environment, a fixed `PATH`, a deterministic working
  directory, their own process group, and are terminated when their client
  disconnects instead of being orphaned.
- argv is no longer mangled through lossy UTF-8 conversion, and the client no
  longer panics on a non-UTF-8 argument.
- Terminal resizes are forwarded (the `CH_WINCH` channel existed but nothing
  ever sent on it), and raw mode is entered before stdin is read.
- The release profile no longer sets `panic = "abort"`: a panic in one
  connection handler used to take the whole broker down.
