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
  raw-mode/winsize/euid by `rustix`, and signal teardown by `signal-hook`.

## Build

The dev machine is set up with a Nix flake that provides a Rust toolchain with
the `x86_64-unknown-linux-musl` target. One command:

```sh
nix develop -c cargo build --release --target x86_64-unknown-linux-musl
```

Result: `target/x86_64-unknown-linux-musl/release/sudokey`

```
$ file target/x86_64-unknown-linux-musl/release/sudokey
... ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Static linking flags live in `.cargo/config.toml`
(`target-feature=+crt-static`, `relocation-model=static`).

## Operator setup (on the server, as root)

1. **On the client**, list the ed25519 public keys held by your SSH agent in
   `authorized_keys` format:

   ```sh
   sudokey list-keys
   # ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... Personal Devices
   ```

2. **On the server**, save the line(s) you want to authorize into the root-owned
   key file (mode 600):

   ```sh
   sudo install -d -m 700 /root/.config/sudokey
   sudo tee /root/.config/sudokey/authorized_keys > /dev/null <<'EOF'
   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... Personal Devices
   EOF
   sudo chmod 600 /root/.config/sudokey/authorized_keys
   ```

   The server refuses to start (like OpenSSH StrictModes) if this file is
   group- or world-writable, or is owned by neither root nor the running user.

3. **Start the daemon** as root:

   ```sh
   sudo sudokey serve
   # sudokey: loaded 1 authorized ed25519 key(s) from /root/.config/sudokey/authorized_keys
   # sudokey: listening on /run/sudokey.sock (mode 666) as uid 0
   ```

   Flags: `--authorized PATH` (default `/root/.config/sudokey/authorized_keys`),
   `--socket PATH` (default `/run/sudokey.sock`), `--socket-mode MODE` (default
   `0666`). The socket is unlinked on start and removed on SIGINT/SIGTERM.

## Client usage

With your SSH agent forwarded (`ssh -A`) and holding an authorized ed25519 key:

```sh
# Non-interactive, piped I/O. Streams stdout/stderr, forwards stdin,
# exits with the command's exit code. Primary mode for automation.
sudokey run -- id
sudokey run -- systemctl restart nginx
echo "data" | sudokey run -- tee /root/file

# Interactive shell / command over a pty.
sudokey shell               # root login shell
sudokey shell -- top

# Both accept --socket PATH (default /run/sudokey.sock).
sudokey run --socket /run/sudokey.sock -- whoami
```

`sudokey --help` and `sudokey <subcommand> --help` describe all options.

## Protocol (summary)

Unix socket, one connection per client. All integers big-endian; SSH-style
strings are `u32` length + bytes.

1. Server -> client: 4-byte magic `SDKY`, 1 version byte, 32-byte nonce.
2. Client -> server: `u32` count, then `(key_blob, sig_blob)` pairs. The client
   signs `CONTEXT || nonce` with every ed25519 identity in its agent.
3. Server -> client: 1 status byte (1 = ok, 0 = deny). On deny it closes.
4. Client -> server: mode byte (0 = exec, 1 = pty), `u32` argc + args; for pty
   also `u16` cols, `u16` rows, and a TERM string.
5. Multiplexed frames `[u8 channel][u32 len][payload]`:
   `0` stdin (c→s), `1` stdout (s→c), `2` stderr (s→c, exec),
   `3` i32 exit status (s→c), `4` winsize cols/rows (c→s, pty),
   `5` stdin-EOF (c→s). All lengths are bounded.
6. The client exits with the child's exit code.

The SSH agent is spoken directly over `$SSH_AUTH_SOCK`
(`REQUEST_IDENTITIES` / `SIGN_REQUEST`).

## Security notes

- The socket mode (default 0666) only controls who can *connect*; the ed25519
  challenge is the real authorization gate. A random nonce per connection makes
  captured handshakes non-replayable.
- Only ed25519 keys are supported (RSA is intentionally skipped).
- Anyone whose public key is in `authorized_keys` gets a **full root shell** —
  treat that file exactly like `sudoers`.
