# End-to-end NixOS test: boot a machine running the sudokey module and drive it
# from an unprivileged account with an agent, the way it is actually used.
#
# This is what proves the module, the unit and the client agree with each other.
# Unit tests of the wire format would not have caught the socket permissions,
# the StrictModes walk over /nix/store, or the connection-flood behaviour that
# made the daemon unreachable in the first place.
{
  pkgs,
  module,
  package,
}: let
  # A throwaway keypair, committed on purpose: the daemon needs a valid key file
  # at boot, before anything inside the VM could generate one.
  testKeyPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO6Ti57yEyBMoLag9Ld1b6/ghx593oLQKKDUj4Gb8YXA sudokey-vm-test";
  testKeyPriv = pkgs.writeText "sudokey-test-key" ''
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDuk4ue8hMgTKC2oPS3dW+v4Icefd6C0Cig1I+Bm/GFwAAAAJh8cQv2fHEL
    9gAAAAtzc2gtZWQyNTUxOQAAACDuk4ue8hMgTKC2oPS3dW+v4Icefd6C0Cig1I+Bm/GFwA
    AAAECDw3hseAA4wRwFlv2PCWU06b5YTVVbu8xARcNZz+/s1u6Ti57yEyBMoLag9Ld1b6/g
    hx593oLQKKDUj4Gb8YXAAAAAD3N1ZG9rZXktdm0tdGVzdAECAwQFBg==
    -----END OPENSSH PRIVATE KEY-----
  '';

  # All shell fragments live in their own scripts rather than inline in the
  # Python test script: a bare pair of single quotes (`ssh-keygen -N ''`) is the
  # escape character inside a Nix indented string and silently mangles it.
  withAgent = pkgs.writeShellScript "sudokey-with-agent" ''
    set -eu
    install -d -m 700 "$HOME/.ssh"
    install -m 600 "$1" "$HOME/.ssh/key"
    eval "$(${pkgs.openssh}/bin/ssh-agent -s)" >/dev/null
    ${pkgs.openssh}/bin/ssh-add "$HOME/.ssh/key" 2>/dev/null
    shift
    "$@"
  '';

  makeStrayKey = pkgs.writeShellScript "sudokey-stray-key" ''
    set -eu
    rm -f /tmp/stray /tmp/stray.pub
    ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -C stray -f /tmp/stray
    chmod 644 /tmp/stray
  '';

  # A transparent ssh-agent proxy that counts what passes through it. No
  # crypto: it forwards bytes to the real agent and parses only the
  # length-prefixed framing, so the tally is exactly what the agent was asked
  # to do. Written with writeScript rather than writePython3 to skip the
  # flake8 wrapper.
  agentProxy = pkgs.writeScript "sudokey-agent-proxy" ''
    #!${pkgs.python3}/bin/python3
    import os, socket, struct, sys, threading

    LISTEN, UPSTREAM, COUNTFILE = sys.argv[1], sys.argv[2], sys.argv[3]
    counts = {"list": 0, "sign": 0}
    lock = threading.Lock()

    def up_pump(src, dst):
        buf = b""
        while True:
            try:
                chunk = src.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 4:
                n = struct.unpack(">I", buf[:4])[0]
                if len(buf) < 4 + n:
                    break
                body, buf = buf[4:4 + n], buf[4 + n:]
                if body:
                    with lock:
                        if body[0] == 13:
                            counts["sign"] += 1
                        elif body[0] == 11:
                            counts["list"] += 1
            try:
                dst.sendall(chunk)
            except OSError:
                break

    def down_pump(src, dst):
        while True:
            try:
                chunk = src.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            try:
                dst.sendall(chunk)
            except OSError:
                break

    def serve(conn):
        up = socket.socket(socket.AF_UNIX)
        up.connect(UPSTREAM)
        a = threading.Thread(target=up_pump, args=(conn, up), daemon=True)
        b = threading.Thread(target=down_pump, args=(up, conn), daemon=True)
        a.start(); b.start(); a.join()
        with lock:
            open(COUNTFILE, "w").write(str(counts["list"]) + " " + str(counts["sign"]))

    if os.path.exists(LISTEN):
        os.unlink(LISTEN)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(LISTEN)
    srv.listen(16)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
  '';

  # Loads four keys, only the third of which is authorized, and reports how
  # many signatures one `sudokey run` cost. Prints "<list> <sign>".
  countSignRequests = pkgs.writeShellScript "sudokey-count-sign-requests" ''
    set -eu
    export PATH="${pkgs.openssh}/bin:$PATH"
    d=$(mktemp -d)
    install -m 600 ${testKeyPriv} "$d/real"
    for n in d1 d2 d3; do ssh-keygen -q -t ed25519 -N "" -C "$n" -f "$d/$n"; done
    eval "$(ssh-agent -s)" >/dev/null
    for n in d1 d2 real d3; do ssh-add "$d/$n" 2>/dev/null; done

    # The proxy loops forever, so it must not inherit this script's stdout:
    # the test driver waits for the pipe to close, not merely for the shell to
    # exit, and a descriptor held open by a background process hangs the whole
    # run. This is exactly the failure sudokey's own exec mode drains for.
    ${agentProxy} "$d/proxy.sock" "$SSH_AUTH_SOCK" "$d/counts" >/dev/null 2>&1 </dev/null &
    proxy=$!
    trap 'kill $proxy $SSH_AGENT_PID 2>/dev/null || true' EXIT

    for _ in $(seq 50); do [ -S "$d/proxy.sock" ] && break; sleep 0.1; done
    SSH_AUTH_SOCK="$d/proxy.sock" sudokey run -- true || true
    sleep 1
    kill $proxy 2>/dev/null || true
    cat "$d/counts"
  '';

  # Open as many connections as we can and say nothing on any of them: the
  # original failure mode, where each one cost the daemon a thread and a
  # descriptor forever.
  flood = pkgs.writers.writePython3 "sudokey-flood" {} ''
    import socket
    import sys

    held = []
    for _ in range(300):
        try:
            c = socket.socket(socket.AF_UNIX)
            c.connect("/run/sudokey.sock")
            held.append(c)
        except OSError:
            break
    sys.stdout.write(str(len(held)))
  '';
in
  pkgs.testers.runNixOSTest {
    name = "sudokey";

    nodes.machine = {...}: {
      imports = [module];

      services.sudokey = {
        enable = true;
        inherit package;
        authorizedKeys = [testKeyPub];
      };

      # `alice` is in wheel and so may open the socket; `mallory` is not.
      users.users.alice = {
        isNormalUser = true;
        extraGroups = ["wheel"];
      };
      users.users.mallory.isNormalUser = true;

      environment.systemPackages = [pkgs.openssh];
      virtualisation.memorySize = 1024;
    };

    testScript = ''
      import datetime as dt
      import shlex

      WITH_AGENT = "${withAgent}"
      KEY = "${testKeyPriv}"

      def as_user(user, cmd, key=KEY):
          """Run a shell command as `user`, under an agent holding `key`."""
          inner = f"{WITH_AGENT} {key} sh -c {shlex.quote(cmd)}"
          return f"su - {user} -c {shlex.quote(inner)}"

      machine.wait_for_unit("sudokey.service")
      machine.wait_for_file("/run/sudokey.sock")

      with subtest("the socket is group-restricted, not world-writable"):
          mode = machine.succeed("stat -c '%a %U:%G' /run/sudokey.sock").strip()
          assert mode == "660 root:wheel", f"unexpected socket mode: {mode}"

      with subtest("an authorized user gets root"):
          out = machine.succeed(as_user("alice", "sudokey run -- id -u"))
          assert out.strip() == "0", f"expected uid 0, got {out!r}"

      with subtest("exit codes propagate"):
          out = machine.succeed(
              as_user("alice", "sudokey run -- sh -c 'exit 7'; echo rc=$?")
          )
          assert "rc=7" in out, f"exit code not propagated: {out!r}"

      with subtest("stdin is forwarded"):
          out = machine.succeed(as_user("alice", "echo ping | sudokey run -- cat"))
          assert out.strip() == "ping", f"stdin round-trip failed: {out!r}"

      with subtest("pty mode gets a real terminal"):
          out = machine.succeed(as_user("alice", "sudokey shell -- tty < /dev/null"))
          assert "/dev/pts/" in out, f"no pty allocated: {out!r}"

      with subtest("the child environment is reset, not inherited"):
          out = machine.succeed(
              as_user("alice", "EVIL=1 LD_PRELOAD=/evil.so sudokey run -- env")
          )
          assert "EVIL=" not in out, "client environment leaked into the root command"
          assert "LD_PRELOAD" not in out, "LD_PRELOAD leaked into the root command"
          assert "USER=root" in out, f"expected USER=root, got:\n{out}"
          assert "HOME=/root" in out, f"expected HOME=/root, got:\n{out}"

      with subtest("commands are audited with the key that authorised them"):
          machine.succeed(as_user("alice", "sudokey run -- true"))
          journal = machine.succeed("journalctl -u sudokey --no-pager")
          assert "audit:" in journal, "no audit records were written"
          assert "SHA256:" in journal, "audit records do not name the key"

      with subtest("a user outside the socket group cannot even connect"):
          err = machine.fail("su - mallory -c 'sudokey run -- id' 2>&1")
          assert "ermission denied" in err, f"unexpected failure mode: {err!r}"

      with subtest("only the key the server selects is ever signed with"):
          # The bug this guards: v1 asked the agent to sign with every ed25519
          # identity it held, so an agent that confirms before signing
          # (1Password, ssh-add -c) raised a prompt per key -- for keys with
          # nothing to do with sudokey -- on every single invocation.
          out = machine.succeed("su - alice -c ${countSignRequests}").strip().split()
          lists, signs = int(out[0]), int(out[1])
          assert signs == 1, f"expected exactly 1 signature, agent was asked for {signs}"
          assert lists == 1, f"expected exactly 1 identity listing, got {lists}"

      with subtest("an unauthorized agent is refused without signing at all"):
          machine.succeed("${makeStrayKey}")
          err = machine.fail(as_user("alice", "sudokey run -- id", key="/tmp/stray") + " 2>&1")
          assert "denied" in err, f"unexpected failure mode: {err!r}"

      with subtest("reload re-reads the key file without restarting the daemon"):
          before = machine.succeed("systemctl show -p MainPID --value sudokey").strip()
          machine.succeed("systemctl reload sudokey")
          machine.wait_until_succeeds(
              "journalctl -u sudokey --no-pager | grep -q reloaded"
          )
          after = machine.succeed("systemctl show -p MainPID --value sudokey").strip()
          assert before == after, "reload restarted the daemon instead of reloading it"
          machine.succeed(as_user("alice", "sudokey run -- true"))

      with subtest("a connection flood neither kills the daemon nor leaks descriptors"):
          opened = machine.succeed("su - alice -c ${flood}").strip()
          print(f"flood opened {opened} connections")
          machine.succeed("systemctl is-active sudokey")
          pid = machine.succeed("systemctl show -p MainPID --value sudokey").strip()
          fds = int(machine.succeed(f"ls /proc/{pid}/fd | wc -l"))
          assert fds < 100, f"daemon leaked descriptors after a flood: {fds}"
          # And once the handshake deadline has passed, service is normal again.
          machine.sleep(duration=dt.timedelta(seconds=12))
          machine.succeed(as_user("alice", "sudokey run -- true"))
    '';
  }
