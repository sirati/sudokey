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

      with subtest("an unauthorized key is refused even from inside the group"):
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
