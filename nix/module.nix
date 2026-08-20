# NixOS module for sudokey.
#
# Import it from the flake (`sudokey.nixosModules.default`), or directly if you
# apply `sudokey.overlays.default` so `pkgs.sudokey` exists.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.sudokey;

  declarative = cfg.authorizedKeys != [];

  # Keeping the path stable rather than baking a store path into ExecStart is
  # deliberate: the daemon re-reads its key file whenever the file changes, so a
  # key added or revoked through this option takes effect without restarting the
  # broker and cutting off live sessions.
  authorizedPath =
    if declarative
    then "/etc/sudokey/authorized_keys"
    else cfg.authorizedKeysFile;

  args =
    [
      "serve"
      "--authorized"
      authorizedPath
      "--socket"
      cfg.socketPath
      "--socket-mode"
      cfg.socketMode
      "--max-connections"
      (toString cfg.maxConnections)
      "--max-per-uid"
      (toString cfg.maxConnectionsPerUid)
      "--auth-timeout"
      (toString cfg.authTimeout)
      "--path"
      cfg.commandPath
    ]
    ++ lib.optionals (cfg.socketGroup != null) ["--socket-group" cfg.socketGroup]
    ++ cfg.extraArgs;
in {
  options.services.sudokey = {
    enable = lib.mkEnableOption "the sudokey root command broker";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sudokey;
      defaultText = lib.literalExpression "pkgs.sudokey";
      description = "The sudokey package to run.";
    };

    authorizedKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = lib.literalExpression ''
        [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... laptop" ]
      '';
      description = ''
        ed25519 public keys, in `authorized_keys` format, that may run commands
        as root. Get them with `sudokey list-keys` on the client.

        Every key listed here is equivalent to an unrestricted root shell, so
        treat this exactly as you would {file}`/etc/sudoers`.

        Setting this writes {file}`/etc/sudokey/authorized_keys` and points the
        daemon at it. Leave it empty to manage the file yourself and set
        {option}`services.sudokey.authorizedKeysFile` instead.
      '';
    };

    authorizedKeysFile = lib.mkOption {
      type = lib.types.path;
      default = "/root/.config/sudokey/authorized_keys";
      description = ''
        Key file to read when {option}`services.sudokey.authorizedKeys` is
        empty. The daemon refuses to start unless this file and every directory
        above it are owned by root and not writable by group or other.
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/sudokey.sock";
      description = "Unix socket clients connect to.";
    };

    socketMode = lib.mkOption {
      type = lib.types.str;
      default = "0660";
      example = "0666";
      description = ''
        Octal permissions for the socket.

        The default pairs with {option}`services.sudokey.socketGroup` so that
        only members of that group can even open a connection. The ed25519
        challenge is still the real authorisation gate — this is defence in
        depth, and it keeps unrelated local accounts from being able to spend
        the daemon's connection budget at all.
      '';
    };

    socketGroup = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "wheel";
      description = ''
        Group that owns the socket. Set to `null` to leave it owned by root's
        group, which with the default mode means only root can connect.
      '';
    };

    maxConnections = lib.mkOption {
      type = lib.types.ints.positive;
      default = 128;
      description = "Concurrent connections the daemon will accept.";
    };

    maxConnectionsPerUid = lib.mkOption {
      type = lib.types.ints.positive;
      default = 32;
      description = ''
        Concurrent connections allowed per connecting uid, so one account
        cannot consume the whole budget and lock everyone else out.
      '';
    };

    authTimeout = lib.mkOption {
      type = lib.types.ints.positive;
      default = 10;
      description = "Seconds a client gets to finish the handshake.";
    };

    commandPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin";
      description = ''
        `PATH` given to commands run as root. Built explicitly rather than
        inherited, so nothing in the daemon's own environment can decide which
        binary runs with root privileges.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Extra arguments appended to `sudokey serve`.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    environment.etc."sudokey/authorized_keys" = lib.mkIf declarative {
      text = lib.concatMapStrings (k: k + "\n") cfg.authorizedKeys;
      mode = "0444";
    };

    systemd.services.sudokey = {
      description = "sudokey ssh-agent-authenticated root command broker";
      documentation = ["https://github.com/sirati/sudokey"];
      wantedBy = ["multi-user.target"];
      after = ["network.target"];


      serviceConfig = {
        # `exec` rather than `simple`: systemd then reports a failure to even
        # start the binary, instead of calling the unit active regardless.
        Type = "exec";
        ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs args}";
        # SIGHUP re-reads the key file without disturbing live sessions.
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        RestartSec = "2s";

        SyslogIdentifier = "sudokey";

        # Only the broker itself is killed on stop/restart. Commands started
        # through it are long-lived root sessions and must survive a restart of
        # the broker, exactly as ssh sessions survive restarting sshd.
        KillMode = "process";

        # The daemon spends its life waiting on accept(); this is the ceiling on
        # descriptors it can hold, well above the connection cap.
        LimitNOFILE = 65536;

        # NOTE ON SANDBOXING. There are deliberately no ProtectSystem,
        # PrivateTmp, NoNewPrivileges, ProtectKernel*, RestrictSUIDSGID or
        # MemoryDenyWriteExecute settings here. Every one of them is inherited
        # by the commands this service starts, and those commands are meant to
        # be unrestricted root: ProtectSystem=strict would break
        # `nixos-rebuild switch`, NoNewPrivileges would break every setuid
        # helper, ProtectKernelTunables would break `sysctl`. A sandbox that has
        # to be disabled to do the job is worse than none, because it reads as
        # protection that is not there. The hardening that does apply lives in
        # the daemon: a cryptographic gate on every connection, connection caps
        # and handshake deadlines, a reset environment for children, and an
        # audit record of who ran what.
      };
    };

    assertions = [
      {
        assertion = !(declarative && cfg.authorizedKeysFile != "/root/.config/sudokey/authorized_keys");
        message = ''
          services.sudokey: set either authorizedKeys (declarative) or
          authorizedKeysFile (managed outside Nix), not both.
        '';
      }
      {
        assertion = cfg.socketGroup == null || cfg.socketMode != "0666";
        message = ''
          services.sudokey: socketMode 0666 makes socketGroup meaningless —
          drop the group, or tighten the mode to 0660.
        '';
      }
    ];
  };
}
