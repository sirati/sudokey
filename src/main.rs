//! sudokey - a minimal ssh-agent-authenticated root command broker.
//!
//! A root `serve` process listens on a unix socket. Unprivileged clients prove
//! control of an authorized ed25519 key (via the forwarded ssh-agent) and then
//! run commands / interactive shells as root, without interactive sudo.

#[macro_use]
mod log;

mod agent;
mod client;
mod keys;
mod passwd;
mod proto;
mod pty;
mod server;
mod wire;

use std::ffi::{OsStr, OsString};
use std::process::exit;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/sudokey.sock";
const DEFAULT_AUTHORIZED: &str = "/root/.config/sudokey/authorized_keys";
/// `PATH` handed to commands run as root. Never inherited from the daemon's
/// environment; `/run/current-system/sw/bin` is first so this works on NixOS.
const DEFAULT_CHILD_PATH: &str =
    "/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEFAULT_MAX_CONNS: usize = 128;
const DEFAULT_MAX_CONNS_PER_UID: usize = 32;
const DEFAULT_AUTH_TIMEOUT_SECS: u64 = 10;

fn usage() -> &'static str {
    "\
sudokey - ssh-agent-authenticated root command broker

USAGE:
    sudokey <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    serve      Run the root broker daemon
    run        Run a command as root (non-interactive, piped I/O)
    shell      Open an interactive root shell / command (pty)
    list-keys  Print the ssh-agent's ed25519 keys in authorized_keys format
    help       Show this help

Run `sudokey <SUBCOMMAND> --help` for per-command options.
"
}

fn serve_help() -> &'static str {
    "\
sudokey serve - run the root broker daemon (run as root)

USAGE:
    sudokey serve [OPTIONS]

OPTIONS:
    --authorized PATH     authorized_keys file
                          (default /root/.config/sudokey/authorized_keys)
    --socket PATH         unix socket path (default /run/sudokey.sock,
                          or $SUDOKEY_SOCKET)
    --socket-mode MODE    octal permissions for the socket (default 0666)
    --socket-group GROUP  group to own the socket; pair with --socket-mode 0660
                          to let only that group even open a connection
    --max-connections N   concurrent connections to accept (default 128)
    --max-per-uid N       concurrent connections per peer uid (default 32)
    --auth-timeout SECS   deadline for a client to finish the handshake
                          (default 10)
    --path PATH           PATH given to commands run as root
    -h, --help            show this help

SIGNALS:
    SIGHUP                re-read the authorized_keys file
    SIGINT, SIGTERM       remove the socket and exit
"
}

fn run_help() -> &'static str {
    "\
sudokey run - execute a command as root (non-interactive)

USAGE:
    sudokey run [--socket PATH] [-n] -- <cmd> [args...]

OPTIONS:
    --socket PATH   unix socket path (default /run/sudokey.sock,
                    or $SUDOKEY_SOCKET)
    -n, --no-stdin  do not forward local stdin; the command sees it closed
    -h, --help      show this help

Streams stdout/stderr separately and exits with the command's exit code.
Local stdin is forwarded to the command, except when there is nothing to
forward from: reading a terminal that this process is not in the foreground
of would raise SIGTTIN and suspend it, so stdin is reported closed instead.
That is what makes `sudokey run -- ... &` work without `< /dev/null`.

Disconnecting terminates the remote command rather than orphaning it, and a
closed output pipe (`sudokey run -- yes | head`) ends the command quietly
with status 141, as any other pipeline member would.
"
}

fn shell_help() -> &'static str {
    "\
sudokey shell - interactive root shell or command over a pty

USAGE:
    sudokey shell [--socket PATH] [-- <cmd> [args...]]

With no command, starts root's login shell. If stdin is a tty the local
terminal is put in raw mode and restored on exit, and window resizes are
forwarded to the remote pty.
"
}

/// Socket path to use when none is given on the command line.
fn default_socket() -> OsString {
    std::env::var_os("SUDOKEY_SOCKET").unwrap_or_else(|| DEFAULT_SOCKET.into())
}

fn main() {
    // `args_os`, not `args`: the latter panics outright on an argument that is
    // not valid UTF-8, and the whole point of `sudokey run -- ...` is to pass
    // arbitrary arguments (filenames, in particular) through untouched.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", usage());
        exit(2);
    }

    let sub = args[0].to_str().unwrap_or("");
    let rest = &args[1..];

    let result = match sub {
        "-h" | "--help" | "help" => {
            print!("{}", usage());
            Ok(0)
        }
        "serve" => cmd_serve(rest),
        "run" => cmd_run(rest),
        "shell" => cmd_shell(rest),
        "list-keys" => cmd_list_keys(rest),
        other => {
            eprintln!("sudokey: unknown subcommand '{other}'\n");
            eprint!("{}", usage());
            exit(2);
        }
    };

    match result {
        Ok(code) => exit(code),
        Err(e) => {
            eprintln!("sudokey: {e}");
            exit(1);
        }
    }
}

/// Pull an option value that may be an arbitrary byte string, e.g. a path.
fn arg_os(args: &[OsString], i: &mut usize, name: &str) -> std::io::Result<OsString> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("option {name} requires a value"),
        )
    })
}

/// Pull an option value that must be text.
fn arg_val(args: &[OsString], i: &mut usize, name: &str) -> std::io::Result<String> {
    let v = arg_os(args, i, name)?;
    v.into_string().map_err(|v| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("option {name} needs text, got '{}'", v.to_string_lossy()),
        )
    })
}

fn arg_num<T: std::str::FromStr>(
    args: &[OsString],
    i: &mut usize,
    name: &str,
) -> std::io::Result<T> {
    let v = arg_val(args, i, name)?;
    v.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("option {name} needs a number, got '{v}'"),
        )
    })
}

fn cmd_serve(args: &[OsString]) -> std::io::Result<i32> {
    let mut opts = server::ServeOpts {
        authorized_path: DEFAULT_AUTHORIZED.to_string(),
        socket_path: default_socket().to_string_lossy().into_owned(),
        socket_mode: 0o666,
        socket_group: None,
        max_conns: DEFAULT_MAX_CONNS,
        max_conns_per_uid: DEFAULT_MAX_CONNS_PER_UID,
        auth_timeout: Duration::from_secs(DEFAULT_AUTH_TIMEOUT_SECS),
        child_path: DEFAULT_CHILD_PATH.to_string(),
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].to_str().unwrap_or("") {
            "--authorized" => opts.authorized_path = arg_val(args, &mut i, "--authorized")?,
            "--socket" => opts.socket_path = arg_val(args, &mut i, "--socket")?,
            "--socket-mode" => {
                let v = arg_val(args, &mut i, "--socket-mode")?;
                opts.socket_mode = u32::from_str_radix(v.trim_start_matches("0o"), 8)
                    .ok()
                    .filter(|m| *m <= 0o777)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid octal socket mode '{v}'"),
                        )
                    })?;
            }
            "--socket-group" => opts.socket_group = Some(arg_val(args, &mut i, "--socket-group")?),
            "--max-connections" => opts.max_conns = arg_num(args, &mut i, "--max-connections")?,
            "--max-per-uid" => opts.max_conns_per_uid = arg_num(args, &mut i, "--max-per-uid")?,
            "--auth-timeout" => {
                let secs: u64 = arg_num(args, &mut i, "--auth-timeout")?;
                opts.auth_timeout = Duration::from_secs(secs.max(1));
            }
            "--path" => opts.child_path = arg_val(args, &mut i, "--path")?,
            "-h" | "--help" => {
                print!("{}", serve_help());
                return Ok(0);
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("serve: unexpected argument '{}'", args[i].to_string_lossy()),
                ));
            }
        }
        i += 1;
    }

    if opts.max_conns == 0 || opts.max_conns_per_uid == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "connection limits must be at least 1",
        ));
    }

    server::serve(opts)?;
    Ok(0)
}

/// Options common to the client subcommands, plus the command to run.
struct ClientArgs {
    socket: OsString,
    argv: Vec<OsString>,
    /// False for `-n`: do not forward local stdin at all.
    forward_stdin: bool,
}

/// Split off options before `--`. `Ok(None)` means help was printed.
fn parse_client_args(
    args: &[OsString],
    help: &'static str,
) -> Result<Option<ClientArgs>, std::io::Error> {
    let mut parsed = ClientArgs {
        socket: default_socket(),
        argv: Vec::new(),
        forward_stdin: true,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str().unwrap_or("") {
            "--socket" => parsed.socket = arg_os(args, &mut i, "--socket")?,
            "-n" | "--no-stdin" => parsed.forward_stdin = false,
            "-h" | "--help" => {
                print!("{help}");
                return Ok(None);
            }
            "--" => {
                parsed.argv = args[i + 1..].to_vec();
                break;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unexpected argument '{}' (put the command after `--`)",
                        args[i].to_string_lossy()
                    ),
                ));
            }
        }
        i += 1;
    }
    Ok(Some(parsed))
}

fn cmd_run(args: &[OsString]) -> std::io::Result<i32> {
    match parse_client_args(args, run_help())? {
        None => Ok(0),
        Some(a) => client::run(&a.socket, a.argv, a.forward_stdin),
    }
}

fn cmd_shell(args: &[OsString]) -> std::io::Result<i32> {
    match parse_client_args(args, shell_help())? {
        None => Ok(0),
        Some(a) => client::shell(&a.socket, a.argv),
    }
}

fn cmd_list_keys(args: &[OsString]) -> std::io::Result<i32> {
    for a in args {
        if a == OsStr::new("-h") || a == OsStr::new("--help") {
            println!(
                "sudokey list-keys - print the agent's ed25519 keys in authorized_keys format"
            );
            return Ok(0);
        }
    }
    client::list_keys()
}
