//! sudokey - a minimal ssh-agent-authenticated root command broker.
//!
//! A root `serve` process listens on a unix socket. Unprivileged clients prove
//! control of an authorized ed25519 key (via the forwarded ssh-agent) and then
//! run commands / interactive shells as root, without interactive sudo.

mod agent;
mod client;
mod proto;
mod pty;
mod server;
mod wire;

use std::process::exit;

const DEFAULT_SOCKET: &str = "/run/sudokey.sock";
const DEFAULT_AUTHORIZED: &str = "/root/.config/sudokey/authorized_keys";

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
    --authorized PATH   authorized_keys file (default /root/.config/sudokey/authorized_keys)
    --socket PATH       unix socket path (default /run/sudokey.sock)
    --socket-mode MODE  octal permissions for the socket (default 0666)
    -h, --help          show this help
"
}

fn run_help() -> &'static str {
    "\
sudokey run - execute a command as root (non-interactive)

USAGE:
    sudokey run [--socket PATH] -- <cmd> [args...]

Streams stdout/stderr separately and exits with the command's exit code.
Local stdin is forwarded to the command.
"
}

fn shell_help() -> &'static str {
    "\
sudokey shell - interactive root shell or command over a pty

USAGE:
    sudokey shell [--socket PATH] [-- <cmd> [args...]]

With no command, starts root's login shell. If stdin is a tty the local
terminal is put in raw mode and restored on exit.
"
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", usage());
        exit(2);
    }

    let sub = args[0].as_str();
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

/// Pull an option that takes a value, e.g. `--socket PATH`.
fn take_value(args: &[String], i: &mut usize, name: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("option {name} requires a value"))
}

fn cmd_serve(args: &[String]) -> std::io::Result<i32> {
    let mut authorized = DEFAULT_AUTHORIZED.to_string();
    let mut socket = DEFAULT_SOCKET.to_string();
    let mut socket_mode: u32 = 0o666;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--authorized" => authorized = arg_val(args, &mut i, "--authorized")?,
            "--socket" => socket = arg_val(args, &mut i, "--socket")?,
            "--socket-mode" => {
                let v = arg_val(args, &mut i, "--socket-mode")?;
                socket_mode = u32::from_str_radix(v.trim_start_matches("0o"), 8).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid octal socket mode '{v}'"),
                    )
                })?;
            }
            "-h" | "--help" => {
                print!("{}", serve_help());
                return Ok(0);
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("serve: unexpected argument '{other}'"),
                ));
            }
        }
        i += 1;
    }

    server::serve(server::ServeOpts {
        authorized_path: authorized,
        socket_path: socket,
        socket_mode,
    })?;
    Ok(0)
}

/// Split off options before `--`, returning (socket_override, command_argv).
fn parse_client_args(
    args: &[String],
    help: &'static str,
) -> Result<Option<(String, Vec<String>)>, std::io::Error> {
    let mut socket = DEFAULT_SOCKET.to_string();
    let mut i = 0;
    let mut argv = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = arg_val(args, &mut i, "--socket")?,
            "-h" | "--help" => {
                print!("{help}");
                return Ok(None);
            }
            "--" => {
                argv = args[i + 1..].to_vec();
                break;
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unexpected argument '{other}' (put the command after `--`)"),
                ));
            }
        }
        i += 1;
    }
    Ok(Some((socket, argv)))
}

fn cmd_run(args: &[String]) -> std::io::Result<i32> {
    match parse_client_args(args, run_help())? {
        None => Ok(0),
        Some((socket, argv)) => client::run(&socket, argv),
    }
}

fn cmd_shell(args: &[String]) -> std::io::Result<i32> {
    match parse_client_args(args, shell_help())? {
        None => Ok(0),
        Some((socket, argv)) => client::shell(&socket, argv),
    }
}

fn cmd_list_keys(args: &[String]) -> std::io::Result<i32> {
    for a in args {
        if a == "-h" || a == "--help" {
            println!("sudokey list-keys - print the agent's ed25519 keys in authorized_keys format");
            return Ok(0);
        }
    }
    client::list_keys()
}

/// Helper wrapping `take_value` into an `io::Result`.
fn arg_val(args: &[String], i: &mut usize, name: &str) -> std::io::Result<String> {
    take_value(args, i, name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}
