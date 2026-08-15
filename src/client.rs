//! Client subcommands: `run` (exec), `shell` (pty), and `list-keys`.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use crate::agent;
use crate::proto::*;
use crate::pty;
use crate::wire::*;

/// Connect to the broker socket and complete the ssh-agent challenge/response.
/// Returns the authenticated stream, or an error if access is denied.
fn connect_and_auth(socket_path: &str) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        io::Error::new(e.kind(), format!("cannot connect to {socket_path}: {e}"))
    })?;

    // 1. Receive magic + version + nonce.
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad server magic"));
    }
    let version = read_u8(&mut stream)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported server protocol version {version}"),
        ));
    }
    let mut nonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut nonce)?;

    // Data to sign: CONTEXT || nonce.
    let mut signed = Vec::with_capacity(CONTEXT.len() + NONCE_LEN);
    signed.extend_from_slice(CONTEXT);
    signed.extend_from_slice(&nonce);

    // 2. Sign with every ed25519 identity the agent holds.
    let mut agent_conn = agent::connect().map_err(|e| {
        io::Error::new(e.kind(), format!("ssh-agent: {e}"))
    })?;
    let ids = agent::list_identities(&mut agent_conn)?;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for id in ids.iter().filter(|i| i.is_ed25519()) {
        // Agent refused to sign with this key -> skip it.
        if let Ok(Some(sig)) = agent::sign(&mut agent_conn, &id.key_blob, &signed) {
            pairs.push((id.key_blob.clone(), sig));
        }
    }

    write_u32(&mut stream, pairs.len() as u32)?;
    for (kb, sig) in &pairs {
        write_string(&mut stream, kb)?;
        write_string(&mut stream, sig)?;
    }
    stream.flush()?;

    // 3. Read status.
    let status = read_u8(&mut stream)?;
    if status != STATUS_OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access denied: no authorized key proved (is your pubkey in the server's authorized_keys?)",
        ));
    }
    Ok(stream)
}

fn write_argv(w: &mut impl Write, argv: &[String]) -> io::Result<()> {
    write_u32(w, argv.len() as u32)?;
    for a in argv {
        write_string(w, a.as_bytes())?;
    }
    Ok(())
}

/// `sudokey run -- <cmd>` : non-interactive exec mode.
pub fn run(socket_path: &str, argv: Vec<String>) -> io::Result<i32> {
    if argv.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run requires a command, e.g. `sudokey run -- id`",
        ));
    }

    let mut stream = connect_and_auth(socket_path)?;
    write_u8(&mut stream, MODE_EXEC)?;
    write_argv(&mut stream, &argv)?;
    stream.flush()?;

    // Forward local stdin -> CH_STDIN, EOF -> CH_STDIN_EOF.
    let mut write_half = stream.try_clone()?;
    thread::spawn(move || {
        let mut inp = io::stdin();
        let mut buf = [0u8; 32 * 1024];
        loop {
            match inp.read(&mut buf) {
                Ok(0) => {
                    let _ = write_frame(&mut write_half, CH_STDIN_EOF, &[]);
                    break;
                }
                Ok(n) => {
                    if write_frame(&mut write_half, CH_STDIN, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let code = read_output_loop(&mut stream, true)?;
    Ok(code)
}

/// `sudokey shell [-- <cmd>]` : interactive pty mode.
pub fn shell(socket_path: &str, argv: Vec<String>) -> io::Result<i32> {
    let mut stream = connect_and_auth(socket_path)?;

    let stdin = io::stdin();
    let is_tty = pty::is_tty(&stdin);
    let (cols, rows) = if is_tty {
        pty::get_winsize(&stdin)
    } else {
        (80, 24)
    };
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());

    write_u8(&mut stream, MODE_PTY)?;
    write_argv(&mut stream, &argv)?;
    write_u16(&mut stream, cols)?;
    write_u16(&mut stream, rows)?;
    write_string(&mut stream, term.as_bytes())?;
    stream.flush()?;

    // Forward local stdin -> CH_STDIN.
    let mut write_half = stream.try_clone()?;
    thread::spawn(move || {
        let mut inp = io::stdin();
        let mut buf = [0u8; 32 * 1024];
        loop {
            match inp.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if write_frame(&mut write_half, CH_STDIN, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Raw mode is scoped so the guard restores the terminal before we return
    // (std::process::exit at the top level would skip destructors).
    let code = {
        let _raw = pty::RawGuard::new(io::stdin())?;
        read_output_loop(&mut stream, false)?
    };
    Ok(code)
}

/// Read server->client frames until the exit frame; write stdout (and stderr
/// if `split_stderr`). Returns the propagated exit code.
fn read_output_loop(stream: &mut UnixStream, split_stderr: bool) -> io::Result<i32> {
    let mut code = 1;
    loop {
        match read_frame(stream) {
            Ok((CH_STDOUT, data)) => {
                let mut out = io::stdout();
                out.write_all(&data)?;
                out.flush()?;
            }
            Ok((CH_STDERR, data)) => {
                if split_stderr {
                    let mut err = io::stderr();
                    err.write_all(&data)?;
                    err.flush()?;
                } else {
                    // pty mode: everything is one stream
                    let mut out = io::stdout();
                    out.write_all(&data)?;
                    out.flush()?;
                }
            }
            Ok((CH_EXIT, data)) if data.len() >= 4 => {
                code = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                break;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(code)
}

/// `sudokey list-keys` : print the agent's ed25519 identities in
/// authorized_keys format.
pub fn list_keys() -> io::Result<i32> {
    let mut agent_conn = agent::connect()?;
    let ids = agent::list_identities(&mut agent_conn)?;
    use base64::Engine;
    let mut count = 0;
    for id in ids.iter().filter(|i| i.is_ed25519()) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&id.key_blob);
        if id.comment.is_empty() {
            println!("ssh-ed25519 {b64}");
        } else {
            println!("ssh-ed25519 {b64} {}", id.comment);
        }
        count += 1;
    }
    if count == 0 {
        eprintln!("sudokey: the agent holds no ed25519 identities");
        return Ok(1);
    }
    Ok(0)
}
