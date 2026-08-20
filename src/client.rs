//! Client subcommands: `run` (exec), `shell` (pty), and `list-keys`.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::agent;
use crate::proto::*;
use crate::pty;
use crate::wire::*;

/// Connect to the broker socket and complete the ssh-agent challenge/response.
/// Returns the authenticated stream, or an error if access is denied.
fn connect_and_auth(socket_path: &OsStr) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        let hint = match e.kind() {
            io::ErrorKind::NotFound => "  (is `sudokey serve` running?)",
            io::ErrorKind::ConnectionRefused => {
                "  (the socket is stale — the daemon is not listening on it)"
            }
            io::ErrorKind::PermissionDenied => {
                "  (you are not permitted to open the socket; check its mode and group)"
            }
            _ => "",
        };
        io::Error::new(
            e.kind(),
            format!(
                "cannot connect to {}: {e}{hint}",
                std::path::Path::new(socket_path).display()
            ),
        )
    })?;

    // 1. Receive magic + version + nonce.
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the server closed the connection before greeting us \
                 (it is most likely at its connection limit — see its log)",
            )
        } else {
            e
        }
    })?;
    if magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad server magic",
        ));
    }
    let version = read_u8(&mut stream)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported server protocol version {version} (this client speaks {VERSION})"),
        ));
    }
    let mut nonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut nonce)?;

    // Data to sign: CONTEXT || nonce.
    let mut signed = Vec::with_capacity(CONTEXT.len() + NONCE_LEN);
    signed.extend_from_slice(CONTEXT);
    signed.extend_from_slice(&nonce);

    // 2. Offer the agent's ed25519 public keys, and sign only the one the
    //    server picks.
    //
    //    Signing with every identity up front (protocol v1) meant one agent
    //    signature request per key. Against an agent that asks before signing
    //    -- 1Password, or `ssh-add -c` -- that is a prompt per key, for keys
    //    that have nothing to do with sudokey, every single invocation.
    //    Listing and offering never prompt; only signing does. So this asks
    //    the agent for exactly one signature, and for none at all when the
    //    server recognises none of our keys.
    let mut agent_conn =
        agent::connect().map_err(|e| io::Error::new(e.kind(), format!("ssh-agent: {e}")))?;
    let ids = agent::list_identities(&mut agent_conn)?;
    let offers: Vec<Vec<u8>> = ids
        .iter()
        .filter(|i| i.is_ed25519())
        .take(MAX_KEYS as usize)
        .map(|i| i.key_blob.clone())
        .collect();
    if offers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the ssh-agent holds no ed25519 identities \
             (is an agent running, and forwarded if you are over ssh?)",
        ));
    }

    write_u32(&mut stream, offers.len() as u32)?;
    for blob in &offers {
        write_string(&mut stream, blob)?;
    }
    stream.flush()?;

    let selected = read_u32(&mut stream)?;
    if selected == KEY_NONE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access denied: none of your agent's ed25519 keys is authorized \
             (is your public key in the server's authorized_keys?)",
        ));
    }
    let Some(key_blob) = offers.get(selected as usize) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server selected a key we did not offer",
        ));
    };

    let sig = agent::sign(&mut agent_conn, key_blob, &signed)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the ssh-agent refused to sign with the key the server selected",
        )
    })?;
    write_string(&mut stream, &sig)?;
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

/// argv goes over the wire as raw bytes. Arguments are frequently filenames,
/// and a filename is a byte string, not text — round-tripping it through UTF-8
/// would quietly hand the server a different command than the one asked for.
fn write_argv(w: &mut impl Write, argv: &[std::ffi::OsString]) -> io::Result<()> {
    write_u32(w, argv.len() as u32)?;
    for a in argv {
        write_string(w, a.as_bytes())?;
    }
    Ok(())
}

/// `sudokey run -- <cmd>` : non-interactive exec mode.
pub fn run(socket_path: &OsStr, argv: Vec<std::ffi::OsString>) -> io::Result<i32> {
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
    thread::Builder::new().name("stdin".into()).spawn(move || {
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
    })?;

    read_output_loop(&mut stream, true)
}

/// `sudokey shell [-- <cmd>]` : interactive pty mode.
pub fn shell(socket_path: &OsStr, argv: Vec<std::ffi::OsString>) -> io::Result<i32> {
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

    // Raw mode goes on before anything reads stdin, otherwise the terminal's
    // line discipline swallows whatever the user types in the meantime. The
    // guard is scoped so the terminal is restored before we return (the
    // top-level `process::exit` would skip destructors).
    let code = {
        let _raw = pty::RawGuard::new(io::stdin())?;

        // The write half is shared between the stdin pump and the SIGWINCH
        // thread, so their frames cannot interleave mid-frame.
        let write_half = Arc::new(Mutex::new(stream.try_clone()?));

        if is_tty {
            spawn_winch_forwarder(Arc::clone(&write_half))?;
        }

        let stdin_half = Arc::clone(&write_half);
        thread::Builder::new().name("stdin".into()).spawn(move || {
            let mut inp = io::stdin();
            let mut buf = [0u8; 32 * 1024];
            loop {
                match inp.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut g = stdin_half.lock().unwrap_or_else(|e| e.into_inner());
                        if write_frame(&mut *g, CH_STDIN, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })?;

        read_output_loop(&mut stream, false)?
    };
    Ok(code)
}

/// Relay terminal resizes to the remote pty. Without this the protocol's
/// `CH_WINCH` channel existed but nothing ever sent on it, so resizing the
/// window left the remote `top`/`vim` drawing at the original size.
fn spawn_winch_forwarder(write_half: Arc<Mutex<UnixStream>>) -> io::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH])?;
    thread::Builder::new().name("winch".into()).spawn(move || {
        for _ in signals.forever() {
            let (cols, rows) = pty::get_winsize(io::stdin());
            let mut payload = [0u8; 4];
            payload[..2].copy_from_slice(&cols.to_be_bytes());
            payload[2..].copy_from_slice(&rows.to_be_bytes());
            let mut g = write_half.lock().unwrap_or_else(|e| e.into_inner());
            if write_frame(&mut *g, CH_WINCH, &payload).is_err() {
                break;
            }
        }
    })?;
    Ok(())
}

/// Read server->client frames until the exit frame; write stdout (and stderr
/// if `split_stderr`). Returns the propagated exit code.
fn read_output_loop(stream: &mut UnixStream, split_stderr: bool) -> io::Result<i32> {
    // Not 0: if the connection dies before an exit frame arrives we must not
    // claim the remote command succeeded.
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
