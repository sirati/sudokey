//! The root broker daemon: authenticate a connection against the ssh-agent
//! challenge, then run the requested command (exec or pty) as this process's
//! (root's) identity, streaming I/O back over the socket.
//!
//! This module contains no `unsafe`: the pty is handled by `portable-pty`,
//! privilege/permission queries by std + `rustix`, and signal-driven teardown
//! by `signal-hook`.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use ed25519_dalek::{Signature, VerifyingKey};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::agent;
use crate::proto::*;
use crate::pty;
use crate::wire::*;

/// Parsed CLI options for `serve`.
pub struct ServeOpts {
    pub authorized_path: String,
    pub socket_path: String,
    pub socket_mode: u32,
}

/// Load and validate the authorized key set. Mirrors OpenSSH StrictModes: the
/// file must be owned by root or by the running user, and must not be group- or
/// world-writable.
fn load_authorized(path: &str) -> io::Result<HashSet<Vec<u8>>> {
    let meta = std::fs::metadata(path).map_err(|e| {
        io::Error::new(e.kind(), format!("cannot stat authorized_keys file {path}: {e}"))
    })?;

    let euid = rustix::process::geteuid().as_raw();
    let owner = meta.uid();
    if owner != 0 && owner != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing: {path} is owned by uid {owner}, not root or the server user ({euid})"),
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing: {path} is group- or world-writable (mode {:o})", meta.mode() & 0o7777),
        ));
    }

    let text = std::fs::read_to_string(path)?;
    let mut set = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // authorized_keys format: <type> <base64> [comment]
        let mut parts = line.split_whitespace();
        let ktype = parts.next().unwrap_or("");
        if ktype != "ssh-ed25519" {
            continue; // only ed25519 supported
        }
        let Some(b64) = parts.next() else { continue };
        use base64::Engine;
        if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) {
            set.insert(blob);
        }
    }
    if set.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no usable ed25519 keys found in {path}"),
        ));
    }
    Ok(set)
}

pub fn serve(opts: ServeOpts) -> io::Result<()> {
    let authorized = Arc::new(load_authorized(&opts.authorized_path)?);
    eprintln!(
        "sudokey: loaded {} authorized ed25519 key(s) from {}",
        authorized.len(),
        opts.authorized_path
    );

    // Remove a stale socket, then bind.
    let _ = std::fs::remove_file(&opts.socket_path);
    let listener = UnixListener::bind(&opts.socket_path)?;

    // Socket permissions: the crypto challenge is the real gate.
    std::fs::set_permissions(
        &opts.socket_path,
        std::fs::Permissions::from_mode(opts.socket_mode),
    )?;

    // Clean up the socket on SIGINT/SIGTERM (safe, thread-based).
    {
        let path = opts.socket_path.clone();
        let mut signals =
            signal_hook::iterator::Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM])?;
        thread::spawn(move || {
            if signals.forever().next().is_some() {
                let _ = std::fs::remove_file(&path);
                std::process::exit(0);
            }
        });
    }

    eprintln!(
        "sudokey: listening on {} (mode {:o}) as uid {}",
        opts.socket_path,
        opts.socket_mode,
        rustix::process::geteuid().as_raw()
    );

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let auth = Arc::clone(&authorized);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &auth) {
                        eprintln!("sudokey: connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("sudokey: accept error: {e}"),
        }
    }
    Ok(())
}

/// Run the authentication handshake. Returns true if the client proved control
/// of an authorized key.
fn authenticate(stream: &mut UnixStream, authorized: &HashSet<Vec<u8>>) -> io::Result<bool> {
    // 1. Send magic + version + nonce.
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
    stream.write_all(&MAGIC)?;
    write_u8(stream, VERSION)?;
    stream.write_all(&nonce)?;
    stream.flush()?;

    // Signed message is CONTEXT || nonce.
    let mut signed = Vec::with_capacity(CONTEXT.len() + NONCE_LEN);
    signed.extend_from_slice(CONTEXT);
    signed.extend_from_slice(&nonce);

    // 2. Read (key_blob, sig_blob) pairs.
    let npairs = read_u32(stream)?;
    if npairs > MAX_KEYS {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too many auth pairs"));
    }

    let mut ok = false;
    for _ in 0..npairs {
        let key_blob = read_string(stream)?;
        let sig_blob = read_string(stream)?;
        if ok {
            continue; // already authorized; still drain the rest
        }
        if !authorized.contains(&key_blob) {
            continue;
        }
        let (Some(pk), Some(sig)) =
            (agent::ed25519_pubkey(&key_blob), agent::ed25519_sig(&sig_blob))
        else {
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            continue;
        };
        let signature = Signature::from_bytes(&sig);
        if vk.verify_strict(&signed, &signature).is_ok() {
            ok = true;
        }
    }
    Ok(ok)
}

fn handle_conn(mut stream: UnixStream, authorized: &HashSet<Vec<u8>>) -> io::Result<()> {
    let ok = authenticate(&mut stream, authorized)?;
    write_u8(&mut stream, if ok { STATUS_OK } else { STATUS_DENY })?;
    stream.flush()?;
    if !ok {
        return Ok(());
    }

    // 4. Read request.
    let mode = read_u8(&mut stream)?;
    let argc = read_u32(&mut stream)?;
    if argc > MAX_ARGV {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "argv too long"));
    }
    let mut argv = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let a = read_string(&mut stream)?;
        argv.push(String::from_utf8_lossy(&a).into_owned());
    }

    match mode {
        MODE_EXEC => handle_exec(stream, argv),
        MODE_PTY => {
            let cols = read_u16(&mut stream)?;
            let rows = read_u16(&mut stream)?;
            let term = read_string(&mut stream)?;
            let term = String::from_utf8_lossy(&term).into_owned();
            handle_pty(stream, argv, cols, rows, term)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown mode byte {other}"),
        )),
    }
}

fn send_exit(w: &Arc<Mutex<UnixStream>>, code: i32) {
    let mut buf = Vec::with_capacity(4);
    let _ = write_i32(&mut buf, code);
    let mut g = w.lock().unwrap();
    let _ = write_frame(&mut *g, CH_EXIT, &buf);
}

fn handle_exec(stream: UnixStream, argv: Vec<String>) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = stream; // used only for reading below

    if argv.is_empty() {
        {
            let mut g = writer.lock().unwrap();
            let _ = write_frame(&mut *g, CH_STDERR, b"sudokey: exec mode requires a command\n");
        }
        send_exit(&writer, 2);
        return Ok(());
    }

    let child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            {
                let mut g = writer.lock().unwrap();
                let msg = format!("sudokey: failed to execute {}: {e}\n", argv[0]);
                let _ = write_frame(&mut *g, CH_STDERR, msg.as_bytes());
            }
            send_exit(&writer, 127);
            return Ok(());
        }
    };

    let child_stdin = Arc::new(Mutex::new(child.stdin.take()));
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // stdout pump: child -> CH_STDOUT
    let w_out = Arc::clone(&writer);
    let t_out = thread::spawn(move || pump(&mut child_stdout, &w_out, CH_STDOUT));

    // stderr pump: child -> CH_STDERR
    let w_err = Arc::clone(&writer);
    let t_err = thread::spawn(move || pump(&mut child_stderr, &w_err, CH_STDERR));

    // socket read pump: client stdin/EOF -> child stdin. Detached; ends when
    // the client closes the connection.
    let stdin_ref = Arc::clone(&child_stdin);
    thread::spawn(move || loop {
        match read_frame(&mut reader) {
            Ok((CH_STDIN, data)) => {
                let mut g = stdin_ref.lock().unwrap();
                if let Some(si) = g.as_mut() {
                    if si.write_all(&data).is_err() {
                        *g = None;
                    }
                }
            }
            Ok((CH_STDIN_EOF, _)) => {
                *stdin_ref.lock().unwrap() = None; // close child's stdin
            }
            Ok(_) => {}
            Err(_) => {
                *stdin_ref.lock().unwrap() = None;
                break;
            }
        }
    });

    let status = child.wait()?;
    let _ = t_out.join();
    let _ = t_err.join();
    let code = status.code().unwrap_or(1);
    send_exit(&writer, code);
    Ok(())
}

/// Copy everything from `src` into frames on `channel`, one lock per chunk.
fn pump(src: &mut impl Read, w: &Arc<Mutex<UnixStream>>, channel: u8) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut g = w.lock().unwrap();
                if write_frame(&mut *g, channel, &buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn handle_pty(
    stream: UnixStream,
    argv: Vec<String>,
    cols: u16,
    rows: u16,
    term: String,
) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = stream;

    // Default argv: root's login shell.
    let argv = if argv.is_empty() {
        vec![pty::default_shell()]
    } else {
        argv
    };

    let size = PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|e| io::Error::other(format!("openpty: {e}")))?;

    let mut cmd = CommandBuilder::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    // Inherit our environment explicitly, then override TERM.
    for (k, v) in std::env::vars() {
        if k != "TERM" {
            cmd.env(k, v);
        }
    }
    cmd.env("TERM", if term.is_empty() { "xterm".into() } else { term });

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| io::Error::other(format!("spawn: {e}")))?;
    drop(pair.slave); // parent doesn't need the slave

    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| io::Error::other(format!("clone reader: {e}")))?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .map_err(|e| io::Error::other(format!("take writer: {e}")))?;
    let master = Arc::new(Mutex::new(pair.master));

    // pty master -> CH_STDOUT
    let w_out = Arc::clone(&writer);
    let t_out = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut g = w_out.lock().unwrap();
                    if write_frame(&mut *g, CH_STDOUT, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // socket -> pty master (input / resize). Detached; ends on client close.
    let master_r = Arc::clone(&master);
    thread::spawn(move || loop {
        match read_frame(&mut reader) {
            Ok((CH_STDIN, data)) => {
                if pty_writer.write_all(&data).is_err() {
                    break;
                }
                let _ = pty_writer.flush();
            }
            Ok((CH_WINCH, data)) if data.len() >= 4 => {
                let c = u16::from_be_bytes([data[0], data[1]]);
                let r = u16::from_be_bytes([data[2], data[3]]);
                let _ = master_r.lock().unwrap().resize(PtySize {
                    rows: r.max(1),
                    cols: c.max(1),
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });

    let status = child
        .wait()
        .map_err(|e| io::Error::other(format!("wait: {e}")))?;
    let _ = t_out.join();
    send_exit(&writer, status.exit_code() as i32);
    Ok(())
}
