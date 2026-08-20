//! The root broker daemon: authenticate a connection against the ssh-agent
//! challenge, then run the requested command (exec or pty) as this process's
//! (root's) identity, streaming I/O back over the socket.
//!
//! This module contains no `unsafe`: the pty is handled by `portable-pty`,
//! privilege/permission queries and signalling by `rustix`, and signal-driven
//! teardown by `signal-hook`.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use rustix::process::{Pid, Signal};

use crate::agent;
use crate::keys::{KeyMap, KeyStore};
use crate::passwd;
use crate::proto::*;
use crate::wire::*;

/// How long a child gets between `SIGTERM` and `SIGKILL` once its client is gone.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// How long we wait for I/O pump threads to drain after a child exits.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Per-connection thread stacks. The handlers only ever hold a 32 KiB I/O
/// buffer, so the 2 MiB default is pure per-connection overhead.
const THREAD_STACK: usize = 256 * 1024;

/// Parsed CLI options for `serve`.
pub struct ServeOpts {
    pub authorized_path: String,
    pub socket_path: String,
    pub socket_mode: u32,
    pub socket_group: Option<String>,
    pub max_conns: usize,
    pub max_conns_per_uid: usize,
    pub auth_timeout: Duration,
    pub child_path: String,
}

/// Everything a spawned child needs that does not come from the client.
struct ChildCfg {
    /// `PATH` handed to children. Never inherited from the daemon's own
    /// environment, so a stray `PATH` in the unit file cannot decide which
    /// binary runs as root.
    path: String,
    home: String,
    shell: String,
    user: String,
}

impl ChildCfg {
    fn new(child_path: String) -> ChildCfg {
        let uid = rustix::process::geteuid().as_raw();
        ChildCfg {
            path: child_path,
            home: passwd::home_for(uid),
            shell: passwd::shell_for(uid),
            user: passwd::name_for(uid),
        }
    }

    /// The environment every child gets. Deliberately built from scratch rather
    /// than inherited: the daemon's environment is attacker-influenced whenever
    /// someone starts it from a shell, and `LD_PRELOAD`, `LD_LIBRARY_PATH`,
    /// `BASH_ENV` and friends all turn "run this command as root" into "run
    /// this attacker's code as root". This is `sudo`'s `env_reset`.
    fn env(&self, peer: &Peer, key_fp: &str, term: Option<&str>) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), self.path.clone().into()),
            ("HOME".into(), self.home.clone().into()),
            ("SHELL".into(), self.shell.clone().into()),
            ("USER".into(), self.user.clone().into()),
            ("LOGNAME".into(), self.user.clone().into()),
            // Provenance, so scripts and shell prompts can tell who is driving.
            ("SUDOKEY_UID".into(), peer.uid.to_string().into()),
            ("SUDOKEY_KEY".into(), key_fp.into()),
        ];
        // Locale and timezone come from the daemon's own environment, which the
        // operator controls through the unit file — never from the client.
        for k in [
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LC_MESSAGES",
            "TZ",
            // NixOS points at locale and zoneinfo data through these; without
            // them a root shell on NixOS cannot resolve its own locale.
            "LOCALE_ARCHIVE",
            "TZDIR",
        ] {
            if let Some(v) = std::env::var_os(k) {
                env.push((k.into(), v));
            }
        }
        if let Some(term) = term {
            env.push(("TERM".into(), term.into()));
        }
        env
    }

    /// Directory children start in. The protocol carries no working directory,
    /// so pick one deterministically instead of leaking whatever directory the
    /// daemon happens to have been started in.
    fn cwd(&self) -> &Path {
        let home = Path::new(&self.home);
        if home.is_dir() {
            home
        } else {
            Path::new("/")
        }
    }
}

/// `TERM` is client-controlled and lands in the environment of a root process,
/// where terminfo will happily use it as a filename. Restrict it to the
/// characters real terminal names use.
fn sanitize_term(term: &[u8]) -> String {
    let ok = !term.is_empty()
        && term.len() <= MAX_TERM
        && term
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'+'));
    if ok {
        String::from_utf8_lossy(term).into_owned()
    } else {
        "xterm".to_string()
    }
}

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

/// Kernel-attested identity of whoever opened the socket. This is *not* the
/// authorisation gate — the ed25519 challenge is — but it is what makes the
/// audit log and the per-uid connection cap meaningful, because the kernel
/// fills it in and the client cannot forge it.
#[derive(Clone, Copy)]
struct Peer {
    uid: u32,
    gid: u32,
    pid: i32,
}

impl Peer {
    fn of(stream: &UnixStream) -> Peer {
        match rustix::net::sockopt::get_socket_peercred(stream) {
            Ok(c) => Peer {
                uid: c.uid.as_raw(),
                gid: c.gid.as_raw(),
                pid: c.pid.as_raw_nonzero().get(),
            },
            // Cannot happen for AF_UNIX on Linux, but do not take the daemon
            // down over it; fall back to values that fail the caps closed.
            Err(_) => Peer {
                uid: u32::MAX,
                gid: u32::MAX,
                pid: -1,
            },
        }
    }

    fn label(&self) -> String {
        format!(
            "uid={} gid={} pid={}",
            passwd::uid_label(self.uid),
            self.gid,
            self.pid
        )
    }
}

// ---------------------------------------------------------------------------
// Connection accounting
// ---------------------------------------------------------------------------

/// Bounds on concurrent connections.
///
/// This is the fix for the failure mode where the daemon is up, the socket is
/// there, and clients still cannot get in: every connection used to cost a
/// thread and a file descriptor with no cap and no timeout, so a few hundred
/// connections that never say anything exhausted the process's descriptor
/// table. `accept()` then failed forever, and because the old accept loop
/// simply logged and retried, it also span at full CPU writing that error to
/// the journal.
struct Limiter {
    max_total: usize,
    max_per_uid: usize,
    state: Mutex<LimiterState>,
}

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_uid: HashMap<u32, usize>,
}

/// Held for as long as *any* thread is still working on a connection, so a slot
/// is only returned once the descriptors really are.
struct Slot {
    limiter: Arc<Limiter>,
    uid: u32,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut st = self.limiter.state.lock().unwrap_or_else(|e| e.into_inner());
        st.total = st.total.saturating_sub(1);
        if let Some(n) = st.per_uid.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                st.per_uid.remove(&self.uid);
            }
        }
    }
}

/// Why a connection was turned away, for the log line.
enum Rejected {
    Total(usize),
    PerUid(usize),
}

impl Limiter {
    fn new(max_total: usize, max_per_uid: usize) -> Arc<Limiter> {
        Arc::new(Limiter {
            max_total,
            max_per_uid,
            state: Mutex::new(LimiterState::default()),
        })
    }

    fn acquire(self: &Arc<Self>, uid: u32) -> Result<Arc<Slot>, Rejected> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.total >= self.max_total {
            return Err(Rejected::Total(self.max_total));
        }
        let per = st.per_uid.entry(uid).or_insert(0);
        if *per >= self.max_per_uid {
            return Err(Rejected::PerUid(self.max_per_uid));
        }
        *per += 1;
        st.total += 1;
        Ok(Arc::new(Slot {
            limiter: Arc::clone(self),
            uid,
        }))
    }
}

/// Log at most one line per `interval` for a recurring condition, so a stuck
/// accept loop cannot fill the journal (and the disk behind it).
struct Throttle {
    interval: Duration,
    state: Mutex<(Option<Instant>, u64)>,
}

impl Throttle {
    fn new(interval: Duration) -> Throttle {
        Throttle {
            interval,
            state: Mutex::new((None, 0)),
        }
    }

    /// Returns `Some(suppressed_since_last)` when the caller should log.
    fn allow(&self) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match st.0 {
            Some(last) if now.duration_since(last) < self.interval => {
                st.1 += 1;
                None
            }
            _ => {
                let suppressed = st.1;
                *st = (Some(now), 0);
                Some(suppressed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket setup
// ---------------------------------------------------------------------------

/// A bound socket plus the identity it had at bind time, so shutdown only
/// unlinks the socket it actually created and never a successor's.
struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    ident: Option<(u64, u64)>,
}

impl BoundSocket {
    fn unlink_if_ours(&self) {
        let now = std::fs::metadata(&self.path)
            .ok()
            .map(|m| (m.dev(), m.ino()));
        if now.is_some() && now == self.ident {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bind the listening socket.
///
/// The old code unconditionally `unlink`ed the path first, which meant a second
/// daemon (a stray manual `sudokey serve`, or a restart racing the old process)
/// silently stole the socket: the first daemon stayed up and "running" while
/// every client reached the second one. So probe for a live daemon first and
/// refuse rather than take over.
///
/// The socket is also created unreachable and only opened up once its group and
/// mode are final, closing the window in which it existed with whatever the
/// ambient umask allowed.
fn bind_socket(path: &str, mode: u32, gid: Option<u32>) -> io::Result<BoundSocket> {
    let path = PathBuf::from(path);

    match UnixStream::connect(&path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another sudokey daemon is already listening on {} \
                     (stop it first, or pass a different --socket)",
                    path.display()
                ),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            // Nothing is listening: a leftover socket from an unclean exit.
            info!("removing stale socket {}", path.display());
            std::fs::remove_file(&path)?;
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!(
                    "{} exists but cannot be probed ({e}); refusing to replace it",
                    path.display()
                ),
            ));
        }
    }

    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path has no filename")
    })?;
    let staging = parent.join(format!(".{name}.{}.new", std::process::id()));
    let _ = std::fs::remove_file(&staging);

    // Create with mode 000, then widen deliberately.
    let prev_umask = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o777));
    let bound = UnixListener::bind(&staging);
    rustix::process::umask(prev_umask);
    let listener = bound?;

    let finish = || -> io::Result<()> {
        if let Some(gid) = gid {
            std::os::unix::fs::chown(&staging, None, Some(gid))?;
        }
        std::fs::set_permissions(&staging, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        // rename() over the final path is atomic: clients either see the old
        // socket or the fully-configured new one, never a half-set-up socket.
        std::fs::rename(&staging, &path)
    };
    if let Err(e) = finish() {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }

    let ident = std::fs::metadata(&path).ok().map(|m| (m.dev(), m.ino()));
    Ok(BoundSocket {
        listener,
        path,
        ident,
    })
}

// ---------------------------------------------------------------------------
// Daemon entry point
// ---------------------------------------------------------------------------

pub fn serve(opts: ServeOpts) -> io::Result<()> {
    if !rustix::process::geteuid().is_root() {
        warn!(
            "running as uid {} — clients will get that user's privileges, not root's",
            rustix::process::geteuid().as_raw()
        );
    }

    let gid = match &opts.socket_group {
        Some(g) => Some(passwd::gid_for(g).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown socket group '{g}'"),
            )
        })?),
        None => None,
    };

    let store = KeyStore::open(&opts.authorized_path)?;
    let socket = Arc::new(bind_socket(&opts.socket_path, opts.socket_mode, gid)?);
    let cfg = Arc::new(ChildCfg::new(opts.child_path));
    let limiter = Limiter::new(opts.max_conns, opts.max_conns_per_uid);

    // Children inherit this; keep root-created files off-limits to other users
    // by default rather than whatever umask the daemon was started with.
    rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o022));

    // SIGHUP reloads keys; SIGINT/SIGTERM unlink the socket and exit.
    {
        let socket = Arc::clone(&socket);
        let store = Arc::clone(&store);
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ])?;
        thread::Builder::new()
            .name("signals".into())
            .spawn(move || {
                for sig in signals.forever() {
                    if sig == signal_hook::consts::SIGHUP {
                        info!("SIGHUP: reloading {}", store.path().display());
                        store.reload();
                        continue;
                    }
                    info!("signal {sig}: shutting down");
                    socket.unlink_if_ours();
                    std::process::exit(0);
                }
            })?;
    }

    info!(
        "listening on {} (mode {:o}{}) as uid {}; max {} connections ({} per uid)",
        opts.socket_path,
        opts.socket_mode,
        match &opts.socket_group {
            Some(g) => format!(", group {g}"),
            None => String::new(),
        },
        rustix::process::geteuid().as_raw(),
        opts.max_conns,
        opts.max_conns_per_uid,
    );

    accept_loop(&socket, &limiter, &store, &cfg, opts.auth_timeout);
    Ok(())
}

fn accept_loop(
    socket: &BoundSocket,
    limiter: &Arc<Limiter>,
    store: &Arc<KeyStore>,
    cfg: &Arc<ChildCfg>,
    auth_timeout: Duration,
) {
    let busy_log = Throttle::new(Duration::from_secs(10));
    let accept_log = Throttle::new(Duration::from_secs(10));
    // Shared with the handler threads: a flood of failing handshakes is exactly
    // when the journal must not be allowed to run away.
    let conn_log = Arc::new(Throttle::new(Duration::from_secs(10)));
    let mut backoff = Duration::from_millis(0);

    loop {
        let (stream, _) = match socket.listener.accept() {
            Ok(v) => {
                backoff = Duration::from_millis(0);
                v
            }
            Err(e) => {
                // ECONNABORTED/EINTR are routine; everything else is resource
                // pressure, where retrying immediately turns a temporary
                // shortage into a CPU-burning, journal-filling spin.
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                if let Some(n) = accept_log.allow() {
                    let extra = if n > 0 {
                        format!(" ({n} similar suppressed)")
                    } else {
                        String::new()
                    };
                    error!("accept failed: {e}{extra}");
                }
                backoff = (backoff * 2).clamp(Duration::from_millis(20), Duration::from_secs(1));
                thread::sleep(backoff);
                continue;
            }
        };

        let peer = Peer::of(&stream);
        let slot = match limiter.acquire(peer.uid) {
            Ok(slot) => slot,
            Err(why) => {
                if let Some(n) = busy_log.allow() {
                    let extra = if n > 0 {
                        format!(" ({n} similar suppressed)")
                    } else {
                        String::new()
                    };
                    match why {
                        Rejected::Total(max) => warn!(
                            "refused connection from {}: at the {max}-connection limit{extra}",
                            peer.label()
                        ),
                        Rejected::PerUid(max) => warn!(
                            "refused connection from {}: at the {max}-connection per-uid limit{extra}",
                            peer.label()
                        ),
                    }
                }
                drop(stream);
                continue;
            }
        };

        let store = Arc::clone(store);
        let cfg = Arc::clone(cfg);
        let conn_log = Arc::clone(&conn_log);
        let spawned = thread::Builder::new()
            .name(format!("conn-{}", peer.pid))
            .stack_size(THREAD_STACK)
            .spawn(move || {
                if let Err(e) = handle_conn(stream, peer, &store, &cfg, auth_timeout, &slot) {
                    // A client that hangs up mid-session is normal, not an error.
                    if !is_disconnect(&e) {
                        if let Some(n) = conn_log.allow() {
                            let extra = if n > 0 {
                                format!(" ({n} similar suppressed)")
                            } else {
                                String::new()
                            };
                            warn!("connection from {}: {e}{extra}", peer.label());
                        }
                    }
                }
            });
        // `thread::spawn` panics when the process is out of threads. With a
        // panicking accept loop that would take the whole broker down at
        // exactly the moment it is under pressure.
        if let Err(e) = spawned {
            error!("cannot spawn handler for {}: {e}", peer.label());
        }
    }
}

fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// A reader that enforces a wall-clock deadline across the whole handshake.
///
/// A per-read timeout alone is not enough: a peer that dribbles one byte just
/// inside the timeout can hold a slot open indefinitely. Re-deriving the socket
/// timeout from a single deadline before every read bounds the entire
/// pre-authentication phase instead of each individual read.
struct Deadline<'a> {
    stream: &'a UnixStream,
    at: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let now = Instant::now();
        if now >= self.at {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out during handshake",
            ));
        }
        self.stream.set_read_timeout(Some(self.at - now))?;
        (&*self.stream).read(buf).map_err(|e| {
            // A socket read timeout arrives as `WouldBlock`/EAGAIN; report the
            // deadline that actually expired instead.
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                io::Error::new(io::ErrorKind::TimedOut, "timed out during handshake")
            } else {
                e
            }
        })
    }
}

/// The authorized key a client proved control of.
struct Granted {
    fingerprint: String,
    comment: String,
}

/// Run the challenge/response. `Ok(None)` means "authenticated nobody".
fn authenticate(
    stream: &UnixStream,
    deadline: Instant,
    keys: &KeyMap,
) -> io::Result<Option<Granted>> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;

    let mut w = stream;
    w.write_all(&MAGIC)?;
    write_u8(&mut w, VERSION)?;
    w.write_all(&nonce)?;
    w.flush()?;

    // Signed message is CONTEXT || nonce.
    let mut signed = Vec::with_capacity(CONTEXT.len() + NONCE_LEN);
    signed.extend_from_slice(CONTEXT);
    signed.extend_from_slice(&nonce);

    let mut r = Deadline {
        stream,
        at: deadline,
    };
    let npairs = read_u32(&mut r)?;
    if npairs > MAX_KEYS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("too many auth pairs: {npairs}"),
        ));
    }

    let mut granted = None;
    for _ in 0..npairs {
        let key_blob = read_string_bounded(&mut r, MAX_BLOB)?;
        let sig_blob = read_string_bounded(&mut r, MAX_BLOB)?;
        if granted.is_some() {
            continue; // already authorized; still drain the rest of the message
        }
        let Some(info) = keys.get(&key_blob) else {
            continue;
        };
        let (Some(pk), Some(sig)) = (
            agent::ed25519_pubkey(&key_blob),
            agent::ed25519_sig(&sig_blob),
        ) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            continue;
        };
        if vk
            .verify_strict(&signed, &Signature::from_bytes(&sig))
            .is_ok()
        {
            granted = Some(Granted {
                fingerprint: info.fingerprint.clone(),
                comment: info.comment.clone(),
            });
        }
    }
    Ok(granted)
}

/// Render argv for the audit log without letting a crafted command forge log
/// lines: control characters and quotes are escaped.
fn quote_argv(argv: &[OsString]) -> String {
    let mut out = String::new();
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('"');
        for c in String::from_utf8_lossy(a.as_encoded_bytes()).chars() {
            match c {
                '"' | '\\' => {
                    out.push('\\');
                    out.push(c);
                }
                c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32 & 0xff)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out
}

fn handle_conn(
    stream: UnixStream,
    peer: Peer,
    store: &KeyStore,
    cfg: &ChildCfg,
    auth_timeout: Duration,
    slot: &Arc<Slot>,
) -> io::Result<()> {
    let deadline = Instant::now() + auth_timeout;
    // A peer that stops reading must not be able to wedge a handler thread in
    // `write` forever either.
    stream.set_write_timeout(Some(auth_timeout))?;

    let keys = store.current();
    let granted = authenticate(&stream, deadline, &keys)?;

    let mut w = &stream;
    write_u8(
        &mut w,
        if granted.is_some() {
            STATUS_OK
        } else {
            STATUS_DENY
        },
    )?;
    w.flush()?;

    let Some(granted) = granted else {
        audit!("DENIED {}: no authorized key proved control", peer.label());
        return Ok(());
    };

    // Read the request while the handshake deadline is still in force.
    let mut r = Deadline {
        stream: &stream,
        at: deadline,
    };
    let mode = read_u8(&mut r)?;
    let argc = read_u32(&mut r)?;
    if argc > MAX_ARGV {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("argv too long: {argc} elements"),
        ));
    }
    let mut argv: Vec<OsString> = Vec::with_capacity(argc.min(64) as usize);
    let mut argv_bytes = 0usize;
    for _ in 0..argc {
        let a = read_string_bounded(&mut r, MAX_BLOB)?;
        argv_bytes += a.len();
        if argv_bytes > MAX_ARGV_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "argv exceeds the total size limit",
            ));
        }
        // Keep argv as raw bytes. `from_utf8_lossy` silently rewrites any
        // non-UTF-8 path or argument into replacement characters, so the
        // command that runs as root stops being the command that was asked for.
        argv.push(OsString::from_vec(a));
    }

    let pty_req = if mode == MODE_PTY {
        let cols = read_u16(&mut r)?;
        let rows = read_u16(&mut r)?;
        let term = read_string_bounded(&mut r, MAX_TERM)?;
        Some((cols, rows, sanitize_term(&term)))
    } else if mode == MODE_EXEC {
        None
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown mode byte {mode}"),
        ));
    };

    let who = format!(
        "{} key={}{}",
        peer.label(),
        granted.fingerprint,
        if granted.comment.is_empty() {
            String::new()
        } else {
            format!(" ({})", granted.comment)
        }
    );
    audit!(
        "{} {} as {}: {}",
        who,
        if pty_req.is_some() { "pty" } else { "exec" },
        cfg.user,
        if argv.is_empty() {
            "<login shell>".to_string()
        } else {
            quote_argv(&argv)
        }
    );

    // The session itself is interactive and may idle for hours; the handshake
    // timeouts must not apply to it.
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    match pty_req {
        None => handle_exec(stream, argv, cfg, &peer, &granted, slot, &who),
        Some((cols, rows, term)) => handle_pty(
            stream, argv, cols, rows, term, cfg, &peer, &granted, slot, &who,
        ),
    }
}

// ---------------------------------------------------------------------------
// Child lifecycle
// ---------------------------------------------------------------------------

/// Signals a child once its client is gone.
///
/// Without this, killing a client left its root process running with nothing
/// attached to it — `sudokey run -- sleep 3600`, Ctrl-C, and an orphaned root
/// process stays behind. `reaped` is held across the signal so we can never
/// deliver to a pid the kernel has already handed to someone else.
struct Terminator {
    pid: Pid,
    group: bool,
    reaped: Mutex<bool>,
    fired: AtomicBool,
}

impl Terminator {
    fn new(pid: u32, group: bool) -> Option<Arc<Terminator>> {
        Pid::from_raw(pid as i32).map(|pid| {
            Arc::new(Terminator {
                pid,
                group,
                reaped: Mutex::new(false),
                fired: AtomicBool::new(false),
            })
        })
    }

    /// Returns false when the child has already been reaped, in which case
    /// nothing was signalled.
    fn signal(&self, sig: Signal) -> bool {
        let reaped = self.reaped.lock().unwrap_or_else(|e| e.into_inner());
        if *reaped {
            return false;
        }
        let _ = if self.group {
            rustix::process::kill_process_group(self.pid, sig)
        } else {
            rustix::process::kill_process(self.pid, sig)
        };
        true
    }

    fn mark_reaped(&self) {
        *self.reaped.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }

    /// `SIGTERM` now, `SIGKILL` after a grace period. Idempotent.
    fn terminate(self: &Arc<Self>, who: &str) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        // The normal end of a session also ends the stdin thread; only report a
        // termination when there was in fact something left to terminate.
        if !self.signal(Signal::Term) {
            return;
        }
        audit!(
            "{who}: client disconnected, terminating child pid {}",
            self.pid.as_raw_nonzero()
        );
        let me = Arc::clone(self);
        let _ = thread::Builder::new()
            .name("reaper".into())
            .stack_size(64 * 1024)
            .spawn(move || {
                thread::sleep(KILL_GRACE);
                me.signal(Signal::Kill);
            });
    }
}

fn send_exit(w: &Arc<Mutex<UnixStream>>, code: i32) {
    let mut buf = Vec::with_capacity(4);
    let _ = write_i32(&mut buf, code);
    let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
    let _ = write_frame(&mut *g, CH_EXIT, &buf);
}

fn send_stderr(w: &Arc<Mutex<UnixStream>>, msg: &str) {
    let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
    let _ = write_frame(&mut *g, CH_STDERR, msg.as_bytes());
}

/// Wait for `n` worker threads to report completion, giving up after `budget`.
///
/// Joining unconditionally is not safe here: a command that leaves a background
/// process holding the inherited stdout pipe (`systemctl start`, a nohup'd
/// daemon) keeps that pipe open forever, so the pump thread never sees EOF and
/// an unconditional join wedges the connection — and its descriptors — for the
/// life of the daemon.
fn await_workers(rx: &mpsc::Receiver<()>, n: usize, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    for _ in 0..n {
        let now = Instant::now();
        if now >= deadline || rx.recv_timeout(deadline - now).is_err() {
            return false;
        }
    }
    true
}

/// Copy everything from `src` into frames on `channel`, one lock per chunk.
fn pump(src: &mut impl Read, w: &Arc<Mutex<UnixStream>>, channel: u8) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
                if write_frame(&mut *g, channel, &buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn handle_exec(
    stream: UnixStream,
    argv: Vec<OsString>,
    cfg: &ChildCfg,
    peer: &Peer,
    granted: &Granted,
    slot: &Arc<Slot>,
    who: &str,
) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));

    if argv.is_empty() {
        send_stderr(&writer, "sudokey: exec mode requires a command\n");
        send_exit(&writer, 2);
        return Ok(());
    }

    let child = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(cfg.env(peer, &granted.fingerprint, None))
        .current_dir(cfg.cwd())
        // Its own process group, so the child is insulated from signals aimed
        // at the daemon and so we can tear down the whole job at once.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            send_stderr(
                &writer,
                &format!(
                    "sudokey: failed to execute {}: {e}\n",
                    argv[0].to_string_lossy()
                ),
            );
            send_exit(&writer, 127);
            return Ok(());
        }
    };

    let terminator = Terminator::new(child.id(), true);
    let child_stdin = Arc::new(Mutex::new(child.stdin.take()));
    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    let (done_tx, done_rx) = mpsc::channel();

    for (name, mut src, channel) in [
        (
            "stdout",
            Box::new(child_stdout) as Box<dyn Read + Send>,
            CH_STDOUT,
        ),
        (
            "stderr",
            Box::new(child_stderr) as Box<dyn Read + Send>,
            CH_STDERR,
        ),
    ] {
        let w = Arc::clone(&writer);
        let slot = Arc::clone(slot);
        let tx = done_tx.clone();
        thread::Builder::new()
            .name(format!("exec-{name}"))
            .stack_size(THREAD_STACK)
            .spawn(move || {
                pump(&mut src, &w, channel);
                let _ = tx.send(());
                drop(slot);
            })?;
    }

    // Client -> child stdin. Also the disconnect detector: when this loop ends
    // the client is gone, and anything still running as root goes with it.
    {
        let stdin_ref = Arc::clone(&child_stdin);
        let slot = Arc::clone(slot);
        let mut reader = stream.try_clone()?;
        let terminator = terminator.clone();
        let who = who.to_string();
        thread::Builder::new()
            .name("exec-stdin".into())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                loop {
                    match read_frame(&mut reader) {
                        Ok((CH_STDIN, data)) => {
                            let mut g = stdin_ref.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(si) = g.as_mut() {
                                if si.write_all(&data).is_err() {
                                    *g = None;
                                }
                            }
                        }
                        Ok((CH_STDIN_EOF, _)) => {
                            *stdin_ref.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                *stdin_ref.lock().unwrap_or_else(|e| e.into_inner()) = None;
                if let Some(t) = &terminator {
                    t.terminate(&who);
                }
                drop(slot);
            })?;
    }

    let status = child.wait()?;
    if let Some(t) = &terminator {
        t.mark_reaped();
    }
    if !await_workers(&done_rx, 2, DRAIN_GRACE) {
        warn!("{who}: output still open after the child exited; closing anyway");
    }
    send_exit(&writer, status.code().unwrap_or(1));

    // Half-close so the stdin thread's blocking read returns instead of parking
    // on a descriptor for as long as the client cares to hold the socket open.
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_pty(
    stream: UnixStream,
    argv: Vec<OsString>,
    cols: u16,
    rows: u16,
    term: String,
    cfg: &ChildCfg,
    peer: &Peer,
    granted: &Granted,
    slot: &Arc<Slot>,
    who: &str,
) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));

    let argv = if argv.is_empty() {
        vec![OsString::from(cfg.shell.clone())]
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
    // `CommandBuilder::new` seeds itself from our own environment; clear it and
    // supply a known-good one, exactly as for exec mode.
    cmd.env_clear();
    for (k, v) in cfg.env(peer, &granted.fingerprint, Some(&term)) {
        cmd.env(k, v);
    }
    cmd.cwd(cfg.cwd());
    cmd.umask(Some(0o022));

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| io::Error::other(format!("spawn: {e}")))?;
    drop(pair.slave); // parent does not need the slave

    let terminator = child.process_id().and_then(|p| Terminator::new(p, false));

    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| io::Error::other(format!("clone reader: {e}")))?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .map_err(|e| io::Error::other(format!("take writer: {e}")))?;
    let master = Arc::new(Mutex::new(pair.master));

    let (done_tx, done_rx) = mpsc::channel();

    // pty master -> CH_STDOUT
    {
        let w = Arc::clone(&writer);
        let slot = Arc::clone(slot);
        thread::Builder::new()
            .name("pty-out".into())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                pump(&mut pty_reader, &w, CH_STDOUT);
                let _ = done_tx.send(());
                drop(slot);
            })?;
    }

    // socket -> pty master (input / resize), and disconnect detection.
    {
        let master_r = Arc::clone(&master);
        let slot = Arc::clone(slot);
        let mut reader = stream.try_clone()?;
        let terminator = terminator.clone();
        let who = who.to_string();
        thread::Builder::new()
            .name("pty-in".into())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                loop {
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
                            let g = master_r.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = g.resize(PtySize {
                                rows: r.max(1),
                                cols: c.max(1),
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                if let Some(t) = &terminator {
                    t.terminate(&who);
                }
                drop(slot);
            })?;
    }

    let status = child
        .wait()
        .map_err(|e| io::Error::other(format!("wait: {e}")))?;
    if let Some(t) = &terminator {
        t.mark_reaped();
    }
    if !await_workers(&done_rx, 1, DRAIN_GRACE) {
        warn!("{who}: pty still open after the shell exited; closing anyway");
    }
    send_exit(&writer, status.exit_code() as i32);
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}
