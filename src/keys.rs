//! The authorized-key store: loading, StrictModes-style validation, SHA256
//! fingerprints, and hot reload.
//!
//! Reload matters for security, not convenience: with a load-once daemon,
//! deleting a line from `authorized_keys` does nothing until someone remembers
//! to restart the broker, so revoking root access silently fails. The store
//! re-reads the file whenever its identity or mtime changes, and on `SIGHUP`.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use sha2::{Digest, Sha256};

/// What we remember about an authorized key, beyond the blob used for lookup.
pub struct KeyInfo {
    /// OpenSSH-style `SHA256:...` fingerprint, for the audit log.
    pub fingerprint: String,
    /// Trailing comment from the `authorized_keys` line, if any.
    pub comment: String,
}

pub type KeyMap = HashMap<Vec<u8>, KeyInfo>;

/// Identity + mtime of the key file, used to detect that it changed.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Stamp {
    fn of(meta: &std::fs::Metadata) -> Self {
        Stamp {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

struct Loaded {
    keys: Arc<KeyMap>,
    stamp: Option<Stamp>,
}

pub struct KeyStore {
    path: PathBuf,
    state: Mutex<Loaded>,
}

/// OpenSSH-compatible fingerprint: base64 (unpadded) of SHA256 over the blob.
pub fn fingerprint(key_blob: &[u8]) -> String {
    let digest = Sha256::digest(key_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

impl KeyStore {
    /// Load the store once, failing loudly if the file is missing or unsafe —
    /// the daemon must not come up believing it has an empty allowlist.
    pub fn open(path: &str) -> io::Result<Arc<KeyStore>> {
        let path = PathBuf::from(path);
        let (keys, stamp) = read_and_validate(&path)?;
        info!(
            "loaded {} authorized ed25519 key(s) from {}",
            keys.len(),
            path.display()
        );
        Ok(Arc::new(KeyStore {
            path,
            state: Mutex::new(Loaded {
                keys: Arc::new(keys),
                stamp: Some(stamp),
            }),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current key set, re-reading the file first if it looks changed.
    ///
    /// A failed reload keeps the previous set and logs an error rather than
    /// failing closed: the common cause is catching the file mid-write, and
    /// locking every operator out of root over a half-written line is a worse
    /// outcome than briefly honouring the previous contents.
    pub fn current(&self) -> Arc<KeyMap> {
        let fresh_stamp = std::fs::metadata(&self.path).ok().map(|m| Stamp::of(&m));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match (fresh_stamp, state.stamp) {
            (Some(fresh), Some(old)) if fresh == old => return Arc::clone(&state.keys),
            (None, _) => {
                error!(
                    "{} disappeared; continuing with the {} key(s) already loaded",
                    self.path.display(),
                    state.keys.len()
                );
                return Arc::clone(&state.keys);
            }
            _ => {}
        }
        match read_and_validate(&self.path) {
            Ok((keys, stamp)) => {
                info!(
                    "reloaded {} authorized ed25519 key(s) from {}",
                    keys.len(),
                    self.path.display()
                );
                state.keys = Arc::new(keys);
                state.stamp = Some(stamp);
            }
            Err(e) => {
                error!(
                    "reload of {} failed ({e}); keeping the {} key(s) already loaded",
                    self.path.display(),
                    state.keys.len()
                );
            }
        }
        Arc::clone(&state.keys)
    }

    /// Force a reload regardless of the stamp (used by `SIGHUP`).
    pub fn reload(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).stamp = None;
        let _ = self.current();
    }
}

/// StrictModes, the OpenSSH rule: the key file and *every directory above it*
/// must be owned by root or by us, and must not be writable by group or other.
///
/// Checking only the file is not enough — a key file that root owns inside a
/// directory an attacker can write to can simply be renamed away and replaced.
/// The path is canonicalised first so a symlink cannot smuggle the real file
/// out from under the checks.
fn check_strict_modes(path: &Path) -> io::Result<()> {
    let euid = rustix::process::geteuid().as_raw();
    let real = std::fs::canonicalize(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot resolve {}: {e}", path.display())))?;

    for (depth, component) in real.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(component).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot stat {}: {e}", component.display()),
            )
        })?;
        let owner = meta.uid();
        if owner != 0 && owner != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing: {} is owned by uid {owner}, not root or the server user ({euid})",
                    component.display()
                ),
            ));
        }
        if meta.mode() & 0o022 == 0 {
            continue;
        }
        // A sticky directory is safe even when it is group- or world-writable:
        // the sticky bit is exactly the rule that stops a non-owner renaming or
        // unlinking someone else's entry, so nobody can swap our key file out.
        // This is not a nicety — `/nix/store` is mode 1775 root:nixbld, so
        // without it no key file provisioned through Nix could ever be used.
        let is_dir = depth > 0 || meta.is_dir();
        if is_dir && meta.mode() & 0o1000 != 0 {
            continue;
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing: {} is group- or world-writable (mode {:o})",
                component.display(),
                meta.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

fn read_and_validate(path: &Path) -> io::Result<(KeyMap, Stamp)> {
    check_strict_modes(path)?;

    // Stat *after* the read so that a file rewritten while we were reading it
    // leaves a stamp that no longer matches, and the next caller reloads.
    let text = std::fs::read_to_string(path)?;
    let meta = std::fs::metadata(path)?;

    let mut keys = KeyMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // authorized_keys format: <type> <base64> [comment]
        let mut parts = line.splitn(3, char::is_whitespace);
        let ktype = parts.next().unwrap_or("");
        if ktype != "ssh-ed25519" {
            // Options-prefixed and non-ed25519 lines are both skipped; say so
            // rather than silently ignoring a line the operator thinks is live.
            crate::warn!(
                "{}:{}: ignoring unsupported key type '{ktype}' (only ssh-ed25519 is accepted)",
                path.display(),
                lineno + 1
            );
            continue;
        }
        let Some(b64) = parts.next() else { continue };
        let comment = parts.next().unwrap_or("").trim().to_string();
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            crate::warn!(
                "{}:{}: ignoring malformed base64",
                path.display(),
                lineno + 1
            );
            continue;
        };
        // Reject anything that is not a well-formed ed25519 blob up front, so a
        // typo cannot masquerade as an authorized entry.
        if crate::agent::ed25519_pubkey(&blob).is_none() {
            crate::warn!(
                "{}:{}: ignoring key that is not a valid ssh-ed25519 blob",
                path.display(),
                lineno + 1
            );
            continue;
        }
        let fingerprint = fingerprint(&blob);
        keys.insert(
            blob,
            KeyInfo {
                fingerprint,
                comment,
            },
        );
    }

    if keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no usable ed25519 keys found in {}", path.display()),
        ));
    }
    Ok((keys, Stamp::of(&meta)))
}
