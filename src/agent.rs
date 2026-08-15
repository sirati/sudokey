//! Minimal ssh-agent protocol client over `$SSH_AUTH_SOCK`.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use crate::wire::{parse_string, read_string, write_string, write_u32};

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const ED25519_TYPE: &[u8] = b"ssh-ed25519";

pub struct Identity {
    /// Raw SSH public-key blob: string "ssh-ed25519", string pubkey(32).
    pub key_blob: Vec<u8>,
    pub comment: String,
}

impl Identity {
    /// True if this identity is an ed25519 key.
    pub fn is_ed25519(&self) -> bool {
        matches!(parse_string(&self.key_blob), Some((t, _)) if t == ED25519_TYPE)
    }
}

/// Connect to the running ssh-agent named by `$SSH_AUTH_SOCK`.
pub fn connect() -> io::Result<UnixStream> {
    let sock = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "SSH_AUTH_SOCK is not set (no ssh-agent available)",
        )
    })?;
    UnixStream::connect(sock)
}

/// Send one agent request message (a type byte plus body) and read the reply
/// body (with its leading type byte).
fn transact(stream: &mut UnixStream, msg: &[u8]) -> io::Result<Vec<u8>> {
    write_u32(stream, msg.len() as u32)?;
    stream.write_all(msg)?;
    stream.flush()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Agent replies are small; cap to avoid a bogus allocation.
    if len > (1 << 20) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh-agent reply too large",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// List all identities held by the agent.
pub fn list_identities(stream: &mut UnixStream) -> io::Result<Vec<Identity>> {
    let reply = transact(stream, &[SSH_AGENTC_REQUEST_IDENTITIES])?;
    let mut cur = io::Cursor::new(reply);

    let mut t = [0u8; 1];
    cur.read_exact(&mut t)?;
    if t[0] != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected agent reply type {}", t[0]),
        ));
    }

    let mut n_buf = [0u8; 4];
    cur.read_exact(&mut n_buf)?;
    let nkeys = u32::from_be_bytes(n_buf);
    if nkeys > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "implausible key count from agent",
        ));
    }

    let mut ids = Vec::with_capacity(nkeys as usize);
    for _ in 0..nkeys {
        let key_blob = read_string(&mut cur)?;
        let comment = read_string(&mut cur)?;
        ids.push(Identity {
            key_blob,
            comment: String::from_utf8_lossy(&comment).into_owned(),
        });
    }
    Ok(ids)
}

/// Ask the agent to sign `data` with the given key blob. Returns the raw
/// signature blob (string "ssh-ed25519", string sig(64)). Returns `Ok(None)`
/// if the agent refuses to sign with this key so the caller can skip it.
pub fn sign(stream: &mut UnixStream, key_blob: &[u8], data: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut msg = Vec::new();
    msg.push(SSH_AGENTC_SIGN_REQUEST);
    write_string(&mut msg, key_blob)?;
    write_string(&mut msg, data)?;
    write_u32(&mut msg, 0)?; // flags = 0 (plain ed25519)

    let reply = transact(stream, &msg)?;
    if reply.is_empty() || reply[0] != SSH_AGENT_SIGN_RESPONSE {
        // SSH_AGENT_FAILURE or anything else: skip this key.
        return Ok(None);
    }
    let mut cur = io::Cursor::new(&reply[1..]);
    let sig = read_string(&mut cur)?;
    Ok(Some(sig))
}

/// Extract the 32-byte ed25519 public key from an "ssh-ed25519" key blob.
pub fn ed25519_pubkey(key_blob: &[u8]) -> Option<[u8; 32]> {
    let (ktype, off) = parse_string(key_blob)?;
    if ktype != ED25519_TYPE {
        return None;
    }
    let (pk, _) = parse_string(&key_blob[off..])?;
    pk.try_into().ok()
}

/// Extract the 64-byte raw signature from an "ssh-ed25519" signature blob.
pub fn ed25519_sig(sig_blob: &[u8]) -> Option<[u8; 64]> {
    let (stype, off) = parse_string(sig_blob)?;
    if stype != ED25519_TYPE {
        return None;
    }
    let (sig, _) = parse_string(&sig_blob[off..])?;
    sig.try_into().ok()
}
