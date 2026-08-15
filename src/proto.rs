//! On-the-wire protocol constants shared by client and server.

/// 4-byte magic sent by the server at the start of every connection.
pub const MAGIC: [u8; 4] = *b"SDKY";
/// Protocol version byte.
pub const VERSION: u8 = 1;

/// Context string mixed into the signed data so signatures produced for
/// sudokey cannot be confused with signatures for any other purpose.
pub const CONTEXT: &[u8] = b"sudokey-auth-v1";

/// Length of the per-connection random challenge nonce.
pub const NONCE_LEN: usize = 32;

/// Auth result byte sent by the server after the challenge/response.
pub const STATUS_OK: u8 = 1;
pub const STATUS_DENY: u8 = 0;

/// Request modes.
pub const MODE_EXEC: u8 = 0;
pub const MODE_PTY: u8 = 1;

/// Multiplexed stream channels.
pub const CH_STDIN: u8 = 0; // client -> server (stdin / pty input)
pub const CH_STDOUT: u8 = 1; // server -> client (stdout / pty output)
pub const CH_STDERR: u8 = 2; // server -> client (exec stderr)
pub const CH_EXIT: u8 = 3; // server -> client (i32 exit status)
pub const CH_WINCH: u8 = 4; // client -> server (cols/rows resize, pty)
pub const CH_STDIN_EOF: u8 = 5; // client -> server (stdin closed)

/// Upper bounds to keep a malicious/confused peer from allocating unbounded
/// memory. Frame payloads and ssh-wire strings are both capped.
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB per stream frame
pub const MAX_STRING: usize = 1 << 18; // 256 KiB per ssh-wire string
pub const MAX_KEYS: u32 = 64; // auth pairs per connection
pub const MAX_ARGV: u32 = 4096; // argv elements
