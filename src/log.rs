//! Tiny leveled logger.
//!
//! Everything goes to stderr. When systemd is capturing our stderr (it sets
//! `JOURNAL_STREAM`) each line is prefixed with a `<N>` syslog priority, which
//! journald strips and turns into a real priority — so `journalctl -p err` and
//! friends work. Outside systemd we print a human prefix instead.

use std::io::Write;
use std::sync::OnceLock;

pub const PRI_ERR: u8 = 3;
pub const PRI_WARNING: u8 = 4;
pub const PRI_NOTICE: u8 = 5;
pub const PRI_INFO: u8 = 6;

fn under_journald() -> bool {
    static J: OnceLock<bool> = OnceLock::new();
    *J.get_or_init(|| std::env::var_os("JOURNAL_STREAM").is_some())
}

/// Write one log line. Not a macro so the formatting machinery is monomorphised
/// once; the macros below are the ergonomic front end.
pub fn emit(priority: u8, plain_prefix: &str, msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = if under_journald() {
        writeln!(err, "<{priority}>{msg}")
    } else {
        writeln!(err, "sudokey: {plain_prefix}{msg}")
    };
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::log::emit($crate::log::PRI_INFO, "", &format!($($t)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { $crate::log::emit($crate::log::PRI_WARNING, "warning: ", &format!($($t)*)) };
}

#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { $crate::log::emit($crate::log::PRI_ERR, "error: ", &format!($($t)*)) };
}

/// Authorisation and command-execution events. These are the lines an operator
/// greps for after the fact, so they are logged at NOTICE and tagged.
#[macro_export]
macro_rules! audit {
    ($($t:tt)*) => {
        $crate::log::emit($crate::log::PRI_NOTICE, "", &format!("audit: {}", format_args!($($t)*)))
    };
}
