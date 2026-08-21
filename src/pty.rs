//! Terminal helpers for the client side, built entirely on the safe `rustix`
//! API (no `unsafe` in this crate).

use std::io;
use std::os::fd::AsFd;

use rustix::termios::{self, OptionalActions, Termios};

/// Guard that restores the terminal to its saved state on drop.
pub struct RawGuard<Fd: AsFd> {
    fd: Fd,
    saved: Termios,
}

impl<Fd: AsFd> RawGuard<Fd> {
    /// Put `fd` into raw mode if it is a tty, returning a restoring guard.
    /// Returns `Ok(None)` when `fd` is not a terminal.
    pub fn new(fd: Fd) -> io::Result<Option<RawGuard<Fd>>> {
        if !termios::isatty(&fd) {
            return Ok(None);
        }
        let saved = termios::tcgetattr(&fd)?;
        let mut raw = saved.clone();
        raw.make_raw();
        termios::tcsetattr(&fd, OptionalActions::Now, &raw)?;
        Ok(Some(RawGuard { fd, saved }))
    }
}

impl<Fd: AsFd> Drop for RawGuard<Fd> {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(&self.fd, OptionalActions::Now, &self.saved);
    }
}

/// Query the window size of a tty fd, defaulting to 80x24 if unavailable.
pub fn get_winsize<Fd: AsFd>(fd: Fd) -> (u16, u16) {
    match termios::tcgetwinsize(fd) {
        Ok(ws) if ws.ws_col > 0 && ws.ws_row > 0 => (ws.ws_col, ws.ws_row),
        _ => (80, 24),
    }
}

/// True if `fd` is a terminal.
pub fn is_tty<Fd: AsFd>(fd: Fd) -> bool {
    termios::isatty(fd)
}

/// True if reading `fd` would block on the terminal rather than raise SIGTTIN.
///
/// Reading the controlling terminal from a *background* process group raises
/// SIGTTIN, whose default action stops the process. A client that forwards
/// stdin unconditionally therefore wedges the moment it is backgrounded --
/// `sudokey run -- id &` stops before the command finishes, and the only way
/// out is `< /dev/null`. Comparing the terminal's foreground process group
/// with our own says up front whether reading is safe.
///
/// Anything that is not a terminal (a pipe, a file, /dev/null) is always
/// readable in this sense.
pub fn is_foreground<Fd: AsFd>(fd: Fd) -> bool {
    if !termios::isatty(&fd) {
        return true;
    }
    match termios::tcgetpgrp(&fd) {
        Ok(fg) => fg == rustix::process::getpgrp(),
        // No controlling terminal for this fd: nothing will send us SIGTTIN.
        Err(_) => true,
    }
}
