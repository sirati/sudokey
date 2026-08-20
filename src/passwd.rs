//! Direct `/etc/passwd` and `/etc/group` lookups.
//!
//! The binary is built as a fully static musl executable, so `getpwuid()` and
//! friends would be unable to consult NSS anyway — reading the files is both
//! honest about what we can see and avoids needing `unsafe` FFI.

/// The fields of a `/etc/passwd` line that we care about.
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

fn parse_passwd_line(line: &str) -> Option<User> {
    // name:passwd:uid:gid:gecos:home:shell
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 7 {
        return None;
    }
    Some(User {
        name: f[0].to_string(),
        uid: f[2].parse().ok()?,
        home: f[5].to_string(),
        shell: f[6].to_string(),
    })
}

fn each_line(path: &str, mut f: impl FnMut(&str) -> bool) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if f(line) {
            return;
        }
    }
}

/// Look up a user by numeric uid.
pub fn user_by_uid(uid: u32) -> Option<User> {
    let mut found = None;
    each_line("/etc/passwd", |line| match parse_passwd_line(line) {
        Some(u) if u.uid == uid => {
            found = Some(u);
            true
        }
        _ => false,
    });
    found
}

/// Human-readable name for a uid, falling back to the number itself.
pub fn uid_label(uid: u32) -> String {
    match user_by_uid(uid) {
        Some(u) => format!("{}({})", uid, u.name),
        None => uid.to_string(),
    }
}

/// Resolve a group given either its name or a numeric gid.
pub fn gid_for(spec: &str) -> Option<u32> {
    if let Ok(gid) = spec.parse::<u32>() {
        return Some(gid);
    }
    let mut found = None;
    each_line("/etc/group", |line| {
        // name:passwd:gid:members
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[0] == spec {
            found = f[2].parse().ok();
            return true;
        }
        false
    });
    found
}

/// Login shell for `uid`, falling back to the first shell that exists.
pub fn shell_for(uid: u32) -> String {
    if let Some(u) = user_by_uid(uid) {
        if !u.shell.is_empty() && std::path::Path::new(&u.shell).exists() {
            return u.shell;
        }
    }
    for cand in ["/run/current-system/sw/bin/bash", "/bin/bash", "/bin/sh"] {
        if std::path::Path::new(cand).exists() {
            return cand.to_string();
        }
    }
    "/bin/sh".to_string()
}

/// Home directory for `uid`, defaulting to `/root` for uid 0 and `/` otherwise.
pub fn home_for(uid: u32) -> String {
    match user_by_uid(uid) {
        Some(u) if !u.home.is_empty() => u.home,
        _ if uid == 0 => "/root".to_string(),
        _ => "/".to_string(),
    }
}

/// Account name for `uid`, defaulting to `root` / the numeric uid.
pub fn name_for(uid: u32) -> String {
    match user_by_uid(uid) {
        Some(u) => u.name,
        None if uid == 0 => "root".to_string(),
        None => uid.to_string(),
    }
}
