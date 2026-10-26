//! The POSIX process start token behind `current_process_identity`: the
//! Linux `/proc` start tick, else the start time a trusted `ps` reports.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_render::py_strip;

const TRUSTED_PS_PATHS: [&str; 2] = ["/bin/ps", "/usr/bin/ps"];
const PS_TIMEOUT: Duration = Duration::from_millis(500);
const PS_POLL: Duration = Duration::from_millis(1);
const PROC_STAT_LIMIT: u64 = 4096;

/// `str.split()` with no argument: CPython's whitespace for ASCII text.
fn py_split(text: &str) -> Vec<&str> {
    text.split(|character: char| {
        matches!(
            character,
            ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f'
        )
    })
    .filter(|field| !field.is_empty())
    .collect()
}

/// `_linux_proc_stat(pid)`: field 22 of `/proc/<pid>/stat`.
fn linux_proc_stat(pid: u32) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/stat"))
        .ok()?
        .take(PROC_STAT_LIMIT)
        .read_to_end(&mut bytes)
        .ok()?;
    if !bytes.is_ascii() {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    let (_, suffix) = text.rsplit_once(')')?;
    let fields = py_split(suffix);
    let tick = fields.get(19)?;
    (!tick.is_empty() && tick.bytes().all(|byte| byte.is_ascii_digit())).then(|| (*tick).to_owned())
}

/// `_trusted_posix_ps_path()`.
fn trusted_ps_path() -> Option<String> {
    TRUSTED_PS_PATHS.iter().find_map(|raw| {
        let resolved = std::fs::canonicalize(raw).ok()?;
        let metadata = std::fs::metadata(&resolved).ok()?;
        let regular = metadata.file_type().is_file();
        let executable = nix::unistd::access(&resolved, nix::unistd::AccessFlags::X_OK).is_ok();
        (regular && executable).then(|| resolved.to_string_lossy().into_owned())
    })
}

/// Text-mode decoding of the `ps` output: universal newlines.
fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `ps -p <pid> -o lstart=` with the 0.5 second cap Python applies.
fn ps_start_time(ps: &str, pid: u32) -> Option<String> {
    let mut child = Command::new(ps)
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + PS_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(PS_POLL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut stdout = Vec::new();
    child.stdout.take()?.read_to_end(&mut stdout).ok()?;
    if !status.success() {
        return None;
    }
    let text = universal_newlines(std::str::from_utf8(&stdout).ok()?);
    let started = py_strip(&text);
    (!started.is_empty()).then(|| started.to_owned())
}

/// `_process_start_token(pid)` without a deadline.
pub(crate) fn process_start_token(pid: u32) -> Option<String> {
    if Path::new("/proc").is_dir() {
        if let Some(tick) = linux_proc_stat(pid) {
            return Some(format!("linux:{tick}"));
        }
    }
    let ps = trusted_ps_path()?;
    ps_start_time(&ps, pid).map(|started| format!("posix:{started}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn split_matches_python_whitespace() {
        assert_eq!(py_split(" a\x1cb\x0bc  d\n"), vec!["a", "b", "c", "d"]);
        assert!(py_split(" \t ").is_empty());
    }

    #[test]
    fn newlines_follow_text_mode() {
        assert_eq!(universal_newlines("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn own_identity_is_present_and_stable() {
        let (pid, token) =
            crate::codex_hook_identity::current_process_identity().expect("identity");
        assert_eq!(pid, std::process::id());
        assert!(
            token.starts_with("linux:") || token.starts_with("posix:"),
            "{token}"
        );
        assert_eq!(process_start_token(pid), Some(token));
    }
}
