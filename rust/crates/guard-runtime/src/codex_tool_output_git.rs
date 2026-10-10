//! Bounded `git` runs for the Codex tool-output pathspec review.
//!
//! The profile mirrors the retired Python pathspec query: hooks disabled, no
//! user or system configuration, no pager or terminal prompts, a two second
//! deadline and a one MiB output ceiling. The caller's snapshot supplies only
//! the locale and temp-directory names.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use guard_command::GitRun;

const TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_LIMIT: u64 = 1_048_576;
const PRESERVED_NAMES: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "TMP",
    "TEMP",
    "TMPDIR",
];
#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";

pub(crate) fn run_pathspec_git(
    git: &str,
    arguments: &[String],
    cwd: &str,
    environment: &BTreeMap<String, String>,
) -> GitRun {
    let mut command = Command::new(git);
    command
        .arg("--no-pager")
        .arg("-c")
        .arg(format!("core.hooksPath={NULL_DEVICE}"))
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (name, value) in environment {
        if PRESERVED_NAMES.contains(&name.to_uppercase().as_str()) {
            command.env(name, value);
        }
    }
    command
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("PAGER", "cat");
    let deadline = Instant::now() + TIMEOUT;
    let Ok(mut child) = command.spawn() else {
        return GitRun::Failed("git_pathspec_unavailable");
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return GitRun::Failed("git_pathspec_unavailable");
    };
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes);
        bytes
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let bytes = reader.join().unwrap_or_default();
    let Some(status) = status else {
        return GitRun::Failed("git_pathspec_timeout");
    };
    if !status.success() {
        return GitRun::Failed("git_pathspec_command_failed");
    }
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return GitRun::Failed("git_pathspec_output_limit_exceeded");
    }
    GitRun::Output(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_and_failed_command_are_distinct_reasons() {
        let env = BTreeMap::new();
        assert_eq!(
            run_pathspec_git("/nonexistent/git", &[], "/tmp", &env),
            GitRun::Failed("git_pathspec_unavailable")
        );
        assert_eq!(
            run_pathspec_git("/usr/bin/false", &[], "/tmp", &env),
            GitRun::Failed("git_pathspec_command_failed")
        );
    }
}
