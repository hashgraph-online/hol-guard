//! Run a verified `--help` argv and keep what it prints
//! (`runtime/local_cli_help.run_cli_help`).
//!
//! The program runs in a fresh temporary folder that is also its `HOME` and
//! `TMPDIR`, with a fixed `PATH`, no input, and stdout and stderr on one pipe.
//! It stays in this command's process group (a Job Object on Windows), which
//! the bounded launcher Python runs this command through kills when the
//! command ends, times out or is cancelled. So nothing a help run started
//! outlives the discovery, and a cancel reaches the help run too; a group of
//! its own would escape that kill.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use crate::local_cli_script_source::safe_probe_path;

const HELP_TIMEOUT: Duration = Duration::from_millis(2500);
const HELP_OUTPUT_LIMIT: usize = 8192;
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";

pub(crate) static COMMAND_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$").expect("command name pattern"));

/// What `argv` printed, or an empty string when it may not run or failed to.
pub(crate) fn run_cli_help(argv: &[String]) -> String {
    if argv.len() < 2 || argv.last().map(String::as_str) != Some("--help") {
        return String::new();
    }
    if argv
        .iter()
        .any(|part| part.is_empty() || part.contains('\0'))
    {
        return String::new();
    }
    if !safe_probe_path(&argv[0]) {
        return String::new();
    }
    if argv.len() >= 3
        && !safe_probe_path(&argv[1])
        && argv[1] != "--help"
        && !COMMAND_NAME.is_match(&argv[1])
    {
        return String::new();
    }
    let Ok(folder) = tempfile::Builder::new()
        .prefix("hol-guard-cli-help-")
        .tempdir()
    else {
        return String::new();
    };
    read_help_output(argv, folder.path()).unwrap_or_default()
}

fn read_help_output(argv: &[String], folder: &std::path::Path) -> std::io::Result<String> {
    let (mut reader, writer) = std::io::pipe()?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(folder)
        .env_clear()
        .envs(help_env(folder))
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer);
    let mut child = command.spawn()?;
    // The parent's copies of the write end go with `command`, so the read
    // below ends when the program and everything it started let go.
    drop(command);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0u8; 4096];
        while captured.len() < HELP_OUTPUT_LIMIT {
            let room = (HELP_OUTPUT_LIMIT - captured.len()).min(buffer.len());
            match reader.read(&mut buffer[..room]) {
                Ok(0) | Err(_) => break,
                Ok(read) => captured.extend_from_slice(&buffer[..read]),
            }
        }
        let _ = sender.send(captured);
    });
    let captured = receiver.recv_timeout(HELP_TIMEOUT);
    stop(&mut child);
    let captured = match captured {
        Ok(bytes) => bytes,
        // Killing the group closes the pipe, so the reader hands over what it has.
        Err(_) => receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_default(),
    };
    let text = String::from_utf8_lossy(&captured);
    Ok(text.chars().take(HELP_OUTPUT_LIMIT).collect())
}

/// Stop the program. Anything it started is in this command's group, which
/// the launcher kills when the command ends.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn help_env(folder: &std::path::Path) -> Vec<(String, String)> {
    let folder = folder.to_string_lossy().into_owned();
    let mut env = vec![
        ("PATH".to_owned(), SAFE_PATH.to_owned()),
        ("HOME".to_owned(), folder.clone()),
        ("TMPDIR".to_owned(), folder),
        ("LANG".to_owned(), "C".to_owned()),
        ("LC_ALL".to_owned(), "C".to_owned()),
        ("TERM".to_owned(), "dumb".to_owned()),
    ];
    if cfg!(windows) {
        if let Ok(path) = std::env::var("PATH") {
            env[0].1 = path;
        }
        if let Ok(root) = std::env::var("SYSTEMROOT") {
            env.push(("SYSTEMROOT".to_owned(), root));
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn only_a_help_argv_runs() {
        assert_eq!(run_cli_help(&argv(&["/bin/echo", "hello"])), "");
        assert_eq!(run_cli_help(&argv(&["--help"])), "");
        assert_eq!(run_cli_help(&argv(&["", "--help"])), "");
        assert_eq!(run_cli_help(&argv(&["/bin/echo", "a\0b", "--help"])), "");
    }

    #[test]
    fn a_middle_word_must_be_a_command_name_or_a_safe_path() {
        assert_eq!(
            run_cli_help(&argv(&["/bin/echo", "$(touch x)", "--help"])),
            ""
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_help_run_gets_a_private_home_and_a_fixed_path() {
        let folder = tempfile::tempdir().unwrap();
        let env = help_env(folder.path());
        assert!(env.contains(&("PATH".to_owned(), SAFE_PATH.to_owned())));
        assert!(env.contains(&(
            "HOME".to_owned(),
            folder.path().to_string_lossy().into_owned()
        )));
    }
}
