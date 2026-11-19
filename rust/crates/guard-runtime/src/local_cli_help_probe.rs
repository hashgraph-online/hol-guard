//! Run a verified `--help` argv and keep what it prints
//! (`runtime/local_cli_help.run_cli_help`).
//!
//! The program runs in a fresh temporary folder that is also its `HOME` and
//! `TMPDIR`, with a fixed `PATH`, no input, and stdout and stderr on one pipe.
//! On Unix it leads a process group of its own, and that whole group is
//! killed when the help run ends, whether it exited, timed out or printed too
//! much, so nothing it started outlives the probe. The group is killed before
//! the program is reaped, so its id cannot have been reused.
//!
//! A group of its own is outside the launcher's process group, so the
//! launcher's cancel or deadline kill would miss it if this command were
//! killed mid-probe. A small watcher in a group of its own holds a pipe from
//! this command: when the probe ends normally it is told so and exits, and
//! when the pipe closes without that word (this command was killed) it kills
//! the help group. A help run never starts without its watcher.
//!
//! On Windows the help run stays in this command's Job Object, which the
//! bounded launcher closes when the command ends. Output read before a
//! timeout is kept even when a leftover child still holds the pipe.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
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
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    #[cfg(unix)]
    let watch = match GroupWatch::start(child.id()) {
        Ok(watch) => watch,
        Err(error) => {
            stop(&mut child);
            return Err(error);
        }
    };
    // The parent's copies of the write end go with `command`, so the read
    // below ends when the program and everything it started let go.
    drop(command);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (sender, receiver) = mpsc::channel();
    let sink = Arc::clone(&captured);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let room = match sink.lock() {
                Ok(bytes) => HELP_OUTPUT_LIMIT.saturating_sub(bytes.len()),
                Err(_) => 0,
            };
            if room == 0 {
                break;
            }
            match reader.read(&mut buffer[..room.min(4096)]) {
                Ok(0) | Err(_) => break,
                Ok(read) => match sink.lock() {
                    Ok(mut bytes) => bytes.extend_from_slice(&buffer[..read]),
                    Err(_) => break,
                },
            }
        }
        let _ = sender.send(());
    });
    let finished = receiver.recv_timeout(HELP_TIMEOUT).is_ok();
    stop(&mut child);
    #[cfg(unix)]
    watch.release();
    if !finished {
        // Killing the group closes every copy of the pipe, so the reader ends.
        let _ = receiver.recv_timeout(Duration::from_secs(1));
    }
    let bytes = captured
        .lock()
        .map(|bytes| bytes.clone())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.chars().take(HELP_OUTPUT_LIMIT).collect())
}

/// Stop the program and, on Unix, everything in its process group. The group
/// goes first: the unreaped program keeps the group id from being reused.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{killpg, Signal};
        use nix::unistd::Pid;
        if let Ok(id) = i32::try_from(child.id()) {
            let _ = killpg(Pid::from_raw(id), Signal::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Kills the help run's process group if this command dies before
/// [`GroupWatch::release`]: the watcher reads one line from a pipe this
/// command holds, and a pipe closed without that line means this command was
/// killed. The watcher leads a group of its own, so the launcher's kill of
/// this command's group cannot take it down first.
#[cfg(unix)]
struct GroupWatch {
    watcher: Child,
    line: Option<std::process::ChildStdin>,
}

#[cfg(unix)]
impl GroupWatch {
    const SCRIPT: &'static str = "read done || kill -s KILL -- \"-$1\"";

    fn start(group: u32) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;
        let mut watcher = Command::new("/bin/sh")
            .args(["-c", Self::SCRIPT, "sh", &group.to_string()])
            .env_clear()
            .env("PATH", SAFE_PATH)
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let line = watcher.stdin.take();
        if line.is_none() {
            let _ = watcher.kill();
            let _ = watcher.wait();
            return Err(std::io::Error::other("help watcher has no input pipe"));
        }
        Ok(Self { watcher, line })
    }

    /// The probe ended here and its group is already killed: tell the watcher
    /// and reap it.
    fn release(mut self) {
        use std::io::Write;
        if let Some(mut line) = self.line.take() {
            let _ = line.write_all(b"done\n");
        }
        if self.watcher.wait().is_err() {
            let _ = self.watcher.kill();
        }
    }
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
    fn script(folder: &std::path::Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = folder.join("probe-tool");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    fn running(marker: &str) -> bool {
        Command::new("/bin/ps")
            .args(["-ax", "-o", "command="])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains(marker))
            .unwrap_or(false)
    }

    #[cfg(unix)]
    #[test]
    fn a_probe_that_exits_keeps_its_output_and_stops_what_it_left_behind() {
        let folder = tempfile::tempdir().unwrap();
        let marker = format!("31.{}", std::process::id());
        let tool = script(
            folder.path(),
            &format!("/bin/sleep {marker} &\necho \"Usage: forks\""),
        );
        let output = read_help_output(&argv(&[&tool, "--help"]), folder.path()).unwrap();
        assert!(output.contains("Usage: forks"), "{output:?}");
        std::thread::sleep(Duration::from_millis(200));
        assert!(!running(&format!("sleep {marker}")));
    }

    #[cfg(unix)]
    #[test]
    fn a_probe_that_hangs_keeps_what_it_printed_and_is_stopped() {
        let folder = tempfile::tempdir().unwrap();
        let marker = format!("32.{}", std::process::id());
        let tool = script(
            folder.path(),
            &format!("echo \"Usage: slow\"\nexec /bin/sleep {marker}"),
        );
        let output = read_help_output(&argv(&[&tool, "--help"]), folder.path()).unwrap();
        assert!(output.contains("Usage: slow"), "{output:?}");
        std::thread::sleep(Duration::from_millis(200));
        assert!(!running(&format!("sleep {marker}")));
    }

    #[cfg(unix)]
    #[test]
    fn the_watcher_kills_the_help_group_when_this_command_dies_mid_probe() {
        use std::os::unix::process::CommandExt;
        let marker = format!("33.{}", std::process::id());
        let mut probe = Command::new("/bin/sleep")
            .arg(&marker)
            .process_group(0)
            .spawn()
            .unwrap();
        let mut watch = GroupWatch::start(probe.id()).unwrap();
        // Closing the pipe without the word is what this command's death looks like.
        drop(watch.line.take());
        watch.watcher.wait().unwrap();
        probe.wait().unwrap();
        assert!(!running(&format!("sleep {marker}")));
    }

    #[cfg(unix)]
    #[test]
    fn a_released_watcher_leaves_the_group_alone() {
        use std::os::unix::process::CommandExt;
        let marker = format!("34.{}", std::process::id());
        let mut probe = Command::new("/bin/sleep")
            .arg(&marker)
            .process_group(0)
            .spawn()
            .unwrap();
        GroupWatch::start(probe.id()).unwrap().release();
        assert!(probe.try_wait().unwrap().is_none());
        let _ = probe.kill();
        let _ = probe.wait();
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
