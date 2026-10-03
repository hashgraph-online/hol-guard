//! Bounded, non-interactive Git metadata probes.
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(super) fn output(
    command: &mut Command,
    deadline: Instant,
    limit: u64,
) -> Option<(ExitStatus, Vec<u8>)> {
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(limit + 1).read_to_end(&mut bytes).ok()?;
        (bytes.len() <= limit as usize).then_some(bytes)
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
    let bytes = reader.join().ok()??;
    Some((status?, bytes))
}

pub(super) fn submodules_are_inert(
    base: &Command,
    arguments: &[String],
    deadline: Instant,
) -> Option<bool> {
    let ignored = arguments
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_str() != "--")
        .filter_map(|arg| {
            if arg == "--ignore-submodules" {
                Some(true)
            } else {
                arg.strip_prefix("--ignore-submodules=")
                    .map(|value| value == "all")
            }
        })
        .last()
        == Some(true);
    if ignored {
        return Some(true);
    }
    let mut index = copy_command(base)?;
    // Inspect index metadata with fsmonitor and paging explicitly disabled.
    index.args([
        "-c",
        "core.fsmonitor=false",
        "--no-pager",
        "ls-files",
        "--stage",
        "-z",
    ]);
    let (status, bytes) = output(&mut index, deadline, 2 * 1024 * 1024)?;
    if !status.success() {
        return None;
    }
    // Gitlinks may launch children whose local configuration is unprobed.
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .all(|record| {
                [b"100644 ", b"100755 ", b"120000 "]
                    .iter()
                    .any(|mode| record.starts_with(*mode))
            }),
    )
}

/// Copy only the explicit lookup environment and directory, never ambient state.
pub(super) fn copy_command(base: &Command) -> Option<Command> {
    let mut command = Command::new(base.get_program());
    command.args(base.get_args()).env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command.current_dir(base.get_current_dir()?);
    Some(command)
}
