//! Bounded executor for fixed, read-only host probes. It never uses a shell,
//! accepts stdin, or returns diagnostics that might contain private data.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixedProcessError {
    Unavailable,
    Failed,
    TimedOut,
    TooLarge,
}

fn drain_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, FixedProcessError> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut overflow = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| FixedProcessError::Unavailable)?;
        if count == 0 {
            break;
        }
        if kept.len().saturating_add(count) > limit {
            overflow = true;
        } else if !overflow {
            kept.extend_from_slice(&buffer[..count]);
        }
    }
    if overflow {
        Err(FixedProcessError::TooLarge)
    } else {
        Ok(kept)
    }
}

pub(crate) fn run_fixed(
    argv: &[String],
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    environment: &[(&str, &str)],
) -> Result<Vec<u8>, FixedProcessError> {
    run_fixed_input_inner(
        argv,
        None,
        timeout,
        stdout_limit,
        stderr_limit,
        environment,
        false,
    )
}

/// Run a fixed program without inheriting caller environment variables.
pub(crate) fn run_fixed_clean(
    argv: &[String],
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    environment: &[(&str, &str)],
) -> Result<Vec<u8>, FixedProcessError> {
    run_fixed_input_inner(
        argv,
        None,
        timeout,
        stdout_limit,
        stderr_limit,
        environment,
        true,
    )
}

pub(crate) fn run_fixed_input(
    argv: &[String],
    input: Option<&[u8]>,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    environment: &[(&str, &str)],
) -> Result<Vec<u8>, FixedProcessError> {
    run_fixed_input_inner(
        argv,
        input,
        timeout,
        stdout_limit,
        stderr_limit,
        environment,
        false,
    )
}

fn run_fixed_input_inner(
    argv: &[String],
    input: Option<&[u8]>,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    environment: &[(&str, &str)],
    clean_environment: bool,
) -> Result<Vec<u8>, FixedProcessError> {
    if input.is_some_and(|bytes| bytes.len() > 1024) {
        return Err(FixedProcessError::TooLarge);
    }
    let executable = argv.first().ok_or(FixedProcessError::Unavailable)?;
    if !Path::new(executable).is_absolute() {
        return Err(FixedProcessError::Unavailable);
    }
    let mut command = Command::new(executable);
    if clean_environment {
        command.env_clear();
    }
    let mut child = command
        .args(&argv[1..])
        .envs(environment.iter().copied())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| FixedProcessError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(FixedProcessError::Unavailable)?;
    let stderr = child.stderr.take().ok_or(FixedProcessError::Unavailable)?;
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    thread::spawn(move || {
        let _ = stdout_sender.send((true, drain_bounded(stdout, stdout_limit)));
    });
    thread::spawn(move || {
        let _ = sender.send((false, drain_bounded(stderr, stderr_limit)));
    });
    if let Some(bytes) = input {
        let write_result = child
            .stdin
            .take()
            .ok_or(FixedProcessError::Unavailable)
            .and_then(|mut stream| {
                stream
                    .write_all(bytes)
                    .map_err(|_| FixedProcessError::Failed)
            });
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FixedProcessError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FixedProcessError::Unavailable);
            }
        }
    };
    let mut output = None;
    let mut diagnostics = None;
    for _ in 0..2 {
        let (is_stdout, result) = receiver
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| FixedProcessError::Unavailable)?;
        if is_stdout {
            output = Some(result);
        } else {
            diagnostics = Some(result);
        }
    }
    let output = output.ok_or(FixedProcessError::Unavailable)??;
    diagnostics.ok_or(FixedProcessError::Unavailable)??;
    if !status.success() {
        return Err(FixedProcessError::Failed);
    }
    Ok(output)
}
