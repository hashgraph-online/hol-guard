//! Bounded secret delivery for a resident-issued execution binding.
//!
//! The public CLI cannot construct [`ApprovedExecutionBinding`]. A future
//! resident approval route must create it after validating the existing Guard
//! approval contract. Keeping the sink implementation behind that type avoids
//! treating a caller-computed digest as authority.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::secret_store_platform::NativeSecret;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_RUNTIME: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Sink {
    Environment(String),
    Stdin,
    FileDescriptor,
}

#[derive(Debug)]
pub(crate) struct ApprovedExecutionBinding {
    digest: String,
}

impl ApprovedExecutionBinding {
    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            digest: "a".repeat(64),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeliveryResult {
    pub(crate) status: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) redacted: bool,
}

pub(crate) fn deliver(
    secret: &NativeSecret,
    program: &str,
    args: &[String],
    sink: Sink,
    binding: &ApprovedExecutionBinding,
) -> Result<DeliveryResult, String> {
    let _binding_digest = &binding.digest;
    validate_program(program)?;
    if args
        .iter()
        .any(|argument| argument.contains(secret.expose()))
    {
        return Err("secret_argument_refused".to_owned());
    }
    let mut command = Command::new(program);
    command.args(args);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    match &sink {
        Sink::Environment(name) => {
            validate_env_name(name)?;
            command.env(name, secret.expose());
            command.stdin(Stdio::null());
        }
        Sink::Stdin => {
            command.stdin(Stdio::piped());
        }
        Sink::FileDescriptor => return Err("secret_sink_unsupported".to_owned()),
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| "secret_child_spawn_failed".to_owned())?;
    let stdout = spawn_reader(child.stdout.take().ok_or("secret_child_output_failed")?);
    let stderr = spawn_reader(child.stderr.take().ok_or("secret_child_output_failed")?);
    let writer = if matches!(sink, Sink::Stdin) {
        let stdin = child.stdin.take().ok_or("secret_child_stdin_failed")?;
        Some(thread::spawn({
            let value = Zeroizing::new(secret.expose().as_bytes().to_vec());
            move || write_secret(stdin, value)
        }))
    } else {
        None
    };
    let status = wait_bounded(&mut child)?;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| "secret_child_stdin_failed".to_owned())??;
    }
    let stdout = stdout
        .join()
        .map_err(|_| "secret_child_output_failed".to_owned())?;
    let stderr = stderr
        .join()
        .map_err(|_| "secret_child_output_failed".to_owned())?;
    let stdout = redact_bounded(stdout?, secret.expose());
    let stderr = redact_bounded(stderr?, secret.expose());
    Ok(DeliveryResult {
        status,
        redacted: stdout.1 || stderr.1,
        stdout: stdout.0,
        stderr: stderr.0,
    })
}

fn write_secret(mut stdin: impl Write, value: Zeroizing<Vec<u8>>) -> Result<(), String> {
    stdin
        .write_all(&value)
        .map_err(|_| "secret_child_stdin_failed".to_owned())?;
    stdin
        .flush()
        .map_err(|_| "secret_child_stdin_failed".to_owned())
}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
) -> thread::JoinHandle<Result<(Vec<u8>, bool), String>> {
    thread::spawn(move || {
        let mut output = Vec::with_capacity(MAX_OUTPUT_BYTES.min(8192));
        let mut buffer = [0_u8; 8192];
        let mut truncated = false;
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|_| "secret_child_output_failed".to_owned())?;
            if count == 0 {
                break;
            }
            if output.len() < MAX_OUTPUT_BYTES {
                let keep = (MAX_OUTPUT_BYTES - output.len()).min(count);
                output.extend_from_slice(&buffer[..keep]);
                truncated |= keep < count;
            } else {
                truncated = true;
            }
        }
        Ok((output, truncated))
    })
}

fn wait_bounded(child: &mut Child) -> Result<Option<i32>, String> {
    let deadline = Instant::now() + MAX_RUNTIME;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("secret_child_timeout".to_owned());
            }
            Err(_) => return Err("secret_child_wait_failed".to_owned()),
        }
    }
}

fn validate_program(program: &str) -> Result<(), String> {
    if program.is_empty()
        || program.len() > 4096
        || program.chars().any(char::is_control)
        || program.contains(['\r', '\n'])
    {
        return Err("secret_program_invalid".to_owned());
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.as_bytes()[0].is_ascii_digit()
    {
        return Err("secret_destination_invalid".to_owned());
    }
    Ok(())
}

fn redact_bounded(bytes: (Vec<u8>, bool), secret: &str) -> (String, bool) {
    let (bytes, truncated) = bytes;
    let mut output = String::from_utf8_lossy(&bytes).into_owned();
    let mut redacted = false;
    if !secret.is_empty() && output.contains(secret) {
        output = output.replace(secret, "[REDACTED]");
        redacted = true;
    }
    if truncated {
        output.push_str("\n[OUTPUT_TRUNCATED]");
    }
    (output, redacted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_secret_in_arguments_and_unsupported_fd() {
        let secret = NativeSecret::new("fixture-value-7".to_owned());
        let binding = ApprovedExecutionBinding::fixture();
        assert_eq!(
            deliver(
                &secret,
                "fixture-program",
                &["fixture-value-7".to_owned()],
                Sink::Stdin,
                &binding,
            )
            .unwrap_err(),
            "secret_argument_refused"
        );
        assert_eq!(
            deliver(
                &secret,
                "fixture-program",
                &[],
                Sink::FileDescriptor,
                &binding,
            )
            .unwrap_err(),
            "secret_sink_unsupported"
        );
    }

    #[test]
    fn redacts_reflection_and_bounds_output() {
        let (output, reflected) = redact_bounded(
            (b"prefix fixture-value-7 suffix".to_vec(), false),
            "fixture-value-7",
        );
        assert_eq!(output, "prefix [REDACTED] suffix");
        assert!(reflected);
        let (output, _) = redact_bounded((vec![b'x'; MAX_OUTPUT_BYTES], true), "fixture-value-7");
        assert!(output.ends_with("[OUTPUT_TRUNCATED]"));
    }

    #[cfg(unix)]
    #[test]
    fn approved_delivery_uses_a_named_sink_and_redacts_child_output() {
        let secret = NativeSecret::new("fixture-value-7".to_owned());
        let result = deliver(
            &secret,
            "sh",
            &["-c".to_owned(), "printf '%s' \"$GUARD_SECRET\"".to_owned()],
            Sink::Environment("GUARD_SECRET".to_owned()),
            &ApprovedExecutionBinding::fixture(),
        )
        .unwrap();
        assert_eq!(result.status, Some(0));
        assert_eq!(result.stdout, "[REDACTED]");
        assert!(result.redacted);
    }
}
