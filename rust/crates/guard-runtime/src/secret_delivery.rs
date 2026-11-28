//! Bounded secret delivery into a child process. The value never crosses the
//! JSON/CLI boundary and returned output is redacted before it leaves Rust.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::secret_store_platform::NativeSecret;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Sink {
    Environment(String),
    Stdin,
    FileDescriptor,
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
) -> Result<DeliveryResult, String> {
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
    if matches!(sink, Sink::Stdin) {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(secret.expose().as_bytes())
                .map_err(|_| "secret_child_stdin_failed".to_owned())?;
            stdin
                .flush()
                .map_err(|_| "secret_child_stdin_failed".to_owned())?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "secret_child_wait_failed".to_owned())?;
    let stdout = redact_bounded(&output.stdout, secret.expose());
    let stderr = redact_bounded(&output.stderr, secret.expose());
    Ok(DeliveryResult {
        status: output.status.code(),
        redacted: stdout.1 || stderr.1,
        stdout: stdout.0,
        stderr: stderr.0,
    })
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

fn redact_bounded(bytes: &[u8], secret: &str) -> (String, bool) {
    let truncated = bytes.len() > MAX_OUTPUT_BYTES;
    let bounded = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
    let text = String::from_utf8_lossy(bounded);
    let mut redacted = false;
    let mut output = text.into_owned();
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
        assert_eq!(
            deliver(
                &secret,
                "fixture-program",
                &["fixture-value-7".to_owned()],
                Sink::Stdin,
            )
            .unwrap_err(),
            "secret_argument_refused"
        );
        assert_eq!(
            deliver(&secret, "fixture-program", &[], Sink::FileDescriptor).unwrap_err(),
            "secret_sink_unsupported"
        );
    }

    #[test]
    fn redacts_reflection_and_bounds_output() {
        let (output, reflected) =
            redact_bounded(b"prefix fixture-value-7 suffix", "fixture-value-7");
        assert_eq!(output, "prefix [REDACTED] suffix");
        assert!(reflected);
        let (output, _) = redact_bounded(&vec![b'x'; MAX_OUTPUT_BYTES + 1], "fixture-value-7");
        assert!(output.ends_with("[OUTPUT_TRUNCATED]"));
    }
}
