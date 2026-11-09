//! The answers that depend on how Guard was installed, which only the
//! installed CLI can describe: the edge runs the daemon's own CLI with the
//! hidden `desktop daemon-query` command and reads one JSON envelope back,
//! `{"status": <http status>, "body": <object>}`.

use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Map, Value};

use super::ReadConfig;

/// How long a route answered through the CLI may take: the CLI's own start
/// plus the harness detection it runs.
pub(in crate::daemon_edge) const ROUTE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most a query answer may print.
const ANSWER_LIMIT_BYTES: u64 = 4 * 1024 * 1024;

/// The status and body the CLI answers `name` with, or `None` when the daemon
/// named no CLI, the CLI failed, ran past `timeout`, or printed anything else.
pub(in crate::daemon_edge) fn query(
    config: &ReadConfig,
    name: &str,
    input: Option<&Value>,
    timeout: Duration,
) -> Option<(u16, Map<String, Value>)> {
    let argv = config.cli_command.as_deref()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(query_args(&config.guard_home, name))
        .stderr(Stdio::null());
    if let Some(cwd) = &config.daemon_cwd {
        command.current_dir(cwd);
    }
    let output = match input {
        // The input goes on stdin, never argv: request bodies can carry
        // one-time codes.
        Some(input) => {
            command.arg("--input-stdin");
            crate::onefile_open_paths::bounded_stdout_in_group_with_input(
                command,
                input.to_string().into_bytes(),
                ANSWER_LIMIT_BYTES,
                timeout,
            )?
        }
        None => crate::onefile_open_paths::bounded_stdout_in_group(
            command,
            ANSWER_LIMIT_BYTES,
            timeout,
        )?,
    };
    parse_answer(&output)
}

/// The arguments after the CLI's own argv prefix.
pub(in crate::daemon_edge) fn query_args(guard_home: &str, name: &str) -> [String; 7] {
    [
        "desktop".to_owned(),
        "daemon-query".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
        "--query".to_owned(),
        name.to_owned(),
        "--json".to_owned(),
    ]
}

/// The envelope on the answer's last non-empty line.
pub(in crate::daemon_edge) fn parse_answer(output: &[u8]) -> Option<(u16, Map<String, Value>)> {
    let text = std::str::from_utf8(output).ok()?;
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let Value::Object(mut envelope) = serde_json::from_str(line.trim()).ok()? else {
        return None;
    };
    let status = envelope
        .get("status")?
        .as_u64()
        .filter(|status| (200..600).contains(status))?;
    match envelope.remove("body")? {
        Value::Object(body) => Some((u16::try_from(status).ok()?, body)),
        _ => None,
    }
}
