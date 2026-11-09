//! The answers that depend on how Guard was installed, which only the
//! installed CLI can describe: the edge runs the daemon's own CLI with the
//! hidden `desktop daemon-query` command and reads one JSON object back.

use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Map, Value};

use super::ReadConfig;

/// The most a query answer may print.
const ANSWER_LIMIT_BYTES: u64 = 4 * 1024 * 1024;

/// The JSON object the CLI prints for `name`, or `None` when the daemon named
/// no CLI, the CLI failed, ran past `timeout`, or printed anything else.
pub(in crate::daemon_edge) fn query(
    config: &ReadConfig,
    name: &str,
    timeout: Duration,
) -> Option<Map<String, Value>> {
    let argv = config.cli_command.as_deref()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(query_args(&config.guard_home, name))
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(cwd) = &config.daemon_cwd {
        command.current_dir(cwd);
    }
    let output =
        crate::onefile_open_paths::bounded_stdout_in_group(command, ANSWER_LIMIT_BYTES, timeout)?;
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

/// The one JSON object on the answer's last non-empty line.
pub(in crate::daemon_edge) fn parse_answer(output: &[u8]) -> Option<Map<String, Value>> {
    let text = std::str::from_utf8(output).ok()?;
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    match serde_json::from_str(line.trim()).ok()? {
        Value::Object(answer) => Some(answer),
        _ => None,
    }
}
