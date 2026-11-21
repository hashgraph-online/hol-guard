//! `codex_remote_launch` op `run`: the whole guarded Codex launch in one call.
//!
//! The caller names the authorized executable prefix, its home, the user's
//! arguments and its environment. The resident plans the launch, runs each
//! process the `prepare` sequence names (`remote-control start`, or a direct
//! `app-server` in a session of its own), and answers the one argv to run:
//! the remote TUI when the control socket is ready, else the ordinary
//! command. A refusal is answered as `{"refusal": ...}`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::codex_remote_launch::{launch, string_list};
use super::codex_remote_prepare::prepare;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 5] = ["op", "prefixes", "home_dir", "args", "environ"];
const READY_SECONDS: f64 = 3.0;
/// Each step may wait for the socket and the sequence has three steps.
const MAX_STEPS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

type Environment = BTreeMap<String, String>;

pub(super) fn run(map: &Map<String, Value>) -> KindResult {
    if map.len() != KEYS.len() || !map.keys().all(|key| KEYS.contains(&key.as_str())) {
        return Err(ERR_INVALID);
    }
    let mut environment = Environment::new();
    for (key, value) in map
        .get("environ")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
    {
        environment.insert(key.clone(), value.as_str().ok_or(ERR_INVALID)?.to_owned());
    }
    let mut planned = Map::new();
    for key in ["prefixes", "home_dir", "args"] {
        planned.insert(key.to_owned(), map[key].clone());
    }
    let plan = launch(&planned)?;
    if plan.get("refusal").is_some() {
        return Ok(plan);
    }
    let argv = |key: &str| -> Result<Vec<String>, &'static str> {
        let parts = string_list(plan.get(key))?;
        Ok(parts.into_iter().map(str::to_owned).collect())
    };
    let remote = plan.get("prepare") == Some(&Value::Bool(true))
        && prepare_remote(
            &plan,
            map["home_dir"].as_str().ok_or(ERR_INVALID)?,
            environment,
        );
    Ok(json!({ "argv": argv(if remote { "remote" } else { "plain" })? }))
}

/// Run each process the `prepare` sequence names; true when the remote TUI can connect.
fn prepare_remote(plan: &Value, home: &str, mut environment: Environment) -> bool {
    let (Some(prefix), Some(socket)) = (
        string_list(plan.get("prefix")).ok(),
        plan.get("socket").and_then(Value::as_str),
    ) else {
        return false;
    };
    let mut request = json!({
        "op": "prepare",
        "home_dir": home,
        "socket": socket,
        "seconds": READY_SECONDS,
        "stage": "start",
    });
    for _ in 0..MAX_STEPS {
        let Some(answer) = request
            .as_object()
            .and_then(|request| prepare(request).ok())
        else {
            return false;
        };
        if let Some(launch) = answer.get("launch") {
            return launch == "remote";
        }
        if let Some(env) = answer.get("env").and_then(Value::as_object) {
            for (key, value) in env {
                if let Some(value) = value.as_str() {
                    environment.insert(key.clone(), value.to_owned());
                }
            }
        }
        let Some(stage) = answer.get("stage").cloned() else {
            return false;
        };
        let tail = |key: &str| {
            string_list(answer.get(key))
                .ok()
                .filter(|tail| !tail.is_empty())
        };
        if let (Some(tail), Some(timeout)) =
            (tail("run"), answer.get("timeout").and_then(Value::as_u64))
        {
            let exit = run_to_exit(&prefix, &tail, &environment, Duration::from_secs(timeout));
            request["stage"] = stage;
            request["exit"] = json!(exit);
        } else if let Some(tail) = tail("spawn") {
            let Some(pid) = spawn(&prefix, &tail, &environment) else {
                return false;
            };
            request["stage"] = stage;
            request["pid"] = json!(pid);
        } else {
            return false;
        }
    }
    false
}

fn command_line(prefix: &[&str], tail: &[&str]) -> Vec<OsString> {
    prefix
        .iter()
        .map(OsString::from)
        .chain(tail.iter().map(OsString::from))
        .collect()
}

/// The exit code of `prefix tail`, or none when it cannot start, outlives `timeout` or is signalled.
fn run_to_exit(
    prefix: &[&str],
    tail: &[&str],
    environment: &Environment,
    timeout: Duration,
) -> Option<i32> {
    let argv = command_line(prefix, tail);
    let mut child = Command::new(argv.first()?)
        .args(&argv[1..])
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// The pid of `prefix tail` started detached, or none when it cannot start.
fn spawn(prefix: &[&str], tail: &[&str], environment: &Environment) -> Option<u32> {
    let argv = command_line(prefix, tail);
    let env: Vec<(OsString, OsString)> = environment
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    guard_contained_process::detached::spawn_detached(Path::new(argv.first()?), &argv[1..], &env)
        .ok()
}

#[cfg(test)]
#[path = "codex_remote_run_tests.rs"]
mod tests;
