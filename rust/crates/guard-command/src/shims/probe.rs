//! Intercept probes: run installed shims and read the protect evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::generate::launcher_paths;
use super::manifest::record_test_results;
use super::pyfs::universal_newlines;
use super::status::{package_shim_dashboard_status, package_shim_status};
use super::values::{dict_items, py_is_space, py_json_dumps, py_str_value, py_strip, string_items};
use super::{
    package_shim_command, ShimContext, ShimResult, SHIM_PROBE_ENV_VALUE, SHIM_PROBE_ENV_VAR,
};
use crate::local_supply_chain::stable_digest_hex;

/// Ceiling on a whole probe batch; every manager gets an equal share of it when
/// the requested per-probe timeouts would add up to more.
const PROBE_BATCH_CEILING: Duration = Duration::from_secs(600);
/// Output kept from a probe child; the rest is drained and discarded.
const PROBE_OUTPUT_CAP: u64 = 4 * 1024 * 1024;

/// Inputs of one probe batch.
#[derive(Debug, Clone, Default)]
pub struct ProbeOptions {
    pub managers: Option<Vec<String>>,
    pub workspace_dir: Option<String>,
    pub allow_inactive_path: bool,
    pub project_shell_profile: bool,
    pub timeout_seconds: u64,
}

const PROBE_ARGS: [(&str, &[&str]); 17] = [
    ("brew", &["install", "--dry-run", "jq"]),
    ("npm", &["install", "--dry-run", "lodash@4.17.21"]),
    ("npx", &["-y", "lodash@4.17.21"]),
    ("pnpm", &["add", "--dry-run", "lodash@4.17.21"]),
    ("yarn", &["add", "--dry-run", "lodash@4.17.21"]),
    ("bun", &["add", "--dry-run", "lodash@4.17.21"]),
    ("bunx", &["--version"]),
    ("pip", &["install", "--dry-run", "requests==2.32.3"]),
    ("pip3", &["install", "--dry-run", "requests==2.32.3"]),
    ("uv", &["add", "--dry-run", "requests==2.32.3"]),
    ("poetry", &["add", "--dry-run", "requests@2.32.3"]),
    ("pipenv", &["install", "--dry-run", "requests==2.32.3"]),
    ("pipx", &["install", "--dry-run", "requests==2.32.3"]),
    ("cargo", &["add", "serde@1.0.203"]),
    ("go", &["install", "-n", "github.com/pkg/errors@v0.9.1"]),
    (
        "composer",
        &["require", "--dry-run", "monolog/monolog:3.6.0"],
    ),
    ("bundle", &["add", "rails", "--version", "7.1.3"]),
];

/// `package_shim_probe_args`.
pub(crate) fn package_shim_probe_args(manager: &str) -> Vec<String> {
    PROBE_ARGS
        .iter()
        .find(|(name, _)| *name == manager)
        .map_or_else(
            || vec!["--version".to_owned()],
            |(_, args)| args.iter().map(|arg| (*arg).to_owned()).collect(),
        )
}

/// `parse_protect_json_stdout`.
fn parse_protect_json_stdout(stdout: &str) -> Map<String, Value> {
    let text = stdout.trim_start_matches(py_is_space);
    if text.is_empty() {
        return Map::new();
    }
    match serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .next()
    {
        Some(Ok(Value::Object(map))) => map,
        _ => Map::new(),
    }
}

fn non_blank(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(text),
        _ => None,
    }
}

struct Evidence {
    invoked: bool,
    source: String,
    decision: Value,
    permitted: bool,
    evidence_ids: Vec<String>,
}

/// `protect_evaluator_evidence`.
fn protect_evaluator_evidence(payload: &Map<String, Value>) -> Evidence {
    let empty = Map::new();
    let supply_chain = match payload.get("supply_chain_evaluation") {
        Some(Value::Object(map)) => map,
        _ => &empty,
    };
    let verdict = match payload.get("verdict") {
        Some(Value::Object(map)) => map,
        _ => &empty,
    };
    let evidence_ids = match supply_chain.get("evidence_ids") {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| !item.is_null())
            .map(py_str_value)
            .collect(),
        _ => Vec::new(),
    };
    let source = non_blank(supply_chain.get("source"))
        .or_else(|| non_blank(supply_chain.get("decision_source")))
        .or_else(|| non_blank(verdict.get("source")))
        .unwrap_or("local-heuristic")
        .to_owned();
    let policy_action = match supply_chain.get("policy_action") {
        Some(Value::String(text)) => Some(text.as_str()),
        _ => verdict.get("action").and_then(Value::as_str),
    };
    Evidence {
        invoked: payload.contains_key("supply_chain_evaluation") || payload.contains_key("verdict"),
        source,
        decision: verdict.get("action").cloned().unwrap_or(Value::Null),
        permitted: matches!(policy_action, Some("allow" | "warn")),
        evidence_ids,
    }
}

/// Output of a probe child.
struct ProbeRun {
    exit_code: i64,
    stdout: Vec<u8>,
}

/// Reads a child pipe to EOF. `None` means the output passed the cap, so the
/// kept prefix is not the whole stream and must not be parsed as evidence.
///
/// Passing the cap is answered before the rest of the stream is drained. A
/// descendant holding that same pipe open would otherwise keep the verdict
/// until the deadline, and a probe that produced more evidence than can be
/// read whole would be reported as a busy host rather than the broken probe
/// it is. The drain still runs afterwards so the child never blocks on a
/// full pipe.
fn spawn_reader<R: Read + Send + 'static>(mut stream: R) -> mpsc::Receiver<Option<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = stream
            .by_ref()
            .take(PROBE_OUTPUT_CAP + 1)
            .read_to_end(&mut kept);
        let within_cap = u64::try_from(kept.len()).is_ok_and(|len| len <= PROBE_OUTPUT_CAP);
        if !within_cap {
            let _ = sender.send(None);
        }
        let _ = std::io::copy(&mut stream, &mut std::io::sink());
        if within_cap {
            let _ = sender.send(Some(kept));
        }
    });
    receiver
}

#[cfg(unix)]
fn kill_tree(child: &mut std::process::Child) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn kill_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

#[cfg(unix)]
fn exit_code(status: std::process::ExitStatus) -> i64 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .map(i64::from)
        .or_else(|| status.signal().map(|signal| -i64::from(signal)))
        .unwrap_or(-1)
}

#[cfg(not(unix))]
fn exit_code(status: std::process::ExitStatus) -> i64 {
    status.code().map_or(-1, i64::from)
}

/// Why a probe child produced no evidence.
///
/// A child that merely outlived its share of the batch budget says the host was
/// busy; one that could not be started, waited on, or read whole says the probe
/// itself is broken. Reporting both as one reason sends a developer looking for
/// a damaged shim when the machine was only loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeFailure {
    TimedOut,
    Failed,
}

impl ProbeFailure {
    fn reason(self) -> &'static str {
        match self {
            Self::TimedOut => "probe_timed_out",
            Self::Failed => "probe_failed",
        }
    }

    /// The reason to report when both halves of a probe failed. A reader that
    /// answered is definite; a drain that ran out of time only says the host
    /// was busy, and it would send a developer looking at load when the probe
    /// had already produced more evidence than can be read whole.
    fn or_definite(self, other: Self) -> Self {
        match (self, other) {
            (Self::Failed, _) | (_, Self::Failed) => Self::Failed,
            _ => Self::TimedOut,
        }
    }
}

/// `subprocess.run([...], capture_output=True, timeout=...)`; the error stands
/// for `TimeoutExpired`/`OSError` and says which of the two it was.
fn run_probe(
    program: &Path,
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<ProbeRun, ProbeFailure> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| ProbeFailure::Failed)?;
    let stdout = spawn_reader(child.stdout.take().ok_or(ProbeFailure::Failed)?);
    let stderr = spawn_reader(child.stderr.take().ok_or(ProbeFailure::Failed)?);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                kill_tree(&mut child);
                let _ = child.wait();
                return Err(ProbeFailure::TimedOut);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                kill_tree(&mut child);
                let _ = child.wait();
                return Err(ProbeFailure::Failed);
            }
        }
    };
    // `communicate()` waits for EOF on both pipes within the same timeout; a
    // descendant that keeps a pipe open past it is a timeout, and the whole
    // group is reaped so nothing lingers in the resident.
    // Evidence larger than the cap cannot be read whole, so a reader that
    // reports the cap was passed fails the probe rather than let a truncated
    // object be parsed as "no evaluator ran". Both pipes are classified before
    // a reason is chosen: one half passing the cap while the other is still
    // held open is a broken probe, not a busy host.
    let drain = |receiver: &mpsc::Receiver<Option<Vec<u8>>>| match receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        Ok(Some(kept)) => Ok(kept),
        Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(ProbeFailure::Failed),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ProbeFailure::TimedOut),
    };
    let stdout = match (drain(&stdout), drain(&stderr)) {
        (Ok(stdout), Ok(_)) => stdout,
        (Err(first), Err(second)) => {
            kill_tree(&mut child);
            return Err(first.or_definite(second));
        }
        (Err(failure), Ok(_)) | (Ok(_), Err(failure)) => {
            kill_tree(&mut child);
            return Err(failure);
        }
    };
    Ok(ProbeRun {
        exit_code: exit_code(status),
        stdout,
    })
}

fn skipped(manager: &str, reason: &str) -> Value {
    json!({
        "evaluator_invoked": false,
        "intercept_ran": false,
        "manager": manager,
        "skipped_reason": reason,
    })
}

/// `probe_package_shim_intercepts`.
pub fn probe_package_shim_intercepts(
    context: &ShimContext,
    options: &ProbeOptions,
) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let status = if options.project_shell_profile {
        package_shim_dashboard_status(context)?
    } else {
        package_shim_status(context, None)?
    };
    let installed_list = string_items(status.get("installed_managers"));
    let installed: BTreeSet<&String> = installed_list.iter().collect();
    let protected = string_items(status.get("protected_managers"));
    let tested: Vec<String> = match options.managers.as_ref().filter(|items| !items.is_empty()) {
        Some(items) => items.clone(),
        None => installed.iter().map(|manager| (*manager).clone()).collect(),
    };
    let path_repair_required: Vec<&String> = tested
        .iter()
        .filter(|manager| installed.contains(manager) && !protected.contains(manager))
        .collect();
    let details = dict_items(status.get("manager_details"));
    let workspace = options
        .workspace_dir
        .clone()
        .or_else(|| context.workspace_dir.clone())
        .or_else(|| context.home_dir.clone())
        .unwrap_or_else(|| facts.cwd.clone());
    let shim_dir = context.shim_dir();
    let tested_count = u32::try_from(tested.len().max(1)).unwrap_or(u32::MAX);
    // Each manager keeps its own allowance (as the sequential `subprocess.run`
    // calls did); only a batch that would exceed the ceiling is scaled down, and
    // then evenly, so a slow early probe cannot starve a later one.
    let per_probe =
        Duration::from_secs(options.timeout_seconds).min(PROBE_BATCH_CEILING / tested_count);
    let mut probe_env = facts.environ.clone();
    probe_env.insert(
        SHIM_PROBE_ENV_VAR.to_owned(),
        SHIM_PROBE_ENV_VALUE.to_owned(),
    );
    let mut results: Vec<Value> = Vec::new();
    for manager in &tested {
        if !installed.contains(manager) {
            continue;
        }
        let integrity = details
            .iter()
            .find(|item| item.get("manager").and_then(Value::as_str) == Some(manager.as_str()))
            .and_then(|item| item.get("integrity").and_then(Value::as_str));
        if integrity == Some("tampered") {
            results.push(skipped(manager, "shim_tampered"));
            continue;
        }
        if !protected.contains(manager) && !options.allow_inactive_path {
            results.push(skipped(manager, "path_inactive"));
            continue;
        }
        let Some(command) = package_shim_command(manager) else {
            results.push(skipped(manager, "unsupported_manager"));
            continue;
        };
        let (shim_path, _) = launcher_paths(facts, &shim_dir, command);
        if !facts.exists(&shim_path) {
            results.push(skipped(manager, "shim_missing"));
            continue;
        }
        let probe_args = package_shim_probe_args(manager);
        let run = match run_probe(
            &facts.fs_path(&shim_path),
            &probe_args,
            &facts.fs_path(&workspace),
            &probe_env,
            per_probe,
        ) {
            Ok(run) => run,
            Err(failure) => {
                results.push(skipped(manager, failure.reason()));
                continue;
            }
        };
        let stdout = String::from_utf8(run.stdout)
            .map_err(|_| format!("probe output of {manager} is not valid UTF-8"))?;
        let evidence =
            protect_evaluator_evidence(&parse_protect_json_stdout(&universal_newlines(&stdout)));
        let mut hashed: Vec<Value> = vec![json!(manager)];
        hashed.extend(probe_args.iter().map(|arg| json!(arg)));
        let command_hash =
            stable_digest_hex(py_json_dumps(&Value::Array(hashed), false).as_bytes());
        results.push(json!({
            "command_hash": command_hash,
            "evaluator_invoked": evidence.invoked,
            "evaluator_source": evidence.source,
            "evidence_ids": evidence.evidence_ids,
            "execution_permitted": evidence.permitted,
            "intercept_ran": evidence.invoked,
            "manager": manager,
            "protect_decision": evidence.decision,
            "probe_args": probe_args,
            "shim_exit_code": run.exit_code,
        }));
    }
    let intercept_proved = results
        .iter()
        .any(|item| item.get("evaluator_invoked").and_then(Value::as_bool) == Some(true));
    if !results.is_empty() {
        let recorded: Vec<String> = results
            .iter()
            .filter_map(|item| {
                item.get("manager")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        record_test_results(context, &recorded)?;
    }
    let missing: Vec<&String> = tested
        .iter()
        .filter(|manager| !installed.contains(manager))
        .collect();
    let mut result = Map::new();
    result.insert(
        "blocked_execution".into(),
        json!(!tested.is_empty() && tested.iter().all(|manager| protected.contains(manager))),
    );
    result.insert("intercept_proved".into(), json!(intercept_proved));
    result.insert("manager_results".into(), Value::Array(results));
    result.insert("missing_managers".into(), json!(missing));
    result.insert("package_shims".into(), Value::Object(status));
    result.insert("path_repair_required".into(), json!(path_repair_required));
    result.insert("tested_managers".into(), json!(tested));
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn run(script: &str, timeout: Duration) -> Result<ProbeRun, ProbeFailure> {
        run_probe(
            Path::new("/bin/sh"),
            &["-c".to_owned(), script.to_owned()],
            &std::env::temp_dir(),
            &BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]),
            timeout,
        )
    }

    fn sh(script: &str) -> Result<ProbeRun, ProbeFailure> {
        run(script, Duration::from_secs(20))
    }

    #[test]
    fn output_within_the_cap_is_kept_whole() {
        let run = sh("printf '{\"verdict\": {}}'").expect("probe runs");
        assert_eq!(run.stdout, br#"{"verdict": {}}"#);
    }

    #[test]
    fn output_past_the_cap_fails_the_probe() {
        let script = format!("head -c {} /dev/zero", PROBE_OUTPUT_CAP + 1);
        assert_eq!(sh(&script).err(), Some(ProbeFailure::Failed));
    }

    #[test]
    fn a_child_that_outlives_its_budget_is_a_timeout_not_a_failure() {
        assert_eq!(
            run("sleep 30", Duration::from_millis(200)).err(),
            Some(ProbeFailure::TimedOut),
        );
    }

    #[test]
    fn output_past_the_cap_outranks_a_pipe_held_open_past_the_budget() {
        // stderr passes the cap and its reader answers once the shell exits,
        // which is definite; a descendant keeps stdout open past the budget,
        // which on its own would only say the host was busy.
        let script = format!(
            "head -c {} /dev/zero >&2; sleep 30 2>/dev/null & exit 0",
            PROBE_OUTPUT_CAP + 1
        );
        assert_eq!(
            run(&script, Duration::from_millis(500)).err(),
            Some(ProbeFailure::Failed),
        );
    }

    #[test]
    fn a_pipe_that_passed_the_cap_is_definite_while_it_is_still_held_open() {
        // The over-cap pipe is the held-open one, so nothing else can speak for
        // it. Waiting for its EOF would report the busy-host reason for a probe
        // that had already produced more evidence than can be read whole.
        let script = format!(
            "head -c {} /dev/zero; sleep 30 & exit 0",
            PROBE_OUTPUT_CAP + 1
        );
        assert_eq!(
            run(&script, Duration::from_millis(500)).err(),
            Some(ProbeFailure::Failed),
        );
    }

    #[test]
    fn a_child_that_holds_a_pipe_open_past_the_budget_is_a_timeout() {
        // The child exits, but a descendant keeps stdout open, so the drain is
        // what runs out of time rather than the wait.
        assert_eq!(
            run("sleep 30 & exit 0", Duration::from_millis(200)).err(),
            Some(ProbeFailure::TimedOut),
        );
    }
}
