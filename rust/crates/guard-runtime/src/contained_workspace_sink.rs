//! The native sink for a call the resident routed to the workspace sandbox.
//!
//! A `PreToolUse` hook whose native answer is `workspace-contained-v1` is
//! rewritten to run this sink on a private snapshot of the call. The sink
//! reads and removes the snapshot, asks the live resident for the receipt
//! again, prepares the sandbox plan, asks once more so the plan and the launch
//! bind the same evidence, and runs the command under Seatbelt. It replaces
//! `guard execute-contained-test` for that shape, step for step: every check
//! that fails, fails closed with the reason that command printed, and nothing
//! runs outside the sandbox except the `git init` a plan bootstraps.
//!
//! Rust owns every verdict: the resident's receipt, the operations' plan.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

#[path = "contained_workspace_sink_denial.rs"]
mod denial;
#[path = "contained_workspace_sink_grant.rs"]
mod grant;
#[path = "contained_workspace_sink_plan.rs"]
mod plan_check;
#[path = "contained_workspace_sink_process.rs"]
mod process;
#[path = "contained_workspace_sink_launch.rs"]
mod runner;
#[path = "contained_workspace_sink_request.rs"]
mod snapshot;

use plan_check::{plan_paths, validated_plan};
use runner::{bootstrap_init, Launch, PrivateRoot};
use snapshot::read_request;

pub(crate) use process::launch;

pub(crate) const SINK_COMMAND: &str = "contained-workspace-sink";
pub(crate) const LAUNCH_COMMAND: &str = "contained-workspace-launch";
pub(crate) const WORKSPACE_REASON: &str = "native_workspace_containment_required";
pub(crate) const WORKSPACE_PROFILE: &str = "workspace-contained-v1";
/// The reason a chain carries whose trailing Git steps run after the
/// contained checks. It must match the command crate's text exactly; that
/// shape stays with `guard execute-contained-test`.
pub(crate) const PUBLISH_REASON: &str = concat!(
    "HOL Guard runs the checks in this command in a protected workspace sandbox ",
    "(no network, no home access, no PTY or Docker socket), then runs the Git ",
    "steps that follow directly, outside the sandbox, once it proves them again. ",
    "Every program the checks start, including children of an interpreter, runs ",
    "contained and can write only the workspace, $TMPDIR and a private ",
    "scratch $HOME.",
);
const AUTHORIZATION_FAILED: &str = "contained_run_authorization_failed";
const AUTHORIZATION_MESSAGE: &str = "Guard could not authorize this contained run.";
const INVALID_COMMAND: &str = "pytest_restricted_invalid_command";
const SANDBOX_UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
const PLAN_MISMATCH: &str = "The workspace sandbox plan does not match the authorized command.";
const INVALID_PLAN: &str = "Invalid workspace sandbox plan.";
const PLAN_FIELDS: [&str; 20] = [
    "profile_version",
    "backend",
    "backend_executable",
    "workspace",
    "cwd",
    "executable",
    "command",
    "command_sha256",
    "allowed_executables",
    "read_only_roots",
    "exec_roots",
    "write_denials",
    "linked_git",
    "sandbox_path",
    "bootstrap_git",
    "prefix_command",
    "native_suffix",
    "denied_capabilities",
    "grant_identity_hash",
    "capabilities",
];
/// The reasons a restricted-execution operation may fail with by name.
const NATIVE_REASONS: [&str; 10] = [
    "node_test_restricted_invalid_command",
    "node_test_restricted_sandbox_unavailable",
    "vitest_restricted_invalid_command",
    "vitest_restricted_dependency_unavailable",
    "inline_eval_invalid_command",
    "linux_mapping_unavailable",
    "pytest_restricted_external_pythonpath",
    INVALID_COMMAND,
    "pytest_restricted_invalid_workspace",
    SANDBOX_UNAVAILABLE,
];
const MAX_NATIVE_MESSAGE_CHARACTERS: usize = 4096;
const NATIVE_BUDGET_MILLISECONDS: u64 = 9_000;
const AUTHORIZE_BUDGET: Duration = Duration::from_secs(10);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(10);
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
const RUN_TIMEOUT_SECONDS: u64 = 30 * 60;
/// Names besides `GIT_*` the trusted-Git resolution reads.
const GIT_SNAPSHOT_NAMES: [&str; 8] = [
    "SSH_ASKPASS",
    "PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "PAGER",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
];
#[cfg(target_os = "macos")]
const HOST_BACKEND: Option<&str> = Some("macos-seatbelt");
#[cfg(not(target_os = "macos"))]
const HOST_BACKEND: Option<&str> = None;
const HOST_PLATFORM: &str = if cfg!(target_os = "macos") {
    "darwin"
} else {
    "linux"
};

/// Why the sink stopped: printed as `reason: message`, exiting `exit_code`.
#[derive(Debug, PartialEq)]
pub(crate) struct Failure {
    reason: String,
    message: String,
    exit_code: i32,
}

impl Failure {
    fn new(reason: &str, message: impl Into<String>) -> Self {
        Self::with_exit(reason, message, 126)
    }

    fn with_exit(reason: &str, message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            reason: reason.to_owned(),
            message: message.into(),
            exit_code,
        }
    }

    fn unauthorized() -> Self {
        Self::new(AUTHORIZATION_FAILED, AUTHORIZATION_MESSAGE)
    }

    fn invalid(message: &str) -> Self {
        Self::new(INVALID_COMMAND, message)
    }
}

type Outcome<T> = Result<T, Failure>;

struct Arguments {
    harness: String,
    guard_home: PathBuf,
    workspace: PathBuf,
    request_file: PathBuf,
    request_sha256: String,
    home: PathBuf,
}

impl Arguments {
    fn parse(args: &[String]) -> Option<Self> {
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        let mut pairs = args.chunks_exact(2);
        for pair in pairs.by_ref() {
            let name = pair[0].strip_prefix("--")?;
            if values.insert(name, pair[1].as_str()).is_some() {
                return None;
            }
        }
        if !pairs.remainder().is_empty() || values.len() != 6 {
            return None;
        }
        Some(Self {
            harness: (*values.get("harness")?).to_owned(),
            guard_home: PathBuf::from(values.get("guard-home")?),
            workspace: PathBuf::from(values.get("workspace")?),
            request_file: PathBuf::from(values.get("request-file")?),
            request_sha256: (*values.get("request-sha256")?).to_owned(),
            home: PathBuf::from(values.get("home")?),
        })
    }
}

/// `contained-workspace-sink --harness H --guard-home G --workspace W
/// --request-file R --request-sha256 D --home HOME`: the exit code.
pub(crate) fn run(args: &[String]) -> i32 {
    let signals = process::Signals::install();
    let Some(arguments) = Arguments::parse(args) else {
        return report(&Failure::unauthorized());
    };
    match sink(&arguments, &signals) {
        Ok(code) => code,
        Err(failure) => report(&failure),
    }
}

fn report(failure: &Failure) -> i32 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{}: {}", failure.reason, failure.message);
    let _ = stderr.flush();
    failure.exit_code
}

fn sink(arguments: &Arguments, signals: &process::Signals) -> Outcome<i32> {
    let workspace = std::fs::canonicalize(&arguments.workspace)
        .ok()
        .filter(|path| path.is_dir())
        .ok_or_else(Failure::unauthorized)?;
    let payload = read_request(
        &arguments.request_file,
        &arguments.request_sha256,
        &workspace,
    )?;
    let authority = Authority {
        arguments,
        workspace: path_text(&workspace)?,
    };
    let receipt = authority
        .authorize(&payload)
        .ok_or_else(Failure::unauthorized)?;
    if !receipt_matches(&receipt) || receipt.get("reason") == Some(&json!(PUBLISH_REASON)) {
        return Err(Failure::unauthorized());
    }
    run_workspace_contained(&payload, &workspace, &authority, &receipt, signals)
}

fn path_text(path: &Path) -> Outcome<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(Failure::unauthorized)
}

/// Asks the live resident for the receipt of the call as this sink sees it.
struct Authority<'a> {
    arguments: &'a Arguments,
    workspace: String,
}

impl Authority<'_> {
    /// The resident's harness response for `payload`, receipt only, stamped
    /// with the environment this process launches the command from.
    fn authorize(&self, payload: &Map<String, Value>) -> Option<Map<String, Value>> {
        let mut asked = payload.clone();
        asked.insert(RECEIPT_ONLY_FIELD.to_owned(), Value::Bool(true));
        let text = serde_json::to_string(&asked).ok()?;
        let environment = crate::hook_env_stamp::current_environment();
        let crate::hook_env_stamp::Stamp::Text(stamped) =
            crate::hook_env_stamp::stamp_hook_input_text(&text, &environment)
        else {
            return None;
        };
        let answer = crate::codex_hook_bridge_direct::resident_hook_answer(
            &self.arguments.harness,
            &self.arguments.guard_home,
            &self.arguments.home,
            &self.workspace,
            &stamped,
            Instant::now() + AUTHORIZE_BUDGET,
        )?;
        match serde_json::from_str(&answer).ok()? {
            Value::Object(response) => Some(response),
            _ => None,
        }
    }
}

/// Whether `receipt` is a live workspace-sandbox requirement.
fn receipt_matches(receipt: &Map<String, Value>) -> bool {
    let text = |name: &str| receipt.get(name).and_then(Value::as_str);
    text("decision") == Some("deny")
        && text("policy_action") == Some("sandbox-required")
        && text("reason_code") == Some(WORKSPACE_REASON)
        && text("required_execution_profile") == Some(WORKSPACE_PROFILE)
        && receipt.get("observe_mode") != Some(&Value::Bool(true))
        && text("command_binding_digest").is_some()
}

fn run_workspace_contained(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    first_receipt: &Map<String, Value>,
    signals: &process::Signals,
) -> Outcome<i32> {
    let command = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::invalid("Invalid workspace sandbox request."))?;
    let home = wire_path(&authority.arguments.home);
    let git_environment: Map<String, Value> = environment()
        .into_iter()
        .filter(|(name, _)| name.starts_with("GIT_CONFIG") || name == "XDG_CONFIG_HOME")
        .map(|(name, value)| (name, Value::String(value)))
        .collect();
    let store = grant::request(
        &authority.arguments.guard_home,
        &home,
        &authority.workspace,
        command,
    )?;
    let decided = grant::decided(&store)?;
    let mut input = json!({
        "text": command,
        "workspace": authority.workspace,
        "cwd": authority.workspace,
        "platform": HOST_PLATFORM,
        "home": home,
        "git_environment": git_environment,
        "publish_suffix": false,
    });
    let expected = match &decided {
        Some(decided) => {
            input["grant"] = grant::prepare_input(decided);
            Some(grant::expected(decided, &home)?)
        }
        None => None,
    };
    let plan = native("prepare_workspace_contained", input)?;
    let plan = validated_plan(plan, command, &authority.workspace, expected.as_ref())?;
    // A second receipt taken after planning must still bind the same evidence.
    let second = authority
        .authorize(payload)
        .filter(receipt_matches)
        .ok_or_else(|| {
            Failure::invalid("Guard could not re-authorize this workspace sandbox execution.")
        })?;
    if second.get("command_binding_digest") != first_receipt.get("command_binding_digest")
        || second.get("reason") == Some(&json!(PUBLISH_REASON))
    {
        return Err(Failure::invalid(
            "The command evidence changed before launch.",
        ));
    }
    grant::unchanged(&decided, grant::decided(&store))?;
    let exec_roots = plan_paths(&plan.exec_roots)?;
    let write_denials = plan_paths(&plan.write_denials)?;
    let private = PrivateRoot::create().ok_or_else(|| {
        Failure::new(
            SANDBOX_UNAVAILABLE,
            "The workspace sandbox directory is unavailable.",
        )
    })?;
    signals.clean_up(private.path.clone());
    grant::link_state(&private.path, expected.as_ref(), &plan.capabilities)?;
    let launch = Launch {
        plan: &plan,
        workspace,
        workspace_text: &authority.workspace,
        home: &home,
        private: &private,
        exec_roots: &exec_roots,
        write_denials: &write_denials,
        signals,
        loopback: grant::LoopbackNote::new(&store, decided.as_ref()),
    };
    if let Some(prefix) = &plan.prefix {
        // `prefix && git init && rest`: a failed prefix ends the command.
        let exit_code = launch.contained(&["/bin/sh".into(), "-c".into(), prefix.clone()])?;
        if exit_code != 0 {
            return Ok(exit_code);
        }
    }
    if let Some(arguments) = &plan.bootstrap {
        bootstrap_init(arguments, workspace, &private)?;
        if plan.argv[2].is_empty() {
            return Ok(0);
        }
    }
    launch.contained(&plan.argv)
}

/// Run a restricted-execution operation in process: its value, or the
/// failure it named.
fn native(operation: &str, mut input: Value) -> Outcome<Value> {
    input["search_path"] = Value::String(search_path());
    let budget =
        crate::request_context_op::Budget::bounded_milliseconds(NATIVE_BUDGET_MILLISECONDS);
    match crate::restricted_pytest_op::evaluate(operation, &input, &budget) {
        Ok(reply) => envelope(reply),
        Err(code) => Err(unavailable(code)),
    }
}

fn envelope(reply: Value) -> Outcome<Value> {
    let Value::Object(mut reply) = reply else {
        return Err(unavailable("invalid_reply"));
    };
    if reply.len() == 1 {
        if let Some(value) = reply.remove("value") {
            return Ok(value);
        }
    }
    if reply.len() == 2 {
        if let (Some(Value::String(reason)), Some(Value::String(message))) =
            (reply.get("reason_code"), reply.get("message"))
        {
            if NATIVE_REASONS.contains(&reason.as_str())
                && message.chars().count() <= MAX_NATIVE_MESSAGE_CHARACTERS
            {
                return Err(Failure::new(reason, message.clone()));
            }
        }
    }
    Err(unavailable("invalid_reply"))
}

fn unavailable(code: &str) -> Failure {
    Failure::new(
        SANDBOX_UNAVAILABLE,
        format!(
            "Native restricted execution preparation is unavailable ({code}); execution was not started."
        ),
    )
}

/// The process environment, as text.
fn environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

/// `PATH`, each entry made absolute, as the operations search it.
fn search_path() -> String {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".to_owned());
    path.split(':')
        .map(|item| absolute(&py_normal(item)))
        .collect::<Vec<_>>()
        .join(":")
}

/// `str(path.expanduser().absolute())`.
fn wire_path(path: &Path) -> String {
    absolute(&py_normal(&expand_user(&path.to_string_lossy())))
}

/// `os.path.expanduser` for `~` and `~/...`.
fn expand_user(text: &str) -> String {
    let home = || {
        crate::claude_hook_bridge::home_directory()
            .map(|home| home.to_string_lossy().into_owned())
            .unwrap_or_else(|| "~".to_owned())
    };
    if text == "~" {
        return home();
    }
    match text.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home().trim_end_matches('/')),
        None => text.to_owned(),
    }
}

/// `str(Path(text))`: repeated and trailing slashes and `.` parts dropped.
fn py_normal(text: &str) -> String {
    if text.is_empty() {
        return ".".to_owned();
    }
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = parts.join("/");
    match (root, joined.is_empty()) {
        ("", true) => ".".to_owned(),
        (root, _) => format!("{root}{joined}"),
    }
}

/// `Path.absolute()` of a normalized path: relative paths join the current
/// directory.
fn absolute(normal: &str) -> String {
    if normal.starts_with('/') {
        return normal.to_owned();
    }
    let cwd = std::env::current_dir()
        .map(|cwd| cwd.to_string_lossy().into_owned())
        .unwrap_or_default();
    if normal == "." {
        cwd
    } else {
        format!("{}/{normal}", cwd.trim_end_matches('/'))
    }
}

#[cfg(test)]
#[path = "contained_workspace_sink_tests.rs"]
mod tests;
