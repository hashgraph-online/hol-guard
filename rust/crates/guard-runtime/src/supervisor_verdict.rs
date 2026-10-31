//! Whether the machine health supervisor is the one Guard installs.
//!
//! On macOS the supervisor is a LaunchDaemon and on Windows a SYSTEM scheduled
//! task. Python reads the property list and runs `launchctl` or `schtasks`;
//! this module decides what that evidence says. A macOS verdict can need more
//! evidence than the caller sent, so it answers with the next probe to run
//! (`disabled`, then `loaded`) until it can decide, and the caller never runs
//! a probe the registration already ruled out.

use std::io::Read;
use std::sync::LazyLock;

use regex::Regex;
use roxmltree::{Document, Node, NodeType, ParsingOptions};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::daemon_lifecycle_text::{nt_root_end, py_splitlines, py_strip};

const SCHEMA: &str = "supervisor-verdict.v1";
const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
const LABEL: &str = "org.hol.guard.machine-health";
const WINDOWS_TASK_NAME: &str = r"\HOL Guard\Machine Health";
const TASK_NAMESPACE: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";
const HEALTH_ARGUMENTS: [&str; 5] = ["mdm", "health-report", "--scope", "machine", "--json"];
const START_BOUNDARY: &str = "2000-01-01T00:00:00";
/// `ERROR_FILE_NOT_FOUND` as `schtasks /HRESULT` exits with it, in each
/// spelling a Windows exit status reaches Python.
const ABSENT_HRESULTS: [i64; 3] = [2, 0x8007_0002, -2_147_024_894];
const MACOS_ENVIRONMENT: [(&str, &str); 3] = [
    ("HOME", "/var/root"),
    ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
    ("TMPDIR", "/var/tmp"),
];
/// Python's `\s` in a `str` pattern: Unicode whitespace plus the ASCII
/// information separators `str.isspace` also counts.
const WS: &str = r"[\s\x1C-\x1F]";

type Verdict = (&'static str, &'static str);

const PROBE_FAILED: Verdict = ("unknown", "supervisor_probe_failed");
const REGISTRATION_INVALID: Verdict = ("stopped", "supervisor_registration_invalid");
const EXECUTABLE_MISMATCH: Verdict = ("stopped", "supervisor_executable_mismatch");
const SCHEDULE_INVALID: Verdict = ("stopped", "supervisor_schedule_invalid");
const STOPPED: Verdict = ("stopped", "supervisor_stopped");
const DISABLED: Verdict = ("disabled", "supervisor_disabled");
const RUNNING: Verdict = ("running", "supervisor_running");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    executable: String,
    /// The property list as `plistlib` read it; any value that is not a
    /// dictionary, `null` included, is a registration Guard did not write.
    #[serde(default)]
    plist: Value,
    #[serde(default)]
    plist_path: Option<String>,
    #[serde(default)]
    stdout_log: Option<String>,
    #[serde(default)]
    stderr_log: Option<String>,
    #[serde(default)]
    disabled: Option<Probe>,
    #[serde(default)]
    loaded: Option<Probe>,
    #[serde(default)]
    task: Option<Probe>,
}

/// One `launchctl` or `schtasks` run: its exit status and standard output.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    returncode: i64,
    stdout: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "supervisor-verdict"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "supervisor_verdict_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("supervisor_verdict_request_too_large".to_owned());
    }
    let answer = answer(&bytes)?;
    serde_json::to_vec(&answer).map_err(|_| "supervisor_verdict_response_unwritable".to_owned())
}

fn answer(bytes: &[u8]) -> Result<Value, String> {
    let invalid = || "supervisor_verdict_request_invalid".to_owned();
    let request: Request = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    match request.op.as_str() {
        "macos" => macos(&request).ok_or_else(invalid),
        "windows" => request
            .task
            .as_ref()
            .map(|task| verdict(windows(task, &request.executable)))
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

fn verdict((state, reason_code): Verdict) -> Value {
    json!({"ok": true, "state": state, "reason_code": reason_code})
}

fn next(probe: &str) -> Value {
    json!({"ok": true, "next": probe})
}

fn macos(request: &Request) -> Option<Value> {
    let plist = &request.plist;
    let plist_path = request.plist_path.as_deref()?;
    let stdout_log = request.stdout_log.as_deref()?;
    let stderr_log = request.stderr_log.as_deref()?;
    if let Some(failure) = macos_registration(plist, &request.executable, stdout_log, stderr_log) {
        return Some(verdict(failure));
    }
    let Some(disabled) = &request.disabled else {
        return Some(next("disabled"));
    };
    if disabled.returncode != 0 {
        return Some(verdict(PROBE_FAILED));
    }
    if DISABLED_PATTERN.is_match(&disabled.stdout) {
        return Some(verdict(DISABLED));
    }
    let Some(loaded) = &request.loaded else {
        return Some(next("loaded"));
    };
    if loaded.returncode != 0 {
        return Some(verdict(STOPPED));
    }
    Some(verdict(
        macos_loaded(&loaded.stdout, &request.executable, plist_path).unwrap_or(RUNNING),
    ))
}

/// The LaunchDaemon property list, as `plistlib` read it. Values JSON cannot
/// carry (`data`, `date`) arrive as `null`, which no checked key accepts.
fn macos_registration(
    plist: &Value,
    executable: &str,
    stdout_log: &str,
    stderr_log: &str,
) -> Option<Verdict> {
    let Some(payload) = plist.as_object() else {
        return Some(REGISTRATION_INVALID);
    };
    if payload.get("Label").and_then(Value::as_str) != Some(LABEL) {
        return Some(REGISTRATION_INVALID);
    }
    let arguments = payload.get("ProgramArguments").and_then(Value::as_array);
    if !arguments.is_some_and(|items| strings_equal(items, executable)) {
        return Some(EXECUTABLE_MISMATCH);
    }
    let environment = payload
        .get("EnvironmentVariables")
        .and_then(Value::as_object);
    let environment_exact = environment.is_some_and(|variables| {
        variables.len() == MACOS_ENVIRONMENT.len()
            && MACOS_ENVIRONMENT
                .iter()
                .all(|(name, value)| variables.get(*name).and_then(Value::as_str) == Some(value))
    });
    if !environment_exact {
        return Some(REGISTRATION_INVALID);
    }
    // `StartInterval != 300` is false for the integer and for the real
    // `300.0`; a boolean is never a number here.
    let interval = payload
        .get("StartInterval")
        .and_then(Value::as_number)
        .and_then(serde_json::Number::as_f64);
    if payload.get("RunAtLoad") != Some(&Value::Bool(true))
        || interval != Some(300.0)
        || payload.get("ProcessType").and_then(Value::as_str) != Some("Background")
    {
        return Some(SCHEDULE_INVALID);
    }
    if payload.get("StandardOutPath").and_then(Value::as_str) != Some(stdout_log)
        || payload.get("StandardErrorPath").and_then(Value::as_str) != Some(stderr_log)
    {
        return Some(REGISTRATION_INVALID);
    }
    None
}

/// Whether `items` is exactly the executable followed by the health arguments.
fn strings_equal(items: &[Value], executable: &str) -> bool {
    let expected = std::iter::once(executable).chain(HEALTH_ARGUMENTS);
    items.len() == HEALTH_ARGUMENTS.len() + 1
        && items
            .iter()
            .zip(expected)
            .all(|(item, want)| item.as_str() == Some(want))
}

static DISABLED_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)"{}"{WS}*=>{WS}*true"#,
        regex::escape(LABEL)
    ))
    .expect("static pattern")
});

static ARGUMENTS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?ms)^{WS}*arguments{WS}*={WS}*\{{{WS}*\n(?P<body>.*?)^{WS}*\}}{WS}*$"
    ))
    .expect("static pattern")
});

/// `launchctl print`'s `name = value` line, the first one in the output.
fn launchctl_scalar<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    let pattern = Regex::new(&format!(
        r"(?m)^{WS}*{}{WS}*={WS}*(.*?){WS}*$",
        regex::escape(name)
    ))
    .ok()?;
    Some(pattern.captures(output)?.get(1)?.as_str())
}

fn launchctl_arguments(output: &str) -> Option<Vec<&str>> {
    let body = ARGUMENTS_PATTERN.captures(output)?.name("body")?.as_str();
    Some(
        py_splitlines(body)
            .into_iter()
            .map(py_strip)
            .filter(|line| !line.is_empty())
            .collect(),
    )
}

/// The job `launchctl` has loaded, which must be the registered one.
fn macos_loaded(output: &str, executable: &str, plist_path: &str) -> Option<Verdict> {
    if launchctl_scalar(output, "path") != Some(plist_path) {
        return Some(REGISTRATION_INVALID);
    }
    if launchctl_scalar(output, "program") != Some(executable) {
        return Some(EXECUTABLE_MISMATCH);
    }
    let expected: Vec<&str> = std::iter::once(executable)
        .chain(HEALTH_ARGUMENTS)
        .collect();
    if launchctl_arguments(output) != Some(expected) {
        return Some(EXECUTABLE_MISMATCH);
    }
    if launchctl_scalar(output, "run interval") != Some("300 seconds") {
        return Some(SCHEDULE_INVALID);
    }
    if !matches!(
        launchctl_scalar(output, "state"),
        Some("running" | "not running")
    ) {
        return Some(STOPPED);
    }
    None
}

fn windows(task: &Probe, executable: &str) -> Verdict {
    if ABSENT_HRESULTS.contains(&task.returncode) {
        return ("absent", "supervisor_absent");
    }
    if task.returncode != 0 {
        return PROBE_FAILED;
    }
    let options = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    match Document::parse_with_options(task.stdout.trim_start_matches('\u{feff}'), options) {
        Ok(document) => windows_registration(document.root_element(), executable),
        Err(_) => PROBE_FAILED,
    }
}

fn is_task(node: Node, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(TASK_NAMESPACE)
        && node.tag_name().name() == name
}

/// ElementTree's `findall` for a path of task-namespace names, where `None`
/// is `*`: every element child.
fn findall<'a, 'i>(node: Node<'a, 'i>, path: &[Option<&str>]) -> Vec<Node<'a, 'i>> {
    let mut current = vec![node];
    for step in path {
        current = current
            .into_iter()
            .flat_map(|parent| parent.children())
            .filter(|child| match step {
                Some(name) => is_task(*child, name),
                None => child.is_element(),
            })
            .collect();
    }
    current
}

/// ElementTree's `element.text`: the character data before the first child
/// element. Its parser drops comments and processing instructions, so text on
/// either side of one joins.
fn element_text(node: Node) -> Option<String> {
    let mut text: Option<String> = None;
    for child in node.children() {
        match child.node_type() {
            NodeType::Element => break,
            NodeType::Text => text.get_or_insert_with(String::new).push_str(child.text()?),
            _ => {}
        }
    }
    text
}

/// `_xml_text(node, "./task:A/task:B")`.
fn xml_text(node: Node, path: &[&str]) -> Option<String> {
    let steps: Vec<Option<&str>> = path.iter().copied().map(Some).collect();
    findall(node, &steps)
        .first()
        .copied()
        .and_then(element_text)
}

/// `str.casefold` for the values compared here, which are ASCII: the only
/// folds that reach ASCII from elsewhere are the long s and its ligatures.
fn casefold(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            'ſ' => "s".chars().collect::<Vec<_>>(),
            'ﬅ' | 'ﬆ' => "st".chars().collect(),
            'ß' => "ss".chars().collect(),
            other => other.to_lowercase().collect(),
        })
        .collect()
}

fn windows_registration(root: Node, executable: &str) -> Verdict {
    if !is_task(root, "Task") {
        return REGISTRATION_INVALID;
    }
    let enabled = xml_text(root, &["Settings", "Enabled"]);
    if enabled.is_some_and(|value| casefold(&value) == "false") {
        return DISABLED;
    }
    if xml_text(root, &["RegistrationInfo", "URI"]).as_deref() != Some(WINDOWS_TASK_NAME) {
        return REGISTRATION_INVALID;
    }
    let descriptor = xml_text(root, &["RegistrationInfo", "SecurityDescriptor"]);
    if !descriptor.is_some_and(|value| security_descriptor_valid(&value)) {
        return REGISTRATION_INVALID;
    }
    if let Some(failure) = principal_status(root) {
        return failure;
    }
    if let Some(failure) = trigger_status(root) {
        return failure;
    }
    if let Some(failure) = action_status(root, executable) {
        return failure;
    }
    let settings = |name: &str| xml_text(root, &["Settings", name]);
    if settings("MultipleInstancesPolicy").as_deref() != Some("IgnoreNew")
        || settings("ExecutionTimeLimit").as_deref() != Some("PT5M")
        || settings("StartWhenAvailable").as_deref() != Some("true")
        || settings("Hidden").as_deref() != Some("true")
        || settings("Enabled").as_deref() != Some("true")
        || settings("DisallowStartIfOnBatteries").as_deref() != Some("false")
        || settings("StopIfGoingOnBatteries").as_deref() != Some("false")
    {
        return SCHEDULE_INVALID;
    }
    RUNNING
}

fn principal_status(root: Node) -> Option<Verdict> {
    let principals = findall(root, &[Some("Principals"), Some("Principal")]);
    let [principal] = principals.as_slice() else {
        return Some(REGISTRATION_INVALID);
    };
    let user_id = xml_text(*principal, &["UserId"]).map(|value| casefold(&value));
    if !matches!(
        user_id.as_deref(),
        Some("s-1-5-18" | "system" | r"nt authority\system")
    ) {
        return Some(REGISTRATION_INVALID);
    }
    if xml_text(*principal, &["LogonType"]).as_deref() != Some("ServiceAccount")
        || xml_text(*principal, &["RunLevel"]).as_deref() != Some("HighestAvailable")
    {
        return Some(REGISTRATION_INVALID);
    }
    None
}

fn trigger_status(root: Node) -> Option<Verdict> {
    let triggers = findall(root, &[Some("Triggers"), None]);
    let [trigger] = triggers.as_slice() else {
        return Some(SCHEDULE_INVALID);
    };
    let trigger = *trigger;
    if !is_task(trigger, "TimeTrigger")
        || xml_text(trigger, &["Repetition", "Interval"]).as_deref() != Some("PT5M")
        || xml_text(trigger, &["Repetition", "StopAtDurationEnd"]).as_deref() != Some("false")
        || xml_text(trigger, &["StartBoundary"]).as_deref() != Some(START_BOUNDARY)
        || xml_text(trigger, &["EndBoundary"]).is_some()
        || xml_text(trigger, &["Enabled"]).as_deref() != Some("true")
    {
        return Some(SCHEDULE_INVALID);
    }
    None
}

fn action_status(root: Node, executable: &str) -> Option<Verdict> {
    let parent = findall(root, &[Some("Actions")]).first().copied();
    if parent.and_then(|actions| actions.attribute("Context")) != Some("System") {
        return Some(REGISTRATION_INVALID);
    }
    let actions = findall(root, &[Some("Actions"), None]);
    let [action] = actions.as_slice() else {
        return Some(REGISTRATION_INVALID);
    };
    if !is_task(*action, "Exec") {
        return Some(REGISTRATION_INVALID);
    }
    let command = xml_text(*action, &["Command"]);
    if command.map(|value| nt_normcase_normpath(&value)) != Some(nt_normcase_normpath(executable)) {
        return Some(EXECUTABLE_MISMATCH);
    }
    if xml_text(*action, &["Arguments"]).as_deref() != Some(HEALTH_ARGUMENTS.join(" ").as_str()) {
        return Some(EXECUTABLE_MISMATCH);
    }
    None
}

/// `ntpath.normcase(ntpath.normpath(path))`.
fn nt_normcase_normpath(path: &str) -> String {
    let characters: Vec<char> = path
        .chars()
        .map(|character| if character == '/' { '\\' } else { character })
        .collect();
    let end = nt_root_end(&characters);
    let prefix: String = characters[..end].iter().collect();
    let rooted = prefix.ends_with('\\');
    let tail: String = characters[end..].iter().collect();
    let mut parts: Vec<&str> = Vec::new();
    for part in tail.split('\\') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if parts.is_empty() && rooted => {}
            part => parts.push(part),
        }
    }
    let joined = if prefix.is_empty() && parts.is_empty() {
        ".".to_owned()
    } else {
        format!("{prefix}{}", parts.join("\\"))
    };
    joined.to_lowercase()
}

/// `D:P` with exactly the SYSTEM and Administrators full-control entries, in
/// either order and with either SID spelling, and only those owners/groups.
fn security_descriptor_valid(descriptor: &str) -> bool {
    static SDDL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)^(?:O:(?:BA|SY|S-1-5-32-544|S-1-5-18))?(?:G:(?:BA|SY|S-1-5-32-544|S-1-5-18))?D:P(?P<aces>(?:\([^()]+\))+)$",
        )
        .expect("static pattern")
    });
    static ACE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\(([^()]+)\)").expect("static pattern"));
    let Some(aces) = SDDL
        .captures(descriptor)
        .and_then(|captures| captures.name("aces"))
    else {
        return false;
    };
    let mut normalized = Vec::new();
    for ace in ACE.captures_iter(aces.as_str()) {
        let mut fields: Vec<String> = ace[1]
            .to_uppercase()
            .split(';')
            .map(str::to_owned)
            .collect();
        if fields.len() != 6 {
            return false;
        }
        fields[5] = match fields[5].as_str() {
            "SY" => "S-1-5-18".to_owned(),
            "BA" => "S-1-5-32-544".to_owned(),
            other => other.to_owned(),
        };
        normalized.push(format!("({})", fields.join(";")));
    }
    let system = "(A;;FA;;;S-1-5-18)";
    let administrators = "(A;;FA;;;S-1-5-32-544)";
    normalized.len() == 2
        && normalized.iter().any(|ace| ace == system)
        && normalized.iter().any(|ace| ace == administrators)
}

#[cfg(test)]
#[path = "supervisor_verdict_tests.rs"]
mod tests;
