//! The pure parts of admitting a runtime hook: its event, deadline, lane and
//! client, and the directories it named, settled in process.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::claude_hook_bridge_render::py_strip;
use crate::directory_trust::{
    evaluate, DirectoryTrustCandidateV1, DirectoryTrustRequestV1, DIRECTORY_TRUST_REQUEST_SCHEMA,
};

/// A tool hook's admission window, and the longer one a prompt gets: the
/// first prompt in a new workspace waits for its policy overlay to publish.
const TOOL_ADMISSION_SECONDS: f64 = 3.0;
const PROMPT_ADMISSION_SECONDS: f64 = 10.0;
const MIN_BUDGET_SECONDS: f64 = 0.1;
const MAX_TOOL_BUDGET_SECONDS: f64 = 4.0;
const TRANSPORT_RESERVE_SECONDS: f64 = 0.25;
/// `native_directory_trust.UNAVAILABLE_REASON`.
const DIRECTORY_TRUST_UNAVAILABLE: &str = "native_directory_trust_unavailable";

/// `runtime_hook_event_name`: the hook's event, normalized to the four the
/// daemon tells apart, or as the hook spelled it.
pub(super) fn runtime_event(payload: &Map<String, Value>) -> String {
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        let Some(raw) = payload.get(key).and_then(Value::as_str).map(py_strip) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let compact: String = raw
            .to_lowercase()
            .chars()
            .filter(|character| *character != '_' && *character != '-')
            .collect();
        return match compact.as_str() {
            "pretool"
            | "pretooluse"
            | "pretoolcall"
            | "beforeshellexecution"
            | "beforereadfile"
            | "beforewritefile"
            | "beforemcpexecution" => "PreToolUse",
            "posttool"
            | "posttooluse"
            | "posttoolcall"
            | "aftershellexecution"
            | "afterreadfile"
            | "afterwritefile"
            | "aftermcpexecution" => "PostToolUse",
            "permissionrequest" | "permissionrequestv2" => "PermissionRequest",
            "prompt" | "userpromptsubmit" | "userpromptsubmitted" => "UserPromptSubmit",
            _ => raw,
        }
        .to_owned();
    }
    "PreToolUse".to_owned()
}

/// The event name a fail-safe answer carries: `hook_event_name`, else
/// `event`, as the hook spelled it.
pub(super) fn reply_event(payload: &Map<String, Value>) -> String {
    payload
        .get("hook_event_name")
        .or_else(|| payload.get("event"))
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|event| !event.is_empty())
        .unwrap_or("PreToolUse")
        .to_owned()
}

/// The scheduler lane: decisions ahead of content-security work.
pub(super) fn lane(event: &str) -> &'static str {
    let compact: String = event
        .to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect();
    match compact.as_str() {
        "pretooluse" | "permissionrequest" | "userpromptsubmit" | "userpromptsubmitted" => {
            "decision"
        }
        _ => "content-security",
    }
}

/// Takes the harness's remaining-time hint out of the payload: the seconds
/// hint, else the milliseconds one. Booleans and non-finite numbers are not
/// hints. The flag says whether the payload carried either key at all.
pub(super) fn take_hint(payload: &mut Map<String, Value>) -> (Option<f64>, bool) {
    let missing = !payload.contains_key("guard_remaining_seconds")
        && !payload.contains_key("guard_remaining_ms");
    let seconds = payload.remove("guard_remaining_seconds");
    let millis = payload.remove("guard_remaining_ms");
    let hint = [(seconds, 1.0), (millis, 1000.0)]
        .into_iter()
        .find_map(|(raw, scale)| {
            raw.as_ref()
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite())
                .map(|value| value / scale)
        });
    (hint, missing)
}

/// `RuntimeHookDeadline.for_admission`: the hint bounded to the event's
/// budget, less the transport reserve, and never past the admission window.
pub(super) fn expires_at(now: f64, hint: Option<f64>, missing: bool, prompt: bool) -> f64 {
    let hinted = hint.unwrap_or(TOOL_ADMISSION_SECONDS);
    let (admission, value, maximum) = if prompt {
        let value = if missing {
            PROMPT_ADMISSION_SECONDS
        } else {
            hinted
        };
        (PROMPT_ADMISSION_SECONDS, value, PROMPT_ADMISSION_SECONDS)
    } else {
        (TOOL_ADMISSION_SECONDS, hinted, MAX_TOOL_BUDGET_SECONDS)
    };
    let budget = (value.clamp(MIN_BUDGET_SECONDS, maximum) - TRANSPORT_RESERVE_SECONDS)
        .max(MIN_BUDGET_SECONDS);
    (now + budget).min(now + admission)
}

/// The fair-share key: the workspace and the hook's session, digested.
pub(super) fn client_key(payload: &Map<String, Value>, workspace: Option<&str>) -> String {
    let session = ["session_id", "conversation_id", "thread_id"]
        .iter()
        .find_map(|key| {
            payload
                .get(*key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or("");
    let digest = Sha256::digest(format!("{}\0{session}", workspace.unwrap_or("")).as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..32].to_owned()
}

/// Whether an `exec_command` call named a working directory, and how.
pub(super) fn exec_workdir(payload: &Map<String, Value>) -> (bool, Option<String>) {
    let exec = payload
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|name| py_strip(name).to_lowercase() == "exec_command");
    match payload.get("tool_input").and_then(Value::as_object) {
        Some(input) if exec && input.contains_key("workdir") => (
            true,
            input
                .get("workdir")
                .and_then(Value::as_str)
                .map(str::to_owned),
        ),
        _ => (false, None),
    }
}

/// The reservation a referenced payload takes before it is read.
pub(super) const MAX_PAYLOAD_REFERENCE_BYTES: u64 = 5 * 1024 * 1024;
const PAYLOAD_REFERENCE_KEY: &str = "guard_payload_ref";

/// The path an out-of-band payload reference names, once its metadata reads
/// as Guard's writer left it: version 1, a path, and a sha256 digest. `None`
/// for an inline payload; `Err` for a reference the daemon must refuse.
pub(super) fn payload_reference(payload: &Map<String, Value>) -> Result<Option<String>, ()> {
    let Some(reference) = payload
        .get(PAYLOAD_REFERENCE_KEY)
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };
    let version_one = match reference.get("version") {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() == Some(1.0),
        _ => false,
    };
    let (Some(path), Some(digest)) = (
        reference.get("path").and_then(Value::as_str),
        reference.get("sha256").and_then(Value::as_str),
    ) else {
        return Err(());
    };
    let digest = py_strip(digest).to_lowercase();
    if !version_one
        || digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(());
    }
    Ok(Some(path.to_owned()))
}

/// Python truthiness for a JSON value.
pub(super) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(map)) => !map.is_empty(),
    }
}

/// `os.path.normpath` for a POSIX path.
pub(super) fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            ".." if absolute => {}
            part => parts.push(part),
        }
    }
    let joined = parts.join("/");
    match (absolute, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// `os.path.expanduser` for `~` and `~/...`.
pub(super) fn expanduser(path: &str, home: &str) -> String {
    if path == "~" {
        return home.to_owned();
    }
    match path.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home.trim_end_matches('/')),
        None => path.to_owned(),
    }
}

/// Why a directory the hook named was refused, under the parameter the
/// route reports it as.
#[derive(Debug, PartialEq)]
pub(super) struct Rejection {
    pub parameter: String,
    pub reason: String,
}

impl Rejection {
    pub(super) fn to_value(&self) -> Value {
        json!({ "parameter": self.parameter, "reason": self.reason })
    }
}

/// The parameter a rejection of this candidate is reported under.
fn reported(parameter: &str) -> &str {
    match parameter {
        "exec-workdir" | "workspace-payload" | "workspace-query" => "workspace",
        other => other,
    }
}

/// The verdicts for every directory one request named.
pub(super) struct Directories {
    verdicts: Vec<Value>,
    unavailable: Option<String>,
}

impl Directories {
    /// Settles each `(parameter, spelling, rule)` that named something.
    pub(super) fn settle(
        guard_home: &str,
        home_dir: &str,
        candidates: &[(&str, Option<String>, Option<&str>)],
    ) -> Self {
        let asked: Vec<DirectoryTrustCandidateV1> = candidates
            .iter()
            .filter_map(|(parameter, value, rule)| {
                value.as_ref().map(|value| DirectoryTrustCandidateV1 {
                    parameter: (*parameter).to_owned(),
                    value: value.clone(),
                    rule: rule.map(str::to_owned),
                })
            })
            .collect();
        let Some(first) = asked.first().map(|candidate| candidate.parameter.clone()) else {
            return Self {
                verdicts: Vec::new(),
                unavailable: None,
            };
        };
        let temp_dir = std::env::temp_dir();
        let temp_dir = temp_dir.to_string_lossy();
        let temp_dir = match temp_dir.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        };
        let request = DirectoryTrustRequestV1 {
            schema: DIRECTORY_TRUST_REQUEST_SCHEMA.to_owned(),
            request_id: "daemon-hook".to_owned(),
            guard_home: guard_home.to_owned(),
            home_dir: home_dir.to_owned(),
            temp_dir: temp_dir.to_owned(),
            candidates: asked,
        };
        let result = evaluate(&request);
        match result.get("results").and_then(Value::as_array) {
            Some(verdicts) if result["status"] == "ok" => Self {
                verdicts: verdicts.clone(),
                unavailable: None,
            },
            _ => Self {
                verdicts: Vec::new(),
                unavailable: Some(first),
            },
        }
    }

    /// The settled path for one candidate, `None` where it named none.
    pub(super) fn require(&self, parameter: &str) -> Result<Option<String>, Rejection> {
        if let Some(first) = &self.unavailable {
            return Err(Rejection {
                parameter: reported(first).to_owned(),
                reason: DIRECTORY_TRUST_UNAVAILABLE.to_owned(),
            });
        }
        let Some(verdict) = self
            .verdicts
            .iter()
            .find(|verdict| verdict["parameter"] == parameter)
        else {
            return Ok(None);
        };
        if let Some(reason) = verdict.get("reason").and_then(Value::as_str) {
            return Err(Rejection {
                parameter: reported(parameter).to_owned(),
                reason: reason.to_owned(),
            });
        }
        Ok(verdict
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned))
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_admission_tests.rs"]
mod tests;
