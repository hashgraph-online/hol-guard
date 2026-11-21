use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "guard-swarm-snapshot.v1";
pub const MAX_AGENTS: usize = 256;
pub const MAX_RUNS: usize = 16;
pub const MAX_EVENTS: usize = 200;
pub const MAX_TEXT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Starting,
    Running,
    Observed,
    AwaitingInput,
    NeedsAttention,
    Completed,
    Failed,
    Stopping,
    Stopped,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOrigin {
    Managed,
    Observed,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Controls {
    pub message: bool,
    pub steer: bool,
    pub interrupt: bool,
    pub stop: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Agent {
    pub id: String,
    pub harness: String,
    pub label: String,
    pub origin: AgentOrigin,
    pub state: AgentState,
    pub workspace: Option<String>,
    pub task: Option<String>,
    pub model: Option<String>,
    pub pid: Option<u32>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub controls: Controls,
    pub detail: String,
    #[serde(default)]
    pub activity: Option<String>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub queued: usize,
    #[serde(default)]
    pub context_calls: u64,
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    /// Project paths this agent's file tools may not open or change.
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(skip)]
    pub parent_pid: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Adapter {
    pub id: String,
    pub label: String,
    pub installed: bool,
    pub launch_supported: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Coverage {
    pub state: String,
    pub limited: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub schema: String,
    pub epoch: String,
    pub observed_at_ms: u64,
    pub discovery: Coverage,
    pub agents: Vec<Agent>,
    pub adapters: Vec<Adapter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    pub sequence: u64,
    pub at_ms: u64,
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub request_id: String,
    pub epoch: String,
    pub harness: String,
    pub workspace: String,
    pub task: String,
    /// Left out, `null`, or a model name. See [`sent`].
    #[serde(
        default,
        deserialize_with = "sent",
        skip_serializing_if = "Option::is_none"
    )]
    pub model: Option<Option<String>>,
    /// Left out, `null`, or project paths the agent may not open. Claude Code
    /// enforces them through its own deny rules; Codex has no such control,
    /// so a Codex launch with paths is refused rather than run unlimited.
    #[serde(
        default,
        deserialize_with = "sent",
        skip_serializing_if = "Option::is_none"
    )]
    pub blocked: Option<Option<Vec<String>>>,
}

pub const MAX_BLOCKED: usize = 32;
/// Characters Claude Code reads as permission-rule syntax; a project path
/// holding any of them cannot anchor a blocked-path rule.
pub(crate) const RULE_SYNTAX: [char; 8] = ['(', ')', '*', '?', '[', ']', '{', '}'];

/// A project-relative path or glob that fits inside a Claude Code permission
/// rule: no absolute or parent paths, no characters a rule could close on.
pub fn valid_blocked(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with(['/', '-', '~'])
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/*@+".contains(&b))
        && path
            .trim_end_matches('/')
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

/// Reads a field the sender may leave out, send as `null`, or set. The reply
/// carries a digest of the decoded request, and the sender checks it against
/// a digest of what it sent, so a `null` must stay `null` and a missing field
/// must stay missing.
fn sent<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

impl Launch {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.request_id)
            || !valid_id(&self.epoch)
            || !matches!(self.harness.as_str(), "codex" | "claude-code")
            || self.workspace.len() > 4096
            || !std::path::Path::new(&self.workspace).is_absolute()
            || !valid_text(&self.task, MAX_TEXT_BYTES)
            || self.workspace.contains('\0')
            || self
                .model
                .as_ref()
                .and_then(Option::as_ref)
                .is_some_and(|m| {
                    !valid_text(m, 128)
                        || m.starts_with('-')
                        || !m
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
                })
            || self
                .blocked
                .as_ref()
                .and_then(Option::as_ref)
                .is_some_and(|paths| {
                    paths.len() > MAX_BLOCKED
                        || (!paths.is_empty()
                            && (self.harness != "claude-code"
                                || self.workspace.contains(RULE_SYNTAX)))
                        || !paths.iter().all(|p| valid_blocked(p))
                })
        {
            return Err("swarm_launch_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub request_id: String,
    pub epoch: String,
    pub run_id: String,
    pub expected_revision: u64,
    pub action: String,
    /// Left out, `null`, or the instruction. See [`sent`].
    #[serde(
        default,
        deserialize_with = "sent",
        skip_serializing_if = "Option::is_none"
    )]
    pub text: Option<Option<String>>,
}

impl Action {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.request_id)
            || !valid_id(&self.epoch)
            || !valid_id(&self.run_id)
            || !matches!(self.action.as_str(), "message" | "interrupt" | "stop")
            || if self.action == "message" {
                !self
                    .text
                    .as_ref()
                    .and_then(Option::as_ref)
                    .is_some_and(|t| valid_text(t, MAX_TEXT_BYTES))
            } else {
                self.text.as_ref().is_some_and(Option::is_some)
            }
        {
            return Err("swarm_action_invalid");
        }
        Ok(())
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

pub fn valid_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.len() <= max && !text.contains('\0')
}

pub(crate) fn clipped(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes.saturating_sub("…".len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_are_data_and_cannot_choose_an_executable_or_flags() {
        let mut request = Launch {
            request_id: "launch-1".into(),
            epoch: "epoch".into(),
            harness: "codex".into(),
            workspace: std::env::temp_dir().to_string_lossy().into(),
            task: "Review $(not-a-shell) and --dangerously-bypass-approvals".into(),
            model: None,
            blocked: None,
        };
        assert!(request.validate().is_ok());
        request.harness = "/bin/sh".into();
        assert!(request.validate().is_err());
        request.harness = "codex".into();
        request.model = Some(Some("--dangerously-skip-permissions".into()));
        assert!(request.validate().is_err());
        request.model = None;
        request.workspace = "../project".into();
        assert!(request.validate().is_err());
    }

    #[test]
    fn blocked_paths_stay_inside_the_project_and_need_claude_code() {
        let mut request = Launch {
            request_id: "launch-1".into(),
            epoch: "epoch".into(),
            harness: "claude-code".into(),
            workspace: std::env::temp_dir().to_string_lossy().into(),
            task: "Fix the parser".into(),
            model: None,
            blocked: Some(Some(vec!["private/".into(), "**/.env.*".into()])),
        };
        assert!(request.validate().is_ok());
        for bad in [
            "/etc", "../up", "a/../b", "~/x", "-x", "a)b", "a b", "a,b", "./a", "",
        ] {
            request.blocked = Some(Some(vec![bad.into()]));
            assert!(request.validate().is_err(), "{bad}");
        }
        request.blocked = Some(Some(vec!["x".into(); MAX_BLOCKED + 1]));
        assert!(request.validate().is_err());
        // A project path with rule syntax in it could not be named exactly.
        let workspace = request.workspace.clone();
        request.blocked = Some(Some(vec!["private".into()]));
        request.workspace = format!("{workspace}/odd (copy)");
        assert!(request.validate().is_err());
        request.workspace = workspace;
        // Codex cannot keep an agent out of a folder; refuse rather than pretend.
        request.harness = "codex".into();
        request.blocked = Some(Some(vec!["private".into()]));
        assert!(request.validate().is_err());
        request.blocked = Some(Some(Vec::new()));
        assert!(request.validate().is_ok());
    }

    #[test]
    fn input_limits_and_unknown_fields_are_enforced() {
        assert!(!valid_id("../run"));
        assert!(!valid_text("\0", MAX_TEXT_BYTES));
        assert!(!valid_text(&"x".repeat(MAX_TEXT_BYTES + 1), MAX_TEXT_BYTES));
        assert!(serde_json::from_value::<Launch>(serde_json::json!({
            "request_id":"a", "harness":"codex", "workspace":"/tmp", "task":"hello",
            "model":null, "executable":"/bin/sh"
        }))
        .is_err());
    }

    #[test]
    fn null_and_missing_fields_round_trip_as_sent() {
        for sent in [
            serde_json::json!({"request_id":"a", "epoch":"e", "harness":"codex",
                "workspace":"/tmp", "task":"hello", "model":null}),
            serde_json::json!({"request_id":"a", "epoch":"e", "harness":"codex",
                "workspace":"/tmp", "task":"hello"}),
            serde_json::json!({"request_id":"a", "epoch":"e", "harness":"codex",
                "workspace":"/tmp", "task":"hello", "model":"gpt-5"}),
            serde_json::json!({"request_id":"a", "epoch":"e", "harness":"claude-code",
                "workspace":"/tmp", "task":"hello", "blocked":["private"]}),
            serde_json::json!({"request_id":"a", "epoch":"e", "harness":"codex",
                "workspace":"/tmp", "task":"hello", "blocked":null}),
        ] {
            let launch: Launch = serde_json::from_value(sent.clone()).unwrap();
            assert!(launch.validate().is_ok(), "{sent}");
            assert_eq!(serde_json::to_value(&launch).unwrap(), sent);
        }
        for sent in [
            serde_json::json!({"request_id":"a", "epoch":"e", "run_id":"r",
                "expected_revision":2, "action":"stop", "text":null}),
            serde_json::json!({"request_id":"a", "epoch":"e", "run_id":"r",
                "expected_revision":2, "action":"stop"}),
            serde_json::json!({"request_id":"a", "epoch":"e", "run_id":"r",
                "expected_revision":2, "action":"message", "text":"go on"}),
        ] {
            let action: Action = serde_json::from_value(sent.clone()).unwrap();
            assert!(action.validate().is_ok(), "{sent}");
            assert_eq!(serde_json::to_value(&action).unwrap(), sent);
        }
        let stop_with_text: Action = serde_json::from_value(serde_json::json!({
            "request_id":"a", "epoch":"e", "run_id":"r", "expected_revision":2,
            "action":"stop", "text":"x"
        }))
        .unwrap();
        assert!(stop_with_text.validate().is_err());
    }
}
