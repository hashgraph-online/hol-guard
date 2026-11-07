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
    pub model: Option<String>,
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
            || self.model.as_ref().is_some_and(|m| {
                !valid_text(m, 128)
                    || m.starts_with('-')
                    || !m
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
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
    pub text: Option<String>,
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
                    .is_some_and(|t| valid_text(t, MAX_TEXT_BYTES))
            } else {
                self.text.is_some()
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
        };
        assert!(request.validate().is_ok());
        request.harness = "/bin/sh".into();
        assert!(request.validate().is_err());
        request.harness = "codex".into();
        request.model = Some("--dangerously-skip-permissions".into());
        assert!(request.validate().is_err());
        request.model = None;
        request.workspace = "../project".into();
        assert!(request.validate().is_err());
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
}
