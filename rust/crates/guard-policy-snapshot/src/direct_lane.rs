//! Freshness binding carried by a policy push for the direct resident hook lane.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DIRECT_LANE_MAX_WORKSPACES: usize = 512;
pub const DIRECT_LANE_MAX_HARNESS_POSTURES: usize = 32;
pub const DIRECT_LANE_HARNESS_POSTURES: &[&str] = &["protected", "extra_careful", "watch"];
pub const DIRECT_LANE_MAX_INPUTS: usize = 256;
pub const DIRECT_LANE_MAX_PATH_BYTES: usize = 4096;
pub const DIRECT_LANE_MAX_SINK_ARGS: usize = 8;
pub const DIRECT_LANE_MAX_SINK_ARG_BYTES: usize = 16_384;
pub const DIRECT_LANE_MAX_INTEGRITY_KEY_B64_BYTES: usize = 2048;
pub const DIRECT_LANE_MAX_INTEGRITY_KEY_ID_BYTES: usize = 256;
pub const DIRECT_LANE_MAX_ENVIRONMENT_ENTRIES: usize = 1024;
pub const DIRECT_LANE_MAX_ENVIRONMENT_BYTES: usize = 262_144;
pub const DIRECT_LANE_MAX_INTEGRITY_STATE_FIELD_BYTES: usize = 256;
pub const DIRECT_LANE_MAX_INTEGRITY_DEGRADED_REASONS: usize = 16;

/// Publisher-observed state that a pushed snapshot was compiled against.
///
/// `workspaces` are the workspace roots whose overlays the snapshot settled.
/// `inputs` are the non-database policy files the publisher watched, each
/// with the stat identity observed before compilation, or `None` when the
/// file was absent. The resident re-observes the inputs before using the
/// snapshot without the daemon.
///
/// The remaining fields carry daemon state that the snapshot itself does not:
/// the daemon's home directory, the per-harness posture overrides it binds to
/// the same ACK, and whether any custom command-line block rule existed when
/// the snapshot was compiled. A direct hook defers whenever one is absent.
/// `evidence_drain` says the daemon drains the evidence of direct answers;
/// without it the resident answers nothing directly.
/// `contained_sink_command` is the argv prefix that starts the daemon's
/// Guard CLI, which the daemon puts in front of a contained execution
/// rewrite; without it such a rewrite stays with the daemon.
/// `integrity_key_b64` and `integrity_key_id` are the policy-integrity key the
/// daemon signs and verifies hook authority state with, as the daemon sends
/// it on every hook authority state request. Without both, a hook that needs
/// that state stays with the daemon.
/// `exact_action_environment` and `exact_action_control_digest` are the
/// process environment and extension-control digest the daemon sends with
/// every exact-action proof it asks the resident for, and
/// `policy_integrity_state` is the policy-integrity state the daemon refreshed
/// when it published. Without all three, a saved decision for an exact action
/// stays with the daemon.
/// `blocked_request_mode`, `approval_center_origin`, `review_oauth_source` and
/// `review_host_cwd` are what the daemon queues a reviewed `PreToolUse` for
/// approval with: the blocked-request mode every bound config resolves to,
/// the approval center it links, the connection source it binds the request
/// to, and the working directory it rebuilds the action envelope with. The
/// resident checks each one itself; one it cannot accept reads as absent, so
/// such a hook stays with the daemon rather than costing the lane.
/// `structured_output_config` is the managed-policy view the daemon resolves
/// structured output mediation from for an Oh My Pi or Pi `PostToolUse`. The
/// resident resolves it itself; a value it cannot read as that view reads as
/// absent, so such a hook stays with the daemon rather than costing the lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneBindingV1 {
    pub workspaces: Vec<String>,
    pub inputs: Vec<DirectLaneInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_postures: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cli_block_rules: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_drain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contained_sink_command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<DirectLaneSecretV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_action_environment: Option<DirectLaneEnvironmentV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_action_control_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_integrity_state: Option<DirectLanePolicyIntegrityStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_request_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_center_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_oauth_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_host_cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output_config: Option<serde_json::Value>,
    /// The per-harness tool-call configuration and extension layers the
    /// daemon decides a relayed MCP tool call with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_relay: Option<serde_json::Value>,
}

/// A process environment whose `Debug` output never shows the values.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct DirectLaneEnvironmentV1(pub BTreeMap<String, String>);

impl std::fmt::Debug for DirectLaneEnvironmentV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "DirectLaneEnvironmentV1({} entries)",
            self.0.len()
        )
    }
}

impl DirectLaneEnvironmentV1 {
    fn is_valid(&self) -> bool {
        if self.0.len() > DIRECT_LANE_MAX_ENVIRONMENT_ENTRIES {
            return false;
        }
        let mut total = 0usize;
        for (name, value) in &self.0 {
            if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
                return false;
            }
            total = total.saturating_add(name.len()).saturating_add(value.len());
        }
        total <= DIRECT_LANE_MAX_ENVIRONMENT_BYTES
    }
}

/// The `_refresh_policy_integrity_state` payload the daemon stores in
/// `sync_state`, field for field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLanePolicyIntegrityStateV1 {
    pub backend: String,
    pub cutover_complete: bool,
    pub degraded_reasons: Vec<String>,
    pub enforcement: String,
    pub generation: Option<u64>,
    pub key_id: Option<String>,
    pub mode: String,
}

impl DirectLanePolicyIntegrityStateV1 {
    fn is_valid(&self) -> bool {
        let field_valid = integrity_state_field_valid;
        field_valid(&self.backend)
            && field_valid(&self.enforcement)
            && field_valid(&self.mode)
            && self.key_id.as_deref().is_none_or(field_valid)
            && self.degraded_reasons.len() <= DIRECT_LANE_MAX_INTEGRITY_DEGRADED_REASONS
            && self
                .degraded_reasons
                .iter()
                .all(|reason| field_valid(reason))
    }
}

fn integrity_state_field_valid(value: &str) -> bool {
    value.len() <= DIRECT_LANE_MAX_INTEGRITY_STATE_FIELD_BYTES
        && !value.chars().any(char::is_control)
}

/// Key material whose `Debug` output never shows the value.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct DirectLaneSecretV1(pub String);

impl std::fmt::Debug for DirectLaneSecretV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectLaneSecretV1(..)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneInputV1 {
    pub path: String,
    pub stat: Option<DirectLaneStatV1>,
}

/// The `(mtime_ns, size, ino, ctime_ns)` identity of a followed `stat`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneStatV1 {
    pub mtime_ns: i64,
    pub size: u64,
    pub ino: u64,
    pub ctime_ns: i64,
}

impl DirectLaneBindingV1 {
    pub fn is_valid(&self) -> bool {
        if self.workspaces.len() > DIRECT_LANE_MAX_WORKSPACES
            || self.inputs.len() > DIRECT_LANE_MAX_INPUTS
        {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        for workspace in &self.workspaces {
            if !direct_lane_path_valid(workspace) || !seen.insert(workspace.as_str()) {
                return false;
            }
        }
        seen.clear();
        for input in &self.inputs {
            if !direct_lane_path_valid(&input.path) || !seen.insert(input.path.as_str()) {
                return false;
            }
        }
        if self
            .home_dir
            .as_deref()
            .is_some_and(|home_dir| !direct_lane_path_valid(home_dir))
        {
            return false;
        }
        if let Some(postures) = &self.harness_postures {
            if postures.len() > DIRECT_LANE_MAX_HARNESS_POSTURES
                || postures.iter().any(|(harness, posture)| {
                    harness.is_empty()
                        || harness.len() > 64
                        || !DIRECT_LANE_HARNESS_POSTURES.contains(&posture.as_str())
                })
            {
                return false;
            }
        }
        if let Some(command) = &self.contained_sink_command {
            if command.is_empty()
                || command.len() > DIRECT_LANE_MAX_SINK_ARGS
                || !direct_lane_path_valid(&command[0])
                || command.iter().any(|argument| {
                    argument.is_empty()
                        || argument.len() > DIRECT_LANE_MAX_SINK_ARG_BYTES
                        || argument.contains('\0')
                })
            {
                return false;
            }
        }
        match (&self.integrity_key_b64, &self.integrity_key_id) {
            (None, None) => {}
            (Some(key), Some(key_id)) => {
                if key.0.is_empty()
                    || key.0.len() > DIRECT_LANE_MAX_INTEGRITY_KEY_B64_BYTES
                    || !key
                        .0
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    || key_id.is_empty()
                    || key_id.len() > DIRECT_LANE_MAX_INTEGRITY_KEY_ID_BYTES
                    || key_id.chars().any(char::is_control)
                {
                    return false;
                }
            }
            _ => return false,
        }
        if self
            .exact_action_environment
            .as_ref()
            .is_some_and(|environment| !environment.is_valid())
            || self
                .exact_action_control_digest
                .as_deref()
                .is_some_and(|digest| !integrity_state_field_valid(digest))
            || self
                .policy_integrity_state
                .as_ref()
                .is_some_and(|state| !state.is_valid())
        {
            return false;
        }
        true
    }
}

fn direct_lane_path_valid(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= DIRECT_LANE_MAX_PATH_BYTES
        && !path.contains('\0')
        && std::path::Path::new(path).is_absolute()
}
