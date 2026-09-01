#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod approval_contracts;
pub use approval_contracts::*;

pub const NATIVE_PROTOCOL_VERSION: u16 = 1;
pub const GUARD_HOOK_ENVELOPE_V2_SCHEMA: &str = "guard-hook-envelope.v2";
pub const GUARD_HOOK_EDGE_RESULT_V2_SCHEMA: &str = "guard-hook-edge-result.v2";
pub const PRE_TOOL_ACTION_V1_SCHEMA: &str = "guard-pre-tool-action.v1";
pub const PRE_TOOL_RESULT_V1_SCHEMA: &str = "guard-pre-tool-result.v1";
pub const PRE_TOOL_GENERIC_AUTHORITY_V1: &str = "pre-tool-generic-authority-v1";
pub const MAX_NATIVE_REQUEST_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_NATIVE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardHookSourceMetadataV2 {
    #[serde(default)]
    pub cwd: Option<String>,
    pub home_dir: String,
    pub guard_home: String,
    #[serde(default)]
    pub source_ref_external_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardHookEnvelopeV2 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub harness: String,
    pub event: String,
    pub raw_payload: Value,
    #[serde(default)]
    pub deadline_budget_ms: Option<u64>,
    pub policy_generation: u64,
    pub policy_snapshot: Value,
    pub source: GuardHookSourceMetadataV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardHookPayloadKindV2 {
    Inline,
    SourceFileRef,
    EncryptedPayloadRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardHookEdgeResultV2 {
    pub schema: String,
    pub authority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub harness: String,
    pub event_name: String,
    pub payload_kind: GuardHookPayloadKindV2,
    pub result: Value,
}

/// Result-safe action classes understood by the native PreToolUse edge.
///
/// The edge deliberately returns the class and bounded operation metadata,
/// never the command, prompt, path, URL, or raw tool arguments that led to
/// the decision.  The request remains inside `GuardHookEnvelopeV2` and is
/// consumed only by the native edge.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreToolActionTypeV1 {
    Command,
    FileRead,
    FileWrite,
    Package,
    McpTool,
    Network,
    ProcessService,
    Browser,
    Config,
    Prompt,
    Harness,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreToolOperationV1 {
    Execute,
    Read,
    Write,
    Install,
    Call,
    Request,
    Start,
    Stop,
    Navigate,
    Set,
    Submit,
    Unknown,
}

/// Versioned generic PreToolUse result. Keep this contract independent of
/// harness JSON so adapters can only render the native minimum floor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreToolResultV1 {
    pub schema: String,
    pub version: u16,
    pub authority: String,
    pub action: PreToolActionV1,
    pub decision: String,
    pub policy_action: String,
    pub minimum_action: String,
    pub reason_code: String,
    pub reason: String,
    pub explicitly_benign: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookSourceFileRefV1 {
    pub version: i64,
    pub path: String,
    pub output_sha256: String,
    pub output_chars: i64,
    #[serde(default)]
    pub tool_input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookOutputSummaryV1 {
    pub text_excerpt: String,
    pub excerpt_truncated: bool,
    #[serde(default)]
    pub output_sha256: Option<String>,
    #[serde(default)]
    pub output_chars: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeHookRequestV1 {
    pub protocol_version: u16,
    #[serde(default)]
    pub request_id: Option<String>,
    pub harness: String,
    pub event_name: String,
    pub payload: Value,
    #[serde(default)]
    pub cwd: Option<String>,
    pub home_dir: String,
    pub guard_home: String,
    #[serde(default)]
    pub source_ref_external_allowed: bool,
    #[serde(default)]
    pub observe_mode: bool,
    #[serde(default)]
    pub deadline_budget_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookReviewResponseV1 {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub model_output_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_output_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_excerpt: Option<String>,
    pub notice: String,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_policy_action: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub observe_mode: bool,
}

impl HookReviewResponseV1 {
    pub fn allow(reason_code: impl Into<String>) -> Self {
        Self {
            decision: "allow".into(),
            reason: None,
            model_output_action: "allow_original".into(),
            reviewed_output_sha256: None,
            reviewed_excerpt: None,
            notice: "none".into(),
            reason_code: reason_code.into(),
            policy_action: Some("allow".into()),
            observed_policy_action: None,
            observe_mode: false,
        }
    }

    pub fn deny(reason_code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: "deny".into(),
            reason: Some(reason.into()),
            model_output_action: "block".into(),
            reviewed_output_sha256: None,
            reviewed_excerpt: None,
            notice: "warning".into(),
            reason_code: reason_code.into(),
            policy_action: None,
            observed_policy_action: None,
            observe_mode: false,
        }
    }

    pub fn reviewed_excerpt(
        reason_code: impl Into<String>,
        reason: impl Into<String>,
        excerpt: String,
    ) -> Self {
        Self {
            decision: "allow".into(),
            reason: Some(reason.into()),
            model_output_action: "replace_with_reviewed_excerpt".into(),
            reviewed_output_sha256: None,
            reviewed_excerpt: Some(excerpt),
            notice: "excerpt".into(),
            reason_code: reason_code.into(),
            policy_action: None,
            observed_policy_action: None,
            observe_mode: false,
        }
    }

    pub fn observed(mut self, output_sha256: Option<String>) -> Self {
        if self.decision != "deny" {
            return self;
        }
        let original_reason = self.reason_code.clone();
        self.decision = "allow".into();
        self.reason = None;
        self.model_output_action = "allow_original".into();
        self.reviewed_output_sha256 = output_sha256;
        self.notice = "none".into();
        self.reason_code = format!("observe_{original_reason}");
        self.policy_action = Some("allow".into());
        self.observed_policy_action = Some("block".into());
        self.observe_mode = true;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapabilitiesV1 {
    pub protocol_version: u16,
    pub runtime_version: String,
    pub rule_digest: String,
    pub build_sha: String,
    pub target: String,
    pub features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_omits_empty_optionals() {
        let encoded =
            serde_json::to_value(HookReviewResponseV1::allow("output_scan_allow")).unwrap();
        assert!(encoded.get("reason").is_none());
        assert_eq!(encoded["decision"], "allow");
        assert_eq!(encoded["reason_code"], "output_scan_allow");
    }

    #[test]
    fn hook_envelope_v2_rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema": GUARD_HOOK_ENVELOPE_V2_SCHEMA,
            "harness": "claude-code",
            "event": "PostToolUse",
            "raw_payload": {},
            "deadline_budget_ms": 100,
            "policy_generation": 1,
            "policy_snapshot": {},
            "source": {
                "home_dir": "/home/test",
                "guard_home": "/home/test/.hol-guard"
            },
            "unexpected": true
        });
        assert!(serde_json::from_value::<GuardHookEnvelopeV2>(value).is_err());
    }

    #[test]
    fn generic_pre_tool_result_rejects_raw_content_and_unknown_fields() {
        let value = serde_json::json!({
            "schema": PRE_TOOL_RESULT_V1_SCHEMA,
            "version": 1,
            "authority": "rust",
            "action": {
                "schema": PRE_TOOL_ACTION_V1_SCHEMA,
                "version": 1,
                "harness": "claude-code",
                "event": "PreToolUse",
                "action_type": "command",
                "operation": "execute",
                "bounded": true,
                "sensitive_target": false
            },
            "decision": "allow",
            "policy_action": "allow",
            "minimum_action": "allow",
            "reason_code": "native_exact_safe_command",
            "reason": "bounded",
            "explicitly_benign": true,
            "command": "must-not-be-in-result"
        });
        assert!(serde_json::from_value::<PreToolResultV1>(value).is_err());
    }
}
