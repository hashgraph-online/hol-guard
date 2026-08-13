#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const NATIVE_PROTOCOL_VERSION: u16 = 1;
pub const MAX_NATIVE_REQUEST_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_NATIVE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeRuntimeIdentityV1 {
    pub binary_sha256: String,
    pub runtime_version: String,
    pub build_sha: String,
    pub rule_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativePolicySnapshotIdentityV1 {
    pub schema_version: u16,
    pub generation: u64,
    pub rule_set_digest: String,
    pub strict_config_digest: String,
    pub never_allow_digest: String,
    pub source_policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeHookRequestV1 {
    pub protocol_version: u16,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub payload_size_bytes: Option<usize>,
    #[serde(default)]
    pub runtime_identity: Option<NativeRuntimeIdentityV1>,
    #[serde(default)]
    pub policy_snapshot: Option<NativePolicySnapshotIdentityV1>,
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
    fn identity_bound_request_fields_are_backward_compatible() {
        let value = serde_json::json!({
            "protocol_version": 1,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": {},
            "home_dir": "/home/test",
            "guard_home": "/home/test/.guard"
        });
        let request: NativeHookRequestV1 = serde_json::from_value(value).unwrap();
        assert!(request.operation.is_none());
        assert!(request.runtime_identity.is_none());
        assert!(request.policy_snapshot.is_none());
    }
}
