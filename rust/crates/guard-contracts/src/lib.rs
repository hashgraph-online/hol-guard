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
}
