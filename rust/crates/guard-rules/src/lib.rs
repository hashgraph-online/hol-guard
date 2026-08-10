#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const SCANNER_VERSION: &str = "hook-content-v1";
pub const SOURCE_CLASSIFIER_VERSION: &str = "source-paths-v1";
pub const SOURCE_READ_VERSION: &str = "source-read-fast-v1";
pub const MAX_SCAN_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_OUTPUT_CHARS: usize = 5 * 1024 * 1024;
pub const MAX_DEPTH: usize = 24;
pub const MAX_CONTENT_ITEMS: usize = 24;
pub const MAX_OBJECT_KEYS: usize = 24;
pub const MAX_MATCHES: usize = 16;
pub const CONTEXT_CHARS: usize = 8192;
pub const REVIEWED_EXCERPT_CHARS: usize = 1024 * 1024;

pub const OUTPUT_TEXT_KEYS: &[&str] = &["stdout", "stderr", "output", "content", "result", "message", "text"];
pub const PAYLOAD_OUTPUT_KEYS: &[&str] = &[
    "tool_response",
    "tool_output",
    "tool_result",
    "toolOutput",
    "stdout",
    "stderr",
    "output",
    "content",
    "result",
    "response",
];

pub const REASON_CODES: &[&str] = &[
    "binary_file",
    "engine_exception",
    "invalid_output_hash",
    "invalid_output_to_review",
    "invalid_source_ref_version",
    "invalid_utf8",
    "missing_source_ref",
    "no_output_to_review",
    "not_file_read",
    "not_post_tool",
    "not_single_target_path",
    "output_empty_allow",
    "output_mismatch",
    "output_scan_allow",
    "output_secret_match",
    "output_too_large",
    "read_failed",
    "reviewed_excerpt",
    "scanner_budget_exhausted",
    "sensitive_path",
    "source_file_too_large",
    "source_full_scan_allow",
    "source_read_limit_exceeded",
    "source_ref_target_mismatch",
    "source_secret_match",
    "source_stat_changed",
    "stat_failed",
    "unresolved_envelope_target",
    "unresolved_path",
];

const RULE_MATERIAL: &str = concat!(
    "hook-content-v1\nsource-paths-v1\nsource-read-fast-v1\n",
    "github-token|aws-access-key|openai-api-key|anthropic-api-key|hedera-private-key|pem-private-key|npm-auth-token|generic-bearer-token|credential-marker|credential-assignment\n",
    ".env|.npmrc|.pypirc|.netrc|.git-credentials|.aws/credentials|.aws/config|.docker/config.json|.kube/config|.ssh|.gnupg|terraform.tfvars|private-key\n",
    "depth=24|items=24|keys=24|max=5242880|matches=16|context=8192"
);

pub fn rule_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(RULE_MATERIAL.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn is_reason_code_known(reason: &str) -> bool {
    REASON_CODES.contains(&reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_shape() {
        let digest = rule_digest();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
