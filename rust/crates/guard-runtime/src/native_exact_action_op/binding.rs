//! The short-lived binding that fences a retry of one native review.

use std::path::Path;
use std::sync::OnceLock;

use guard_contracts::{write_canonical_json, NativePolicyBindingV1, NativeReviewFactsV1};
use regex::Regex;
use serde_json::Value;

use super::fs_path::sha256_hex;
use super::launcher_sets::{
    is_code_launcher, is_direct_reusable, rg_runs_preprocessor, uses_file_backed_program,
};
use crate::mcp_proxy_shlex::split_with;

const RECEIPT_SCHEMA: &str = "guard-native-hook-decision-receipt.v1";
const DOMAIN_PREFIX: &[u8] = b"hol-guard.native-review-extension-binding.v1\0";
const SHELL_PUNCTUATION: &str = ";&|<>";
const FILE_BACKED_PROGRAM_COMMANDS: [&str; 5] = ["sed", "grep", "egrep", "fgrep", "rg"];

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("static pattern"))
}

fn digest_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^[0-9a-f]{64}\z")
}

fn identity_token_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^[a-z0-9_-]{1,128}\z")
}

fn assignment_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(?s)^[A-Za-z_][A-Za-z0-9_]*=.*\z")
}

/// Whether retry reuse is safe: mutable local code cannot hide behind argv.
pub(super) fn command_reuse_is_payload_bound(command: &str) -> bool {
    if ["`", "$(", "${", "\n", "\r"]
        .iter()
        .any(|marker| command.contains(marker))
    {
        return false;
    }
    let Some(tokens) = split_with(command, SHELL_PUNCTUATION, "#") else {
        return false;
    };
    let Some(executable) = tokens.first() else {
        return false;
    };
    // shlex groups adjacent punctuation, so every punctuation-only token is rejected.
    if tokens.iter().any(|token| {
        !token.is_empty()
            && token
                .chars()
                .all(|character| SHELL_PUNCTUATION.contains(character))
    }) {
        return false;
    }
    // Leading environment assignments can change lookup or loader behavior.
    if assignment_pattern().is_match(executable) {
        return false;
    }
    if executable.contains('/') || executable.contains('\\') || executable.starts_with('.') {
        return false;
    }
    let basename = Path::new(executable)
        .file_name()
        .map_or(String::new(), |name| name.to_string_lossy().to_lowercase());
    if is_code_launcher(&basename) {
        return false;
    }
    let rest = &tokens[1..];
    if FILE_BACKED_PROGRAM_COMMANDS.contains(&basename.as_str()) && uses_file_backed_program(rest) {
        return false;
    }
    if basename == "rg" && rg_runs_preprocessor(rest) {
        return false;
    }
    is_direct_reusable(&basename)
}

/// `receipt[field]` equals the verdict text of `value`.
fn receipt_text_is(receipt: &Value, field: &str, value: &str) -> bool {
    receipt.get(field).and_then(Value::as_str) == Some(value)
}

/// Python's `receipt.get("version") != 1`: `1`, `1.0` and `true` all equal 1.
fn receipt_version_is_one(receipt: &Value) -> bool {
    match receipt.get("version") {
        Some(Value::Number(number)) => number.as_f64() == Some(1.0),
        Some(Value::Bool(flag)) => *flag,
        _ => false,
    }
}

/// `_native_review_binding`: bind a retry to Rust-owned request and decision evidence.
pub(super) fn review_binding(
    harness: &str,
    command: Option<&str>,
    workspace_bound: bool,
    facts: &NativeReviewFactsV1,
    receipt: Option<&Value>,
    policy_binding: &NativePolicyBindingV1,
) -> Option<String> {
    if facts.action_type.as_deref() == Some("package") {
        return None;
    }
    if command.is_some_and(|text| !command_reuse_is_payload_bound(text)) {
        return None;
    }
    let receipt = receipt.filter(|value| value.is_object())?;
    if !receipt_text_is(receipt, "schema", RECEIPT_SCHEMA)
        || !receipt_version_is_one(receipt)
        || !receipt_text_is(receipt, "authority", "rust")
        || !receipt_text_is(receipt, "harness", harness)
        || !receipt_text_is(receipt, "event_name", "PreToolUse")
        || receipt.get("workspace_bound").and_then(Value::as_bool) != Some(workspace_bound)
    {
        return None;
    }
    let request_digest = receipt.get("request_digest").and_then(Value::as_str)?;
    if !digest_pattern().is_match(request_digest) {
        return None;
    }
    let decision = facts.decision.as_deref().unwrap_or("");
    let minimum_action = facts.minimum_action.as_deref().unwrap_or("");
    let policy_action = facts.policy_action.as_deref().unwrap_or("");
    let reason_code = facts.reason_code.as_deref().unwrap_or("");
    if !receipt_text_is(receipt, "decision", decision)
        || !receipt_text_is(receipt, "policy_action", policy_action)
        || !receipt_text_is(receipt, "reason_code", reason_code)
    {
        return None;
    }
    let tokens = [decision, minimum_action, policy_action, reason_code];
    if tokens
        .iter()
        .any(|value| !identity_token_pattern().is_match(value))
    {
        return None;
    }
    let identity = format!("native-review-v4:{request_digest}:{}", tokens.join(":"));
    match policy_binding {
        NativePolicyBindingV1::Invalid => None,
        NativePolicyBindingV1::Unbound => Some(identity),
        NativePolicyBindingV1::Bound { value } => {
            let mut encoded = DOMAIN_PREFIX.to_vec();
            write_canonical_json(value, &mut encoded).ok()?;
            Some(format!("{identity}:{}", sha256_hex(&encoded)))
        }
    }
}
