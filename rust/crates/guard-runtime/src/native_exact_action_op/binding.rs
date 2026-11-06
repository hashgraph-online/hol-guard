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
use super::reuse_shape::{self, Reuse};
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

/// What binds a retry of `command` beyond its request, or `None` when the
/// retry could run code the review never saw.
pub(super) fn payload_reuse(command: &str, cwd: Option<&Path>) -> Option<Reuse> {
    if ["`", "$(", "${", "\n", "\r"]
        .iter()
        .any(|marker| command.contains(marker))
    {
        return None;
    }
    let tokens = split_with(command, SHELL_PUNCTUATION, "#")?;
    if reuse_shape::is_simple(&tokens) && legacy_command_bound(&tokens) {
        return Some(Reuse::Argv);
    }
    // shlex and the shell disagree on some comment positions.
    if command.contains('#') {
        return None;
    }
    reuse_shape::shaped(&tokens, cwd)
}

fn legacy_command_bound(tokens: &[String]) -> bool {
    let Some(executable) = tokens.first() else {
        return false;
    };
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
    if is_code_launcher(&basename) || !is_direct_reusable(&basename) {
        return false;
    }
    let rest: Vec<&str> = tokens[1..].iter().map(String::as_str).collect();
    legacy_arguments_bound(&basename, &rest)
}

/// A file-backed `sed`/`grep` program or an `rg` preprocessor is mutable code.
pub(super) fn legacy_arguments_bound(basename: &str, rest: &[&str]) -> bool {
    let rest: Vec<String> = rest.iter().map(|word| (*word).to_owned()).collect();
    if FILE_BACKED_PROGRAM_COMMANDS.contains(&basename) && uses_file_backed_program(&rest) {
        return false;
    }
    !(basename == "rg" && rg_runs_preprocessor(&rest))
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

/// The policy binding minus `policy_digest`, which moves on every snapshot
/// republish. `rule_digest`, `runtime_identity` and the command-extension
/// binding still change the binding whenever the rules that decide a verdict do.
fn verdict_policy_binding(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(fields) = value.as_object_mut() {
        fields.remove("policy_digest");
    }
    value
}

/// `_native_review_binding`: bind a retry to Rust-owned request and decision evidence.
/// `launcher` is asked only for a command whose payload alone cannot bind it.
#[allow(clippy::too_many_arguments)]
pub(super) fn review_binding(
    harness: &str,
    command: Option<&str>,
    cwd: Option<&Path>,
    workspace_bound: bool,
    facts: &NativeReviewFactsV1,
    receipt: Option<&Value>,
    policy_binding: &NativePolicyBindingV1,
    launcher: impl FnOnce() -> Option<Reuse>,
) -> Option<String> {
    let reuse = match command {
        Some(text) => payload_reuse(text, cwd).or_else(launcher)?,
        None => Reuse::Argv,
    };
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
    // Anchor to the review anchor rather than the request digest, which also
    // hashes the policy snapshot: a republish that leaves the verdict unchanged
    // must not orphan a pending one-time approval (#4955). Only the review
    // anchor is accepted. `execution_intent_digest` drops `guard_home`,
    // `home_dir` and `source_ref_external_allowed`, so an approval anchored to
    // it could be consumed under another guard home. A receipt that carries no
    // review anchor keeps the request digest instead, so a republish queues the
    // review again rather than matching it on weaker evidence; an anchor that
    // is not a digest has no binding at all.
    let anchor = match receipt.get("review_anchor_digest") {
        None => request_digest,
        Some(value) => match value.as_str() {
            Some(digest) if digest_pattern().is_match(digest) => digest,
            _ => return None,
        },
    };
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
    let identity = format!("native-review-v4:{anchor}:{}", tokens.join(":"));
    let mut encoded = match policy_binding {
        NativePolicyBindingV1::Invalid => return None,
        NativePolicyBindingV1::Unbound => Vec::new(),
        NativePolicyBindingV1::Bound { value } => {
            let mut encoded = DOMAIN_PREFIX.to_vec();
            write_canonical_json(&verdict_policy_binding(value), &mut encoded).ok()?;
            encoded
        }
    };
    // Standard-input content shares the one digest slot under its own domain.
    if let Some(mut extra) = reuse.extra() {
        extra.append(&mut encoded);
        encoded = extra;
    }
    if encoded.is_empty() {
        return Some(identity);
    }
    Some(format!("{identity}:{}", sha256_hex(&encoded)))
}
