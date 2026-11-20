//! `rejection_payload`: the stored record of why a policy bundle was not
//! applied, with the sentence that tells an administrator what to do next.
//!
//! Both sync routes store it: the CLI's `sync_receipts` and the daemon's
//! headless policy sync. `{"reason", "rule_id"}` answers `{"reason",
//! "message"?, "ruleId"?}`. A missing reason reads as `invalid_policy_bundle`.
//! A rule that does not compile rejects the whole bundle, so the rejection
//! names that rule; a compile code reported for the policy document itself
//! names no rule.

use serde_json::{json, Map, Value};

use crate::policy_bundle_op::{optional_text, Fail, Handled};
use crate::policy_bundle_py::Obj;

pub(crate) const CANONICAL_COMPILE_PREFIX: &str = "canonical_compile_";
const NATIVE_UNAVAILABLE: &str = "native_policy_bundle_unavailable";
const RULE_ID_CHARS: usize = 128;

/// Compile codes the compiler reports before it reads any rule.
const DOCUMENT_CODES: [&str; 3] = [
    "invalid_policy_spec",
    "invalid_policy_rules",
    "unsupported_policy_budgets",
];

const TRUST: [&str; 13] = [
    "missing_signature",
    "missing_signing_key_id",
    "signing_key_fingerprint_mismatch",
    "signing_key_not_current",
    "signing_key_purpose_mismatch",
    "signing_key_revoked",
    "signing_key_workspace_mismatch",
    "trusted_key_unavailable",
    "unsupported_signature_algorithm",
    "untrusted_signing_key",
    "bundle_signature_invalid",
    "invalid_signature_encoding",
    "invalid_verifier",
];
const INTEGRITY: [&str; 4] = [
    "bundle_hash_mismatch",
    "invalid_bundle_hash",
    "invalid_payload_hash",
    "payload_hash_mismatch",
];
const SCHEMA: [&str; 8] = [
    "invalid_acknowledgements",
    "invalid_cloud_exceptions",
    "invalid_policy_bundle",
    "invalid_policy_defaults",
    "invalid_receipt_redaction_level",
    "invalid_rollout_state",
    "invalid_rules",
    "missing_required_field",
];
const WORKSPACE: [&str; 2] = ["invalid_workspace_id", "wrong_workspace"];
const FRESHNESS: [&str; 4] = [
    "bundle_expired",
    "bundle_not_yet_valid",
    "invalid_expires_at",
    "invalid_issued_at",
];
const VERSION: [&str; 4] = [
    "invalid_bundle_version",
    "invalid_min_daemon_version",
    "unsupported_contract_version",
    "unsupported_daemon_version",
];

/// What Guard can enforce instead, for each rule compile code.
fn compile_remediation(code: &str) -> Option<&'static str> {
    Some(match code {
        "unsupported_policy_match" => "Guard enforces match on artifacts, exact commands, harnesses, publishers, tools and workspaces; other match fields, such as packages, domains or paths, are not enforced on this device. Tools cannot be combined with artifacts or publishers, and an exact command cannot be combined with artifacts, tools or publishers.",
        "invalid_policy_match_selector" => "Every match field needs at least one non-empty value.",
        "unsupported_policy_effect" => "Guard enforces allow, block and review rules.",
        "unsupported_exact_command_review" => "Guard cannot ask for review on an exact command; it enforces only allow and block there. Block the command, or ask for review on its tool instead.",
        "unsupported_policy_lifetime" => "Guard enforces lifetime.mode permanent, or until with an expiresAt time.",
        "unsupported_policy_budgets" => "Budgets are not enforced by Guard.",
        "command_expression_requires_guard_3_1_runtime" => "This device enforces a command pattern only on an allow rule, so a block or review rule with a command expression stays unapplied. Match the exact command instead, which Guard enforces under every spelling. A tool match is not a substitute: it covers every call to that tool, not only this command, so widen the rule only as a deliberate policy decision.",
        "command_pattern_allow_single_condition" => "A command pattern allows with one condition. Write every limit the command must meet into that one pattern; use separate rules only for commands that are each acceptable on their own.",
        "command_pattern_allow_case_sensitive" => "A command pattern must match case-sensitively.",
        "command_pattern_allow_operator" => "A command pattern matches with exact, startsWith or glob. Contains, endsWith and regex are not enforced on this device.",
        "command_pattern_allow_wildcard" => "A command pattern's only wildcard is *. Escape ? and [ with a backslash to match them literally.",
        "command_pattern_allow_literal_head" => "A command pattern keeps the program and the word after it as plain literal words, with no wildcard, quote, escape or expansion, so it cannot allow every use of a program.",
        "command_pattern_allow_program_literal" => "A command pattern must start with a literal program name.",
        "command_pattern_allow_wrapper" => "A command pattern cannot start with a program that runs another one, such as env, sudo, xargs or npx. Allow the exact command instead.",
        "command_pattern_allow_interpreter_option" => "A command pattern cannot follow an interpreter with an option such as -c, -e or /c, which would allow any script. Name the script file, or allow the exact command.",
        "command_pattern_allow_runner" => "A command pattern cannot follow a tool with the subcommand that runs a program or code it is given, such as npm exec, deno eval, uv run or git submodule, or start such a tool with an option, such as npm --silent or git -c. After npm run, name the script, as in npm run test *. Otherwise allow the exact command.",
        "policy_compilation_limit" => "The rules expand into more enforcement rows than one policy may hold. Split the policy, or list fewer tools, artifacts, harnesses, publishers and workspaces per rule.",
        _ => return None,
    })
}

fn compile_message(code: &str) -> String {
    let document = DOCUMENT_CODES.contains(&code);
    let (part, subject) = if document {
        ("its policy", "policy")
    } else {
        ("one of its rules", "rule")
    };
    let detail = compile_remediation(code)
        .map(|detail| format!("{detail} "))
        .unwrap_or_default();
    format!(
        "The policy bundle was not applied because {part} cannot be enforced on this device. \
         {detail}Change the {subject} in Guard Cloud and publish again; this device keeps the policy it already had."
    )
}

/// The remediation sentence for a rejection reason, if Guard has one.
pub(crate) fn message(reason: &str) -> Option<String> {
    if let Some(code) = reason.strip_prefix(CANONICAL_COMPILE_PREFIX) {
        return Some(compile_message(code));
    }
    let text = if reason == "inactive_rollout_state" {
        "The authenticated policy bundle is not active for local enforcement. \
         Approve or publish the rollout in Guard Cloud, then sync again."
    } else if reason == NATIVE_UNAVAILABLE {
        "The policy bundle was not applied because the Guard native runtime could not be reached. \
         Check that Guard is healthy, then sync again."
    } else if TRUST.contains(&reason) {
        "The policy bundle was not applied because its signing authority could not be verified. \
         Sync again after the workspace policy signing key is provisioned or rotated."
    } else if INTEGRITY.contains(&reason) {
        "The policy bundle was not applied because its integrity checks failed. \
         Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."
    } else if SCHEMA.contains(&reason) {
        "The policy bundle was not applied because its schema or required fields are invalid. \
         Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."
    } else if WORKSPACE.contains(&reason) {
        "The policy bundle was not applied because it does not match the connected workspace. \
         Reconnect Guard to the intended workspace. Sync again after the workspace connection is confirmed."
    } else if FRESHNESS.contains(&reason) {
        "The policy bundle was not applied because its validity period is not current. \
         Check the system clock. Sync again to fetch the current workspace policy."
    } else if reason == "bundle_version_downgrade" {
        "The policy bundle was not applied because it is older than, or conflicts with, \
         the policy this device already accepted. This device keeps the policy it already had. \
         Publish the policy again in Guard Cloud so it gets a newer version, then sync again. \
         If a newer publish is also rejected, the policy record on this device may be damaged; \
         contact your workspace administrator."
    } else if VERSION.contains(&reason) {
        "The policy bundle was not applied because its contract or daemon version is incompatible. \
         Update Guard to a supported version if required. Sync again to fetch the current workspace policy."
    } else {
        return None;
    };
    Some(text.to_owned())
}

/// The stored rejection record for `reason`, naming `rule_id` when a rule
/// refused to compile.
pub(crate) fn payload(reason: Option<&str>, rule_id: Option<&str>) -> Value {
    let reason = reason
        .filter(|reason| !reason.is_empty())
        .unwrap_or("invalid_policy_bundle");
    let mut record = Map::new();
    record.insert("reason".to_owned(), json!(reason));
    if let Some(text) = message(reason) {
        record.insert("message".to_owned(), json!(text));
    }
    let names_document = reason
        .strip_prefix(CANONICAL_COMPILE_PREFIX)
        .is_some_and(|code| DOCUMENT_CODES.contains(&code));
    if let Some(rule) = rule_id.filter(|rule| !rule.is_empty() && !names_document) {
        record.insert(
            "ruleId".to_owned(),
            json!(rule.chars().take(RULE_ID_CHARS).collect::<String>()),
        );
    }
    Value::Object(record)
}

pub(crate) fn handle(kind: &str, input: &Obj) -> Option<Handled> {
    (kind == "rejection_payload").then(|| rejection_payload(input))
}

fn rejection_payload(input: &Obj) -> Handled {
    if input.keys().any(|key| key != "reason" && key != "rule_id") {
        return Err(Fail::Invalid);
    }
    let reason = optional_text(input, "reason")?;
    let rule_id = optional_text(input, "rule_id")?;
    Ok(payload(reason, rule_id))
}
