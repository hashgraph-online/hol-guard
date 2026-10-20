//! Result-contract gate for the context-digest op.
//!
//! The resident used to emit whatever it computed and the Python transport
//! re-validated every field's shape and vocabulary before trusting it. The
//! check lives here now, in front of the encoder: a result that breaks the
//! contract never leaves the resident, so the caller sees a resident error
//! envelope (which it records against the breaker) instead of an unchecked
//! answer. Python keeps only the request binding (schema, request id, request
//! digest, status/code pairing), which only the requester can verify.

use guard_contracts::ContextDigestKindV1 as Kind;
use serde_json::{Map, Value};

pub(crate) const ERR_RESULT_INVALID: &str = "native_context_digest_result_invalid";

/// Whether the result of this request kind carries anything the gate checks.
/// The redacted-value and catalog-fingerprint answers can be large and are
/// opaque to the contract, so they skip the intermediate JSON tree.
pub(crate) fn gated(kind: &Kind) -> bool {
    !matches!(
        kind,
        Kind::McpRedactJson { .. } | Kind::McpToolCatalogFingerprint { .. }
    )
}

/// Wire name of the request kind, matching the contract's `snake_case` tag.
pub(crate) fn kind_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::BuildApprovalContextToken { .. } => "build_approval_context_token",
        Kind::ValidateApprovalContextTokens { .. } => "validate_approval_context_tokens",
        Kind::ApprovalContextTokenWellFormed { .. } => "approval_context_token_well_formed",
        Kind::ConfiguredEnvironmentHash { .. } => "configured_environment_hash",
        Kind::ConfiguredHeadersHash { .. } => "configured_headers_hash",
        Kind::LaunchArgvDigest { .. } => "launch_argv_digest",
        Kind::CanonicalSha256 { .. } => "canonical_sha256",
        Kind::OpaqueMaterialDigest { .. } => "opaque_material_digest",
        Kind::McpRedactJson { .. } => "mcp_redact_json",
        Kind::NativeBashReplyValidation { .. } => "native_bash_reply_validation",
        Kind::McpLaunchEnvironment { .. } => "mcp_launch_environment",
        Kind::PackageExecutionContextFromEvidence { .. } => {
            "package_execution_context_from_evidence"
        }
        Kind::PackageExecutionContextFromScannerEvidence { .. } => {
            "package_execution_context_from_scanner_evidence"
        }
        Kind::CustomExtensionContinuity { .. } => "custom_extension_continuity",
        Kind::ManagedControlsPolicyFields { .. } => "managed_controls_policy_fields",
        Kind::LocalCliIdentity { .. } => "local_cli_identity",
        Kind::PackageJsonScripts { .. } => "package_json_scripts",
        Kind::LocalCliIdentify { .. } => "local_cli_identify",
        Kind::CustomExtensionSuggestion { .. } => "custom_extension_suggestion",
        Kind::ClaudeGuardQuestion { .. } => "claude_guard_question",
        Kind::MemoryPattern { .. } => "memory_pattern",
        Kind::McpServerIdentity { .. } => "mcp_server_identity",
        Kind::McpToolIdentity { .. } => "mcp_tool_identity",
        Kind::BrowserMcp { .. } => "browser_mcp",
        Kind::RuntimeExecutableIdentity { .. } => "runtime_executable_identity",
        Kind::RuntimeLaunchIdentity { .. } => "runtime_launch_identity",
        Kind::RuntimeLaunchIdentityMatches { .. } => "runtime_launch_identity_matches",
        Kind::RuntimeLaunchIdentityProjection { .. } => "runtime_launch_identity_projection",
        Kind::McpToolCatalogFingerprint { .. } => "mcp_tool_catalog_fingerprint",
        Kind::RuntimeHookApprovalContext { .. } => "runtime_hook_approval_context",
        Kind::GenericHookApprovalContext { .. } => "generic_hook_approval_context",
    }
}

/// Output a successful result of this kind must carry, truthy.
fn required_output(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "build_approval_context_token" => "token",
        "configured_environment_hash"
        | "configured_headers_hash"
        | "launch_argv_digest"
        | "canonical_sha256"
        | "opaque_material_digest" => "digest",
        "mcp_server_identity" => "mcp_server_identity",
        "mcp_tool_identity" => "mcp_tool_identity",
        "browser_mcp" => "browser_mcp",
        "claude_guard_question" => "claude_guard_question",
        "memory_pattern" => "memory_pattern",
        _ => return None,
    })
}

/// Output a successful result of this kind must carry, though it may be null.
fn nullable_output(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "custom_extension_continuity" => "custom_extension_continuity",
        "managed_controls_policy_fields" => "managed_controls_policy_fields",
        "validate_approval_context_tokens" => "validation_reason",
        "approval_context_token_well_formed" => "approval_context_token_well_formed",
        "package_execution_context_from_evidence"
        | "package_execution_context_from_scanner_evidence" => "package_context",
        "local_cli_identify" => "local_cli_identities",
        "native_bash_reply_validation" => "native_bash_reply_valid",
        _ => return None,
    })
}

/// Fields that only make sense for exactly one request kind.
const KIND_GATED_FIELDS: [(&str, &str); 10] = [
    ("native_bash_reply_valid", "native_bash_reply_validation"),
    (
        "approval_context_token_well_formed",
        "approval_context_token_well_formed",
    ),
    ("local_cli_identity", "local_cli_identity"),
    (
        "managed_controls_policy_fields",
        "managed_controls_policy_fields",
    ),
    ("package_json_scripts", "package_json_scripts"),
    ("local_cli_identities", "local_cli_identify"),
    ("custom_extension_suggestion", "custom_extension_suggestion"),
    ("custom_extension_continuity", "custom_extension_continuity"),
    ("claude_guard_question", "claude_guard_question"),
    ("memory_pattern", "memory_pattern"),
];

fn is_sha256(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Python truthiness of a decoded JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|float| float != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn is_unique_strings(value: Option<&Value>) -> bool {
    let Some(Value::Array(items)) = value else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    items
        .iter()
        .all(|item| item.as_str().is_some_and(|text| seen.insert(text)))
}

fn hashes_ok(identity: &Value, hash_keys: &[&str]) -> bool {
    hash_keys
        .iter()
        .all(|key| identity.get(*key).is_some_and(is_sha256))
}

fn valid_package_context(context: &Value) -> bool {
    let Some(components) = context.get("components").and_then(Value::as_array) else {
        return false;
    };
    context.get("digest").is_some_and(is_sha256)
        && !components.is_empty()
        && components
            .iter()
            .all(|component| component.get("digest").is_some_and(is_sha256))
}

fn present<'a>(payload: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    payload.get(field).filter(|value| !value.is_null())
}

fn fields_valid(kind: &str, payload: &Map<String, Value>) -> bool {
    if payload
        .get("native_bash_reply_valid")
        .is_some_and(|value| !value.is_boolean())
    {
        return false;
    }
    if present(payload, "approval_context_token_well_formed")
        .is_some_and(|verdict| !verdict.is_boolean())
    {
        return false;
    }
    if present(payload, "package_context").is_some_and(|context| !valid_package_context(context)) {
        return false;
    }
    if present(payload, "mcp_server_identity").is_some_and(|identity| {
        !hashes_ok(identity, &["args_hash", "env_values_hash", "identity_hash"])
    }) {
        return false;
    }
    if present(payload, "mcp_tool_identity").is_some_and(|identity| {
        !hashes_ok(
            identity,
            &["schema_hash", "description_hash", "identity_hash"],
        )
    }) {
        return false;
    }
    if let Some(browser) = present(payload, "browser_mcp") {
        let intent = browser.get("intent").filter(|intent| intent.is_object());
        let lists_unique = intent.is_none_or(|model| {
            is_unique_strings(model.get("sensitive_surface_flags"))
                && is_unique_strings(model.get("volatile_fields_dropped"))
        });
        let version_ok = intent.is_none_or(|model| model.get("version") == Some(&Value::from(1)));
        if kind != "browser_mcp" || !lists_unique || !version_ok {
            return false;
        }
    }
    KIND_GATED_FIELDS
        .iter()
        .all(|(field, owner)| !payload.contains_key(*field) || kind == *owner)
}

/// Check one encoded result against the contract for its request kind.
pub(crate) fn check_result(kind: &str, payload: &Value) -> Result<(), &'static str> {
    let Value::Object(map) = payload else {
        return Err(ERR_RESULT_INVALID);
    };
    if !fields_valid(kind, map) {
        return Err(ERR_RESULT_INVALID);
    }
    if map.get("status").and_then(Value::as_str) == Some("ok") {
        if required_output(kind).is_some_and(|field| !map.get(field).is_some_and(truthy)) {
            return Err(ERR_RESULT_INVALID);
        }
        if nullable_output(kind).is_some_and(|field| !map.contains_key(field)) {
            return Err(ERR_RESULT_INVALID);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "context_digest_result_check_tests.rs"]
mod tests;
