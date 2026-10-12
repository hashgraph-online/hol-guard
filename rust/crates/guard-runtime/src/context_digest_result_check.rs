//! Result-contract gate for the context-digest op.
//!
//! The resident used to emit whatever it computed and the Python transport
//! re-validated every field's shape and vocabulary before trusting it. The
//! check lives here now, in front of the encoder: a result that breaks the
//! contract never leaves the resident, so the caller sees a resident error
//! envelope (which it records against the breaker) instead of an unchecked
//! answer. Python keeps only the request binding (schema, request id, request
//! digest, status/code pairing), which only the requester can verify.

use guard_contracts::{ContextDigestKindV1 as Kind, APPROVAL_CONTEXT_TOKEN_PREFIX};
use serde_json::{Map, Value};

pub(crate) const ERR_RESULT_INVALID: &str = "native_context_digest_result_invalid";

const RISK_CATEGORIES: [&str; 15] = [
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "outbound_network",
    "privileged_system_mutation",
    "secret_access",
    "tool_schema_mismatch",
    "browser_navigation",
    "browser_inspection",
    "browser_interaction",
    "browser_transfer",
    "browser_privileged",
    "browser_external_domain",
    "browser_shared_profile",
    "browser_sensitive_surface",
];
const POLICY_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const POLICY_SOURCES: [&str; 4] = ["heuristic", "browser-routine", "policy", "risk-policy"];
const POLICY_SUMMARY_CODES: [&str; 3] = ["no_risk", "risk", "configuration_stricter"];
const SERVER_DESCRIPTOR_STRINGS: [&str; 9] = [
    "argsHash",
    "command",
    "commandHash",
    "configPath",
    "envValuesHash",
    "identityHash",
    "packageSource",
    "transport",
    "transportHash",
];
const SERVER_DESCRIPTOR_OPTIONAL: [&str; 4] = [
    "dependencyHash",
    "packageName",
    "packageVersion",
    "publisherStableId",
];
const SERVER_DESCRIPTOR_HASHES: [&str; 5] = [
    "argsHash",
    "commandHash",
    "envValuesHash",
    "identityHash",
    "transportHash",
];
const TOOL_DESCRIPTOR_STRINGS: [&str; 4] = ["hashScope", "identityHash", "serverHash", "toolName"];
const TOOL_DESCRIPTOR_OPTIONAL: [&str; 3] = ["descriptionHash", "descriptorHash", "schemaHash"];

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
        Kind::ValidateApprovalContext { .. } => "validate_approval_context",
        Kind::ConfiguredEnvironmentHash { .. } => "configured_environment_hash",
        Kind::ConfiguredHeadersHash { .. } => "configured_headers_hash",
        Kind::LaunchArgvDigest { .. } => "launch_argv_digest",
        Kind::CanonicalSha256 { .. } => "canonical_sha256",
        Kind::OpaqueMaterialDigest { .. } => "opaque_material_digest",
        Kind::McpArgumentsProjection { .. } => "mcp_arguments_projection",
        Kind::McpRedactJson { .. } => "mcp_redact_json",
        Kind::PackageEnvironmentPolicy { .. } => "package_environment_policy",
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
        Kind::McpServerDescriptor { .. } => "mcp_server_descriptor",
        Kind::McpToolDescriptor { .. } => "mcp_tool_descriptor",
        Kind::McpToolContentDigest { .. } => "mcp_tool_content_digest",
        Kind::BrowserMcp { .. } => "browser_mcp",
        Kind::McpToolRisk { .. } => "mcp_tool_risk",
        Kind::McpToolPolicy { .. } => "mcp_tool_policy",
        Kind::BuildMcpToolApprovalHash { .. } => "build_mcp_tool_approval_hash",
        Kind::McpToolApprovalDigest { .. } => "mcp_tool_approval_digest",
        Kind::PackageLauncherToken { .. } => "package_launcher_token",
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
        | "opaque_material_digest"
        | "mcp_tool_content_digest" => "digest",
        "package_environment_policy" => "environment_values",
        "mcp_server_identity" => "mcp_server_identity",
        "mcp_tool_identity" => "mcp_tool_identity",
        "mcp_server_descriptor" | "mcp_tool_descriptor" => "mcp_descriptor",
        "browser_mcp" => "browser_mcp",
        "package_launcher_token" => "package_launcher",
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
        "validate_approval_context" | "validate_approval_context_tokens" => "validation_reason",
        "package_execution_context_from_evidence"
        | "package_execution_context_from_scanner_evidence" => "package_context",
        "mcp_tool_risk" => "mcp_tool_risk",
        "mcp_tool_policy" => "mcp_tool_policy",
        "build_mcp_tool_approval_hash" => "mcp_tool_risk",
        "local_cli_identify" => "local_cli_identities",
        _ => return None,
    })
}

/// Fields that only make sense for exactly one request kind.
const KIND_GATED_FIELDS: [(&str, &str); 8] = [
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

fn is_optional_sha256(value: &Value) -> bool {
    value.is_null() || is_sha256(value)
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

fn known_risk_categories(value: &Value) -> bool {
    let Value::Array(items) = value else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    items.iter().all(|item| {
        item.as_str()
            .is_some_and(|text| RISK_CATEGORIES.contains(&text) && seen.insert(text))
    })
}

fn valid_policy(policy: &Value) -> bool {
    let Value::Object(map) = policy else {
        return false;
    };
    map.len() == 4
        && map
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|text| POLICY_ACTIONS.contains(&text))
        && map
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|text| POLICY_SOURCES.contains(&text))
        && map
            .get("summary_code")
            .and_then(Value::as_str)
            .is_some_and(|text| POLICY_SUMMARY_CODES.contains(&text))
        && map
            .get("risk_categories")
            .is_some_and(known_risk_categories)
}

fn exact_keys(map: &Map<String, Value>, groups: &[&[&str]]) -> bool {
    let expected: usize = groups.iter().map(|group| group.len()).sum();
    map.len() == expected
        && groups
            .iter()
            .all(|group| group.iter().all(|key| map.contains_key(*key)))
}

fn valid_descriptor(kind: &str, descriptor: &Value) -> bool {
    let Value::Object(map) = descriptor else {
        return false;
    };
    let strings_ok = |keys: &[&str]| keys.iter().all(|key| map[*key].is_string());
    let optional_strings_ok = |keys: &[&str]| {
        keys.iter()
            .all(|key| map[*key].is_null() || map[*key].is_string())
    };
    match kind {
        "mcp_server_descriptor" => {
            if !exact_keys(
                map,
                &[
                    &SERVER_DESCRIPTOR_STRINGS,
                    &SERVER_DESCRIPTOR_OPTIONAL,
                    &["envKeys"],
                ],
            ) {
                return false;
            }
            let publisher_ok = match &map["publisherStableId"] {
                Value::Null => true,
                Value::String(text) => text
                    .strip_prefix("publisher:")
                    .is_some_and(|rest| is_sha256(&Value::String(rest.to_owned()))),
                _ => false,
            };
            strings_ok(&SERVER_DESCRIPTOR_STRINGS)
                && optional_strings_ok(&SERVER_DESCRIPTOR_OPTIONAL)
                && SERVER_DESCRIPTOR_HASHES
                    .iter()
                    .all(|key| is_sha256(&map[*key]))
                && is_optional_sha256(&map["dependencyHash"])
                && map["envKeys"]
                    .as_array()
                    .is_some_and(|keys| keys.iter().all(Value::is_string))
                && publisher_ok
        }
        "mcp_tool_descriptor" => {
            exact_keys(map, &[&TOOL_DESCRIPTOR_STRINGS, &TOOL_DESCRIPTOR_OPTIONAL])
                && strings_ok(&TOOL_DESCRIPTOR_STRINGS)
                && optional_strings_ok(&TOOL_DESCRIPTOR_OPTIONAL)
                && is_sha256(&map["identityHash"])
                && TOOL_DESCRIPTOR_OPTIONAL
                    .iter()
                    .all(|key| is_optional_sha256(&map[*key]))
                && matches!(map["hashScope"].as_str(), Some("full" | "manifest"))
        }
        _ => false,
    }
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
    if let Some(values) = present(payload, "environment_values") {
        let Value::Object(map) = values else {
            return false;
        };
        if !map.values().all(is_optional_sha256) {
            return false;
        }
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
    if present(payload, "mcp_descriptor")
        .is_some_and(|descriptor| !valid_descriptor(kind, descriptor))
    {
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
    if present(payload, "mcp_tool_risk").is_some_and(|categories| {
        !matches!(kind, "mcp_tool_risk" | "build_mcp_tool_approval_hash")
            || !known_risk_categories(categories)
    }) {
        return false;
    }
    if present(payload, "mcp_tool_policy")
        .is_some_and(|policy| kind != "mcp_tool_policy" || !valid_policy(policy))
    {
        return false;
    }
    KIND_GATED_FIELDS
        .iter()
        .all(|(field, owner)| !payload.contains_key(*field) || kind == *owner)
}

/// Outputs the callers consume without re-checking: a digest is a SHA-256 hex
/// string and an approval token carries the versioned prefix.
fn composed_output_valid(kind: &str, payload: &Map<String, Value>) -> bool {
    match kind {
        "build_mcp_tool_approval_hash" => {
            let token = payload.get("token").filter(|value| !value.is_null());
            let digest = payload.get("digest").filter(|value| !value.is_null());
            (token.is_some() || digest.is_some())
                && token.is_none_or(|value| {
                    value
                        .as_str()
                        .is_some_and(|text| text.starts_with(APPROVAL_CONTEXT_TOKEN_PREFIX))
                })
                && digest.is_none_or(is_sha256)
        }
        "mcp_arguments_projection" => {
            payload.get("digest").is_some_and(is_sha256)
                && payload
                    .get("mcp_launch_target")
                    .is_some_and(Value::is_string)
                && payload
                    .get("mcp_serialized_arguments")
                    .is_some_and(Value::is_string)
                && payload.contains_key("mcp_safe_arguments")
        }
        _ => true,
    }
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
        if !composed_output_valid(kind, map) {
            return Err(ERR_RESULT_INVALID);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "context_digest_result_check_tests.rs"]
mod tests;
