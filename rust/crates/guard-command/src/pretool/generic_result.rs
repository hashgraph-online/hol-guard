use guard_contracts::{
    PreToolActionTypeV1, PreToolActionV1, PreToolOperationV1, PreToolResultV1,
    PRE_TOOL_ACTION_V1_SCHEMA, PRE_TOOL_RESULT_V1_SCHEMA,
};

use super::extract::GenericExtractionError;

fn bounded_identity(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        trimmed.to_owned()
    } else {
        "unknown".to_owned()
    }
}

pub(super) fn generic_action(
    harness: &str,
    event: &str,
    action_type: PreToolActionTypeV1,
    operation: PreToolOperationV1,
    bounded: bool,
    sensitive_target: bool,
) -> PreToolActionV1 {
    PreToolActionV1 {
        schema: PRE_TOOL_ACTION_V1_SCHEMA.to_owned(),
        version: 1,
        harness: bounded_identity(harness),
        event: bounded_identity(event),
        action_type,
        operation,
        bounded,
        sensitive_target,
    }
}

pub(super) fn generic_result(
    action: PreToolActionV1,
    minimum_action: &str,
    reason_code: &str,
    reason: &str,
) -> PreToolResultV1 {
    let explicitly_benign = minimum_action == "allow";
    PreToolResultV1 {
        schema: PRE_TOOL_RESULT_V1_SCHEMA.to_owned(),
        version: 1,
        authority: "rust".to_owned(),
        action,
        decision: if explicitly_benign { "allow" } else { "deny" }.to_owned(),
        policy_action: minimum_action.to_owned(),
        minimum_action: minimum_action.to_owned(),
        reason_code: reason_code.to_owned(),
        reason: reason.to_owned(),
        explicitly_benign,
    }
}

pub(super) fn generic_error_result(
    harness: &str,
    event: &str,
    error: GenericExtractionError,
) -> PreToolResultV1 {
    let (reason_code, reason) = match error {
        GenericExtractionError::Malformed => (
            "native_pre_tool_malformed_payload",
            "HOL Guard blocked this malformed PreToolUse payload before execution.",
        ),
        GenericExtractionError::Ambiguous => (
            "native_pre_tool_ambiguous_payload",
            "HOL Guard blocked this ambiguous PreToolUse payload before execution.",
        ),
        GenericExtractionError::Bounds => (
            "native_pre_tool_bounds_exceeded",
            "HOL Guard blocked this oversized PreToolUse payload before execution.",
        ),
    };
    generic_result(
        generic_action(
            harness,
            event,
            PreToolActionTypeV1::Unknown,
            PreToolOperationV1::Unknown,
            false,
            false,
        ),
        "block",
        reason_code,
        reason,
    )
}

pub(super) fn review_reason(action_type: PreToolActionTypeV1) -> (&'static str, &'static str) {
    match action_type {
        PreToolActionTypeV1::FileRead => (
            "native_file_read_review",
            "HOL Guard requires review before this file action can execute.",
        ),
        PreToolActionTypeV1::FileWrite => (
            "native_file_write_review",
            "HOL Guard requires review before this file mutation can execute.",
        ),
        PreToolActionTypeV1::Package => (
            "native_package_review",
            "HOL Guard requires review before this package action can execute.",
        ),
        PreToolActionTypeV1::McpTool => (
            "native_mcp_tool_review",
            "HOL Guard requires review before this MCP tool can execute.",
        ),
        PreToolActionTypeV1::Network => (
            "native_network_review",
            "HOL Guard requires review before this network action can execute.",
        ),
        PreToolActionTypeV1::ProcessService => (
            "native_process_service_review",
            "HOL Guard requires review before this process or service action can execute.",
        ),
        PreToolActionTypeV1::Browser => (
            "native_browser_review",
            "HOL Guard requires review before this browser action can execute.",
        ),
        PreToolActionTypeV1::Config => (
            "native_config_review",
            "HOL Guard requires review before this configuration action can execute.",
        ),
        PreToolActionTypeV1::Prompt => (
            "native_prompt_review",
            "HOL Guard requires review before this prompt action can execute.",
        ),
        PreToolActionTypeV1::Harness => (
            "native_harness_review",
            "HOL Guard requires review before this harness action can execute.",
        ),
        PreToolActionTypeV1::Command => (
            "native_command_review_required",
            "HOL Guard requires review because the Rust authority could not prove this command explicitly benign.",
        ),
        PreToolActionTypeV1::Unknown => (
            "native_pre_tool_unknown_review",
            "HOL Guard requires review because this PreToolUse action is not yet supported for automatic allow.",
        ),
    }
}
