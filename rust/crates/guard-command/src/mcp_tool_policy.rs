//! Current recommendation precedence over raw config, independent of saved approvals.
use crate::browser_loopback_quiet::{loopback_dev_quiet, LoopbackQuietFacts};
use crate::local_supply_chain::{default_risk_action, DEFAULT_SECURITY_LEVEL};
use crate::mcp_tool_risk::evaluate_tool_risk;
use guard_contracts::{
    most_restrictive_of, write_canonical_json_with_limit, write_json_string, GuardAction,
    McpToolApprovalContextRequestV1, McpToolPolicyRequestV1, McpToolPolicyResultV1,
    CONTEXT_COMPONENT_MAX_BYTES,
};
use serde_json::{Map, Value};

fn string<'a>(config: &'a Map<String, Value>, key: &str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or("")
}
fn action<'a>(config: &'a Map<String, Value>, map: &str, key: &str) -> Option<&'a Value> {
    config.get(map)?.as_object()?.get(key)
}
fn normalize(value: Option<&str>) -> GuardAction {
    match value {
        Some("ask") => GuardAction::Review,
        Some(value) => GuardAction::from_canonical(value).unwrap_or(GuardAction::Review),
        None => GuardAction::Review,
    }
}

fn routine_browser(categories: &[String]) -> bool {
    let mut routine = false;
    for category in categories {
        match category.as_str() {
            "browser_navigation" | "browser_inspection" => routine = true,
            "browser_external_domain" => {}
            _ => return false,
        }
    }
    routine
}

fn configured_override<'a>(
    config: &'a Map<String, Value>,
    harness: &str,
    artifact_id: &str,
    publisher: Option<&str>,
) -> Option<&'a Value> {
    action(config, "artifact_actions", artifact_id)
        .or_else(|| publisher.and_then(|publisher| action(config, "publisher_actions", publisher)))
        .filter(|value| !value.is_null())
        .or_else(|| action(config, "harness_actions", harness).filter(|value| !value.is_null()))
}

fn configured_risk<'a>(config: &'a Map<String, Value>, harness: &str) -> Option<&'a Value> {
    config
        .get("harness_risk_actions")
        .and_then(Value::as_object)
        .and_then(|map| map.get(harness))
        .and_then(Value::as_object)
        .and_then(|map| map.get("mcp_dangerous_tool"))
        .or_else(|| action(config, "risk_actions", "mcp_dangerous_tool"))
}

fn risk_default(config: &Map<String, Value>) -> Option<&'static str> {
    let managed_locks_level = config
        .get("managed_locked_settings")
        .and_then(Value::as_array)
        .is_some_and(|settings| {
            settings
                .iter()
                .any(|setting| setting.as_str() == Some("security_level"))
        });
    default_risk_action(
        string(config, "security_level"),
        string(config, "protection_posture"),
        config
            .get("protection_posture_explicit")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        managed_locks_level,
        "mcp_dangerous_tool",
    )
}

/// Keep the default recommendation and its approval-token bytes in sync.
/// Explicit risk overrides are handled by the callers before this exception.
fn balanced_prompt_review(config: &Map<String, Value>) -> bool {
    !config
        .get("protection_posture_explicit")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && string(config, "mode") == "prompt"
        && string(config, "security_level") == DEFAULT_SECURITY_LEVEL
}

/// Render historical approval policy bytes from borrowed inputs, without a policy DTO clone.
pub fn write_tool_policy_context(
    request: &McpToolApprovalContextRequestV1,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    const FIELDS: &[&str] = &[
        "artifact_override",
        "default_action",
        "effective_risk_action",
        "evaluator_policy_version",
        "managed_locked_settings",
        "managed_policy_hash",
        "managed_policy_status",
        "mode",
        "protection_posture",
        "protection_posture_explicit",
        "security_level",
    ];
    let config = &request.config;
    let posture_explicit = config
        .get("protection_posture_explicit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    out.push(b'{');
    let mut first = true;
    for key in FIELDS {
        if key.starts_with("protection_posture") && !posture_explicit {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        write_json_string(key, out);
        out.push(b':');
        let value = match *key {
            "artifact_override" => configured_override(
                config,
                &request.harness,
                &request.artifact_id,
                request.publisher.as_deref(),
            ),
            "effective_risk_action" => {
                if let Some(value) = configured_risk(config, &request.harness) {
                    Some(value)
                } else if let Some(action) = risk_default(config) {
                    let effective = if balanced_prompt_review(config) {
                        "review"
                    } else {
                        action
                    };
                    write_json_string(effective, out);
                    continue;
                } else {
                    None
                }
            }
            "evaluator_policy_version" => {
                write_json_string("mcp-tool-call-evaluation-v5", out);
                continue;
            }
            _ => config.get(*key),
        };
        write_canonical_json_with_limit(
            value.unwrap_or(&Value::Null),
            out,
            CONTEXT_COMPONENT_MAX_BYTES,
            "native_context_component_invalid",
        )?;
    }
    out.push(b'}');
    if out.len() > CONTEXT_COMPONENT_MAX_BYTES {
        return Err("native_context_component_invalid");
    }
    Ok(())
}

/// Whether this call is a routine browser action on a loopback development origin (D10).
fn loopback_dev_quiet_call(request: &McpToolPolicyRequestV1, categories: &[String]) -> bool {
    let Some(facts) =
        crate::browser_mcp_intent::browser_risk_facts(&request.artifact, &request.arguments)
    else {
        return false;
    };
    loopback_dev_quiet(&LoopbackQuietFacts {
        categories,
        target: facts.target.as_deref(),
        profile: facts.profile,
        debugging_ports: &facts.debugging_ports,
    })
}

/// R-SELF: a browser action on Guard's own approval center is blocked. No configured action,
/// grant, saved approval or contributed default changes that.
const GUARD_ORIGIN: &str = "browser_guard_origin";

pub fn evaluate_tool_policy(
    request: &McpToolPolicyRequestV1,
) -> Result<McpToolPolicyResultV1, &'static str> {
    let config = &request.config;
    let categories = evaluate_tool_risk(&request.artifact, &request.arguments)?;
    let configured_action = configured_override(
        config,
        &request.harness,
        &request.artifact_id,
        request.publisher.as_deref(),
    )
    .or_else(|| config.get("default_action"));
    let risk_override = configured_risk(config, &request.harness);
    let explicit = risk_override.filter(|value| !value.is_null());
    if categories.iter().any(|category| category == GUARD_ORIGIN) {
        return Ok(McpToolPolicyResultV1 {
            action: "block".to_owned(),
            source: "browser-guard-origin".to_owned(),
            summary_code: "guard_origin".to_owned(),
            risk_categories: categories,
        });
    }
    if explicit.is_none() && loopback_dev_quiet_call(request, &categories) {
        // D10: quiet with no grant. Only an action the user configured for this artifact,
        // publisher or harness can make it stricter; the global default does not apply.
        let configured = configured_override(
            config,
            &request.harness,
            &request.artifact_id,
            request.publisher.as_deref(),
        )
        .and_then(Value::as_str);
        let action = configured.map_or(GuardAction::Allow, |value| normalize(Some(value)));
        let (source, summary_code) = if action == GuardAction::Allow {
            ("browser-loopback-quiet", "loopback_dev")
        } else {
            ("policy", "configuration_stricter")
        };
        return Ok(McpToolPolicyResultV1 {
            action: action.as_str().to_owned(),
            source: source.to_owned(),
            summary_code: summary_code.to_owned(),
            risk_categories: categories,
        });
    }
    let (raw_action, mut source, mut summary_code) = if categories.is_empty() {
        (Some("allow"), "heuristic", "no_risk")
    } else if explicit.is_none() && routine_browser(&categories) {
        (Some("allow"), "browser-routine", "risk")
    } else {
        let risk_action = match risk_override {
            Some(value) if value.is_null() => None,
            Some(value) => Some(value.as_str()),
            None => risk_default(config).map(Some),
        };
        if let Some(risk_action) = risk_action {
            if explicit.is_none() && balanced_prompt_review(config) {
                (Some("review"), "risk-policy", "risk")
            } else {
                (risk_action, "policy", "risk")
            }
        } else {
            (
                Some(if string(config, "mode") == "prompt" {
                    "review"
                } else {
                    "block"
                }),
                "heuristic",
                "risk",
            )
        }
    };
    let effective = most_restrictive_of(
        normalize(raw_action),
        normalize(configured_action.and_then(Value::as_str)),
    );
    if Some(effective.as_str()) != raw_action {
        source = "policy";
        summary_code = "configuration_stricter";
    }
    Ok(McpToolPolicyResultV1 {
        action: effective.as_str().to_owned(),
        source: source.to_owned(),
        summary_code: summary_code.to_owned(),
        risk_categories: categories,
    })
}

#[cfg(test)]
#[path = "mcp_tool_policy_quiet_tests.rs"]
mod quiet_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_risk_retains_reapproval_except_prompt_review() {
        for (mode, expected) in [("block", "require-reapproval"), ("prompt", "review")] {
            let request: McpToolPolicyRequestV1 = serde_json::from_value(serde_json::json!({
                "artifact": {"name": "workspace:summarize", "command": "summarize", "metadata": {}},
                "arguments": {"cmd": "echo hi"},
                "config": {"mode": mode, "security_level": "balanced", "default_action": "allow"},
                "harness": "codex", "artifact_id": "policy-proof", "publisher": null,
            }))
            .unwrap();
            assert_eq!(evaluate_tool_policy(&request).unwrap().action, expected);
        }
    }

    #[test]
    fn guard_origin_blocks_over_every_configured_action() {
        use crate::browser_guard_origin::tests::{guard_home, with_guard_home};
        let home = guard_home("policy", Some(51234));
        let target = "http://localhost:51234/approvals";
        for config in [
            serde_json::json!({"mode": "prompt", "default_action": "allow"}),
            serde_json::json!({"mode": "block", "security_level": "balanced", "default_action": "allow",
                "risk_actions": {"mcp_dangerous_tool": "allow"}}),
        ] {
            let request: McpToolPolicyRequestV1 = serde_json::from_value(serde_json::json!({
                "artifact": {"name": "playwright:browser_navigate", "command": "browser_navigate",
                    "metadata": {"server_name": "playwright",
                        "mcp_tool_identity": {"tool_name": "browser_navigate"}}},
                "arguments": {"url": target},
                "config": config,
                "harness": "codex", "artifact_id": "guard-origin", "publisher": null,
            }))
            .unwrap();
            let result = with_guard_home(&home.0, || evaluate_tool_policy(&request).unwrap());
            assert_eq!(result.action, "block");
            assert_eq!(result.summary_code, "guard_origin");
            assert!(result
                .risk_categories
                .iter()
                .any(|name| name == GUARD_ORIGIN));
        }
    }

    fn context_bytes(config: Value) -> Vec<u8> {
        let request = McpToolApprovalContextRequestV1 {
            config: config.as_object().unwrap().clone(),
            harness: "codex".to_owned(),
            artifact_id: "policy-proof".to_owned(),
            publisher: None,
            identity: Value::Null,
            content: Value::Null,
            capabilities: Value::Null,
            sandbox: Value::Null,
            extension_control_digest: String::new(),
        };
        let mut bytes = Vec::new();
        write_tool_policy_context(&request, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn implicit_risk_context_matches_balanced_prompt_recommendation() {
        for (mode, expected) in [("block", "require-reapproval"), ("prompt", "review")] {
            let config = serde_json::json!({
                "mode": mode, "security_level": "balanced", "default_action": "allow",
            });
            let policy: Value = serde_json::from_slice(&context_bytes(config.clone())).unwrap();
            let request: McpToolPolicyRequestV1 = serde_json::from_value(serde_json::json!({
                "artifact": {"name": "workspace:summarize", "command": "summarize", "metadata": {}},
                "arguments": {"cmd": "echo hi"}, "config": config,
                "harness": "codex", "artifact_id": "policy-proof", "publisher": null,
            }))
            .unwrap();
            assert_eq!(policy["effective_risk_action"], expected);
            assert_eq!(
                policy["effective_risk_action"],
                evaluate_tool_policy(&request).unwrap().action
            );
            assert!(policy.get("protection_posture_explicit").is_none());
        }
    }

    #[test]
    fn approval_context_preserves_explicit_risk_overrides_and_null() {
        for override_value in [
            serde_json::json!("block"),
            serde_json::json!("warn"),
            Value::Null,
        ] {
            let mut config = serde_json::json!({
                "mode": "prompt", "security_level": "balanced", "default_action": "allow",
                "risk_actions": {"mcp_dangerous_tool": override_value},
            });
            let global: Value = serde_json::from_slice(&context_bytes(config.clone())).unwrap();
            assert_eq!(global["effective_risk_action"], override_value);
            config["harness_risk_actions"] = serde_json::json!({
                "codex": {"mcp_dangerous_tool": "require-reapproval"},
            });
            let harness: Value = serde_json::from_slice(&context_bytes(config)).unwrap();
            assert_eq!(harness["effective_risk_action"], "require-reapproval");
        }
    }

    #[test]
    fn explicit_posture_and_non_default_levels_keep_their_native_defaults() {
        for level in ["balanced", "strict", "paranoid"] {
            for explicit in [false, true] {
                if level == "balanced" && !explicit {
                    continue;
                }
                let config = serde_json::json!({
                    "mode": "prompt", "security_level": level, "default_action": "allow",
                    "protection_posture": "strict", "protection_posture_explicit": explicit,
                });
                let expected = risk_default(config.as_object().unwrap());
                let policy: Value = serde_json::from_slice(&context_bytes(config)).unwrap();
                assert_eq!(policy["effective_risk_action"], serde_json::json!(expected));
                assert_eq!(
                    policy.get("protection_posture_explicit").is_some(),
                    explicit
                );
            }
        }
    }

    #[test]
    fn balanced_prompt_context_uses_canonical_review_bytes() {
        let bytes = context_bytes(serde_json::json!({
            "mode": "prompt", "security_level": "balanced", "default_action": "allow",
        }));
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
            "{\"artifact_override\":null,\"default_action\":\"allow\",",
            "\"effective_risk_action\":\"review\",",
            "\"evaluator_policy_version\":\"mcp-tool-call-evaluation-v5\",",
            "\"managed_locked_settings\":null,\"managed_policy_hash\":null,",
            "\"managed_policy_status\":null,\"mode\":\"prompt\",\"security_level\":\"balanced\"}",
        )
        );
    }
}
