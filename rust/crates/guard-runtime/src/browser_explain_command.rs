//! The `browser-explain` command behind `hol-guard browser explain` (BP-T052).
//!
//! One request names a shipped driver profile, one of its tools and example arguments. The answer
//! is the `BrowserActionV2` the profile projects, the decision Guard's default policy gives the
//! call, and whether a temporary browser grant could ever cover it. Nothing is written, and no saved
//! approval, grant or setting is read, so the answer describes the shipped rules, not this device's
//! saved choices. The one device fact it reads is which loopback port Guard's own daemon answers
//! on: a call aimed at Guard's approval center is blocked here exactly as it is at runtime.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use guard_command::browser_action_project::{
    project_screened_browser_action, BrowserProjection, BrowserProjectionContext,
    BrowserUnclassifiedReason,
};
use guard_command::browser_driver_compile::CompiledBrowserDriverV1;
use guard_command::browser_driver_match::{BrowserDriverMatch, BrowserDriverMatchKind};
use guard_command::browser_first_party_drivers::first_party_browser_drivers;
use guard_command::mcp_tool_policy::evaluate_tool_policy;
use guard_contracts::{BrowserMcpArtifactV1, McpToolArgumentsV1, McpToolPolicyRequestV1};

use crate::mcp_tool_policy_grants::{grant_category, normalized_browser_intent, risks_allow_grant};

pub(crate) const COMMAND: &str = "browser-explain";

/// The harness name the explanation is evaluated under. No harness setting changes a browser
/// decision under the default policy, so the name is only a label.
const EXPLAIN_HARNESS: &str = "explain";

/// The settings a fresh Guard home starts with (`GuardConfig` defaults): prompt mode, the balanced
/// security level and a `warn` default action.
fn default_config() -> Map<String, Value> {
    let mut config = Map::new();
    config.insert("mode".to_owned(), json!("prompt"));
    config.insert("security_level".to_owned(), json!("balanced"));
    config.insert("default_action".to_owned(), json!("warn"));
    config
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    driver: String,
    tool: String,
    /// Omitted means no arguments; an explicit `null` or any other non-object is refused.
    #[serde(default = "no_arguments")]
    arguments: Value,
}

fn no_arguments() -> Value {
    Value::Object(Map::new())
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("request_invalid", "The request was not understood.");
    };
    explain(first_party_browser_drivers(), &request)
}

fn explain(drivers: &[CompiledBrowserDriverV1], request: &Request) -> Value {
    let Some(driver) = drivers.iter().find(|driver| driver.id == request.driver) else {
        let known: Vec<&str> = drivers.iter().map(|driver| driver.id.as_str()).collect();
        return json!({
            "ok": false,
            "error": {"code": "driver_unknown", "message": "No shipped driver profile has that id."},
            "drivers": known,
        });
    };
    let tool = request.tool.trim();
    if tool.is_empty() {
        return refusal("tool_missing", "Name the tool to explain.");
    }
    let arguments = match &request.arguments {
        Value::Object(object) => object.clone(),
        _ => return refusal("arguments_invalid", "The arguments must be a JSON object."),
    };
    let server = driver
        .matches
        .mcp_server_names
        .first()
        .cloned()
        .unwrap_or_else(|| driver.id.clone());
    let matched = BrowserDriverMatch {
        driver,
        kind: BrowserDriverMatchKind::McpServerName,
        tool_name: tool,
        tool: driver.tools.get(tool),
    };
    let context = BrowserProjectionContext {
        harness: EXPLAIN_HARNESS,
        ..BrowserProjectionContext::default()
    };
    let projection = project_screened_browser_action(&matched, &arguments, &Map::new(), &context);
    let mut metadata = Map::new();
    metadata.insert("server_name".to_owned(), json!(server));
    metadata.insert("mcp_tool_identity".to_owned(), json!({"tool_name": tool}));
    let artifact = BrowserMcpArtifactV1 {
        name: format!("{server}:{tool}"),
        command: Some(tool.to_owned()),
        metadata,
    };
    let arguments = Value::Object(arguments);
    // Grant eligibility reads the normalized intent, exactly as the runtime grant path does; the
    // projected action can be stricter (a `javascript:` navigation projects as privileged).
    let entries = McpToolArgumentsV1::Mapping {
        entries: arguments
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default(),
    };
    let intent = match normalized_browser_intent(&artifact, &entries) {
        Ok(intent) => intent,
        Err(code) => return refusal(code, "The call could not be normalized."),
    };
    let policy = evaluate_tool_policy(&McpToolPolicyRequestV1 {
        artifact,
        arguments,
        config: default_config(),
        harness: EXPLAIN_HARNESS.to_owned(),
        artifact_id: format!("{}:{tool}", driver.id),
        publisher: None,
    });
    let policy = match policy {
        Ok(policy) => policy,
        Err(code) => return refusal(code, "The default policy could not evaluate the call."),
    };
    let (action, unclassified) = match &projection {
        BrowserProjection::Classified(action) => (Some(action.as_ref()), None),
        BrowserProjection::Unclassified { reason, .. } => (None, Some(reason)),
    };
    let category = intent.as_ref().and_then(grant_category);
    let grant_eligible =
        category.is_some_and(|category| risks_allow_grant(category, &policy.risk_categories));
    json!({
        "ok": true,
        "driver": {"id": driver.id, "name": driver.name, "server": server},
        "tool": tool,
        "action": action,
        "unclassified": unclassified.map(|reason| match reason {
            BrowserUnclassifiedReason::ToolNotListed => "tool_not_listed",
            BrowserUnclassifiedReason::CaseNotListed => "case_not_listed",
        }),
        "decision": {
            "action": policy.action,
            "source": policy.source,
            "summaryCode": policy.summary_code,
        },
        "riskCategories": policy.risk_categories,
        "grant": {"eligible": grant_eligible, "category": category},
    })
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

#[cfg(test)]
#[path = "browser_explain_command_tests.rs"]
mod tests;
