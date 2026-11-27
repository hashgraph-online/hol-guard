//! BP-T065: the site scope a browser MCP call is filed and looked up under,
//! and the order its grants are tried in.
//!
//! A queued browser call's intent is filed with what site grants key on: the
//! driver identity hash from the per-driver schema ledger
//! (`browser_driver_ledger.rs`) and the element and input of the projected
//! action. The policy flow reads the same facts for the call it decides, so a
//! grant picked on the card is looked up under the selector it was filed under.
//!
//! Lookups follow PRD 5.5: `session-site`, `site-category`, `site`,
//! `site-group`, then the legacy `exact`, `category` and `server` selectors,
//! and the first allow wins. Each target keeps its own eligibility
//! (`browser_grant_eligibility.rs`), so a shared-profile call reaches
//! `session-site` and nothing else.
//!
//! The ledger lives in the Guard home, so the resident answers the
//! `browser_driver_scope` need itself and never hands it to a caller. Without
//! a home, or for a call no first-party profile maps, the answer is no driver
//! identity and no site grant applies.

use std::path::Path;
use std::time::Duration;

use guard_command::browser_action_project::{
    project_screened_browser_action, BrowserProjection, BrowserProjectionContext,
};
use guard_command::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};
use guard_command::browser_first_party_drivers::{
    first_party_browser_drivers, first_party_profile_digest,
};
use guard_command::mcp_arguments::mcp_safe_arguments;
use guard_contracts::{BrowserAutomationIntentV1, McpToolArgumentsV1, McpToolPolicySubjectV1};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::browser_driver_ledger::{
    covering_driver_hash, observe_driver_tool, DriverGrantScope, DriverIdentity, DriverToolCall,
};
use crate::browser_grant_eligibility::{grant_tier, surface_clean};
use crate::browser_session_schema::{ensure_browser_session_schema, is_digest};
use crate::browser_site_grant::{site_scope, site_selector, site_targets};
use crate::local_store_read::STORE_FILE_NAME;
use crate::mcp_tool_policy_flow::{Ctx, Flow, Phase, Stop, ERR_OBSERVATION};
use crate::mcp_tool_policy_grants::{category_for, grant_selectors};

pub(crate) const NEED_KIND: &str = "browser_driver_scope";
const BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const CALL_FIELDS: [&str; 6] = [
    "profile_id",
    "profile_digest",
    "server_name",
    "server_identity_hash",
    "tool_name",
    "schema_hash",
];

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    fields
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The ledger keeps a schema hash as a lowercase hex digest. Any other text is
/// digested, so a changed schema still reads as changed.
fn ledger_schema_hash(schema: &str) -> String {
    if is_digest(schema) {
        schema.to_owned()
    } else {
        guard_policy_snapshot::digest_bytes(schema.as_bytes())
    }
}

/// The `browser_driver_scope` need for a filed intent, or `None` when no
/// first-party profile matches its server or the intent names no server
/// identity. The need carries whether the profile maps the tool.
pub(crate) fn need(phase: &str, intent: &Map<String, Value>) -> Option<Value> {
    let server_name = text(intent, "mcp_server_name")?;
    let tool_name = text(intent, "mcp_tool_name")?;
    let server_identity_hash = text(intent, "mcp_server_identity_hash")?;
    let call = BrowserToolCallIdentity {
        harness_tool_name: tool_name,
        mcp_server_name: Some(server_name),
        mcp_tool_name: Some(tool_name),
        package: None,
    };
    let matched = match_browser_driver(first_party_browser_drivers(), &call)?;
    let profile_digest = first_party_profile_digest(&matched.driver.id)?;
    Some(json!({
        "kind": NEED_KIND,
        "phase": phase,
        "profile_id": matched.driver.id,
        "profile_digest": profile_digest,
        "server_name": server_name,
        "server_identity_hash": server_identity_hash,
        "tool_name": tool_name,
        "profiled": !matched.is_unclassified(),
        "schema_hash": text(intent, "mcp_schema_hash").map(ledger_schema_hash),
    }))
}

/// The driver and tool call `need` names, or `None` when it is malformed.
fn parts(need: &Map<String, Value>) -> Option<(DriverIdentity<'_>, DriverToolCall<'_>)> {
    let field = |key| need.get(key).and_then(Value::as_str);
    let [profile_id, profile_digest, server_name, server_identity_hash, tool_name, schema_hash] =
        CALL_FIELDS.map(field);
    let identity = DriverIdentity {
        profile_id: profile_id?,
        profile_digest: profile_digest?,
        mcp_server_name: server_name?,
        server_identity_hash: server_identity_hash?,
    };
    let call = DriverToolCall {
        tool_name: tool_name?,
        profiled: need.get("profiled").and_then(Value::as_bool)?,
        schema_hash,
    };
    Some((identity, call))
}

/// Records the call of `need` in the ledger and returns the hash its grants
/// are filed under. `None` when no grant may cover it: an unprofiled tool,
/// a malformed identity or a store that cannot be read or written.
fn observe(connection: &Connection, need: &Map<String, Value>) -> Option<String> {
    let (identity, call) = parts(need)?;
    ensure_browser_session_schema(connection).ok()?;
    match observe_driver_tool(connection, &identity, &call).ok()? {
        DriverGrantScope::Covered {
            driver_identity_hash,
            ..
        }
        | DriverGrantScope::IdentityOnly {
            driver_identity_hash,
        } => Some(driver_identity_hash),
        DriverGrantScope::Unprofiled => None,
    }
}

/// The hash a grant covering the call of `need` is filed under, read without
/// writing. A tool the ledger has not recorded with this schema hash, or a
/// store without the ledger, answers `None`; filing the call records it.
fn covering(connection: &Connection, need: &Map<String, Value>) -> Option<String> {
    let (identity, call) = parts(need)?;
    covering_driver_hash(connection, &identity, &call).ok()?
}

fn open(guard_home: &Path) -> Option<Connection> {
    let connection = Connection::open(guard_home.join(STORE_FILE_NAME)).ok()?;
    connection.busy_timeout(BUSY_TIMEOUT).ok()?;
    Some(connection)
}

/// The resident's answer to a `browser_driver_scope` need, or `None` for any
/// other need. An open `connection` is a decision's read snapshot, so it is
/// only read (`covering`). Otherwise the store under `guard_home` is opened
/// and the call recorded (`observe`). With neither, the call has no driver
/// identity.
pub(crate) fn answer(
    connection: Option<&Connection>,
    guard_home: Option<&Path>,
    need: &Value,
) -> Option<Value> {
    let need = need.as_object()?;
    if need.get("kind").and_then(Value::as_str) != Some(NEED_KIND) {
        return None;
    }
    let hash = match (connection, guard_home) {
        (Some(connection), _) => covering(connection, need),
        (None, Some(home)) => open(home).and_then(|connection| observe(&connection, need)),
        (None, None) => None,
    };
    Some(json!({ "driver_identity_hash": hash }))
}

/// Whether the filed `intent` names the driver identity hash the ledger in
/// `connection` currently files grants under. Read only; a retired hash, a
/// tool the ledger has not recorded or a store without the ledger is not.
pub(crate) fn is_current_driver(connection: &Connection, intent: &Value) -> bool {
    let filed = intent.get("driver_identity_hash").and_then(Value::as_str);
    let current = intent
        .as_object()
        .and_then(|fields| need("file", fields))
        .and_then(|need| covering(connection, need.as_object()?));
    filed.is_some() && filed == current.as_deref()
}

/// The driver identity hash for a filed intent, opening the store under
/// `guard_home`. Used where the relay files a queued call.
pub(crate) fn driver_identity_hash(guard_home: &Path, intent: &Value) -> Option<String> {
    let need = need("file", intent.as_object()?)?;
    let answered = answer(None, Some(guard_home), &need)?;
    answered["driver_identity_hash"].as_str().map(str::to_owned)
}

pub(crate) fn arguments_map(arguments: &McpToolArgumentsV1) -> Map<String, Value> {
    match arguments {
        McpToolArgumentsV1::Mapping { entries } => entries.iter().cloned().collect(),
        McpToolArgumentsV1::Json { text } => match serde_json::from_str(text) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        },
        McpToolArgumentsV1::Other { value } => value.as_object().cloned().unwrap_or_default(),
    }
}

/// The element and input of the projected action, in the shape the
/// eligibility check reads. `None` when no first-party profile classifies it.
fn surface_facts(
    intent: &Map<String, Value>,
    arguments: &Map<String, Value>,
    harness: &str,
) -> Option<(Option<Value>, Option<Value>)> {
    let tool_name = text(intent, "mcp_tool_name")?;
    let call = BrowserToolCallIdentity {
        harness_tool_name: tool_name,
        mcp_server_name: text(intent, "mcp_server_name"),
        mcp_tool_name: Some(tool_name),
        package: None,
    };
    let matched = match_browser_driver(first_party_browser_drivers(), &call)?;
    let context = BrowserProjectionContext {
        harness,
        ..BrowserProjectionContext::default()
    };
    let BrowserProjection::Classified(action) =
        project_screened_browser_action(&matched, arguments, &Map::new(), &context)
    else {
        return None;
    };
    let element = action.element.map(
        |element| json!({"is_password": element.is_password, "is_payment": element.is_payment}),
    );
    let input = action
        .input
        .map(|input| json!({"preview_class": input.preview_class}));
    Some((element, input))
}

/// `intent` with the site-scope facts added. A driver hash is added only when
/// known; a call the profile cannot classify is marked unclean, so no site
/// grant covers it.
pub(crate) fn scoped_intent(
    intent: &Value,
    driver_identity_hash: Option<&str>,
    arguments: &Map<String, Value>,
    harness: &str,
) -> Value {
    let Some(fields) = intent.as_object() else {
        return intent.clone();
    };
    let mut scoped = fields.clone();
    if let Some(hash) = driver_identity_hash {
        scoped.insert("driver_identity_hash".to_owned(), json!(hash));
    }
    match surface_facts(fields, arguments, harness) {
        Some((element, input)) => {
            if let Some(element) = element {
                scoped.insert("element".to_owned(), element);
            }
            if let Some(input) = input {
                scoped.insert("input".to_owned(), input);
            }
        }
        None => {
            scoped.insert("element".to_owned(), json!("unclassified"));
        }
    }
    Value::Object(scoped)
}

/// The site selectors a scoped intent may be covered by, in PRD 5.5 order.
pub(crate) fn site_grant_selectors<S: AsRef<str>>(scoped: &Value, risks: &[S]) -> Vec<String> {
    let Some(fields) = scoped.as_object() else {
        return Vec::new();
    };
    let Some(category) = text(fields, "intent").and_then(category_for) else {
        return Vec::new();
    };
    let (Some(tier), Some(scope)) = (grant_tier(category, risks), site_scope(scoped)) else {
        return Vec::new();
    };
    let clean = surface_clean(fields);
    site_targets(&scope)
        .into_iter()
        .filter(|target| tier.allows(target, clean))
        .filter_map(|target| site_selector(&scope, target, category))
        .collect()
}

/// The filed form of a normalized intent: the masked projection the relay
/// stores on a queued call.
pub(crate) fn filed_intent(intent: &BrowserAutomationIntentV1) -> Option<Value> {
    mcp_safe_arguments(&serde_json::to_value(intent).ok()?).ok()
}

/// Every grant selector the policy flow tries for a held call, in PRD 5.5
/// order: the site selectors, then `exact`, `category` and `server`.
pub(crate) fn selectors_in_order(
    ctx: &Ctx,
    phase: Phase,
    subject: &McpToolPolicySubjectV1,
    intent: Option<&BrowserAutomationIntentV1>,
    risks: &[String],
) -> Flow<Vec<String>> {
    let mut selectors = site_selectors_for(ctx, phase, subject, intent, risks)?;
    selectors.extend(grant_selectors(
        intent,
        risks,
        &subject.artifact_id,
        &subject.artifact_hash,
    ));
    Ok(selectors)
}

/// The site selectors, tried before the legacy ones. The driver identity
/// comes from the resident's ledger through a need; with no identity the
/// list is empty.
fn site_selectors_for(
    ctx: &Ctx,
    phase: Phase,
    subject: &McpToolPolicySubjectV1,
    intent: Option<&BrowserAutomationIntentV1>,
    risks: &[String],
) -> Flow<Vec<String>> {
    let Some(filed) = intent.and_then(filed_intent) else {
        return Ok(Vec::new());
    };
    let Some(need) = filed
        .as_object()
        .and_then(|fields| need(phase.as_str(), fields))
    else {
        return Ok(Vec::new());
    };
    let answered = ctx.ask(need)?;
    let hash = match answered.get("driver_identity_hash") {
        Some(Value::String(hash)) => hash.as_str(),
        Some(Value::Null) => return Ok(Vec::new()),
        _ => return Err(Stop::Fail(ERR_OBSERVATION)),
    };
    let arguments = arguments_map(&subject.arguments);
    let scoped = scoped_intent(&filed, Some(hash), &arguments, &subject.harness);
    Ok(site_grant_selectors(&scoped, risks))
}

#[cfg(test)]
#[path = "browser_grant_scope_tests.rs"]
mod tests;
