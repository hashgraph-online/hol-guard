//! The grant half of workspace plan validation, and the only reading of it.
//! The workspace sink asks for it through the `workspace_grant_script_roots`
//! operation and carries the answer; it does not check these fields again.
//!
//! A base plan (`workspace-contained-v1`) carries no grant: a null identity
//! hash and no capabilities. A grant plan (`workspace-contained-grant-v1`) is
//! admitted only against the grant the resident decided for this command: the
//! same identity, capabilities that are a canonical subset of the decided
//! ones, and, with a state capability, the CLI state directory as the last
//! read root. What is left of the read roots are the scripts the command
//! launches, which the caller checks as before.

use serde_json::{Map, Value};

use crate::contained_workspace_sink::WORKSPACE_PROFILE as BASE_PROFILE;

pub(crate) const GRANT_PROFILE: &str = "workspace-contained-grant-v1";
const GRANT_CAPABILITIES: [&str; 3] = ["loopback-network", "state-dir-read", "state-dir-write"];

/// The grant the resident decided for the command the plan runs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ExpectedGrant {
    pub(crate) identity_hash: String,
    pub(crate) capabilities: Vec<String>,
    pub(crate) state_dir: Option<String>,
}

fn canonical(items: &[Value]) -> Option<Vec<&str>> {
    let names: Vec<&str> = items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|name| GRANT_CAPABILITIES.contains(name))
        })
        .collect::<Option<_>>()?;
    names
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        .then_some(names)
}

/// The plan's script read roots once its grant fields check out against
/// `expected`; `None` refuses the plan.
pub(crate) fn grant_script_roots(
    plan: &Map<String, Value>,
    expected: Option<&ExpectedGrant>,
) -> Option<Value> {
    let roots = plan.get("read_only_roots")?.as_array()?;
    let capabilities = canonical(plan.get("capabilities")?.as_array()?)?;
    let profile = plan.get("profile_version")?.as_str()?;
    let hash = plan.get("grant_identity_hash")?;
    let Some(expected) = expected else {
        return (profile == BASE_PROFILE && hash.is_null() && capabilities.is_empty())
            .then(|| Value::Array(roots.clone()));
    };
    if profile != GRANT_PROFILE
        || hash.as_str() != Some(expected.identity_hash.as_str())
        || !capabilities
            .iter()
            .all(|name| expected.capabilities.iter().any(|item| item == name))
    {
        return None;
    }
    let stateful = capabilities
        .iter()
        .any(|name| *name == "state-dir-read" || *name == "state-dir-write");
    if !stateful {
        return Some(Value::Array(roots.clone()));
    }
    let (last, scripts) = roots.split_last()?;
    let state = expected.state_dir.as_deref()?;
    (last.as_str() == Some(state)).then(|| Value::Array(scripts.to_vec()))
}

fn refusal() -> Value {
    serde_json::json!({
        "reason_code": "pytest_restricted_invalid_command",
        "message": "Invalid restricted execution request.",
    })
}

fn read_expected(value: &Value) -> Option<ExpectedGrant> {
    let object = value.as_object()?;
    let capabilities = object
        .get("capabilities")?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    let state_dir = match object.get("state_dir") {
        None | Some(Value::Null) => None,
        Some(item) => Some(item.as_str()?.to_owned()),
    };
    Some(ExpectedGrant {
        identity_hash: object.get("identity_hash")?.as_str()?.to_owned(),
        capabilities,
        state_dir,
    })
}

/// The reply the workspace sink reads: the script read roots the plan keeps
/// once its grant fields check out, or a refusal.
///
/// A decided grant the caller cannot spell is refused rather than read as no
/// grant, so a malformed `expected` can never admit a plan as a base one.
pub(crate) fn evaluate(input: &Value) -> Value {
    let Some(plan) = input.get("plan").and_then(Value::as_object) else {
        return refusal();
    };
    let expected = match input.get("expected") {
        None | Some(Value::Null) => None,
        Some(value) => match read_expected(value) {
            Some(grant) => Some(grant),
            None => return refusal(),
        },
    };
    match grant_script_roots(plan, expected.as_ref()) {
        Some(roots) => serde_json::json!({ "value": roots }),
        None => refusal(),
    }
}

#[cfg(test)]
#[path = "contained_workspace_grant_plan_tests.rs"]
mod tests;
