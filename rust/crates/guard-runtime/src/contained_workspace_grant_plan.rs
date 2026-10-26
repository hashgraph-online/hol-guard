//! The grant half of workspace plan validation, mirrored byte for byte by
//! `restricted_workspace_grants.grant_script_roots` in Python and pinned by
//! shared vectors.
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

#[cfg(test)]
#[path = "contained_workspace_grant_plan_tests.rs"]
mod tests;
