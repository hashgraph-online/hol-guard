//! Guard Cloud command-pattern Allow rules at the hook edge.
//!
//! An exact-command Allow ([`crate::edge_exact_command_allow`]) matches only
//! the text a person approved, so the next call with a different PR number or
//! branch was held again. A Guard Cloud rule may instead allow a pattern such
//! as `gh pr view * --repo owner/name`. The pattern compiles to no saved row;
//! the hook reads it from the cached signed bundle it was published in, so a
//! bundle Guard cannot validate, or one that no longer carries the rule,
//! allows nothing.
//!
//! The pattern settles a review within the same limits as an exact Allow: only
//! a liftable review of a bounded shell action that touches no sensitive
//! target, after the caller found no block or review rule under any spelling
//! of the command. It also applies only when every spelling the hook received
//! is one simple command whose program is the one the pattern names
//! ([`guard_command::command_pattern_allow`]), so a wildcard never covers a
//! second command chained, piped or substituted into the first.

use guard_command::command_pattern_allow::{allows, parse_allow_pattern, CommandPatternAllow};
use guard_contracts::PreToolResultV1;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::claim_reuse_binding::{local_device, sync_state_payload};
use crate::edge_exact_command_allow::liftable;
use crate::policy_bundle_store_identities::{device_display_name, validated_synced_bundle};
use crate::policy_decision_lookup_op::{normalized_workspace_path, workspace_policy_key};

const POLICY_PATTERN_ALLOW: &str = "policy_command_pattern_allow";
const POLICY_PATTERN_ALLOW_REASON: &str = "Your Guard Cloud policy allows this command pattern.";
/// `contractVersion` of a canonical (v2) policy bundle, the only contract a
/// command pattern is published in.
const CANONICAL_CONTRACT: &str = "guard-policy-bundle.v2";
const COMPILE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One pattern Allow a signed bundle applies to this device.
#[derive(Debug, Clone)]
pub(crate) struct BundlePattern {
    /// `None` applies to every harness.
    pub(crate) harnesses: Option<Vec<String>>,
    /// `None` applies in every folder.
    pub(crate) workspaces: Option<Vec<String>>,
    pub(crate) expires_at: Option<String>,
    pub(crate) pattern: CommandPatternAllow,
}

/// The pattern Allow rules the signed bundle applies at `now`, or `None`
/// when they cannot be derived.
pub(crate) type BundlePatterns = fn(&Connection, &str) -> Option<Vec<BundlePattern>>;

/// The pattern Allow rules of the cached signed bundle for this device, while
/// it is live authority. A bundle without one skips the signature checks.
pub(crate) fn cached_patterns(connection: &Connection, _now: &str) -> Option<Vec<BundlePattern>> {
    let text = sync_state_payload(connection, "policy_bundle").ok()??;
    if !text.contains("\"combinator\"") {
        return Some(Vec::new());
    }
    let Some(bundle) = validated_synced_bundle(connection)? else {
        return Some(Vec::new());
    };
    if bundle.get("contractVersion").and_then(Value::as_str) != Some(CANONICAL_CONTRACT) {
        return Some(Vec::new());
    }
    let (device_id, device_label) = local_device(connection).ok()??;
    let device_name = device_display_name(connection, &device_label)?;
    let input = json!({"bundle": bundle, "device_id": device_id, "device_name": device_name});
    let deadline = std::time::Instant::now() + COMPILE_TIMEOUT;
    let answer =
        guard_command::policy_document::evaluate("command_patterns_bundle", &input, deadline)
            .ok()?;
    answer
        .get("ok")?
        .as_array()?
        .iter()
        .map(parse_pattern)
        .collect()
}

fn parse_pattern(value: &Value) -> Option<BundlePattern> {
    let list = |key: &str| -> Option<Option<Vec<String>>> {
        match value.get(key)? {
            Value::Null => Some(None),
            Value::Array(items) => items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .map(Some),
            _ => None,
        }
    };
    Some(BundlePattern {
        harnesses: list("harnesses")?,
        workspaces: list("workspaces")?,
        expires_at: match value.get("expires_at")? {
            Value::Null => None,
            Value::String(at) => Some(at.clone()),
            _ => return None,
        },
        pattern: parse_allow_pattern(value.get("expression")?).ok()?,
    })
}

/// Settles a liftable review at allow when a live pattern Allow of the signed
/// bundle matches every spelling of the command; any other result, or any
/// read that fails, is returned unchanged.
pub(crate) fn apply(
    connection: &Connection,
    commands: &[&str],
    workspace: Option<&str>,
    now_micros: Option<i64>,
    result: PreToolResultV1,
    patterns: BundlePatterns,
) -> PreToolResultV1 {
    if !liftable(&result) || commands.is_empty() {
        return result;
    }
    let Some(now) = now_micros
        .and_then(|now| crate::policy_bundle_time::micros_to_utc_isoformat(now, "+00:00"))
    else {
        return result;
    };
    let Some(patterns) = patterns(connection, &now) else {
        return result;
    };
    let harness = result.action.harness.as_str();
    let matched = patterns.iter().any(|rule| {
        applies(rule, harness, workspace, now_micros)
            && commands
                .iter()
                .all(|command| allows(&rule.pattern, command))
    });
    if matched {
        settle(result)
    } else {
        result
    }
}

/// Whether `rule` is live for `harness` in `workspace`.
fn applies(
    rule: &BundlePattern,
    harness: &str,
    workspace: Option<&str>,
    now_micros: Option<i64>,
) -> bool {
    if crate::edge_exact_command_review::expired(rule.expires_at.as_deref(), now_micros) {
        return false;
    }
    if let Some(harnesses) = &rule.harnesses {
        if !harnesses.iter().any(|name| name == harness || name == "*") {
            return false;
        }
    }
    let Some(folders) = &rule.workspaces else {
        return true;
    };
    let Some(place) = workspace.filter(|place| !place.trim().is_empty()) else {
        return false;
    };
    let key = workspace_policy_key(Some(place));
    let path = normalized_workspace_path(place);
    folders.iter().any(|folder| {
        key.as_deref() == Some(folder.as_str()) || normalized_workspace_path(folder) == path
    })
}

fn settle(mut result: PreToolResultV1) -> PreToolResultV1 {
    result.policy_action = "allow".into();
    result.minimum_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = POLICY_PATTERN_ALLOW.into();
    result.reason = POLICY_PATTERN_ALLOW_REASON.into();
    result
}

#[cfg(test)]
#[path = "edge_command_pattern_allow_tests.rs"]
mod tests;
