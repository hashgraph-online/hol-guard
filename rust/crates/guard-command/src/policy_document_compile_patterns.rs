//! Guard Cloud command-pattern Allow rules in a canonical policy document.
//!
//! A pattern rule compiles to no row: the hook reads it from the signed bundle
//! ([`command_patterns`]) and applies it only to a simple command
//! ([`crate::command_pattern_allow`]).

use std::time::Instant;

use serde_json::{json, Value};

use super::compiler::{compile_effects, error, expiry, selectors, Effects};
use super::Error;

/// Match keys a pattern Allow may carry. The hook enforces only these, so a
/// rule that narrows itself any other way (a repository, a domain, an actor)
/// is refused instead of being applied everywhere.
const PATTERN_MATCH_KEYS: &[&str] = &["commands", "harnesses", "workspaces"];

/// Refuses a `match.commands` object the device cannot apply: anything but an
/// enabled Allow in a bundle with review effects, an invalid pattern, or a
/// selector the hook would drop.
pub(super) fn validate_pattern_rule(rule: &Value, effects: Effects, id: &str) -> Result<(), Error> {
    if effects != Effects::WithReview || rule["effect"] != "allow" {
        return Err(error("command_expression_requires_guard_3_1_runtime", id));
    }
    pattern_selectors(rule, id)?;
    crate::command_pattern_allow::parse_allow_pattern(&rule["match"]["commands"])
        .map_err(|code| error(&code, id))?;
    Ok(())
}

/// The harness and folder selectors of a pattern Allow, after refusing every
/// other non-empty selector.
fn pattern_selectors(rule: &Value, id: &str) -> Result<(Vec<Value>, Vec<Value>), Error> {
    let matcher = &rule["match"];
    let narrowed = matcher
        .as_object()
        .into_iter()
        .flatten()
        .any(|(key, value)| {
            !key.starts_with("x-")
                && !PATTERN_MATCH_KEYS.contains(&key.as_str())
                && !value.is_null()
                && value != &json!([])
        });
    if narrowed {
        return Err(error("unsupported_policy_match", id));
    }
    Ok((
        selectors(matcher, "harnesses", id)?,
        selectors(matcher, "workspaces", id)?,
    ))
}

/// The enabled pattern Allow rules of a signed Cloud bundle document, each as
/// `{rule_id, harnesses, workspaces, expires_at, expression}`, where a null
/// selector list matches every harness or folder. The document must already
/// compile under [`Effects::WithReview`], which validates every pattern.
pub(super) fn command_patterns(document: &Value, deadline: Instant) -> Result<Value, Error> {
    compile_effects(document, deadline, Effects::WithReview)?;
    let mut patterns = Vec::new();
    for rule in document["spec"]["rules"].as_array().into_iter().flatten() {
        let id = rule["id"].as_str().unwrap_or("unknown");
        let expression = &rule["match"]["commands"];
        if rule["enabled"] != true || rule["effect"] != "allow" || !expression.is_object() {
            continue;
        }
        let (harnesses, workspaces) = pattern_selectors(rule, id)?;
        let expires = expiry(
            if rule["lifetime"]["mode"] == "until" {
                &rule["lifetime"]["expiresAt"]
            } else {
                &Value::Null
            },
            id,
            "invalid_policy_expiry",
        )?;
        let list = |values: Vec<Value>| {
            if values == [Value::Null] {
                Value::Null
            } else {
                Value::Array(values)
            }
        };
        patterns.push(json!({"rule_id":id,"harnesses":list(harnesses),
            "workspaces":list(workspaces),"expires_at":expires,"expression":expression}));
    }
    Ok(Value::Array(patterns))
}
