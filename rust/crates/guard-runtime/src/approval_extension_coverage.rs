//! Which extension governs which step of a paused command, for the review
//! screen.
//!
//! This is the advisory half of the Extensions affordance. The recommendation
//! says "allowing these permissions settles this command"; coverage says only
//! "this step matched this extension". It projects the stored coverage hint
//! onto the catalog labels the dashboard needs, with no decision in it: it
//! changes nothing about what Guard allows, denies or asks, and the card it
//! feeds has no approve button. Ported from the retired Python `approval_extension_coverage.py`.
//!
//! Catalog identifiers are the contract, so an id this catalog no longer
//! carries is dropped rather than labelled from a neighbouring entry, and a
//! step that loses every id that way disappears with it.

use std::collections::HashSet;

use guard_command::native_command_catalog::CommandCatalog;
use serde_json::{json, Value};

use crate::approval_extension_recommendation_op::{bounded, MAX_TEXT_CHARS};
use crate::extension_coverage_hint;

const COVERAGE_SCHEMA: &str = "guard.approval-extension-coverage.v1";
/// Safer alternatives shown per matched rule on the review card.
const MAX_SAFER_ALTERNATIVES: usize = 2;
/// The dashboard renders this many steps; delivering more would store and
/// send a payload whose tail nothing shows.
const MAX_DELIVERED_SEGMENTS: usize = 12;

/// `build_approval_extension_coverage`: the labelled steps of a stored
/// coverage hint, or `None` when the hint is malformed or no step names an
/// extension this catalog carries.
pub(crate) fn coverage(hint: &Value, catalog: &CommandCatalog) -> Option<Value> {
    let hint = extension_coverage_hint::validated(hint)?;
    let stored = hint.get("segments")?.as_array()?;
    let segments: Vec<Value> = stored
        .iter()
        .filter_map(|segment| covered_segment(segment, catalog))
        .collect();
    if segments.is_empty() {
        return None;
    }
    // A step left out above is still a step of the command that needs review.
    let compound =
        is_compound(hint.get("segment_total"), &segments) || segments.len() < stored.len();
    Some(json!({
        "schema": COVERAGE_SCHEMA,
        "catalog_digest": catalog.catalog_digest,
        // A single-step command needs no "the other steps still need review" line.
        "compound": compound || segments.len() > MAX_DELIVERED_SEGMENTS,
        "segments": segments.into_iter().take(MAX_DELIVERED_SEGMENTS).collect::<Vec<_>>(),
    }))
}

fn ids<'a>(segment: &'a Value, key: &str) -> Vec<&'a str> {
    segment
        .get(key)
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// `_handed_off_permissions`: rule-less permissions of extensions that hand
/// their step to another protection.
fn handed_off_permissions<'a>(
    extension_ids: &[&str],
    catalog: &'a CommandCatalog,
) -> HashSet<&'a str> {
    extension_ids
        .iter()
        .filter_map(|extension_id| catalog.get(extension_id))
        .filter(|extension| extension.delegated_protection.is_some())
        .flat_map(|extension| extension.permissions.iter())
        .filter(|permission| permission.rule_ids.is_empty())
        .map(|permission| permission.permission_id.as_str())
        .collect()
}

/// `_covered_segment`: one stored step labelled from the catalog, or `None`
/// when none of its extensions is one this catalog carries.
fn covered_segment(segment: &Value, catalog: &CommandCatalog) -> Option<Value> {
    let extension_ids = ids(segment, "extension_ids");
    let rule_ids = ids(segment, "rule_ids");
    let handed_off = handed_off_permissions(&extension_ids, catalog);
    // A package manager's step matches its package-firewall permission whether
    // or not anything about it needs review: `npx jest` matches it as much as
    // `npm install`. That permission only hands the step to the firewall, which
    // judges packages itself, so it never explains a pause, and the one switch
    // it offers would turn the firewall off. Leave it out, and with it an
    // extension that matched through nothing else.
    let permission_ids: Vec<&str> = ids(segment, "permission_ids")
        .into_iter()
        .filter(|permission_id| !handed_off.contains(permission_id))
        .collect();
    // The rule's own catalog text, so the card can say what matched in the
    // catalog's words.
    let rules: Vec<Value> = rule_ids
        .iter()
        .filter_map(|rule_id| {
            catalog.get_rule(rule_id).map(|(_, rule)| {
                let safer: Vec<String> = rule
                    .safer_alternatives
                    .iter()
                    .filter_map(|text| bounded(text, MAX_TEXT_CHARS))
                    .take(MAX_SAFER_ALTERNATIVES)
                    .collect();
                json!({
                    "rule_id": rule_id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "description": bounded(&rule.description, MAX_TEXT_CHARS),
                    "safer_alternatives": safer,
                })
            })
        })
        .collect();
    let permissions: Vec<Value> = permission_ids
        .iter()
        .filter_map(|permission_id| {
            catalog.permission(permission_id).map(|permission| {
                json!({
                    "permission_id": permission_id,
                    "label": permission.label,
                    "configurable": permission.configurable,
                })
            })
        })
        .collect();
    let mut extensions = Vec::new();
    for extension_id in &extension_ids {
        let Some(extension) = catalog.get(extension_id) else {
            continue;
        };
        let owned: HashSet<&str> = extension
            .rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect();
        let governs = extension
            .permissions
            .iter()
            .any(|permission| permission_ids.contains(&permission.permission_id.as_str()));
        if !governs && !rule_ids.iter().any(|rule_id| owned.contains(rule_id)) {
            continue;
        }
        // The first rule this extension matched is what the link should open
        // on. The dashboard builds the link itself from these two identifiers,
        // so no daemon-built URL ever reaches a href attribute.
        let focus = rule_ids.iter().find(|rule_id| owned.contains(*rule_id));
        extensions.push(json!({
            "extension_id": extension_id,
            "name": extension.name,
            "focus_rule_id": focus,
        }));
    }
    if extensions.is_empty() {
        // Every id in this segment came from a catalog this build does not have.
        return None;
    }
    Some(json!({
        "index": segment.get("index"),
        "executable": segment.get("executable"),
        "extensions": extensions,
        "rules": rules,
        "permissions": permissions,
    }))
}

/// `_is_compound`: whether steps other than the covered ones are still
/// waiting on review.
fn is_compound(total: Option<&Value>, segments: &[Value]) -> bool {
    if let Some(total) = total.and_then(Value::as_u64) {
        // The review counted the steps, so this is the whole answer: a command
        // of one step is settled by its one covered step, and any other is not.
        return total > 1;
    }
    // Without a count, a later step that no extension matched is invisible, so
    // only what the covered steps themselves prove can be claimed.
    segments.len() > 1
        || segments
            .iter()
            .any(|segment| segment.get("index").and_then(Value::as_u64) != Some(0))
}

#[cfg(test)]
#[path = "approval_extension_coverage_tests.rs"]
mod tests;
