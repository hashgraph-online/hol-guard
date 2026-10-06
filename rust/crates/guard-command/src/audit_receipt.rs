//! RTM-019 receipt authority-projection slice
//! (`local_supply_chain.py` :1032-1117 plus the :899-1001 findings/inventory
//! helpers it calls).
//!
//! Reproduces four oracle functions with canonical-JSON parity:
//! - `audit_receipt_metadata` (:1071-1117)
//! - `_incomplete_audit_receipt_metadata` (:1032-1064)
//! - `_audit_package_findings_for_receipt` (:974-991)
//! - `_audit_package_inventory_for_receipt` (:958-972)
//!
//! Boundary contract (per integrator brief): the caller resolves
//! `_cached_supply_chain_bundle_payload(store)` and passes the pre-resolved
//! bundle payload as `Option<&Map<String, Value>>`; the store trait is not
//! touched here. `workspace_dir` is `Option<&Path>` and file hashing goes
//! through the `PathSupportApi` seam (the ported
//! `workspace_audit_path_hashes` / `read_bytes_within_workspace` boundary),
//! so no not-yet-ported helper had to be taken as a raw parameter.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::{Map, Value};

use crate::effect_decision::GuardAction;
use crate::local_supply_chain::{stable_digest_hex, PathSupportApi};
use crate::target_identities::{py_str, py_truthy};

// ---------------------------------------------------------------------------
// Python coercions (`str(x or default)`, truthiness, `str.strip`, `repr`).
// ---------------------------------------------------------------------------

/// Python `str.isspace()` includes the C0 information separators \x1c-\x1f that
/// `char::is_whitespace` omits; `str.strip()` removes them, so spell the set
/// out for byte-exact parity (mirrors `launch_identity::python_str_is_space`).
fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python `str.strip()`.
fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

// Receipt values use the same Python-compatible coercions as package identities.
/// `str(value or default)` — truthiness-gated `str()` coercion. The default is
/// already a `&str`, matching every oracle call site.
fn py_str_or_default(value: Option<&Value>, default: &str) -> String {
    value
        .filter(|v| py_truthy(v))
        .map(py_str)
        .unwrap_or_else(|| default.to_string())
}

/// `str(item.get(key) or default)` for a dict member.
fn py_str_field_or_default(item: &Map<String, Value>, key: &str, default: &str) -> String {
    py_str_or_default(item.get(key), default)
}

/// `_string_items` (:4650-4654): str members of a list/tuple, else `()`.
fn string_items(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Package severity / reason-code helpers (:934-955, :4246-4262).
// ---------------------------------------------------------------------------

/// `_SEVERITY_RANK` (:214-219).
fn severity_rank(severity: &str) -> i64 {
    match severity {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0, // "unknown" and unrecognized severities both rank 0
    }
}

/// `_package_reason_codes` (:934-941): `str(reason.get("code") or "").strip()`
/// per dict reason; empties dropped.
fn package_reason_codes(item: &Map<String, Value>) -> HashSet<String> {
    let mut codes = HashSet::new();
    let Some(reasons) = item.get("reasons").and_then(Value::as_array) else {
        return codes;
    };
    for reason in reasons {
        let Some(reason) = reason.as_object() else {
            continue;
        };
        let code = py_str_or_default(reason.get("code"), "");
        let code = python_strip(&code);
        if !code.is_empty() {
            codes.insert(code.to_string());
        }
    }
    codes
}

/// `_INFORMATIONAL_REASON_CODES` (:153).
fn is_informational_reason_code(code: &str) -> bool {
    matches!(code, "unknown_package" | "no_cached_match")
}

/// `_is_actionable_package_finding` (:944-955).
fn is_actionable_package_finding(item: &Map<String, Value>) -> bool {
    let decision = py_str_field_or_default(item, "decision", "monitor");
    if decision == "block" || decision == "ask" || decision == "warn" {
        return true;
    }
    let reason_codes = package_reason_codes(item);
    if reason_codes.is_empty() {
        return decision != "allow" && decision != "monitor";
    }
    !reason_codes
        .iter()
        .all(|code| is_informational_reason_code(code))
}

/// `_package_severity_rank` (:4246-4262).
fn package_severity_rank(package: &Map<String, Value>) -> i64 {
    if let Some(severity) = package.get("normalized_severity").and_then(Value::as_str) {
        return severity_rank(severity);
    }
    let Some(reasons) = package.get("reasons").and_then(Value::as_array) else {
        return 0;
    };
    let mut highest = 0; // _SEVERITY_RANK["unknown"]
    for reason in reasons {
        let Some(reason) = reason.as_object() else {
            continue;
        };
        let Some(severity) = reason.get("severity").and_then(Value::as_str) else {
            continue;
        };
        highest = highest.max(severity_rank(severity));
    }
    highest
}

// ---------------------------------------------------------------------------
// Advisory-alias enrichment (:811-836, :852-932).
// ---------------------------------------------------------------------------

/// `_package_advisory_ids` (:811-836). First-seen, case-sensitive dedup across
/// the four list keys, the two scalar keys, then per-reason ids.
fn package_advisory_ids(package: &Map<String, Value>) -> Vec<String> {
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add_id = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = python_strip(text);
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                advisory_ids.push(trimmed.to_string());
            }
        }
    };
    for key in [
        "advisoryIds",
        "advisory_ids",
        "relatedAdvisoryIds",
        "related_advisory_ids",
    ] {
        if let Some(raw) = package.get(key).and_then(Value::as_array) {
            for entry in raw {
                add_id(Some(entry));
            }
        }
    }
    add_id(package.get("advisoryId"));
    add_id(package.get("advisory_id"));
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            add_id(reason.get("advisoryId"));
            add_id(reason.get("advisory_id"));
        }
    }
    advisory_ids
}

/// `_resolve_advisory_aliases_from_bundle` (:852-894). Upper-cased alias
/// closure over `bundle["advisories"]`. Lookup keys use the *unstripped*
/// `advisoryId`/alias text (`.upper()` only), matching the oracle — the
/// `isinstance(advisory_id, str) and advisory_id.strip()` check gates, but the
/// raw string is what lands in the lookup table.
fn resolve_advisory_aliases_from_bundle(
    bundle: Option<&Map<String, Value>>,
    advisory_ids: &[String],
) -> Vec<String> {
    let mut aliases: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut lookup: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(bundle) = bundle {
        if let Some(advisories) = bundle.get("advisories").and_then(Value::as_array) {
            for advisory in advisories {
                let Some(advisory) = advisory.as_object() else {
                    continue;
                };
                let Some(advisory_id) = advisory.get("advisoryId").and_then(Value::as_str) else {
                    continue;
                };
                if advisory_id.trim().is_empty() {
                    continue;
                }
                let mut alias_tuple = vec![advisory_id.to_string()];
                if let Some(raw) = advisory.get("aliases").and_then(Value::as_array) {
                    alias_tuple.extend(
                        raw.iter()
                            .filter_map(|a| a.as_str())
                            .filter(|a| !a.trim().is_empty())
                            .map(str::to_owned),
                    );
                }
                let upper_tuple: Vec<String> = alias_tuple
                    .iter()
                    .map(|alias| alias.to_uppercase())
                    .collect();
                lookup.insert(advisory_id.to_uppercase(), upper_tuple.clone());
                for alias in &alias_tuple {
                    lookup
                        .entry(alias.to_uppercase())
                        .or_insert_with(|| upper_tuple.clone());
                }
            }
        }
    }
    for advisory_id in advisory_ids {
        let add_alias = |value: &str, aliases: &mut Vec<String>, seen: &mut HashSet<String>| {
            let trimmed = value.trim().to_uppercase();
            if trimmed.is_empty() || seen.contains(&trimmed) {
                return;
            }
            seen.insert(trimmed.clone());
            aliases.push(trimmed);
        };
        add_alias(advisory_id, &mut aliases, &mut seen);
        if let Some(resolved) = lookup.get(&advisory_id.to_uppercase()) {
            for alias in resolved.clone() {
                add_alias(&alias, &mut aliases, &mut seen);
            }
        }
    }
    aliases
}

/// `_enrich_package_with_advisory_aliases` (:899-912): packages that already
/// carry a non-empty `advisoryAliases` list pass through untouched; otherwise
/// bundle-resolved aliases are merged in (or the package passes through
/// unchanged).
fn enrich_package_with_advisory_aliases(
    package: &Map<String, Value>,
    bundle: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    if package
        .get("advisoryAliases")
        .and_then(Value::as_array)
        .is_some_and(|existing| !existing.is_empty())
    {
        return package.clone();
    }
    let advisory_ids = package_advisory_ids(package);
    if advisory_ids.is_empty() {
        return package.clone();
    }
    let aliases = resolve_advisory_aliases_from_bundle(bundle, &advisory_ids);
    if aliases.is_empty() {
        return package.clone();
    }
    let mut enriched = package.clone();
    enriched.insert(
        "advisoryAliases".to_string(),
        Value::Array(aliases.into_iter().map(Value::String).collect()),
    );
    enriched
}

// ---------------------------------------------------------------------------
// Receipt slices (:958-1001).
// ---------------------------------------------------------------------------

/// `_audit_package_inventory_for_receipt` (:958-972): stable sort by
/// `str(ecosystem or "")` then `str(name or "")`, truncate to `limit`, enrich
/// each surviving row with bundle aliases.
pub fn audit_package_inventory_for_receipt(
    package_items: &[Map<String, Value>],
    limit: usize,
    bundle: Option<&Map<String, Value>>,
) -> Vec<Map<String, Value>> {
    let mut ranked = package_items.to_vec();
    ranked.sort_by(|a, b| {
        (
            py_str_field_or_default(a, "ecosystem", ""),
            py_str_field_or_default(a, "name", ""),
        )
            .cmp(&(
                py_str_field_or_default(b, "ecosystem", ""),
                py_str_field_or_default(b, "name", ""),
            ))
    });
    ranked
        .into_iter()
        .take(limit)
        .map(|item| enrich_package_with_advisory_aliases(&item, bundle))
        .collect()
}

/// `_audit_package_findings_for_receipt` (:974-991): keep actionable findings,
/// stable sort by `(decision_rank, severity_rank)` descending, truncate to
/// `limit`, enrich with bundle aliases.
pub fn audit_package_findings_for_receipt(
    package_items: &[Map<String, Value>],
    limit: usize,
    bundle: Option<&Map<String, Value>>,
) -> Vec<Map<String, Value>> {
    let mut ranked: Vec<(i64, i64, &Map<String, Value>)> = Vec::new();
    for item in package_items {
        if !is_actionable_package_finding(item) {
            continue;
        }
        let decision = py_str_field_or_default(item, "decision", "monitor");
        let decision_rank = match decision.as_str() {
            "block" => 4,
            "ask" => 3,
            "warn" => 2,
            "monitor" => 1,
            _ => 0,
        };
        ranked.push((decision_rank, package_severity_rank(item), item));
    }
    // Python `list.sort(key=..., reverse=True)` is stable; `sort_by` keeps the
    // same input order for equal keys.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, _, item)| enrich_package_with_advisory_aliases(item, bundle))
        .collect()
}

// ---------------------------------------------------------------------------
// Workspace path hashing (:1002-1012, :4201-4208).
// ---------------------------------------------------------------------------

/// `_hash_existing_paths` (:4201-4208): `stable_digest_hex` of file bytes for
/// each relative path that resolves inside the workspace.
fn hash_existing_paths(
    paths_api: &dyn PathSupportApi,
    workspace_dir: &Path,
    paths: &[String],
) -> Vec<String> {
    paths
        .iter()
        .filter_map(|relative| {
            paths_api
                .read_bytes_within_workspace(workspace_dir, relative)
                .map(|bytes| stable_digest_hex(&bytes))
        })
        .collect()
}

/// `workspace_audit_path_hashes` (:1002-1012).
fn workspace_audit_path_hashes(
    paths_api: &dyn PathSupportApi,
    workspace_dir: Option<&Path>,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> (Vec<String>, Vec<String>) {
    match workspace_dir {
        None => (Vec::new(), Vec::new()),
        Some(workspace_dir) => (
            hash_existing_paths(paths_api, workspace_dir, manifest_paths),
            hash_existing_paths(paths_api, workspace_dir, lockfile_paths),
        ),
    }
}

// ---------------------------------------------------------------------------
// Receipt projections (:1032-1117).
// ---------------------------------------------------------------------------

/// `_incomplete_audit_receipt_metadata` (:1032-1064). Used when the audit
/// `result` has no `evaluation` dict: outcome -> `review` for
/// `sync_required`/`inventory_empty`/`no_project_files`, else `warn`.
pub fn incomplete_audit_receipt_metadata(
    paths_api: &dyn PathSupportApi,
    result: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Map<String, Value> {
    let message = py_str_or_default(result.get("message"), "Workspace audit did not complete.");
    let outcome = py_str_or_default(result.get("audit_outcome"), "incomplete");
    let manifest_paths = string_items(result.get("manifest_paths"));
    let lockfile_paths = string_items(result.get("lockfile_paths"));
    let (manifest_hashes, lockfile_hashes) =
        workspace_audit_path_hashes(paths_api, workspace_dir, &manifest_paths, &lockfile_paths);
    let policy_decision = match outcome.as_str() {
        "sync_required" | "inventory_empty" | "no_project_files" => GuardAction::Review,
        _ => GuardAction::Warn,
    };
    let mut scanner_evidence = Map::new();
    scanner_evidence.insert("operation".into(), Value::String("audit".into()));
    scanner_evidence.insert("audit_status".into(), Value::String("incomplete".into()));
    scanner_evidence.insert("audit_outcome".into(), Value::String(outcome));
    scanner_evidence.insert("audit_decision".into(), Value::String("monitor".into()));
    scanner_evidence.insert("blocked_package_count".into(), Value::from(0u64));
    scanner_evidence.insert("total_packages".into(), Value::from(0u64));
    scanner_evidence.insert(
        "manifest_paths".into(),
        Value::Array(manifest_paths.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "lockfile_paths".into(),
        Value::Array(lockfile_paths.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "manifest_hashes".into(),
        Value::Array(manifest_hashes.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "lockfile_hashes".into(),
        Value::Array(lockfile_hashes.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert("package_findings".into(), Value::Array(Vec::new()));
    let mut receipt = Map::new();
    receipt.insert(
        "policy_decision".into(),
        Value::String(policy_decision.as_str().into()),
    );
    receipt.insert("capabilities_summary".into(), Value::String(message));
    receipt.insert(
        "artifact_name".into(),
        Value::String("Workspace supply-chain audit".into()),
    );
    receipt.insert("scanner_evidence".into(), Value::Object(scanner_evidence));
    receipt
}

/// `audit_receipt_metadata` (:1071-1117). Projects the audit `result` dict to
/// the receipt authority map: evaluation decision -> `policy_decision`
/// (block->block, ask->review, warn->warn, else allow) plus the
/// `scanner_evidence` payload.
///
/// `bundle` is the pre-resolved `_cached_supply_chain_bundle_payload(store)`
/// output — the caller owns store access; `None` when the store is absent,
/// has no workspace id, or no cached bundle.
pub fn audit_receipt_metadata(
    paths_api: &dyn PathSupportApi,
    result: &Map<String, Value>,
    workspace_dir: Option<&Path>,
    bundle: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    let Some(evaluation) = result.get("evaluation").and_then(Value::as_object) else {
        return incomplete_audit_receipt_metadata(paths_api, result, workspace_dir);
    };
    let decision = py_str_or_default(evaluation.get("decision"), "monitor");
    let package_items: Vec<&Map<String, Value>> = evaluation
        .get("packages")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    let blocked_count = package_items
        .iter()
        .filter(|item| py_str_field_or_default(item, "decision", "") == "block")
        .count();
    let owned_items: Vec<Map<String, Value>> =
        package_items.iter().map(|item| (*item).clone()).collect();
    let package_findings = audit_package_findings_for_receipt(&owned_items, 100, bundle);
    let package_inventory = audit_package_inventory_for_receipt(&owned_items, 500, bundle);
    let policy_decision = match decision.as_str() {
        "block" => GuardAction::Block,
        "ask" => GuardAction::Review,
        "warn" => GuardAction::Warn,
        _ => GuardAction::Allow,
    };
    let inventory_summary: Option<&Map<String, Value>> =
        result.get("inventory").and_then(Value::as_object);
    let manifest_paths = string_items(result.get("manifest_paths"));
    let lockfile_paths = string_items(result.get("lockfile_paths"));
    let (manifest_hashes, lockfile_hashes) =
        workspace_audit_path_hashes(paths_api, workspace_dir, &manifest_paths, &lockfile_paths);
    // `inventory_summary.get("total_packages", len(package_items))` — the raw
    // JSON value passes through (Python does not coerce it); the f-string
    // renders it with `str()`.
    let total_packages_value: Value = inventory_summary
        .and_then(|summary| summary.get("total_packages").cloned())
        .unwrap_or_else(|| Value::from(package_items.len() as u64));
    let total_packages_text = inventory_summary
        .and_then(|summary| summary.get("total_packages"))
        .map(py_str)
        .unwrap_or_else(|| package_items.len().to_string());
    let capabilities_summary = format!(
        "Workspace audit completed with {} decision across {} packages.",
        policy_decision.as_str(),
        total_packages_text,
    );
    let mut scanner_evidence = Map::new();
    scanner_evidence.insert("operation".into(), Value::String("audit".into()));
    scanner_evidence.insert("audit_decision".into(), Value::String(decision));
    scanner_evidence.insert(
        "blocked_package_count".into(),
        Value::from(blocked_count as u64),
    );
    scanner_evidence.insert(
        "lockfile_paths".into(),
        Value::Array(lockfile_paths.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "manifest_paths".into(),
        Value::Array(manifest_paths.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "manifest_hashes".into(),
        Value::Array(manifest_hashes.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert(
        "lockfile_hashes".into(),
        Value::Array(lockfile_hashes.into_iter().map(Value::String).collect()),
    );
    scanner_evidence.insert("total_packages".into(), total_packages_value);
    scanner_evidence.insert(
        "package_inventory".into(),
        Value::Array(package_inventory.into_iter().map(Value::Object).collect()),
    );
    scanner_evidence.insert(
        "package_findings".into(),
        Value::Array(package_findings.into_iter().map(Value::Object).collect()),
    );
    let mut receipt = Map::new();
    receipt.insert(
        "policy_decision".into(),
        Value::String(policy_decision.as_str().into()),
    );
    receipt.insert(
        "capabilities_summary".into(),
        Value::String(capabilities_summary),
    );
    receipt.insert(
        "artifact_name".into(),
        Value::String("Workspace supply-chain audit".into()),
    );
    receipt.insert("scanner_evidence".into(), Value::Object(scanner_evidence));
    receipt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_intent_common::resolve_path_within_workspace;
    use std::path::PathBuf;

    /// Golden vectors generated from the Python oracle
    /// (`local_supply_chain.py` :1032-1117) for the decision/outcome matrices:
    /// evaluation decision block/ask/warn/monitor/allow/other/empty/non-string,
    /// audit outcome sync_required/inventory_empty/no_project_files/other,
    /// inventory edge cases, advisory-alias bundles, and coercion traps.
    /// `workspace: true` cases run against a fixture dir containing
    /// `package.json` and `package-lock.json` with the same bytes the oracle
    /// hashed, so `manifest_hashes`/`lockfile_hashes` must match byte-for-byte.
    const GOLDEN_VECTORS: &str = concat!(
        "[{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with block decision",
        " across 9 packages.\",\"policy_decision\":\"block\",\"scanner_evidence\":{\"audit_decision\":\"block\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operat",
        "ion\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name",
        "\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ec",
        "osystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malwar",
        "e\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_block\",\"result\":{\"evaluation\":{\"decision\":\"block\",\"packages\":[{",
        "\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\"",
        ":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.j",
        "son\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_s",
        "ummary\":\"Workspace audit completed with review decision across 9 packages.\",\"policy_decision\":\"review\",\"scanner_evidence\":{\"audit_decision\":\"ask\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths",
        "\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":",
        "\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"",
        "MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosys",
        "tem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_ask\",\"res",
        "ult\":{\"evaluation\":{\"decision\":\"ask\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unk",
        "nown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":",
        "[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_na",
        "me\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with warn decision across 9 packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be",
        "417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosyst",
        "em\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"",
        "advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"un",
        "known_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_pac",
        "kages\":9}},\"kind\":\"audit\",\"name\":\"dec_warn\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosys",
        "tem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"",
        "inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\"",
        ",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"",
        "manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-",
        "9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_matc",
        "h\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"",
        "ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"qu",
        "arantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_monitor\",\"result\":{\"evaluation\":{\"decision\":\"monitor\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ec",
        "osystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"",
        "no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"",
        "not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"allow\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24",
        "d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"hig",
        "h\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosyste",
        "m\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"b",
        "eta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"n",
        "o_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_allow\",\"result\":{\"evaluation\":{\"decision\":\"allow\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"n",
        "ormalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\"",
        ",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2",
        "024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"audit_passed\",\"blocked_package_count\":1,\"lockfil",
        "e_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"bloc",
        "k\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"",
        "ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\"",
        ":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"",
        "allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_audit_passed\",\"result\":{\"evaluation\":{\"decision\":\"audit_passed\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"a",
        "dvisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"",
        "},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"alias",
        "es\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_ev",
        "idence\":{\"audit_decision\":\"monitor\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GH",
        "SA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name",
        "\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"cri",
        "tical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"et",
        "a\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_\",\"result\":{\"evaluation\":{\"decision\":\"\",\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"",
        "name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision",
        "\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{",
        "\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 pa",
        "ckages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"5\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"pa",
        "ckage_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"dec",
        "ision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"",
        "name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision",
        "\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_5\",\"result\":{\"evaluation\":{\"decision\":5,\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"",
        "],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"r",
        "easons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc",
        "/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit c",
        "ompleted with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"True\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.j",
        "son\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"wa",
        "rn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA",
        "-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\"",
        ",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"audit\",\"name\":\"dec_True\",\"result\":{\"evaluation\":{\"decis",
        "ion\":true,\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision",
        "\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packages\":9},\"lockfile_paths\":[\"package-lock.json\"],\"mani",
        "fest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain",
        " audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 9 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"blocked_package_count\":1,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93f",
        "e0f1549\"],\"manifest_paths\":[\"package.json\",\"absent.json\",\"/etc/passwd\"],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alph",
        "a\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]}],\"package_inventory\":[{\"advisoryAliases\":[\"GHS",
        "A-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"advisoryAliases\":[\"GHSA-2222\",\"CVE-2024-0002\"],\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"de",
        "cision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"}],\"total_packages\":9}},\"kind\":\"aud",
        "it\",\"name\":\"dec_None\",\"result\":{\"evaluation\":{\"decision\":null,\"packages\":[{\"advisoryIds\":[\"GHSA-2222\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"beta\",\"normalized_severity\":\"high\"},{\"advisoryId\":\"GHSA-1111\",\"decision\":\"ask\",\"ecosystem\":\"npm\",\"name\":\"alpha\",\"normalized_severity\":\"critical\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"gamma\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"delta",
        "\",\"reasons\":[{\"code\":\"unknown_package\"}]},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"epsilon\",\"reasons\":[{\"code\":\"malware\"}]},{\"decision\":\"quarantine\",\"ecosystem\":\"npm\",\"name\":\"zeta\"},{\"decision\":\"monitor\",\"ecosystem\":\"npm\",\"name\":\"eta\"},{\"decision\":\"allow\",\"ecosystem\":\"npm\",\"name\":\"theta\",\"reasons\":[{\"code\":\"no_cached_match\"},{\"code\":\"sig_mismatch\"}]},\"not-a-dict\"]},\"inventory\":{\"total_packa",
        "ges\":9},\"lockfile_paths\":[\"package-lock.json\"],\"manifest_paths\":[\"package.json\",\"absent.json\",7,\"/etc/passwd\"]},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 0 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"allow\",\"blocked_package_count\":0,\"lockfile",
        "_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":0}},\"kind\":\"audit\",\"name\":\"inv_missing\",\"result\":{\"evaluation\":{\"decision\":\"allow\",\"packages\":[]}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed wit",
        "h warn decision across 0 packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":0}},\"kind\":\"audit\",\"name\":\"inv_nondict\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":[]},\"invento",
        "ry\":[1,2]},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with review decision across True packages.\",\"policy_decision\":\"review\",\"scanner_evidence\":{\"audit_decision\":\"ask\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"pac",
        "kage_findings\":[{\"decision\":\"ask\",\"ecosystem\":\"a\",\"name\":\"b\"}],\"package_inventory\":[{\"decision\":\"ask\",\"ecosystem\":\"a\",\"name\":\"b\"}],\"total_packages\":true}},\"kind\":\"audit\",\"name\":\"inv_total_bool\",\"result\":{\"evaluation\":{\"decision\":\"ask\",\"packages\":[{\"decision\":\"ask\",\"ecosystem\":\"a\",\"name\":\"b\"}]},\"inventory\":{\"total_packages\":true}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Works",
        "pace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with warn decision across 17 packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":\"17\"}},\"kind\":\"audit\",\"nam",
        "e\":\"inv_total_str\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":[]},\"inventory\":{\"total_packages\":\"17\"}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with warn decision across 2.5 packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfil",
        "e_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":2.5}},\"kind\":\"audit\",\"name\":\"inv_total_float\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":[]},\"inventory\":{\"total_packages\":2.5}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilitie",
        "s_summary\":\"Workspace audit completed with warn decision across None packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":null}},\"kind\":\"audit\",\"name\":\"inv_total_null\",\"result\":{\"eval",
        "uation\":{\"decision\":\"warn\",\"packages\":[]},\"inventory\":{\"total_packages\":null}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with block decision across 0 packages.\",\"policy_decision\":\"block\",\"scanner_evidence\":{\"audit_decision\":\"block\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],",
        "\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":0}},\"kind\":\"audit\",\"name\":\"pkgs_missing\",\"result\":{\"evaluation\":{\"decision\":\"block\"},\"inventory\":{}},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with warn decision across 0 packag",
        "es.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"package_inventory\":[],\"total_packages\":0}},\"kind\":\"audit\",\"name\":\"pkgs_nondict\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":\"nope\"}},\"workspace\":false},{\"bundle\":null",
        ",\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with block decision across 1 packages.\",\"policy_decision\":\"block\",\"scanner_evidence\":{\"audit_decision\":\"block\",\"blocked_package_count\":1,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"GHSA-1111\"",
        "],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"x\"}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"x\"}],\"total_packages\":1}},\"kind\":\"audit\",\"name\":\"no_bundle\",\"result\":{\"evaluation\":{\"decision\":\"block\",\"packages\":[{\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"block\",\"ecosystem\":\"npm\",\"name\":\"x\"}]",
        "}},\"workspace\":false},{\"bundle\":{\"advisories\":[{\"advisoryId\":\"GHSA-1111\",\"aliases\":[\"CVE-2024-0001\",\"MISC-9\"]},{\"advisoryId\":\"GHSA-2222\",\"aliases\":[\"CVE-2024-0002\"]},{\"advisoryId\":\" GHSA-PAD \",\"aliases\":[]},\"not-a-dict\",{\"aliases\":[\"NOID-1\"]},{\"advisoryId\":\"GHSA-3333\",\"aliases\":\"notalist\"}]},\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit complete",
        "d with warn decision across 2 packages.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"warn\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[{\"advisoryAliases\":[\"KEEP-1\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"keep\"},{\"advisoryAliases\":[\"GHSA-1111\",\"",
        "CVE-2024-0001\",\"MISC-9\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"empty\"}],\"package_inventory\":[{\"advisoryAliases\":[\"GHSA-1111\",\"CVE-2024-0001\",\"MISC-9\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"empty\"},{\"advisoryAliases\":[\"KEEP-1\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"keep\"}],\"total_packages\":2}},\"kin",
        "d\":\"audit\",\"name\":\"preexisting_aliases\",\"result\":{\"evaluation\":{\"decision\":\"warn\",\"packages\":[{\"advisoryAliases\":[\"KEEP-1\"],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"keep\"},{\"advisoryAliases\":[],\"advisoryIds\":[\"GHSA-1111\"],\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"empty\"}]}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\"",
        ",\"capabilities_summary\":\"Workspace audit completed with allow decision across 4 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"sev\",\"reasons\":[{\"severity\":\"critical\"},{\"s",
        "everity\":\"weird\"},\"x\",{\"nosev\":1}]},{\"decision\":\"warn\",\"ecosystem\":null,\"name\":null},{\"decision\":\"warn\",\"ecosystem\":5,\"name\":\"num\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":7}],\"package_inventory\":[{\"decision\":\"warn\",\"ecosystem\":null,\"name\":null},{\"decision\":\"warn\",\"ecosystem\":5,\"name\":\"num\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":7},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"sev\",\"reaso",
        "ns\":[{\"severity\":\"critical\"},{\"severity\":\"weird\"},\"x\",{\"nosev\":1}]}],\"total_packages\":4}},\"kind\":\"audit\",\"name\":\"sort_coercion\",\"result\":{\"evaluation\":{\"decision\":\"monitor\",\"packages\":[{\"decision\":\"warn\",\"ecosystem\":null,\"name\":null},{\"decision\":\"warn\",\"ecosystem\":5,\"name\":\"num\"},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":7},{\"decision\":\"warn\",\"ecosystem\":\"npm\",\"name\":\"sev\",\"reasons\":[{\"severity\"",
        ":\"critical\"},{\"severity\":\"weird\"},\"x\",{\"nosev\":1}]}]}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit completed with allow decision across 6 packages.\",\"policy_decision\":\"allow\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"",
        "manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[{\"decision\":0,\"ecosystem\":\"npm\",\"name\":\"b2\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":true,\"ecosystem\":\"npm\",\"name\":\"b1\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":[\"block\"],\"ecosystem\":\"npm\",\"name\":\"b3\"},{\"decision\":\"block \",\"ecosystem\":\"npm\",\"name\":\"b4\"},{\"decision\":\"BLOCK\",\"ecosystem\":\"npm\",\"name\":\"b5\"},{\"decision\":5,\"ecosystem\":\"npm\",",
        "\"name\":\"b6\",\"reasons\":[{\"code\":7},{\"code\":\" real \"},{\"code\":\"\"}]}],\"package_inventory\":[{\"decision\":true,\"ecosystem\":\"npm\",\"name\":\"b1\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":0,\"ecosystem\":\"npm\",\"name\":\"b2\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":[\"block\"],\"ecosystem\":\"npm\",\"name\":\"b3\"},{\"decision\":\"block \",\"ecosystem\":\"npm\",\"name\":\"b4\"},{\"decision\":\"BLOCK\",\"ecosystem\":\"npm\",\"name\":\"b5\"},{\"d",
        "ecision\":5,\"ecosystem\":\"npm\",\"name\":\"b6\",\"reasons\":[{\"code\":7},{\"code\":\" real \"},{\"code\":\"\"}]}],\"total_packages\":6}},\"kind\":\"audit\",\"name\":\"pkg_decision_coercion\",\"result\":{\"evaluation\":{\"decision\":\"monitor\",\"packages\":[{\"decision\":true,\"ecosystem\":\"npm\",\"name\":\"b1\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":0,\"ecosystem\":\"npm\",\"name\":\"b2\",\"reasons\":[{\"code\":\"custom\"}]},{\"decision\":[\"block\"],\"ecos",
        "ystem\":\"npm\",\"name\":\"b3\"},{\"decision\":\"block \",\"ecosystem\":\"npm\",\"name\":\"b4\"},{\"decision\":\"BLOCK\",\"ecosystem\":\"npm\",\"name\":\"b5\"},{\"decision\":5,\"ecosystem\":\"npm\",\"name\":\"b6\",\"reasons\":[{\"code\":7},{\"code\":\" real \"},{\"code\":\"\"}]}]}},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"msg-sync_required\",\"policy_decision\":\"review\",\"scanne",
        "r_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"sync_required\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":",
        "\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_sync_required\",\"result\":{\"audit_outcome\":\"sync_required\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-sync_required\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"msg-inventory_empty\",\"pol",
        "icy_decision\":\"review\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"inventory_empty\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_path",
        "s\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_inventory_empty\",\"result\":{\"audit_outcome\":\"inventory_empty\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-inventory_empty\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabiliti",
        "es_summary\":\"msg-no_project_files\",\"policy_decision\":\"review\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"no_project_files\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952f3860be417d79",
        "402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_no_project_files\",\"result\":{\"audit_outcome\":\"no_project_files\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-no_project_files\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\"",
        ":\"Workspace supply-chain audit\",\"capabilities_summary\":\"msg-network_error\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"network_error\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09",
        "845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_network_error\",\"result\":{\"audit_outcome\":\"network_error\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-network_error\"},\"workspace\":true},{\"bundle\":null,\"",
        "expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"msg-\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"incomplete\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes",
        "\":[\"bb8e09845cc056a0f7b101420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_\",\"result\":{\"audit_outcome\":\"\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"W",
        "orkspace supply-chain audit\",\"capabilities_summary\":\"msg-None\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"incomplete\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b10",
        "1420952f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_None\",\"result\":{\"audit_outcome\":null,\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-None\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply",
        "-chain audit\",\"capabilities_summary\":\"msg-other_thing\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"other_thing\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[\"8dea79e11fe287e827588c412faef2a98161205a3140aed24d94c04821d0a728\"],\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_hashes\":[\"bb8e09845cc056a0f7b101420952",
        "f3860be417d79402a5abecc0ef93fe0f1549\"],\"manifest_paths\":[\"package.json\"],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_other_thing\",\"result\":{\"audit_outcome\":\"other_thing\",\"lockfile_paths\":[\"package-lock.json\",\"missing.lock\"],\"manifest_paths\":[\"package.json\"],\"message\":\"msg-other_thing\"},\"workspace\":true},{\"bundle\":null,\"expected\":{\"artifact_name\":\"",
        "Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit did not complete.\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"incomplete\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"inc",
        "omplete\",\"name\":\"inc_no_fields\",\"result\":{},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"Workspace audit did not complete.\",\"policy_decision\":\"review\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"audit_outcome\":\"sync_required\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"ma",
        "nifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_falsy_message\",\"result\":{\"audit_outcome\":\"sync_required\",\"message\":\"\"},\"workspace\":false},{\"bundle\":null,\"expected\":{\"artifact_name\":\"Workspace supply-chain audit\",\"capabilities_summary\":\"42\",\"policy_decision\":\"warn\",\"scanner_evidence\":{\"audit_decision\":\"monitor\",\"au",
        "dit_outcome\":\"x\",\"audit_status\":\"incomplete\",\"blocked_package_count\":0,\"lockfile_hashes\":[],\"lockfile_paths\":[],\"manifest_hashes\":[],\"manifest_paths\":[],\"operation\":\"audit\",\"package_findings\":[],\"total_packages\":0}},\"kind\":\"incomplete\",\"name\":\"inc_nonstr_message\",\"result\":{\"audit_outcome\":\"x\",\"lockfile_paths\":{\"a\":1},\"manifest_paths\":\"notalist\",\"message\":42},\"workspace\":false}]",
    );

    struct FixtureWorkspace(PathBuf);

    impl FixtureWorkspace {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rtm019-audit-receipt-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), br#"{"name": "fixture"}"#).unwrap();
            std::fs::write(dir.join("package-lock.json"), br#"{"lockfileVersion": 3}"#).unwrap();
            Self(dir)
        }
    }

    impl Drop for FixtureWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `read_bytes_within_workspace` (workspace_path_guard.py :35-42): resolve
    /// inside the workspace, require a file, return bytes.
    struct FixturePaths;

    impl PathSupportApi for FixturePaths {
        fn resolve_path_within_allowed_roots(
            &self,
            _candidate: &Path,
            _allowed_roots: &[PathBuf],
            _require_exists: bool,
        ) -> Option<PathBuf> {
            None
        }
        fn resolves_within_root(
            &self,
            _root: &Path,
            _candidate: &Path,
            _require_exists: bool,
        ) -> bool {
            false
        }
        fn read_text_within_workspace(
            &self,
            _workspace_dir: &Path,
            _relative_path: &str,
        ) -> Option<String> {
            None
        }
        fn read_bytes_within_workspace(
            &self,
            workspace_dir: &Path,
            relative_path: &str,
        ) -> Option<Vec<u8>> {
            let resolved = resolve_path_within_workspace(workspace_dir, relative_path)?;
            if !resolved.is_file() {
                return None;
            }
            std::fs::read(resolved).ok()
        }
    }

    #[test]
    fn golden_vectors_match_python_oracle() {
        let cases: Value = serde_json::from_str(GOLDEN_VECTORS).unwrap();
        let cases = cases.as_array().unwrap();
        let workspace = FixtureWorkspace::new();
        let paths = FixturePaths;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let kind = case["kind"].as_str().unwrap();
            let result = case["result"].as_object().unwrap();
            let expected = &case["expected"];
            let workspace_dir = case["workspace"]
                .as_bool()
                .unwrap_or(false)
                .then_some(workspace.0.as_path());
            let bundle = case.get("bundle").and_then(Value::as_object);
            let actual = match kind {
                "audit" => audit_receipt_metadata(&paths, result, workspace_dir, bundle),
                "incomplete" => incomplete_audit_receipt_metadata(&paths, result, workspace_dir),
                other => panic!("unknown case kind {other}"),
            };
            let actual = Value::Object(actual);
            assert_eq!(&actual, expected, "golden vector mismatch for {name}");
        }
    }

    #[test]
    fn findings_rank_stability_and_limits() {
        // Equal (decision, severity) keys keep input order (Python stable
        // sort); limit truncates after ranking.
        let items: Vec<Map<String, Value>> = [
            serde_json::json!({"name": "w1", "decision": "warn"}),
            serde_json::json!({"name": "w2", "decision": "warn"}),
            serde_json::json!({"name": "b1", "decision": "block"}),
            serde_json::json!({"name": "b2", "decision": "block"}),
        ]
        .into_iter()
        .map(|v| v.as_object().unwrap().clone())
        .collect();
        let findings = audit_package_findings_for_receipt(&items, 3, None);
        let names: Vec<&str> = findings
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["b1", "b2", "w1"]);

        let inventory = audit_package_inventory_for_receipt(&items, 2, None);
        assert_eq!(inventory.len(), 2);
    }
}
