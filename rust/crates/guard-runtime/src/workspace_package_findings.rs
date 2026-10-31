//! Supply-chain findings of a workspace assessment run.
//!
//! Each package the local audit asks about, blocks or warns on becomes one
//! finding named by its coordinate: ecosystem, scoped name and resolved
//! version. New rule data, a second lockfile listing the same package or
//! another advisory adds evidence to that finding instead of making a new one.
//! A package whose lookup could not be answered offline is a coverage gap, not
//! a finding. A finding carries package coordinates, reason codes and advisory
//! identifiers; never file content, commands or local paths.
//!
//! A package finding keeps the id the worktree's last run gave it, even when
//! that run named the package under an older identity scheme, so its history
//! and Cloud key stay with the package. Earlier runs named a scoped package
//! without its scope, as `traverse` for `@babel/traverse`; such a finding
//! still belongs to the scoped package while no other package would take the
//! bare name. The caller keeps the run budget and the detector-status carry.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{PackageAuditPackageIdentitiesQueryV1, PackageAuditWorkspaceFindingsQueryV1};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const DETECTOR: &str = "supply_chain_local_v1";
const MAX_LIST_ITEMS: usize = 8;
const MAX_TEXT_CHARS: usize = 256;
const MAX_RULE_ID_CHARS: usize = 128;
const SEVERITY_ORDER: [&str; 6] = ["critical", "high", "medium", "low", "info", "unknown"];
const DECISION_ORDER: [&str; 3] = ["block", "ask", "warn"];
// An automatic run never asks Cloud, so a package the cached bundle does not
// cover comes back with one of these codes. They mean the answer is unknown,
// which is a coverage gap rather than evidence that the package is risky.
const LOOKUP_UNAVAILABLE: [&str; 4] = [
    "cloud_auth_error",
    "cloud_http_error",
    "cloud_timeout",
    "cloud_validation_error",
];
// With no advisory bundle cached, a package Guard only recorded was never
// compared with any intelligence: it is unknown, not clean.
const NO_CACHED_MATCH: &str = "no_cached_match";

type Object = Map<String, Value>;

/// The `workspace_findings` reply: findings most severe first, the packages
/// the audit read, and the lookups it could not answer or check.
pub(crate) fn workspace_findings(query: &PackageAuditWorkspaceFindingsQueryV1) -> Value {
    let packages = packages(&query.payload);
    json!({
        "findings": project(&query.worktree_key, &packages),
        "listed": listed(&query.payload),
        "unresolved": packages.iter().filter(|package| lookup_unavailable(package)).count(),
        "unchecked": unchecked(&query.payload, &packages),
    })
}

struct Finding {
    severity: usize,
    decision: usize,
    ecosystem: String,
    name: String,
    version: Option<String>,
    fix_version: Option<String>,
    rule_ids: Vec<String>,
    advisory_ids: Vec<String>,
}

fn project(worktree_key: &str, packages: &[&Object]) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut findings: BTreeMap<String, Finding> = BTreeMap::new();
    for package in packages {
        let Some(mut decision) = package
            .get("decision")
            .and_then(Value::as_str)
            .and_then(|value| DECISION_ORDER.iter().position(|item| *item == value))
        else {
            continue;
        };
        if lookup_unavailable(package) {
            continue;
        }
        let Some(name) = package_name(package) else {
            continue;
        };
        let ecosystem = text(package.get("ecosystem")).unwrap_or_else(|| "unknown".to_owned());
        let version =
            text(package.get("resolvedVersion")).or_else(|| text(package.get("requestedVersion")));
        let reasons = reasons(package);
        let mut rule_ids: BTreeSet<String> = reasons
            .iter()
            .filter_map(|item| text(item.get("code")))
            .map(|value| prefix(&value, MAX_RULE_ID_CHARS))
            .collect();
        if let Some(rule_id) = text(package.get("ruleId")) {
            rule_ids.insert(prefix(&rule_id, MAX_RULE_ID_CHARS));
        }
        let mut advisories: BTreeSet<String> = reasons
            .iter()
            .filter_map(|item| text(item.get("advisoryId")))
            .collect();
        advisories.extend(strings(package.get("relatedAdvisoryIds")));
        advisories.extend(strings(package.get("advisoryAliases")));
        let finding_id = finding_id(worktree_key, &ecosystem, &name, version.as_deref());
        let mut severity = max_severity(&reasons);
        let mut fix_version = text(package.get("recommendedFixVersion"));
        if let Some(earlier) = findings.get(&finding_id) {
            // The same package listed twice is more evidence for one finding.
            rule_ids.extend(earlier.rule_ids.iter().cloned());
            advisories.extend(earlier.advisory_ids.iter().cloned());
            severity = severity.min(earlier.severity);
            decision = decision.min(earlier.decision);
            fix_version = earlier.fix_version.clone().or(fix_version);
        } else {
            order.push(finding_id.clone());
        }
        findings.insert(
            finding_id,
            Finding {
                severity,
                decision,
                ecosystem,
                name,
                version,
                fix_version,
                rule_ids: rule_ids.into_iter().take(MAX_LIST_ITEMS).collect(),
                advisory_ids: advisories.into_iter().take(MAX_LIST_ITEMS).collect(),
            },
        );
    }
    let mut ordered: Vec<(String, Finding)> = order
        .into_iter()
        .filter_map(|id| findings.remove(&id).map(|finding| (id, finding)))
        .collect();
    ordered.sort_by(|(_, left), (_, right)| {
        (left.severity, &left.name).cmp(&(right.severity, &right.name))
    });
    ordered
        .into_iter()
        .map(|(finding_id, finding)| {
            json!({
                "finding_id": finding_id,
                "source_kind": "supply_chain",
                "detector": DETECTOR,
                "severity": SEVERITY_ORDER[finding.severity],
                "decision": DECISION_ORDER[finding.decision],
                "ecosystem": finding.ecosystem,
                "package_name": finding.name,
                "package_version": finding.version,
                "fix_version": finding.fix_version,
                "rule_ids": finding.rule_ids,
                "advisory_ids": finding.advisory_ids,
                "validation_state": "confirmed",
                "lifecycle_state": "open",
            })
        })
        .collect()
}

fn finding_id(worktree_key: &str, ecosystem: &str, name: &str, version: Option<&str>) -> String {
    let joined = [
        "guard.workspace-finding.v1",
        worktree_key,
        "supply_chain",
        ecosystem,
        name,
        version.unwrap_or(""),
    ]
    .join("\0");
    hex::encode(Sha256::digest(joined.as_bytes()))[..32].to_owned()
}

/// The package name with its namespace, such as `@scope/pkg` for npm: the
/// audit reports a scoped package's namespace apart from its name, and
/// `@a/pkg` is a different package from `pkg`.
fn package_name(package: &Object) -> Option<String> {
    let name = text(package.get("name"))?;
    match text(package.get("namespace")) {
        Some(namespace) if !name.starts_with(&format!("{namespace}/")) => {
            Some(prefix(&format!("{namespace}/{name}"), MAX_TEXT_CHARS))
        }
        _ => Some(name),
    }
}

/// `[ecosystem, name, version]` of every package the audit read, or null when
/// the audit stopped early or warned about a lockfile, since its package list
/// may then be short.
fn listed(payload: &Value) -> Value {
    let stopped = payload.get("audit_status").and_then(Value::as_str) == Some("incomplete")
        || payload.get("lockfile_warnings").is_some_and(truthy);
    let Some(packages) = evaluation(payload)
        .and_then(|evaluation| evaluation.get("packages"))
        .and_then(Value::as_array)
        .filter(|_| !stopped)
    else {
        return Value::Null;
    };
    let listed: BTreeSet<[String; 3]> = packages
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|package| {
            let name = package_name(package)?;
            let version = text(package.get("resolvedVersion"))
                .or_else(|| text(package.get("requestedVersion")))
                .unwrap_or_default();
            let ecosystem = text(package.get("ecosystem")).unwrap_or_else(|| "unknown".to_owned());
            Some([ecosystem, name, version])
        })
        .collect();
    json!(listed)
}

/// Packages that went unchecked because no advisory bundle is cached. The
/// evaluator can add review reasons (an unidentified package, a lockfile
/// drift) beside the miss; none of them means advisories were consulted.
fn unchecked(payload: &Value, packages: &[&Object]) -> usize {
    let cached = evaluation(payload).map(|evaluation| {
        evaluation
            .get("bundle_version")
            .is_some_and(|value| !value.is_null())
    });
    if cached != Some(false) {
        return 0;
    }
    packages
        .iter()
        .filter(|package| {
            reason_codes(package)
                .iter()
                .any(|code| code.as_str() == Some(NO_CACHED_MATCH))
        })
        .count()
}

fn evaluation(payload: &Value) -> Option<&Object> {
    payload.get("evaluation").and_then(Value::as_object)
}

fn packages(payload: &Value) -> Vec<&Object> {
    evaluation(payload)
        .and_then(|evaluation| evaluation.get("packages"))
        .and_then(Value::as_array)
        .map(|packages| packages.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn reasons(package: &Object) -> Vec<&Object> {
    package
        .get("reasons")
        .and_then(Value::as_array)
        .map(|reasons| reasons.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn reason_codes(package: &Object) -> Vec<&Value> {
    reasons(package)
        .into_iter()
        .filter_map(|item| item.get("code"))
        .chain(package.get("ruleId"))
        .filter(|code| !code.is_null())
        .collect()
}

fn lookup_unavailable(package: &Object) -> bool {
    if package.get("decision").and_then(Value::as_str) == Some("block") {
        return false;
    }
    let codes = reason_codes(package);
    !codes.is_empty()
        && codes.iter().all(|code| {
            code.as_str()
                .is_some_and(|code| LOOKUP_UNAVAILABLE.contains(&code))
        })
}

fn max_severity(reasons: &[&Object]) -> usize {
    let found: BTreeSet<String> = reasons
        .iter()
        .filter_map(|item| item.get("severity").and_then(Value::as_str))
        .map(str::to_lowercase)
        .collect();
    SEVERITY_ORDER
        .iter()
        .position(|level| found.contains(*level))
        .unwrap_or(SEVERITY_ORDER.len() - 1)
}

/// The `package_identities` reply: each finding's id, under the id the last
/// run gave its package, and whether each earlier finding's package is settled
/// (reported again, or no longer listed by an audit that read every file).
pub(crate) fn package_identities(query: &PackageAuditPackageIdentitiesQueryV1) -> Value {
    let listed: Option<Vec<Coordinate>> = query.listed.as_ref().map(|listed| {
        listed
            .iter()
            .map(|[ecosystem, name, version]| {
                Coordinate([json!(ecosystem), json!(name), json!(version)])
            })
            .collect()
    });
    let mut known: BTreeMap<String, &Value> = BTreeMap::new();
    for item in query.earlier.iter().filter_map(supply_chain) {
        if let Some(id) = item.get("finding_id").filter(|id| truthy(id)) {
            known.entry(Coordinate::of(item).key()).or_insert(id);
        }
    }
    let reported: BTreeSet<String> = query
        .findings
        .iter()
        .filter_map(supply_chain)
        .map(|item| Coordinate::of(item).key())
        .collect();
    let packages: BTreeMap<String, Coordinate> = query
        .findings
        .iter()
        .filter_map(supply_chain)
        .map(Coordinate::of)
        .chain(listed.iter().flatten().cloned())
        .map(|coordinate| (coordinate.key(), coordinate))
        .collect();
    // A bare name is only another run's name for one package when no other
    // reported or listed package has or would take it.
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for (key, coordinate) in &packages {
        *names.entry(key.clone()).or_default() += 1;
        if let Some(unscoped) = coordinate.unscoped() {
            *names.entry(unscoped.key()).or_default() += 1;
        }
    }
    let finding_ids: Vec<Value> = query
        .findings
        .iter()
        .map(|item| {
            let own = item.get("finding_id").cloned().unwrap_or(Value::Null);
            let Some(item) = supply_chain(item) else {
                return own;
            };
            let coordinate = Coordinate::of(item);
            if let Some(id) = known.get(&coordinate.key()) {
                return (*id).clone();
            }
            coordinate
                .unscoped()
                .map(|unscoped| unscoped.key())
                .filter(|key| names.get(key) == Some(&1))
                .and_then(|key| known.get(&key))
                .map_or(own, |id| (*id).clone())
        })
        .collect();
    let settled: Vec<bool> = query
        .earlier
        .iter()
        .map(|item| {
            supply_chain(item).is_some_and(|item| settled(item, &reported, listed.as_deref()))
        })
        .collect();
    json!({ "finding_ids": finding_ids, "settled": settled })
}

fn settled(item: &Object, reported: &BTreeSet<String>, listed: Option<&[Coordinate]>) -> bool {
    let coordinate = Coordinate::of(item);
    let key = coordinate.key();
    if reported.contains(&key) {
        return true;
    }
    let Some(listed) = listed else {
        return false;
    };
    if listed.iter().any(|package| package.key() == key) {
        return false;
    }
    // An earlier run may have named a scoped package the audit still lists by
    // its bare name.
    listed
        .iter()
        .all(|package| package.unscoped().map(|unscoped| unscoped.key()) != Some(key.clone()))
}

fn supply_chain(item: &Value) -> Option<&Object> {
    item.as_object()
        .filter(|item| item.get("source_kind").and_then(Value::as_str) == Some("supply_chain"))
}

/// `(ecosystem, package_name, package_version or "")` as the finding stores them.
#[derive(Clone)]
struct Coordinate([Value; 3]);

impl Coordinate {
    fn of(item: &Object) -> Self {
        let field = |key: &str| item.get(key).cloned().unwrap_or(Value::Null);
        let version = item
            .get("package_version")
            .filter(|version| truthy(version))
            .cloned()
            .unwrap_or_else(|| json!(""));
        Self([field("ecosystem"), field("package_name"), version])
    }

    fn key(&self) -> String {
        Value::Array(self.0.to_vec()).to_string()
    }

    /// The coordinate under the bare name earlier runs gave a scoped package.
    fn unscoped(&self) -> Option<Self> {
        let [ecosystem, name, version] = &self.0;
        let name = name.as_str().filter(|name| name.contains('/'))?;
        let bare = name.rsplit('/').next().unwrap_or(name);
        Some(Self([ecosystem.clone(), json!(bare), version.clone()]))
    }
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

/// `str.strip()` whitespace: Unicode White_Space plus the ASCII separators.
fn python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn prefix(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

/// A stripped, non-empty string cut to 256 characters.
fn text(value: Option<&Value>) -> Option<String> {
    let stripped = value?.as_str()?.trim_matches(python_space);
    (!stripped.is_empty()).then(|| prefix(stripped, MAX_TEXT_CHARS))
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.is_empty())
                .map(|item| prefix(item, MAX_TEXT_CHARS))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "workspace_package_findings_tests.rs"]
mod tests;
