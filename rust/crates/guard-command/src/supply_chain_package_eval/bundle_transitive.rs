//! Lockfile version resolution and transitive lockfile results for the bundle
//! evaluation (`_lockfile_dependency_versions`, `_resolved_target_version`,
//! `_transitive_lockfile_results`, `_transitive_lockfile_decision`).

use super::bundle_results::{
    bundle_package_from_index, bundle_package_index, bundle_package_label,
    emergency_deny_bundle_message, is_bundle_stale,
};
use super::lockfile_evidence::incomplete_lockfile_package_result;
use super::manifest_dependencies::{
    cargo_lock_target_versions, composer_lock_target_versions, gemfile_lock_target_versions,
    manifest_dependency_versions, manifest_direct_dependency_names,
};
use super::package_lock::package_lock_target_versions_from_entries;
use super::pnpm_lock::pnpm_lock_target_versions;
use super::python_lock::{
    pipfile_lock_target_versions, poetry_lock_target_versions, uv_lock_target_versions,
};
use super::version_selectors::dependency_package_name;
use super::yarn_bun_lock::{bun_lock_target_versions, yarn_lock_target_versions};
use super::*;
use crate::supply_chain_bundle::{
    is_high_confidence_block, SupplyChainBundle, SupplyChainBundlePackage,
};

const TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD: i64 = 900;

/// `OfflineSupplyChainDecision` as returned by the bundle seam.
pub(super) struct OfflineDecision {
    pub action: String,
    pub reason: String,
    pub stale: bool,
    pub emergency_deny: bool,
    pub recommended_fix_version: Option<String>,
}

pub(super) fn offline_decision(
    deps: &SupplyChainEvalDeps<'_>,
    response: &SupplyChainBundleResponse,
    package_name: &str,
    package_version: &str,
    ecosystem: Option<&str>,
    now_timestamp: Option<f64>,
) -> OfflineDecision {
    let decision = deps
        .bundle
        .evaluate_cached_supply_chain_bundle(
            response,
            package_name,
            Some(package_version),
            ecosystem,
            now_timestamp,
        )
        .unwrap_or_default();
    OfflineDecision {
        action: optional_string(decision.get("action")).unwrap_or_default(),
        reason: optional_string(decision.get("reason")).unwrap_or_default(),
        stale: decision.get("stale") == Some(&Value::Bool(true)),
        emergency_deny: decision.get("emergency_deny") == Some(&Value::Bool(true)),
        recommended_fix_version: optional_string(decision.get("recommended_fix_version")),
    }
}

fn is_bun_binary_lockfile(name: &str) -> bool {
    name.eq_ignore_ascii_case("bun.lockb")
}

/// `_lockfile_dependency_versions`.
pub(super) fn lockfile_dependency_versions(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let Some(workspace) = workspace_dir else {
        return BTreeMap::new();
    };
    let Some(lockfile_paths) = artifact
        .metadata
        .get("lockfile_paths")
        .and_then(Value::as_array)
    else {
        return BTreeMap::new();
    };
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    let python_names = manifest_direct_dependency_names(deps, Some(workspace), artifact, "pypi");
    for relative in lockfile_paths {
        let relative = value_to_plain_string(relative);
        let Some(path) = resolve_path_within_workspace(workspace, &relative) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if is_bun_binary_lockfile(&name) {
            continue;
        }
        let Some(text) = deps.workspace_io.read_text(workspace, &relative) else {
            continue;
        };
        let parse_result = parse_lockfile_text_result(deps, &name, text.as_bytes());
        if !parse_result.complete {
            continue;
        }
        let found = match name.as_str() {
            "package-lock.json" => {
                package_lock_target_versions_from_entries(deps, &parse_result, targets)
            }
            "pnpm-lock.yaml" => pnpm_lock_target_versions(deps, &text, targets),
            "yarn.lock" => yarn_lock_target_versions(&text, targets),
            "bun.lock" => bun_lock_target_versions(deps, &parse_result, targets),
            "Cargo.lock" => cargo_lock_target_versions(deps, &text, targets),
            "composer.lock" => composer_lock_target_versions(deps, &text, targets),
            "Gemfile.lock" => gemfile_lock_target_versions(deps, &text, targets),
            "poetry.lock" => poetry_lock_target_versions(deps, &text, targets, &python_names),
            "uv.lock" => uv_lock_target_versions(deps, &text, targets, &python_names),
            "Pipfile.lock" => pipfile_lock_target_versions(deps, &text, targets, &python_names),
            _ => BTreeMap::new(),
        };
        versions.extend(found);
    }
    for (key, version) in manifest_dependency_versions(deps, Some(workspace), artifact, targets) {
        versions.entry(key).or_insert(version);
    }
    versions
}

/// `_resolved_target_version`.
pub(super) fn resolved_target_version(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    lockfile_versions: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(version) = optional_string(target.get("version")) {
        return Some(version);
    }
    if let Some(version) = lockfile_target_key(target).and_then(|key| lockfile_versions.get(&key)) {
        return Some(version.clone());
    }
    let requested = optional_string(target.get("range"))?;
    if let Some(exact) = exact_version(&requested) {
        return Some(exact);
    }
    registry_resolved_target_version(deps, target)
}

/// `_transitive_lockfile_decision`.
pub(super) fn transitive_lockfile_decision(
    package: &SupplyChainBundlePackage,
    stale: bool,
) -> String {
    let action = if package.default_action == "allow" {
        "monitor"
    } else {
        package.default_action.as_str()
    };
    let decision = normalize_bundle_action(action);
    if stale && !is_high_confidence_block(package) {
        return if matches!(decision.as_str(), "block" | "ask" | "warn") {
            "warn".to_owned()
        } else {
            "monitor".to_owned()
        };
    }
    if decision != "block" {
        return decision;
    }
    if is_high_confidence_block(package)
        || package.confidence >= TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD
    {
        return "block".to_owned();
    }
    "warn".to_owned()
}

fn split_qualified(package_name: &str) -> (String, Option<String>) {
    let leaf = package_name
        .rsplit('/')
        .next()
        .unwrap_or(package_name)
        .to_owned();
    let namespace = if package_name.starts_with('@') && package_name.contains('/') {
        package_name
            .rsplit_once('/')
            .map(|(head, _)| head.to_owned())
    } else {
        None
    };
    (leaf, namespace)
}

#[allow(clippy::too_many_arguments)]
fn transitive_result(
    artifact: &GuardArtifact,
    decision: &str,
    ecosystem: &str,
    name: &str,
    namespace: Option<String>,
    version: &str,
    fix: Option<String>,
    risk_score: Value,
    dependency_path: &str,
    reason: Value,
) -> Map<String, Value> {
    let mut result = Map::new();
    let entries = [
        ("decision", Value::String(decision.to_owned())),
        ("ecosystem", Value::String(ecosystem.to_owned())),
        ("name", Value::String(name.to_owned())),
        ("namespace", namespace.map_or(Value::Null, Value::String)),
        ("requestedVersion", Value::String(version.to_owned())),
        ("resolvedVersion", Value::String(version.to_owned())),
        (
            "recommendedFixVersion",
            fix.map_or(Value::Null, Value::String),
        ),
        ("riskScore", risk_score),
        ("direct", Value::Bool(false)),
        ("dependencyPath", Value::String(dependency_path.to_owned())),
        (
            "packageManager",
            Value::String(
                optional_string(artifact.metadata.get("package_manager"))
                    .unwrap_or_else(|| "npm".into()),
            ),
        ),
        (
            "redactedCommand",
            optional_string(artifact.metadata.get("redacted_command"))
                .map_or(Value::Null, Value::String),
        ),
        ("reasons", Value::Array(vec![reason])),
    ];
    for (key, value) in entries {
        result.insert(key.to_owned(), value);
    }
    result
}

/// `_transitive_lockfile_results`.
pub(super) fn transitive_lockfile_results(
    deps: &SupplyChainEvalDeps<'_>,
    response: &SupplyChainBundleResponse,
    bundle: &SupplyChainBundle,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    now_timestamp: Option<f64>,
) -> Vec<Map<String, Value>> {
    let Some(workspace) = workspace_dir else {
        return Vec::new();
    };
    let Some(lockfile_paths) = artifact
        .metadata
        .get("lockfile_paths")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut results = Vec::new();
    let stale = is_bundle_stale(deps, response, now_timestamp);
    let index = bundle_package_index(deps, bundle);
    let mut names_by_ecosystem: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut all_names: HashSet<String> = HashSet::new();
    let direct_targets = evaluation_targets(deps, artifact, Some(workspace));
    for target in &direct_targets {
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        let mut candidates: Vec<String> = target_candidate_names(deps, target);
        candidates.push(optional_string(target.get("normalized_name")).unwrap_or_default());
        names_by_ecosystem
            .entry(ecosystem)
            .or_default()
            .extend(candidates.iter().cloned());
        all_names.extend(candidates);
    }
    for relative in lockfile_paths {
        let relative = value_to_plain_string(relative);
        let Some(path) = resolve_path_within_workspace(workspace, &relative) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if is_bun_binary_lockfile(&name) {
            continue;
        }
        let lockfile_ecosystem = lockfile_ecosystem_for_name(&name);
        let direct_names = lockfile_ecosystem
            .as_deref()
            .and_then(|ecosystem| names_by_ecosystem.get(ecosystem))
            .unwrap_or(&all_names);
        let Some(text) = deps.workspace_io.read_text(workspace, &relative) else {
            continue;
        };
        let parse_result = parse_lockfile_text_result(deps, &name, text.as_bytes());
        if !parse_result.complete {
            let target = direct_targets
                .first()
                .cloned()
                .unwrap_or_else(|| incomplete_lockfile_fallback_target(&parse_result));
            results.push(incomplete_lockfile_package_result(
                &target,
                &parse_result,
                "ask",
            ));
            continue;
        }
        let mut entries: Vec<(String, String, String, bool)> = Vec::new();
        for entry in &parse_result.entries {
            let normalized_path = entry.dependency_path.trim_matches('/').to_owned();
            if normalized_path.is_empty() {
                continue;
            }
            let package_name = if name == "package-lock.json" {
                Some(entry.package_name.clone())
            } else {
                dependency_package_name(&normalized_path)
            };
            let Some(package_name) = package_name else {
                continue;
            };
            let direct = direct_names.contains(&normalized_path);
            entries.push((
                entry.dependency_path.clone(),
                package_name,
                entry.version.clone(),
                direct,
            ));
        }
        let ecosystem_label = lockfile_ecosystem
            .clone()
            .unwrap_or_else(|| "npm".to_owned());
        for (dependency_path, package_name, version, direct) in entries {
            if direct {
                continue;
            }
            let package_match = bundle_package_from_index(
                deps,
                &index,
                &package_name,
                &version,
                lockfile_ecosystem.as_deref(),
            );
            let offline = offline_decision(
                deps,
                response,
                &package_name,
                &version,
                lockfile_ecosystem.as_deref(),
                now_timestamp,
            );
            if offline.emergency_deny && offline.action == "block" {
                let (leaf, namespace) = split_qualified(&package_name);
                let message_target = json!({
                    "name": leaf,
                    "namespace": namespace,
                    "ecosystem": ecosystem_label,
                });
                let message = emergency_deny_bundle_message(
                    message_target.as_object().unwrap_or(&Map::new()),
                    &version,
                    &offline.reason,
                );
                results.push(transitive_result(
                    artifact,
                    "block",
                    &ecosystem_label,
                    &leaf,
                    namespace,
                    &version,
                    offline.recommended_fix_version.clone(),
                    Value::Null,
                    &dependency_path,
                    json!({
                        "code": offline.reason,
                        "message": message,
                        "severity": "critical",
                        "source": "bundle",
                    }),
                ));
                continue;
            }
            let Some(package) = package_match else {
                continue;
            };
            let decision = transitive_lockfile_decision(package, stale);
            if !matches!(decision.as_str(), "ask" | "block" | "warn") {
                continue;
            }
            let downgraded =
                decision == "warn" && normalize_bundle_action(&package.default_action) == "block";
            let label = bundle_package_label(package, Some(&version));
            let (code, message) = if downgraded {
                (
                    "transitive_low_confidence_match",
                    format!(
                        "Existing lockfile includes {label} at transitive dependency path \
                         {dependency_path} with lower-confidence risk signals."
                    ),
                )
            } else {
                (
                    "transitive_lockfile_match",
                    format!(
                        "Existing lockfile already includes vulnerable {label} \
                         at dependency path {dependency_path}."
                    ),
                )
            };
            results.push(transitive_result(
                artifact,
                &decision,
                &package.ecosystem,
                &package.name,
                package.namespace.clone(),
                &version,
                package.recommended_fix_version.clone(),
                json!(package.risk_score),
                &dependency_path,
                json!({
                    "code": code,
                    "message": message,
                    "severity": package.normalized_severity,
                    "source": "lockfile",
                }),
            ));
        }
    }
    results
}

/// `_lockfile_ecosystem` keyed by file name; `None` for unknown lockfiles.
fn lockfile_ecosystem_for_name(name: &str) -> Option<String> {
    let ecosystem = match name.to_lowercase().as_str() {
        "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock" | "bun.lockb" => "npm",
        "poetry.lock" | "uv.lock" | "pipfile.lock" => "pypi",
        "cargo.lock" => "cargo",
        "composer.lock" => "packagist",
        "gemfile.lock" => "rubygems",
        "go.sum" => "go",
        "gradle.lockfile" => "maven",
        _ => return None,
    };
    Some(ecosystem.to_owned())
}

/// `package_has_incomplete_lockfile` over a package result.
pub(super) fn package_result_has_incomplete_lockfile(package: &Map<String, Value>) -> bool {
    if package.get("lockfileParseComplete") == Some(&Value::Bool(false)) {
        return true;
    }
    dict_items(package.get("reasons")).iter().any(|reason| {
        reason.get("code").and_then(Value::as_str) == Some("lockfile_parse_incomplete")
    })
}
