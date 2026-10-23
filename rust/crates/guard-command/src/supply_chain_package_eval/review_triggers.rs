//! Which local package signals pause an install.
//!
//! An install pauses by default only on risk: a Guard Cloud advisory, malware
//! or KEV match, an integrity failure, or a suspicious install script. Local
//! signals that only mean Guard cannot vouch for a package (no reputation, a
//! lockfile that does not pin it yet, a direct source, a custom registry) are
//! recorded quietly unless the user's risk actions ask for review. The
//! evaluator still emits those signals as reviewable; this pass resolves them
//! against the user's settings at the evaluator's exit, so a cached evaluation
//! always follows the current settings.

use super::registry_install_identity::LIFECYCLE_SCRIPTS_ENABLED_CODE;
use super::*;

/// A package Guard cannot identify or read evidence for.
pub(crate) const PACKAGE_UNKNOWN: &str = "package_unknown";
/// A manifest dependency the existing lockfile does not pin yet.
pub(crate) const PACKAGE_LOCKFILE_DRIFT: &str = "package_lockfile_drift";
/// A git, URL, archive, local-path or replaced source instead of the registry.
pub(crate) const PACKAGE_DIRECT_SOURCE: &str = "package_direct_source";
/// A non-default package index or registry.
pub(crate) const PACKAGE_CUSTOM_REGISTRY: &str = "package_custom_registry";
/// Every package install or update.
pub(crate) const PACKAGE_INSTALL: &str = "package_install";
/// Package code that runs at install or build time.
const PACKAGE_SCRIPT: &str = "package_script";

const PACKAGE_INSTALL_CODE: &str = "package_install_review";
const PACKAGE_CUSTOM_REGISTRY_CODE: &str = "package_custom_registry";
/// Marks a package result whose review protects Guard's own release, which no
/// setting relaxes. The pass removes it before the result leaves the evaluator.
pub(super) const OWN_PACKAGE_RELEASE_FIELD: &str = "ownPackageRelease";

/// The risk-action key a reviewable reason code is tuned by.
fn trigger_key(code: &str) -> Option<&'static str> {
    Some(match code {
        "no_cached_match"
        | "unidentified_package"
        | "bun_lockfile_binary_fallback"
        | "lockfile_parse_incomplete"
        | LIFECYCLE_SCRIPTS_ENABLED_CODE => PACKAGE_UNKNOWN,
        "manifest_lockfile_unsynced" => PACKAGE_LOCKFILE_DRIFT,
        "git_dependency_source"
        | "external_tarball_source"
        | "local_path_dependency_source"
        | "go_replace_local_source"
        | "go_replace_mutable_source" => PACKAGE_DIRECT_SOURCE,
        "local_build_backend_risk" => PACKAGE_SCRIPT,
        PACKAGE_INSTALL_CODE => PACKAGE_INSTALL,
        PACKAGE_CUSTOM_REGISTRY_CODE => PACKAGE_CUSTOM_REGISTRY,
        _ => return None,
    })
}

/// The user's resolved action for each tunable package signal.
pub(crate) struct ReviewTriggers {
    config: GuardConfig,
    harness: Option<String>,
}

impl ReviewTriggers {
    pub(crate) fn load(
        deps: &SupplyChainEvalDeps<'_>,
        store: &dyn SupplyChainStore,
        artifact: &GuardArtifact,
        workspace_dir: Option<&Path>,
    ) -> Option<Self> {
        // An unreadable config keeps the evaluator's own decision rather than
        // relaxing a review the user may have asked for.
        let config = deps
            .config
            .load_guard_config(store.guard_home(), workspace_dir, false)
            .ok()?;
        let harness = Some(artifact.harness.clone()).filter(|harness| !harness.is_empty());
        Some(Self { config, harness })
    }

    #[cfg(test)]
    pub(crate) fn from_config(config: GuardConfig) -> Self {
        Self {
            config,
            harness: None,
        }
    }

    /// The package decision a risk action maps to.
    pub(crate) fn decision(&self, key: &str) -> &'static str {
        match resolve_risk_action(&self.config, Some(key), self.harness.as_deref()).as_deref() {
            Some("block") => "block",
            Some("require-reapproval" | "review" | "sandbox-required") => "ask",
            Some("warn") => "warn",
            _ => "monitor",
        }
    }

    /// The decision a set of reasons resolves to, when every reason that can
    /// pause an install is tunable. `None` when any reason is not.
    fn resolve_reasons<'r>(
        &self,
        reasons: impl IntoIterator<Item = &'r Map<String, Value>>,
    ) -> Option<&'static str> {
        let mut resolved: Option<&'static str> = None;
        for reason in reasons {
            let code = optional_string(reason.get("code")).unwrap_or_default();
            if is_annotation(&code) {
                continue;
            }
            let mut decision = self.decision(trigger_key(&code)?);
            if code == LIFECYCLE_SCRIPTS_ENABLED_CODE {
                // The install could run package code: a package-script setting
                // that asks for review holds it, a quieter one leaves it to
                // the package-unknown action it accompanies.
                let script = self.decision(PACKAGE_SCRIPT);
                if decision_rank(script) >= decision_rank("ask")
                    && decision_rank(script) > decision_rank(decision)
                {
                    decision = script;
                }
            }
            if resolved.is_none_or(|current| decision_rank(decision) > decision_rank(current)) {
                resolved = Some(decision);
            }
        }
        resolved
    }
}

/// Reasons that explain where evidence came from but never pause an install.
fn is_annotation(code: &str) -> bool {
    matches!(
        code,
        "cloud_auth_error" | "cloud_http_error" | "cloud_timeout"
    )
}

fn package_reasons(package: &Map<String, Value>) -> Vec<Map<String, Value>> {
    dict_items(package.get("reasons"))
}

fn decision_of(map: &Map<String, Value>) -> String {
    optional_string(map.get("decision")).unwrap_or_else(|| "monitor".to_string())
}

/// Wording for a tunable reason Guard only recorded. `None` drops the reason:
/// it exists only to explain a pause.
fn recorded_message(code: &str, name: &str) -> Option<String> {
    Some(match code {
        "unidentified_package" | LIFECYCLE_SCRIPTS_ENABLED_CODE => return None,
        "no_cached_match" => {
            "Guard recorded this package request and will keep watching for new intelligence."
                .to_string()
        }
        "bun_lockfile_binary_fallback" => {
            "Guard could not verify package identity from Bun's binary lockfile (bun.lockb), so it recorded this install.".to_string()
        }
        "lockfile_parse_incomplete" => {
            "Guard could not completely parse the existing lockfile, so it recorded this install without lockfile evidence.".to_string()
        }
        "manifest_lockfile_unsynced" => format!(
            "{name} is declared in the project manifest but is not pinned in the existing lockfile yet."
        ),
        "git_dependency_source" | "external_tarball_source" | "local_path_dependency_source"
        | "go_replace_local_source" | "go_replace_mutable_source" => format!(
            "{name} installs from a direct source instead of the package registry."
        ),
        _ => return Some(String::new()),
    })
}

/// Rewrite tunable reasons that no longer pause the install.
fn record_quietly(reasons: &mut Vec<Map<String, Value>>, name: &str) {
    reasons.retain_mut(|reason| {
        let code = optional_string(reason.get("code")).unwrap_or_default();
        if trigger_key(&code).is_none() {
            return true;
        }
        match recorded_message(&code, name) {
            None => false,
            Some(message) => {
                if !message.is_empty() {
                    reason.insert("message".to_string(), Value::String(message));
                }
                reason.insert("severity".to_string(), Value::String("low".to_string()));
                true
            }
        }
    });
}

fn trigger_reason(code: &str, message: &str) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String("medium".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    reason
}

/// Guard's own distribution from a direct source or custom registry: such an
/// install could replace Guard itself, so its review is never relaxed by a
/// setting. A plain registry install follows the user's settings.
fn is_guard_distribution_off_registry(package: &Map<String, Value>) -> bool {
    if optional_string(package.get("ecosystem")).as_deref() != Some("pypi") {
        return false;
    }
    let off_registry = package_reasons(package).iter().any(|reason| {
        optional_string(reason.get("code"))
            .and_then(|code| trigger_key(&code))
            .is_some_and(|key| key == PACKAGE_DIRECT_SOURCE || key == PACKAGE_CUSTOM_REGISTRY)
    });
    if !off_registry {
        return false;
    }
    optional_string(package.get("name")).is_some_and(|name| {
        let normalized: String = name
            .trim()
            .to_ascii_lowercase()
            .chars()
            .map(|c| if matches!(c, '_' | '.') { '-' } else { c })
            .collect();
        FIRST_PARTY_PYPI_PACKAGES.contains(normalized.as_str())
    })
}

/// Re-resolve every package whose review came only from tunable signals.
/// Returns true when any package decision changed.
fn resolve_packages(triggers: &ReviewTriggers, result: &mut PackageEvalResult) -> bool {
    let mut changed = false;
    for package in &mut result.packages {
        let own_release = package.remove(OWN_PACKAGE_RELEASE_FIELD) == Some(Value::Bool(true))
            || is_guard_distribution_off_registry(package);
        let current = decision_of(package);
        if own_release || decision_rank(&current) < decision_rank("ask") {
            continue;
        }
        let mut reasons = package_reasons(package);
        let Some(resolved) = triggers.resolve_reasons(&reasons) else {
            continue;
        };
        if resolved == current {
            continue;
        }
        if decision_rank(resolved) < decision_rank("ask") {
            record_quietly(&mut reasons, &package_display_name(package));
        }
        package.insert("decision".to_string(), Value::String(resolved.to_string()));
        package.insert(
            "reasons".to_string(),
            Value::Array(reasons.into_iter().map(Value::Object).collect()),
        );
        changed = true;
    }
    changed
}

/// Raise every package to an opt-in trigger's decision.
fn raise_packages(
    result: &mut PackageEvalResult,
    decision: &str,
    code: &str,
    message: &str,
) -> bool {
    let mut changed = false;
    for package in &mut result.packages {
        if decision_rank(&decision_of(package)) >= decision_rank(decision) {
            continue;
        }
        let mut reasons = package_reasons(package);
        reasons.push(trigger_reason(code, message));
        package.insert("decision".to_string(), Value::String(decision.to_string()));
        package.insert(
            "reasons".to_string(),
            Value::Array(reasons.into_iter().map(Value::Object).collect()),
        );
        changed = true;
    }
    changed
}

/// Apply the user's package review settings to a finished evaluation.
pub(crate) fn apply_review_triggers(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    triggers: &ReviewTriggers,
    mut result: PackageEvalResult,
) -> PackageEvalResult {
    let original_top = result.decision.clone();
    let original_max = packages_max(&result);
    let package_codes: BTreeSet<String> = result
        .packages
        .iter()
        .flat_map(package_reasons)
        .filter_map(|reason| optional_string(reason.get("code")))
        .collect();
    // A top-level decision no package explains is only re-resolved when it
    // rests on tunable reasons; anything else keeps it as a floor.
    let top_only: Vec<&Map<String, Value>> = result
        .reasons
        .iter()
        .filter(|reason| {
            optional_string(reason.get("code")).is_none_or(|code| !package_codes.contains(&code))
        })
        .collect();
    let explained_by_packages = original_max
        .as_deref()
        .is_some_and(|max| decision_rank(max) >= decision_rank(&original_top));
    let floor = if top_only.is_empty() && explained_by_packages {
        "allow".to_string()
    } else if decision_rank(&original_top) >= decision_rank("ask")
        && (explained_by_packages || result.packages.is_empty())
    {
        triggers
            .resolve_reasons(top_only.iter().copied())
            .map_or_else(|| original_top.clone(), str::to_string)
    } else {
        original_top.clone()
    };
    let mut changed = resolve_packages(triggers, &mut result);
    // A package exception the user saved answers the opt-in triggers too.
    let opt_in = result.exception_id.is_none();
    let install = triggers.decision(PACKAGE_INSTALL);
    if opt_in && decision_rank(install) > decision_rank("monitor") {
        changed |= raise_packages(
            &mut result,
            install,
            PACKAGE_INSTALL_CODE,
            "Your settings review every package install or update.",
        );
    }
    let registry = triggers.decision(PACKAGE_CUSTOM_REGISTRY);
    if opt_in
        && decision_rank(registry) > decision_rank("monitor")
        && command_uses_alternate_package_index(artifact)
    {
        changed |= raise_packages(
            &mut result,
            registry,
            PACKAGE_CUSTOM_REGISTRY_CODE,
            "This install uses a custom package index or registry, and your settings review those.",
        );
    }
    let decision = match packages_max(&result) {
        Some(max) if decision_rank(&max) > decision_rank(&floor) => max,
        _ => floor,
    };
    if decision == original_top && !changed {
        return result;
    }
    refinalize(deps, result, decision)
}

fn packages_max(result: &PackageEvalResult) -> Option<String> {
    result
        .packages
        .iter()
        .map(decision_of)
        .max_by_key(|decision| decision_rank(decision))
}

/// Rebuild the copy and action for a re-resolved evaluation.
fn refinalize(
    deps: &SupplyChainEvalDeps<'_>,
    mut result: PackageEvalResult,
    decision: String,
) -> PackageEvalResult {
    result
        .packages
        .sort_by_key(|package| std::cmp::Reverse(decision_rank(&decision_of(package))));
    let mut top_reasons = result.reasons.clone();
    if decision_rank(&decision) < decision_rank("ask") {
        // A package already carries its own rewording of a tunable reason.
        let package_codes: BTreeSet<String> = result
            .packages
            .iter()
            .flat_map(package_reasons)
            .filter_map(|reason| optional_string(reason.get("code")))
            .collect();
        top_reasons.retain(|reason| {
            optional_string(reason.get("code"))
                .is_none_or(|code| trigger_key(&code).is_none() || !package_codes.contains(&code))
        });
        record_quietly(&mut top_reasons, "This package");
    }
    let mut reasons: Vec<Map<String, Value>> = Vec::new();
    for reason in result
        .packages
        .iter()
        .flat_map(package_reasons)
        .chain(top_reasons)
    {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    let draft = EvaluationDraft {
        decision,
        enforcement: result.enforcement.clone(),
        entitlement_state: result.entitlement_state.clone(),
        cache_status: result.cache_status.clone(),
        packages: result.packages.clone(),
        reasons,
        matched_rule_id: result.matched_rule_id.clone(),
        exception_id: result.exception_id.clone(),
        refresh_required: result.refresh_required,
        record_monitor_evidence: result.record_monitor_evidence,
        bundle_version: result.bundle_version.clone(),
        policy_version: result.policy_version.clone(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: result.external_archive_source_hashes.clone(),
    };
    let mut refreshed = finalize_evaluation(
        deps,
        &draft,
        &result.package_intent_hash,
        result.workspace_fingerprint.as_deref(),
    );
    refreshed.external_archive_downloads = std::mem::take(&mut result.external_archive_downloads);
    refreshed
}

#[cfg(test)]
#[path = "review_triggers_tests.rs"]
mod tests;
