use super::*;

/// `_own_package_review_message` (:3148-3153).
// supply_chain_package_eval.py:3148-3153
#[allow(dead_code)]
pub(super) fn own_package_review_message(package_name: &str) -> String {
    format!(
        "HOL Guard cannot automatically allow this {package_name} install. \
         Only a reinstall of the release already running on this device, from the default package index, \
         skips review. A new publish or another package source stays on review so a compromised release \
         cannot install by itself. Approve this install once if you trust it."
    )
}

/// `_installed_project_version` (:3075-3088).
/// The bundled Python `importlib.metadata.version` lookup is unavailable in
/// the native runtime; the guard's own distribution version is the only
/// installed value we can resolve (via `CARGO_PKG_VERSION`), validated to a
/// canonical PEP-440 release (no local segment).
// supply_chain_package_eval.py:3075-3088
#[allow(dead_code)]
pub(super) fn installed_project_version(
    deps: &SupplyChainEvalDeps<'_>,
    project_name: &str,
) -> Option<String> {
    // Only the guard's own distribution can be resolved without a Python
    // interpreter; anything else reports not-found.
    let normalized = normalize_package_name(deps, "pypi", project_name);
    if !FIRST_PARTY_PYPI_PACKAGES.contains(normalized.as_str()) {
        return None;
    }
    let found = env!("CARGO_PKG_VERSION").to_string();
    let parsed = deps.semver.version(&found).ok()?;
    // `parsed.local is not None or found != str(parsed)` -> reject.
    if parsed.normalized.contains('+') || found != parsed.normalized {
        return None;
    }
    Some(parsed.normalized)
}

/// `_installed_release_reinstall_result` (:3112-3145).
// supply_chain_package_eval.py:3112-3145
#[allow(dead_code)]
pub(super) fn installed_release_reinstall_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let package_name = own_package_name(deps, target)?;
    let requested = optional_string(target.get("version"))?;
    let normalized_name = optional_string(target.get("normalized_name"))
        .unwrap_or_else(|| normalize_package_name(deps, "pypi", &package_name));
    let installed = installed_project_version(deps, &normalized_name)?;
    let requested_v = deps.semver.version(&requested).ok()?;
    let installed_v = deps.semver.version(&installed).ok()?;
    if requested_v != installed_v {
        return None;
    }
    Some(heuristic_package_result(
        target,
        "allow",
        "installed_release_reinstall",
        &format!(
            "{package_name}=={installed} matches the release already running on this device. \
             Reinstalling that same release does not select a newly published version."
        ),
        "low",
    ))
}

/// `_unknown_package_result` (:3157-3202).
// supply_chain_package_eval.py:3157-3202
#[allow(dead_code)]
pub(super) fn unknown_package_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    fail_closed_unidentified: bool,
    identity_resolved: bool,
) -> Map<String, Value> {
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    let decision =
        unidentified_package_decision(&ecosystem, fail_closed_unidentified, identity_resolved);
    let requires_review = decision == "ask" || decision == "block";
    let package_name =
        optional_string(target.get("name")).unwrap_or_else(|| "this package".to_string());
    let own_package = own_package_name(deps, target);
    let no_match_message = if requires_review && own_package.is_some() {
        own_package_review_message(own_package.as_deref().unwrap())
    } else if requires_review {
        format!(
            "HOL Guard on this device does not have current package reputation for {package_name}. \
             Review this install now. Guard Cloud is optional and can add live package reputation."
        )
    } else {
        "Guard recorded this package request and will keep watching for new intelligence."
            .to_string()
    };
    let mut reasons: Vec<Map<String, Value>> = Vec::new();
    let mut first = Map::new();
    first.insert(
        "code".to_string(),
        Value::String("no_cached_match".to_string()),
    );
    first.insert("message".to_string(), Value::String(no_match_message));
    first.insert(
        "severity".to_string(),
        Value::String(
            if decision == "block" {
                "high"
            } else if requires_review {
                "medium"
            } else {
                "unknown"
            }
            .to_string(),
        ),
    );
    first.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    reasons.push(first);
    if requires_review {
        let mut extra = Map::new();
        extra.insert(
            "code".to_string(),
            Value::String("unidentified_package".to_string()),
        );
        extra.insert(
            "message".to_string(),
            Value::String(format!(
                "Local checks could not confirm current safety details for {}. \
                 This does not mean the package is unsafe; approve it once if you trust it.",
                optional_string(target.get("name")).unwrap_or_default()
            )),
        );
        extra.insert("severity".to_string(), Value::String("medium".to_string()));
        extra.insert(
            "source".to_string(),
            Value::String("guard-local".to_string()),
        );
        reasons.push(extra);
    }
    package_target_result(target, &decision, reasons, None)
}

/// `_system_package_monitor_result` (:2893-2902).
// supply_chain_package_eval.py:2893-2902
#[allow(dead_code)]
pub(super) fn system_package_monitor_result(target: &Map<String, Value>) -> Map<String, Value> {
    heuristic_package_result(
        target,
        "monitor",
        "system_package_manager_monitor_only",
        "Guard treats system package managers as monitor-only coverage today and will not \
         pretend advisory blocking.",
        "low",
    )
}

/// `_homebrew_package_monitor_result` (:2906-2926).
// supply_chain_package_eval.py:2906-2926
#[allow(dead_code)]
pub(super) fn homebrew_package_monitor_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Map<String, Value> {
    let command = optional_string(target.get("redacted_command")).unwrap_or_default();
    let signals = match deps.risk.detect_supply_chain_risk(&command, None) {
        Ok(signals) => signals,
        Err(_) => {
            return heuristic_package_result(
                target,
                "block",
                "supply_chain_risk_evaluation_failed",
                "Guard could not complete the package supply-chain risk evaluation.",
                "high",
            );
        }
    };
    if !signals.is_empty() {
        let strongest = signals
            .iter()
            .rev()
            .max_by_key(|s| {
                severity_rank_value(
                    optional_string(s.get("severity"))
                        .as_deref()
                        .unwrap_or("unknown"),
                )
            })
            .expect("nonempty risk signals");
        return heuristic_package_result(
            target,
            "warn",
            "homebrew_package_manager_generic_risk",
            &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
            &optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string()),
        );
    }
    heuristic_package_result(
        target,
        "warn",
        "homebrew_package_manager_monitor_only",
        "Guard intercepts Homebrew requests today, records formula, cask, tap, and Brewfile intent, \
         and treats them as monitor-only until Homebrew advisory enforcement is available.",
        "low",
    )
}

/// `_unsupported_ecosystem_result` (:2929-2942).
// supply_chain_package_eval.py:2929-2942
#[allow(dead_code)]
pub(super) fn unsupported_ecosystem_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Map<String, Value> {
    let command = optional_string(target.get("redacted_command")).unwrap_or_default();
    let signals = match deps.risk.detect_supply_chain_risk(&command, None) {
        Ok(signals) => signals,
        Err(_) => {
            return heuristic_package_result(
                target,
                "block",
                "supply_chain_risk_evaluation_failed",
                "Guard could not complete the package supply-chain risk evaluation.",
                "high",
            );
        }
    };
    if !signals.is_empty() {
        let strongest = signals
            .iter()
            .rev()
            .max_by_key(|s| {
                severity_rank_value(
                    optional_string(s.get("severity"))
                        .as_deref()
                        .unwrap_or("unknown"),
                )
            })
            .expect("nonempty risk signals");
        let severity =
            optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string());
        let decision = if severity == "critical" || severity == "high" {
            "block"
        } else {
            "warn"
        };
        return heuristic_package_result(
            target,
            decision,
            "unsupported_ecosystem_generic_risk",
            &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
            &severity,
        );
    }
    heuristic_package_result(
        target,
        "monitor",
        "unsupported_ecosystem_monitor_only",
        "Guard does not provide advisory coverage for this ecosystem yet; recording the request.",
        "low",
    )
}

/// `_local_source_dependency_result` (:2944-2954).
// supply_chain_package_eval.py:2944-2954
#[allow(dead_code)]
pub(super) fn local_source_dependency_result(
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let source_url = optional_string(target.get("source_url"))?;
    if !source_url.starts_with("file:") {
        return None;
    }
    Some(heuristic_package_result(
        target,
        "ask",
        "local_path_dependency_source",
        "Local path dependency requires review before install.",
        "medium",
    ))
}
