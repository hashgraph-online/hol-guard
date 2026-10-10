//! Package results built from a cached Guard Cloud bundle (`_bundle_package_result`
//! and its helpers in `supply_chain_package_eval.py`).

use super::advisory_aliases::{bundle_advisory_aliases, primary_bundle_advisory_id};
use super::*;
use crate::supply_chain_bundle::{SupplyChainBundle, SupplyChainBundlePackage};

pub(super) type BundlePackageIndex<'a> =
    BTreeMap<CanonicalPackageIdentity, &'a SupplyChainBundlePackage>;

/// Typed view of the already-validated bundle carried by the response.
pub(super) fn typed_bundle(response: &SupplyChainBundleResponse) -> Option<SupplyChainBundle> {
    SupplyChainBundle::from_dict(&response.bundle).ok()
}

fn target_str(target: &Map<String, Value>, key: &str) -> String {
    optional_string(target.get(key)).unwrap_or_default()
}

fn package_map(package: &SupplyChainBundlePackage) -> Map<String, Value> {
    package.to_dict().as_object().cloned().unwrap_or_default()
}

/// `_bundle_package_label`.
pub(super) fn bundle_package_label(
    package: &SupplyChainBundlePackage,
    version: Option<&str>,
) -> String {
    let name = match &package.namespace {
        Some(namespace) => format!("{namespace}/{}", package.name),
        None => package.name.clone(),
    };
    let version = version
        .filter(|value| !value.is_empty())
        .unwrap_or(package.version.as_str());
    format!("{name}@{version}")
}

/// `_bundle_package_name_matches`.
pub(super) fn bundle_package_name_matches(
    deps: &SupplyChainEvalDeps<'_>,
    package: &SupplyChainBundlePackage,
    target: &Map<String, Value>,
) -> bool {
    let target_ecosystem = optional_string(target.get("ecosystem"));
    if let Some(ecosystem) = target_ecosystem.as_deref() {
        match deps.identity.normalize_ecosystem(ecosystem) {
            Ok(normalized) if normalized == package.ecosystem => {}
            _ => return false,
        }
    }
    let package_identity = deps.identity.canonical_package_identity(
        &package.ecosystem,
        package.namespace.as_deref(),
        &package.name,
        "*",
    );
    let target_identity = deps.identity.canonical_package_identity(
        target_ecosystem.as_deref().unwrap_or(&package.ecosystem),
        optional_string(target.get("namespace")).as_deref(),
        &target_str(target, "name"),
        "*",
    );
    matches!((package_identity, target_identity), (Ok(left), Ok(right)) if left == right)
}

/// `_bundle_package`.
pub(super) fn bundle_package<'a>(
    deps: &SupplyChainEvalDeps<'_>,
    bundle: &'a SupplyChainBundle,
    target: &Map<String, Value>,
    package_version: &str,
) -> Option<&'a SupplyChainBundlePackage> {
    bundle.packages.iter().find(|item| {
        bundle_package_name_matches(deps, item, target) && item.version == package_version
    })
}

/// `_bundle_package_index`.
pub(super) fn bundle_package_index<'a>(
    deps: &SupplyChainEvalDeps<'_>,
    bundle: &'a SupplyChainBundle,
) -> BundlePackageIndex<'a> {
    let mut index = BundlePackageIndex::new();
    for package in &bundle.packages {
        if let Ok(identity) = deps.identity.canonical_package_identity(
            &package.ecosystem,
            package.namespace.as_deref(),
            &package.name,
            &package.version,
        ) {
            index.entry(identity).or_insert(package);
        }
    }
    index
}

/// `_bundle_package_from_index`.
pub(super) fn bundle_package_from_index<'a>(
    deps: &SupplyChainEvalDeps<'_>,
    index: &BundlePackageIndex<'a>,
    package_name: &str,
    package_version: &str,
    ecosystem: Option<&str>,
) -> Option<&'a SupplyChainBundlePackage> {
    let identity = deps
        .identity
        .parse_package_identity(ecosystem?, package_name, package_version)
        .ok()?;
    index.get(&identity).copied()
}

/// `_is_bundle_stale`.
pub(super) fn is_bundle_stale(
    deps: &SupplyChainEvalDeps<'_>,
    response: &SupplyChainBundleResponse,
    now_timestamp: Option<f64>,
) -> bool {
    deps.bundle
        .check_supply_chain_bundle_freshness(&response.bundle, now_timestamp)
        .is_err()
}

/// `_emergency_deny_bundle_message`.
pub(super) fn emergency_deny_bundle_message(
    target: &Map<String, Value>,
    resolved_version: &str,
    reason: &str,
) -> String {
    let label = format!("{}@{resolved_version}", package_display_name(target));
    match reason {
        "known_malware" => format!("Emergency denylist blocked {label} for known malware."),
        "known_exploited" => format!(
            "Emergency denylist blocked {label} because it is a known exploited vulnerability."
        ),
        "critical_active_exploit" => {
            format!("Emergency denylist blocked {label} for a critical active exploit.")
        }
        _ => format!("Emergency denylist blocked {label}."),
    }
}

/// `_bundle_reason_message`.
fn bundle_reason_message(
    package: &SupplyChainBundlePackage,
    decision: &str,
    reason: &str,
    stale: bool,
) -> String {
    let label = bundle_package_label(package, None);
    if stale {
        return match decision {
            "block" => format!(
                "Cached bundle is stale, but Guard still blocked {label} from advisory intelligence."
            ),
            "ask" => format!("Cached bundle is stale, so Guard still requires approval for {label}."),
            "warn" => format!("Cached bundle is stale, so Guard still warns on {label}."),
            _ => format!("Cached bundle is stale, so Guard kept {label} in monitor mode."),
        };
    }
    match reason {
        "known_malware_or_kev" => {
            format!("Cached bundle flagged {label} from advisory intelligence.")
        }
        "maintainer_compromise" => {
            format!("Cached bundle flagged {label} for probable maintainer compromise.")
        }
        _ => format!("Cached bundle matched {label}."),
    }
}

fn optional_value(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

/// Fields shared by every direct package result built from a target.
fn direct_result_base(target: &Map<String, Value>) -> Map<String, Value> {
    let mut result = Map::new();
    result.insert("direct".into(), Value::Bool(true));
    result.insert("dependencyPath".into(), Value::Null);
    result.insert(
        "packageManager".into(),
        Value::String(
            optional_string(target.get("package_manager")).unwrap_or_else(|| "npm".to_owned()),
        ),
    );
    result.insert(
        "redactedCommand".into(),
        optional_value(optional_string(target.get("redacted_command"))),
    );
    result.insert(
        "alias".into(),
        optional_value(optional_string(target.get("alias"))),
    );
    result
}

/// `_bundle_package_result`.
pub(super) fn bundle_package_result(
    target: &Map<String, Value>,
    response: &SupplyChainBundleResponse,
    package: &SupplyChainBundlePackage,
    decision: &str,
    reason: &str,
    stale: bool,
    resolved_version: &str,
) -> Map<String, Value> {
    let severity = if stale {
        "unknown"
    } else {
        package.normalized_severity.as_str()
    };
    let package_dict = package_map(package);
    let aliases = bundle_advisory_aliases(response, &package_dict);
    let mut result = direct_result_base(target);
    let entries = [
        ("decision", Value::String(decision.to_owned())),
        ("ecosystem", Value::String(package.ecosystem.clone())),
        ("name", Value::String(package.name.clone())),
        ("namespace", optional_value(package.namespace.clone())),
        (
            "requestedVersion",
            optional_value(
                optional_string(target.get("range"))
                    .or_else(|| optional_string(target.get("version"))),
            ),
        ),
        (
            "resolvedVersion",
            Value::String(resolved_version.to_owned()),
        ),
        (
            "recommendedFixVersion",
            optional_value(package.recommended_fix_version.clone()),
        ),
        ("riskScore", json!(package.risk_score)),
        (
            "sourceIdentity",
            optional_value(optional_string(target.get("source_identity"))),
        ),
        (
            "sourceRepository",
            optional_value(optional_string(target.get("source_repository"))),
        ),
        (
            "sourceRevisionKind",
            optional_value(optional_string(target.get("source_revision_kind"))),
        ),
        ("relatedAdvisoryIds", json!(package.related_advisory_ids)),
        (
            "reasons",
            json!([{
                "advisoryId": optional_value(primary_bundle_advisory_id(response, &package_dict)),
                "code": reason,
                "message": bundle_reason_message(package, decision, reason, stale),
                "severity": severity,
                "source": "bundle",
            }]),
        ),
    ];
    for (key, value) in entries {
        result.insert(key.to_owned(), value);
    }
    if !aliases.is_empty() {
        result.insert("advisoryAliases".into(), json!(aliases));
    }
    result
}

/// `_recommended_fix_allow_package_result`.
pub(super) fn recommended_fix_allow_package_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    resolved_version: &str,
    bundle: &SupplyChainBundle,
) -> Option<Map<String, Value>> {
    let package = bundle.packages.iter().find(|package| {
        bundle_package_name_matches(deps, package, target)
            && package.version != resolved_version
            && package.recommended_fix_version.as_deref() == Some(resolved_version)
    })?;
    let mut result = direct_result_base(target);
    let entries = [
        ("decision", Value::String("allow".into())),
        ("ecosystem", Value::String(package.ecosystem.clone())),
        ("name", target.get("name").cloned().unwrap_or(Value::Null)),
        (
            "namespace",
            target.get("namespace").cloned().unwrap_or(Value::Null),
        ),
        (
            "requestedVersion",
            Value::String(
                optional_string(target.get("range")).unwrap_or_else(|| resolved_version.to_owned()),
            ),
        ),
        (
            "resolvedVersion",
            Value::String(resolved_version.to_owned()),
        ),
        ("recommendedFixVersion", Value::Null),
        ("riskScore", Value::Null),
        (
            "reasons",
            json!([{
                "code": "recommended_fix_version",
                "message": format!(
                    "Requested version {resolved_version} matches Guard's recommended fix for {}.",
                    package_display_name(target)
                ),
                "severity": "low",
                "source": "bundle",
            }]),
        ),
    ];
    for (key, value) in entries {
        result.insert(key.to_owned(), value);
    }
    Some(result)
}

/// `_policy_package_result`.
pub(super) fn policy_package_result(
    target: &Map<String, Value>,
    decision: &str,
    rule_id: &str,
) -> Map<String, Value> {
    let mut result = direct_result_base(target);
    let entries = [
        ("decision", Value::String(decision.to_owned())),
        (
            "ecosystem",
            target.get("ecosystem").cloned().unwrap_or(Value::Null),
        ),
        ("name", target.get("name").cloned().unwrap_or(Value::Null)),
        (
            "namespace",
            target.get("namespace").cloned().unwrap_or(Value::Null),
        ),
        (
            "requestedVersion",
            optional_value(
                optional_string(target.get("version"))
                    .or_else(|| optional_string(target.get("range"))),
            ),
        ),
        (
            "resolvedVersion",
            optional_value(optional_string(target.get("version"))),
        ),
        ("recommendedFixVersion", Value::Null),
        ("riskScore", Value::Null),
        ("ruleId", Value::String(rule_id.to_owned())),
        (
            "reasons",
            json!([{
                "code": "policy_override",
                "message": format!("Local synced policy rule {rule_id} matched this package request."),
                "severity": "low",
                "source": "policy",
            }]),
        ),
    ];
    for (key, value) in entries {
        result.insert(key.to_owned(), value);
    }
    result
}
