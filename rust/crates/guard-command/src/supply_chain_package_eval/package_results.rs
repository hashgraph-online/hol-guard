use super::*;

pub(super) fn optional_value(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

/// Fields shared by every direct package result built from a target; both the
/// target-only and the cached-bundle builders start from this one definition.
pub(super) fn direct_result_base(target: &Map<String, Value>) -> Map<String, Value> {
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

#[allow(dead_code)]
pub(super) fn package_target_result(
    target: &Map<String, Value>,
    decision: &str,
    reasons: Vec<Map<String, Value>>,
    rule_id: Option<&str>,
) -> Map<String, Value> {
    let mut r = direct_result_base(target);
    r.insert("decision".to_string(), Value::String(decision.to_string()));
    r.insert(
        "ecosystem".to_string(),
        target.get("ecosystem").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "name".to_string(),
        target.get("name").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "namespace".to_string(),
        target.get("namespace").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "requestedVersion".to_string(),
        optional_string(target.get("range"))
            .or_else(|| optional_string(target.get("version")))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert(
        "resolvedVersion".to_string(),
        optional_string(target.get("version"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    r.insert("recommendedFixVersion".to_string(), Value::Null);
    r.insert("riskScore".to_string(), Value::Null);
    if let Some(rid) = rule_id {
        r.insert("ruleId".to_string(), Value::String(rid.to_string()));
    }
    r.insert(
        "reasons".to_string(),
        Value::Array(reasons.into_iter().map(Value::Object).collect()),
    );
    r
}

#[allow(dead_code)]
pub(super) fn heuristic_package_result(
    target: &Map<String, Value>,
    decision: &str,
    code: &str,
    message: &str,
    severity: &str,
) -> Map<String, Value> {
    heuristic_package_result_with(target, decision, code, message, severity, None, None)
}

/// `_heuristic_package_result` with the optional resolved and recommended-fix versions.
pub(super) fn heuristic_package_result_with(
    target: &Map<String, Value>,
    decision: &str,
    code: &str,
    message: &str,
    severity: &str,
    resolved_version: Option<&str>,
    recommended_fix_version: Option<&str>,
) -> Map<String, Value> {
    let mut reason = Map::new();
    reason.insert("code".to_string(), Value::String(code.to_string()));
    reason.insert("message".to_string(), Value::String(message.to_string()));
    reason.insert("severity".to_string(), Value::String(severity.to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    let mut r = package_target_result(target, decision, vec![reason], None);
    if let Some(version) = resolved_version {
        r.insert(
            "resolvedVersion".to_owned(),
            Value::String(version.to_owned()),
        );
    }
    if let Some(version) = recommended_fix_version {
        r.insert(
            "recommendedFixVersion".to_owned(),
            Value::String(version.to_owned()),
        );
    }
    for (key, src) in [
        ("sourceIdentity", "source_identity"),
        ("sourceRepository", "source_repository"),
        ("sourceRevisionKind", "source_revision_kind"),
    ] {
        r.insert(
            key.to_string(),
            optional_string(target.get(src))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    r
}

#[allow(dead_code)]
pub(super) fn target_is_external_https_archive(target: &Map<String, Value>) -> bool {
    let Some(url) = optional_string(target.get("source_url")) else {
        return false;
    };
    url.starts_with("https://")
        && (url.ends_with(".tar.gz")
            || url.ends_with(".tgz")
            || url.ends_with(".tar")
            || url.ends_with(".zip"))
}
