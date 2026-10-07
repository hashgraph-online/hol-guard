use super::*;

fn rule_string<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn policy_selector_matches_target(selector: &str, target: &Map<String, Value>) -> bool {
    let version = rule_string(target, "version");
    let requested = rule_string(target, "range");
    if rule_string(target, "ecosystem").unwrap_or("npm") == "npm" {
        return match version {
            Some(version) => crate::js_semver::version_matches_js_selector(version, selector),
            None => requested == Some(selector),
        };
    }
    if requested == Some(selector) {
        return true;
    }
    let Some(version) = version else { return false };
    if selector == version
        || selector.strip_prefix('=') == Some(version)
        || selector.strip_prefix("==") == Some(version)
    {
        return true;
    }
    match (
        crate::pep440::Version::parse(version),
        crate::pep440::SpecifierSet::parse(selector),
    ) {
        (Ok(version), Ok(specifier)) => specifier.contains(&version),
        _ => false,
    }
}

pub(super) fn matching_policy_rule<'a>(
    bundle_response: &'a SupplyChainBundleResponse,
    target: &Map<String, Value>,
    harness: &str,
    package_severity: Option<&str>,
    now_timestamp: Option<f64>,
) -> Option<&'a Map<String, Value>> {
    let rules = bundle_response.bundle.get("policyRules")?.as_array()?;
    let mut best: Option<&Map<String, Value>> = None;
    let ecosystem = rule_string(target, "ecosystem").unwrap_or("npm");
    let name = rule_string(target, "name")
        .or_else(|| rule_string(target, "package_name"))
        .unwrap_or("");
    let normalized = rule_string(target, "normalized_name")
        .unwrap_or(name)
        .to_lowercase();
    let lower_name = name.to_lowercase();
    let qualified =
        rule_string(target, "namespace").map(|ns| format!("{}/{lower_name}", ns.to_lowercase()));
    let purl = format!("pkg:{ecosystem}/{normalized}");
    let now = now_timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    });
    for rule in rules.iter().filter_map(Value::as_object) {
        if rule.get("enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        if rule_string(rule, "expiresAt")
            .and_then(parse_evaluation_timestamp)
            .is_some_and(|expires| expires <= now)
        {
            continue;
        }
        if rule_string(rule, "harnessSelector")
            .is_some_and(|selector| selector != "*" && selector != harness)
        {
            continue;
        }
        if rule_string(rule, "ecosystemSelector").is_some_and(|selector| selector != ecosystem) {
            continue;
        }
        if let Some(selector) = rule_string(rule, "packageSelector") {
            let selector = selector.to_lowercase();
            if ![
                normalized.as_str(),
                lower_name.as_str(),
                qualified.as_deref().unwrap_or(&lower_name),
                purl.as_str(),
            ]
            .contains(&selector.as_str())
            {
                continue;
            }
        }
        if rule_string(rule, "versionRangeSelector")
            .is_some_and(|selector| !policy_selector_matches_target(selector, target))
        {
            continue;
        }
        if let Some(threshold) = rule_string(rule, "severityThreshold") {
            let Some(severity) = package_severity else {
                continue;
            };
            if severity_rank_value(severity) < severity_rank_value(threshold) {
                continue;
            }
        }
        if best.is_none_or(|selected| {
            let priority = |rule: &Map<String, Value>| {
                rule.get("priority")
                    .and_then(Value::as_i64)
                    .unwrap_or(10_000)
            };
            priority(rule)
                .cmp(&priority(selected))
                .then_with(|| {
                    rule_string(rule, "ruleId")
                        .unwrap_or("")
                        .cmp(rule_string(selected, "ruleId").unwrap_or(""))
                })
                .is_lt()
        }) {
            best = Some(rule);
        }
    }
    best
}

#[allow(dead_code)]
pub(super) fn target_for_resolved_npm_policy_match(
    target: &Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut t = target.clone();
    if rule_string(target, "ecosystem").unwrap_or("npm") == "npm" {
        if let Some(v) = resolved_version {
            t.insert("version".to_string(), Value::String(v.to_string()));
            t.insert("range".to_string(), Value::Null);
        }
    }
    t
}

#[allow(dead_code)]
pub(super) fn policy_package_result(
    target: &Map<String, Value>,
    decision: &str,
    rule: &Map<String, Value>,
) -> Map<String, Value> {
    let rule_id = rule_string(rule, "ruleId");
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String(format!("policy_{decision}")),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Policy rule {} applied to {}.",
            rule_id.unwrap_or(""),
            rule_string(target, "package_name")
                .or_else(|| rule_string(target, "name"))
                .unwrap_or("")
        )),
    );
    reason.insert(
        "severity".to_string(),
        Value::String(
            if decision == "block" {
                "high"
            } else {
                "medium"
            }
            .into(),
        ),
    );
    reason.insert("source".to_string(), Value::String("policy".into()));
    package_target_result(target, decision, vec![reason], rule_id)
}

#[allow(dead_code)]
pub(super) fn bind_resolved_npm_policy_result(
    result: Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut r = result;
    if let Some(v) = resolved_version {
        r.insert("resolvedVersion".to_string(), Value::String(v.to_string()));
    }
    r
}

#[allow(dead_code)]
pub(super) fn dependency_confusion_policy_package_result(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    if rule_string(target, "ecosystem").unwrap_or("npm") != "npm"
        || rule_string(target, "namespace").is_some()
    {
        return None;
    }
    let name = rule_string(target, "name")?.to_lowercase();
    let now = crate::local_supply_chain::Timestamp::now_utc().unix_seconds_f64();
    let rules = bundle_response.bundle.get("policyRules")?.as_array()?;
    let rule = rules
        .iter()
        .filter_map(Value::as_object)
        .filter(|rule| dependency_confusion_selector_matches(target, rule))
        .filter(|rule| {
            !rule_string(rule, "expiresAt")
                .and_then(parse_evaluation_timestamp)
                .is_some_and(|expires| expires <= now)
        })
        .min_by(|a, b| {
            let priority = |rule: &Map<String, Value>| {
                rule.get("priority")
                    .and_then(Value::as_i64)
                    .unwrap_or(10_000)
            };
            priority(a).cmp(&priority(b)).then_with(|| {
                rule_string(a, "ruleId")
                    .unwrap_or("")
                    .cmp(rule_string(b, "ruleId").unwrap_or(""))
            })
        })?;
    let action = normalize_bundle_action(rule_string(rule, "action").unwrap_or(""));
    let decision = match action.as_str() {
        "block" => "block",
        "ask" => "ask",
        _ => "warn",
    };
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String("dependency_confusion_risk".into()),
    );
    reason.insert(
            "message".to_string(),
            Value::String(format!(
                "Policy reserves internal package selector {}; installing public package {} may cause dependency confusion.",
                rule_string(rule, "packageSelector").unwrap_or(""),
                name
            )),
        );
    reason.insert("severity".to_string(), Value::String("high".into()));
    reason.insert("source".to_string(), Value::String("policy".into()));
    Some(package_target_result(
        target,
        decision,
        vec![reason],
        rule_string(rule, "ruleId"),
    ))
}

#[allow(dead_code)]
pub(super) fn dependency_confusion_selector_matches(
    target: &Map<String, Value>,
    rule: &Map<String, Value>,
) -> bool {
    if rule_string(target, "ecosystem").unwrap_or("npm") != "npm"
        || rule_string(target, "namespace").is_some()
        || rule.get("enabled") == Some(&Value::Bool(false))
        || rule_string(rule, "ecosystemSelector").is_some_and(|ecosystem| ecosystem != "npm")
    {
        return false;
    }
    let Some(selector) = rule_string(rule, "packageSelector") else {
        return false;
    };
    if !selector.starts_with('@') {
        return false;
    }
    let Some((_, selector)) = selector.split_once('/') else {
        return false;
    };
    if selector.is_empty() || selector == "*" {
        return false;
    }
    let selector = selector.to_lowercase();
    let name = rule_string(target, "name").unwrap_or("").to_lowercase();
    match selector.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == selector,
    }
}

#[allow(dead_code)]
pub(super) fn emergency_deny_bundle_message(target: &Map<String, Value>) -> String {
    format!(
        "Emergency deny rule blocks {}.",
        optional_string(target.get("package_name"))
            .or_else(|| optional_string(target.get("name")))
            .unwrap_or_else(|| "package".to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn resolved_npm_policy_uses_clause_local_prerelease_membership() {
        let target = object(json!({"ecosystem":"npm","range":"^1.0.0"}));
        assert!(policy_selector_matches_target("^1.0.0", &target));
        let resolved = target_for_resolved_npm_policy_match(&target, Some("1.5.0-beta.1"));
        assert!(!policy_selector_matches_target("^1.0.0", &resolved));
        assert!(policy_selector_matches_target(
            ">=1.5.0-beta.1 <2",
            &resolved
        ));
        assert!(!policy_selector_matches_target("^1 || broken", &resolved));
        let pypi = object(json!({"ecosystem":"pypi","range":">=1","version":"1.2rc1"}));
        assert_eq!(target_for_resolved_npm_policy_match(&pypi, Some("2")), pypi);
        assert!(policy_selector_matches_target(">=1", &pypi));
        assert!(!policy_selector_matches_target("==1.3.*", &pypi));
    }

    #[test]
    fn rule_constraints_exclude_wrong_versions_harnesses_expiry_and_unknown_severity() {
        let target = object(
            json!({"ecosystem":"npm","name":"lab","normalized_name":"lab","version":"2.0.0"}),
        );
        let response = SupplyChainBundleResponse {
            bundle: object(json!({"policyRules":[
                {"ruleId":"wrong-version","priority":0,"versionRangeSelector":"^1"},
                {"ruleId":"wrong-harness","priority":0,"harnessSelector":"codex"},
                {"ruleId":"expired","priority":0,"expiresAt":"2026-01-01T01:00:00+01:00"},
                {"ruleId":"too-severe","priority":0,"severityThreshold":"critical"},
                {"ruleId":"disabled","priority":0,"enabled":false},
                {"ruleId":"eligible","packageSelector":"pkg:npm/lab","harnessSelector":"*","versionRangeSelector":"^2","severityThreshold":"high"}
            ]})),
            ..Default::default()
        };
        let now = parse_evaluation_timestamp("2026-01-01T00:00:00Z").unwrap();
        let matched =
            matching_policy_rule(&response, &target, "omp", Some("high"), Some(now)).unwrap();
        assert_eq!(matched["ruleId"], "eligible");
        assert!(matching_policy_rule(&response, &target, "omp", None, Some(now)).is_none());
        assert!(
            matching_policy_rule(&response, &target, "omp", Some("medium"), Some(now)).is_none()
        );
    }

    #[test]
    fn policy_expiry_preserves_fractional_second_boundaries() {
        let response = SupplyChainBundleResponse {
            bundle: object(json!({"policyRules":[
                {"ruleId":"fractional","expiresAt":"2026-01-01T00:00:00.500001Z"}
            ]})),
            ..Default::default()
        };
        let target = object(json!({"ecosystem":"npm","name":"lab"}));
        let before = parse_evaluation_timestamp("2026-01-01T00:00:00.500000Z");
        let deadline = parse_evaluation_timestamp("2026-01-01T00:00:00.500001Z");
        assert!(matching_policy_rule(&response, &target, "omp", None, before).is_some());
        assert!(matching_policy_rule(&response, &target, "omp", None, deadline).is_none());
    }

    #[test]
    fn priority_and_rule_id_order_apply_only_to_eligible_rules() {
        let target = object(
            json!({"ecosystem":"pypi","name":"lab","normalized_name":"lab","version":"1!1.2+local"}),
        );
        let response = SupplyChainBundleResponse {
            bundle: object(json!({"policyRules":[
                {"ruleId":"first-id-but-ineligible","priority":0,"versionRangeSelector":"==1.2"},
                {"ruleId":"later","priority":10,"versionRangeSelector":"==1!1.2"},
                {"ruleId":"z","priority":5,"versionRangeSelector":"==1!1.2"},
                {"ruleId":"a","priority":5,"versionRangeSelector":"==1!1.2"},
                {"ruleId":"highest-default-priority","versionRangeSelector":"==1!1.2"}
            ]})),
            ..Default::default()
        };
        assert_eq!(
            matching_policy_rule(&response, &target, "omp", None, Some(0.0)).unwrap()["ruleId"],
            "a"
        );
    }
    #[test]
    fn only_live_scoped_reservations_match_public_unscoped_names() {
        let target = json!({"ecosystem":"npm","name":"foo-tool","package_name":"foo-tool"});
        let target = target.as_object().unwrap();
        for selector in ["foo-tool", "@internal/*", "@internal/", "pkg:npm/foo-tool"] {
            let rule = json!({"packageSelector":selector});
            assert!(!dependency_confusion_selector_matches(
                target,
                rule.as_object().unwrap()
            ));
        }
        let rules = json!({"policyRules":[
            {"ruleId":"expired","priority":0,"packageSelector":"@internal/foo*","expiresAt":"2000-01-01T00:00:00Z"},
            {"ruleId":"disabled","priority":0,"packageSelector":"@internal/foo*","enabled":false},
            {"ruleId":"wrong-ecosystem","priority":0,"packageSelector":"@internal/foo*","ecosystemSelector":"pypi"},
            {"ruleId":"live","packageSelector":"@internal/foo*","action":"block"}
        ]});
        let response = SupplyChainBundleResponse {
            bundle: rules.as_object().unwrap().clone(),
            ..Default::default()
        };
        let result = dependency_confusion_policy_package_result(&response, target).unwrap();
        assert_eq!(result["ruleId"], "live");
        assert_eq!(result["reasons"][0]["code"], "dependency_confusion_risk");
        for target in [
            json!({"ecosystem":"pypi","name":"foo-tool"}),
            json!({"ecosystem":"npm","name":"foo-tool","namespace":"@internal"}),
        ] {
            assert!(dependency_confusion_policy_package_result(
                &response,
                target.as_object().unwrap()
            )
            .is_none());
        }
    }
}
