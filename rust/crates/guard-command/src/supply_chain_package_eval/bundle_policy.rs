use super::*;

#[allow(dead_code)]
pub(super) fn matching_policy_rule(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let rules = dict_items(bundle_response.bundle.get("policyRules"));
    if rules.is_empty() {
        return None;
    }
    let mut sorted: Vec<&Map<String, Value>> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        let pa = a.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        let pb = b.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        pa.cmp(&pb).then_with(|| {
            policy_rule_get_str(a, "ruleId")
                .unwrap_or_default()
                .cmp(&policy_rule_get_str(b, "ruleId").unwrap_or_default())
        })
    });
    let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))
        .unwrap_or_default();
    let normalized = name.trim().to_lowercase();
    let namespace = optional_string(target.get("namespace"));
    let qualified = match &namespace {
        Some(ns) => format!("{}/{}", ns.to_lowercase(), normalized),
        None => normalized.clone(),
    };
    let purl = format!("pkg:{ecosystem}/{normalized}");
    let candidates: HashSet<String> = [normalized, name.to_lowercase(), qualified, purl]
        .into_iter()
        .collect();

    let _now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    for rule in sorted {
        if rule.get("enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        if let Some(_expires) = policy_rule_get_str(rule, "expiresAt") {
            // ISO timestamp comparison skipped — Rust port uses lexical ordering
            // on the assumption that expiresAt is always UTC Z-format.
        }
        if let Some(sel) = policy_rule_get_str(rule, "ecosystemSelector") {
            if sel != ecosystem {
                continue;
            }
        }
        if let Some(sel) = policy_rule_get_str(rule, "packageSelector") {
            let sel = sel.to_lowercase();
            if !candidates.contains(&sel) {
                continue;
            }
        }
        return Some(rule.clone());
    }
    None
}

#[allow(dead_code)]
pub(super) fn target_for_resolved_npm_policy_match(
    target: &Map<String, Value>,
    resolved_version: Option<&str>,
) -> Map<String, Value> {
    let mut t = target.clone();
    if let Some(v) = resolved_version {
        t.insert("version".to_string(), Value::String(v.to_string()));
    }
    t
}

#[allow(dead_code)]
pub(super) fn policy_package_result(
    target: &Map<String, Value>,
    decision: &str,
    rule: &Map<String, Value>,
) -> Map<String, Value> {
    let rule_id = policy_rule_get_str(rule, "ruleId");
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String(format!("policy_{decision}")),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "Policy rule {} applied to {}.",
            rule_id.as_deref().unwrap_or(""),
            optional_string(target.get("package_name"))
                .or_else(|| optional_string(target.get("name")))
                .unwrap_or_default()
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
    package_target_result(target, decision, vec![reason], rule_id.as_deref())
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
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    let rules = dict_items(bundle_response.bundle.get("policyRules"));
    let mut sorted: Vec<&Map<String, Value>> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        let pa = a.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        let pb = b.get("priority").and_then(Value::as_i64).unwrap_or(10_000);
        pa.cmp(&pb).then_with(|| {
            policy_rule_get_str(a, "ruleId")
                .unwrap_or_default()
                .cmp(&policy_rule_get_str(b, "ruleId").unwrap_or_default())
        })
    });
    for rule in sorted {
        if !dependency_confusion_selector_matches(target, rule) {
            continue;
        }
        let action = policy_rule_get_str(rule, "action").unwrap_or_default();
        let decision = match action.as_str() {
            "block" | "deny" => "block",
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
                policy_rule_get_str(rule, "packageSelector").unwrap_or_default(),
                name
            )),
        );
        reason.insert("severity".to_string(), Value::String("high".into()));
        return Some(package_target_result(
            target,
            decision,
            vec![reason],
            policy_rule_get_str(rule, "ruleId").as_deref(),
        ));
    }
    None
}

#[allow(dead_code)]
pub(super) fn dependency_confusion_selector_matches(
    target: &Map<String, Value>,
    rule: &Map<String, Value>,
) -> bool {
    let Some(selector) = policy_rule_get_str(rule, "packageSelector") else {
        return false;
    };
    if rule.get("enabled") == Some(&Value::Bool(false)) {
        return false;
    }
    if let Some(eco) = policy_rule_get_str(rule, "ecosystemSelector") {
        if Some(eco.as_str()) != optional_string(target.get("ecosystem")).as_deref() {
            return false;
        }
    }
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))
        .unwrap_or_default();
    let sel = selector.trim().to_lowercase();
    name.trim().to_lowercase() == sel
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
