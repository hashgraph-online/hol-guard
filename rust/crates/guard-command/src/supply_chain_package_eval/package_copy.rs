use super::*;

/// `_normalize_package_user_copy` (:1507-1524).
// supply_chain_package_eval.py:1507-1524
pub(super) fn normalize_package_user_copy(
    user_copy: &SupplyChainUserCopy,
    policy_action: GuardAction,
) -> SupplyChainUserCopy {
    let mut dashboard_url = user_copy.dashboard_url.clone();
    if looks_like_cloud_inbox_url(dashboard_url.as_deref()) {
        dashboard_url = None;
    }
    let mut harness_message = CLOUD_INBOX_URL_RE
        .replace_all(user_copy.harness_message.as_str(), "")
        .trim()
        .to_string();
    harness_message = harness_message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    harness_message = strip_review_evidence_tail(&harness_message);
    let terminal_action = matches!(
        policy_action,
        GuardAction::SandboxRequired | GuardAction::Block
    );
    if terminal_action {
        dashboard_url = None;
        harness_message = LOCAL_APPROVAL_INSTRUCTION_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = LOCAL_APPROVAL_REQUEST_URL_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = LOCAL_REVIEW_INSTRUCTION_RE
            .replace_all(&harness_message, "")
            .to_string();
        harness_message = harness_message
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
    }
    let needs_local_review = matches!(
        policy_action,
        GuardAction::Review | GuardAction::RequireReapproval
    );
    if needs_local_review
        && !harness_message
            .to_ascii_lowercase()
            .contains("review this request in hol guard, then retry.")
    {
        harness_message = format!("{harness_message} {LOCAL_REVIEW_INSTRUCTION}")
            .trim()
            .to_string();
    }
    SupplyChainUserCopy {
        title: user_copy.title.clone(),
        summary: user_copy.summary.clone(),
        next_step: user_copy.next_step.clone(),
        dashboard_url,
        harness_message,
    }
}

/// `_with_support_metadata` (:4746-4751).
// supply_chain_package_eval.py:4746-4751
pub(super) fn with_support_metadata(package: &Map<String, Value>) -> Map<String, Value> {
    let ecosystem =
        optional_string(package.get("ecosystem")).unwrap_or_else(|| "unsupported".to_string());
    let metadata = crate::local_supply_chain::ecosystem_support_metadata(&ecosystem);
    let mut enriched = package.clone();
    if let Some(v) = metadata.get("support_level") {
        enriched.insert("supportLevel".to_string(), v.clone());
    }
    if let Some(v) = metadata.get("support_label") {
        enriched.insert("supportLabel".to_string(), v.clone());
    }
    enriched
}

/// `_package_display_name` (:4989-4995).
// supply_chain_package_eval.py:4989-4995
pub(super) fn package_display_name(package: &Map<String, Value>) -> String {
    if let Some(alias) = optional_string(package.get("alias")) {
        return alias;
    }
    let namespace = optional_string(package.get("namespace"));
    let name = optional_string(package.get("name")).unwrap_or_else(|| "package".to_string());
    match namespace {
        Some(ns) => format!("{ns}/{name}"),
        None => name,
    }
}

/// `_uses_uv_pip_install` (:4975-4977).
// supply_chain_package_eval.py:4975-4977
pub(super) fn uses_uv_pip_install(package: &Map<String, Value>) -> bool {
    let command = optional_string(package.get("redactedCommand")).unwrap_or_default();
    let parts: Vec<&str> = command.split_whitespace().collect();
    parts.len() >= 3 && parts[..3] == ["uv", "pip", "install"]
}

/// `_package_install_target` (:4980-4986).
// supply_chain_package_eval.py:4980-4986
pub(super) fn package_install_target(package: &Map<String, Value>) -> String {
    let alias = optional_string(package.get("alias"));
    let mut no_alias = package.clone();
    no_alias.remove("alias");
    let package_name = package_display_name(&no_alias);
    let ecosystem = optional_string(package.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    match (alias, ecosystem.as_str()) {
        (Some(a), "npm") => format!("{a}@npm:{package_name}"),
        (Some(a), _) => a,
        (None, _) => package_name,
    }
}

/// `_fix_command` (:4949-4972).
// supply_chain_package_eval.py:4949-4972
pub(super) fn fix_command(package: &Map<String, Value>) -> Option<String> {
    let package_name = package_install_target(package);
    let fix_version = optional_string(package.get("recommendedFixVersion"))?;
    let ecosystem = optional_string(package.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
    let package_manager =
        optional_string(package.get("packageManager")).unwrap_or_else(|| "npm".to_string());
    if fix_version.is_empty() {
        return None;
    }
    if ecosystem == "pypi" {
        return Some(match package_manager.as_str() {
            "uv" if uses_uv_pip_install(package) => {
                format!("uv pip install {package_name}=={fix_version}")
            }
            "uv" => format!("uv add {package_name}=={fix_version}"),
            "poetry" => format!("poetry add {package_name}@{fix_version}"),
            "pipenv" => format!("pipenv install {package_name}=={fix_version}"),
            _ => format!("pip install {package_name}=={fix_version}"),
        });
    }
    Some(match package_manager.as_str() {
        "pnpm" => format!("pnpm add {package_name}@{fix_version}"),
        "yarn" => format!("yarn add {package_name}@{fix_version}"),
        "bun" => format!("bun add {package_name}@{fix_version}"),
        _ => format!("npm install {package_name}@{fix_version}"),
    })
}

/// `_result_package_identity` (:5073-5099).
// supply_chain_package_eval.py:5073-5099
pub(super) fn result_package_identity(
    deps: &SupplyChainEvalDeps<'_>,
    package: &Map<String, Value>,
) -> (String, String, String, String, String, String) {
    let ecosystem = optional_string(package.get("ecosystem"));
    let name = optional_string(package.get("name")).unwrap_or_else(|| "package".to_string());
    let namespace = optional_string(package.get("namespace"));
    let version = optional_string(package.get("resolvedVersion"))
        .or_else(|| optional_string(package.get("requestedVersion")));
    if let Some(eco) = &ecosystem {
        if let Ok(identity) = deps.identity.canonical_package_identity(
            eco,
            namespace.as_deref(),
            &name,
            version.as_deref().unwrap_or("*"),
        ) {
            return (
                "canonical".to_string(),
                identity.ecosystem,
                identity.namespace.unwrap_or_default(),
                identity.name,
                identity.version,
                String::new(),
            );
        }
    }
    let opaque_sha256 = stable_digest_hex(
        serde_json::to_string(&Value::Object(package.clone()))
            .unwrap_or_default()
            .as_bytes(),
    );
    (
        "opaque".to_string(),
        ecosystem.unwrap_or_default(),
        namespace.unwrap_or_default(),
        name,
        version.unwrap_or_default(),
        opaque_sha256,
    )
}

/// `_evidence_id` (:5060-5070).
// supply_chain_package_eval.py:5060-5070
pub(super) fn evidence_id(
    deps: &SupplyChainEvalDeps<'_>,
    package_intent_hash: &str,
    package: &Map<String, Value>,
) -> String {
    let decision =
        optional_string(package.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let dependency_path =
        optional_string(package.get("dependencyPath")).unwrap_or_else(|| "direct".to_string());
    let identity = result_package_identity(deps, package);
    let identity_payload = json!({
        "decision": decision,
        "dependency_path": dependency_path,
        "package_identity": [
            identity.0,
            identity.1,
            identity.2,
            identity.3,
            identity.4,
            identity.5,
        ],
        "package_intent_hash": package_intent_hash,
    });
    let encoded = serde_json::to_string(&identity_payload).unwrap_or_default();
    format!(
        "evidence-{}",
        stable_digest_hex_len(encoded.as_bytes(), Some(16))
    )
}

/// `_should_record_package` (:5055-5057).
// supply_chain_package_eval.py:5055-5057
pub(super) fn should_record_package(package: &Map<String, Value>, decision: &str) -> bool {
    let package_decision =
        optional_string(package.get("decision")).unwrap_or_else(|| decision.to_string());
    matches!(package_decision.as_str(), "block" | "ask" | "warn") || decision == "monitor"
}

/// `_looks_like_cloud_inbox_url` (:1536-1540).
// supply_chain_package_eval.py:1536-1540
pub(super) fn looks_like_cloud_inbox_url(url: Option<&str>) -> bool {
    let Some(url) = url else { return false };
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    // The Python uses urllib.parse.urlparse; we match on the path suffix.
    let path = trimmed
        .split("://")
        .nth(1)
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    path == "/guard/inbox"
}

/// `_strip_review_evidence_tail` (:1530-1533).
// supply_chain_package_eval.py:1530-1533
pub(super) fn strip_review_evidence_tail(message: &str) -> String {
    let stripped = message.trim();
    let lower = stripped.to_ascii_lowercase();
    for suffix in [
        "Review evidence: .",
        "Review evidence:.",
        "Review evidence:",
    ] {
        if lower.ends_with(&suffix.to_ascii_lowercase()) {
            return stripped[..stripped.len() - suffix.len()]
                .trim_end()
                .to_string();
        }
    }
    stripped.to_string()
}

/// `_normalize_bundle_action` (:4832-4837).
// supply_chain_package_eval.py:4832-4837
pub(super) fn normalize_bundle_action(value: &str) -> String {
    if value == "review" {
        return "ask".to_string();
    }
    if decision_rank_map().contains_key(value) {
        return value.to_string();
    }
    "monitor".to_string()
}

/// `_EvaluationDraft.to_dict` (:221-231 in the dataclass body).
// supply_chain_package_eval.py:221-231
impl EvaluationDraft {
    pub fn to_dict(&self) -> Value {
        json_obj(vec![
            ("decision", Value::String(self.decision.clone())),
            ("enforcement", Value::String(self.enforcement.clone())),
            (
                "entitlement_state",
                Value::String(self.entitlement_state.clone()),
            ),
            ("cache_status", Value::String(self.cache_status.clone())),
            (
                "packages",
                Value::Array(self.packages.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "reasons",
                Value::Array(self.reasons.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "matched_rule_id",
                self.matched_rule_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "exception_id",
                self.exception_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("refresh_required", Value::Bool(self.refresh_required)),
            (
                "record_monitor_evidence",
                Value::Bool(self.record_monitor_evidence),
            ),
            (
                "bundle_version",
                self.bundle_version
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("policy_version", Value::String(self.policy_version.clone())),
            (
                "external_archive_inspection",
                Value::Array(
                    self.external_archive_downloads
                        .iter()
                        .map(|d| {
                            json_obj(vec![
                                ("sha256", Value::String(d.sha256.clone())),
                                ("size", Value::Number(d.size.into())),
                                (
                                    "source_url_hash",
                                    Value::String(stable_digest_hex(d.source_url.as_bytes())),
                                ),
                                (
                                    "final_url_hash",
                                    Value::String(stable_digest_hex(d.final_url.as_bytes())),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "external_archive_source_hashes",
                Value::Array(
                    self.external_archive_source_hashes
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
        ])
    }
}
