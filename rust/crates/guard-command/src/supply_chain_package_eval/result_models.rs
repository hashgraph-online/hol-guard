use super::*;

/// `SupplyChainUserCopy` dataclass mirror (:163-178).
#[derive(Debug, Clone, Default)]
pub struct SupplyChainUserCopy {
    pub title: String,
    pub summary: String,
    pub next_step: Option<String>,
    pub dashboard_url: Option<String>,
    pub harness_message: String,
}

impl SupplyChainUserCopy {
    pub(super) fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("title".into(), Value::String(self.title.clone()));
        map.insert("summary".into(), Value::String(self.summary.clone()));
        match &self.next_step {
            Some(v) => map.insert("next_step".into(), Value::String(v.clone())),
            None => map.insert("next_step".into(), Value::Null),
        };
        match &self.dashboard_url {
            Some(v) => map.insert("dashboard_url".into(), Value::String(v.clone())),
            None => map.insert("dashboard_url".into(), Value::Null),
        };
        map.insert(
            "harness_message".into(),
            Value::String(self.harness_message.clone()),
        );
        Value::Object(map)
    }
}

/// `PackageRequestEvaluation` dataclass mirror (:181-312). Stored as a
/// `serde_json::Value` mirror so unported callers consume the exact dict.
#[derive(Debug, Clone)]
pub struct PackageEvalResult {
    pub decision: String,
    pub policy_action: String,
    pub enforcement: String,
    pub entitlement_state: String,
    pub cache_status: String,
    pub package_intent_hash: String,
    pub policy_version: String,
    pub bundle_version: Option<String>,
    pub workspace_fingerprint: Option<String>,
    pub reasons: Vec<Map<String, Value>>,
    pub packages: Vec<Map<String, Value>>,
    pub risk_summary: String,
    pub user_copy: SupplyChainUserCopy,
    pub matched_rule_id: Option<String>,
    pub exception_id: Option<String>,
    pub refresh_required: bool,
    pub record_monitor_evidence: bool,
    pub evidence_ids: Vec<String>,
    pub external_archive_downloads: Vec<Map<String, Value>>,
    pub external_archive_source_hashes: Vec<String>,
}

impl PackageEvalResult {
    /// `to_cache_dict` (:204-220).
    pub fn to_cache_dict(&self) -> Value {
        json_obj(vec![
            ("decision", Value::String(self.decision.clone())),
            ("policy_action", Value::String(self.policy_action.clone())),
            ("enforcement", Value::String(self.enforcement.clone())),
            (
                "entitlement_state",
                Value::String(self.entitlement_state.clone()),
            ),
            ("cache_status", Value::String(self.cache_status.clone())),
            (
                "workspace_fingerprint",
                self.workspace_fingerprint
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "reasons",
                Value::Array(self.reasons.iter().cloned().map(Value::Object).collect()),
            ),
            (
                "packages",
                Value::Array(self.packages.iter().cloned().map(Value::Object).collect()),
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
            ("risk_summary", Value::String(self.risk_summary.clone())),
            (
                "record_monitor_evidence",
                Value::Bool(self.record_monitor_evidence),
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
            ("user_copy", self.user_copy.to_value()),
        ])
    }

    /// `to_dict` (:222-241).
    pub fn to_dict(&self) -> Value {
        let mut payload = match self.to_cache_dict() {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        payload.insert(
            "package_intent_hash".into(),
            Value::String(self.package_intent_hash.clone()),
        );
        payload.insert(
            "policy_version".into(),
            Value::String(self.policy_version.clone()),
        );
        payload.insert(
            "bundle_version".into(),
            self.bundle_version
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        payload.insert(
            "workspace_fingerprint".into(),
            self.workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        payload.insert(
            "refresh_required".into(),
            Value::Bool(self.refresh_required),
        );
        payload.insert(
            "evidence_ids".into(),
            Value::Array(
                self.evidence_ids
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        if !self.external_archive_downloads.is_empty() {
            let inspection: Vec<Value> = self
                .external_archive_downloads
                .iter()
                .map(|download| {
                    let download_v = Value::Object(download.clone());
                    let sha256 = value_str(&download_v, "sha256").unwrap_or("");
                    let size = download.get("size").cloned().unwrap_or(Value::Null);
                    let source_url = value_str(&download_v, "source_url").unwrap_or("");
                    let final_url = value_str(&download_v, "final_url").unwrap_or("");
                    json_obj(vec![
                        ("sha256", Value::String(sha256.to_string())),
                        ("size", size),
                        (
                            "source_url_hash",
                            Value::String(stable_digest_hex(source_url.as_bytes())),
                        ),
                        (
                            "final_url_hash",
                            Value::String(stable_digest_hex(final_url.as_bytes())),
                        ),
                    ])
                })
                .collect();
            payload.insert(
                "external_archive_inspection".into(),
                Value::Array(inspection),
            );
        }
        Value::Object(payload)
    }

    /// `from_cache_dict` (:243-312).
    pub fn from_cache_dict(
        payload: &Map<String, Value>,
        package_intent_hash: &str,
        policy_version: &str,
        bundle_version: Option<&str>,
        workspace_fingerprint: Option<&str>,
    ) -> Self {
        let user_copy_map = payload
            .get("user_copy")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let cached_packages: Vec<Map<String, Value>> = dict_items(payload.get("packages"))
            .into_iter()
            .map(|item| with_support_metadata(&item))
            .collect();
        let (policy_action, recognized, reason_code, original_action) =
            normalize_guard_action_result_for_cache(payload.get("policy_action"));
        let mut cached_reasons = dict_items(payload.get("reasons"));
        if !recognized {
            let mut normalization_reason = Map::new();
            normalization_reason.insert("code".into(), Value::String(reason_code));
            normalization_reason.insert(
                "message".into(),
                Value::String(
                    "Cached package policy action was missing or unknown; Guard requires review."
                        .to_string(),
                ),
            );
            normalization_reason.insert(
                "original_action".into(),
                original_action.map(Value::String).unwrap_or(Value::Null),
            );
            normalization_reason.insert(
                "normalized_action".into(),
                Value::String(policy_action.clone()),
            );
            cached_reasons.push(normalization_reason);
        }
        let normalized_user_copy = normalize_package_user_copy(
            &SupplyChainUserCopy {
                title: optional_string(user_copy_map.get("title"))
                    .unwrap_or_else(|| "Monitoring this package".to_string()),
                summary: optional_string(user_copy_map.get("summary"))
                    .unwrap_or_else(|| "HOL Guard recorded this package request.".to_string()),
                next_step: optional_string(user_copy_map.get("next_step")),
                dashboard_url: optional_string(user_copy_map.get("dashboard_url")),
                harness_message: optional_string(user_copy_map.get("harness_message"))
                    .or_else(|| optional_string(payload.get("risk_summary")))
                    .unwrap_or_default(),
            },
            decision_to_guard_action_variant(&policy_action),
        );
        let external_archive_source_hashes = payload
            .get("external_archive_source_hashes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        PackageEvalResult {
            decision: optional_string(payload.get("decision"))
                .unwrap_or_else(|| "monitor".to_string()),
            policy_action,
            enforcement: optional_string(payload.get("enforcement"))
                .unwrap_or_else(|| "offline_cached".to_string()),
            entitlement_state: optional_string(payload.get("entitlement_state"))
                .unwrap_or_else(|| "premium".to_string()),
            cache_status: optional_string(payload.get("cache_status"))
                .unwrap_or_else(|| "hit".to_string()),
            package_intent_hash: package_intent_hash.to_string(),
            policy_version: policy_version.to_string(),
            bundle_version: bundle_version.map(str::to_string),
            workspace_fingerprint: workspace_fingerprint.map(str::to_string),
            reasons: cached_reasons,
            packages: cached_packages,
            risk_summary: optional_string(payload.get("risk_summary"))
                .unwrap_or_else(|| "HOL Guard recorded this package request.".to_string()),
            user_copy: normalized_user_copy,
            matched_rule_id: optional_string(payload.get("matched_rule_id")),
            exception_id: optional_string(payload.get("exception_id")),
            refresh_required: payload
                .get("refresh_required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            record_monitor_evidence: payload
                .get("record_monitor_evidence")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            evidence_ids: Vec::new(),
            external_archive_downloads: Vec::new(),
            external_archive_source_hashes,
        }
    }
}

/// `normalize_guard_action_result(value, unknown_action="require-reapproval")`
/// returns `(action, recognized, reason_code, original_action)`.
pub(super) fn normalize_guard_action_result_for_cache(
    raw: Option<&Value>,
) -> (String, bool, String, Option<String>) {
    let input = raw.cloned().unwrap_or(Value::Null);
    let normalized = normalize_guard_action_result(&input, GuardAction::RequireReapproval);
    (
        normalized.action.as_str().to_string(),
        normalized.recognized(),
        normalized
            .reason_code
            .unwrap_or(UNKNOWN_GUARD_ACTION_REASON)
            .to_string(),
        normalized.original_action,
    )
}
