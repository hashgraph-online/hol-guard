//! Byte-exact ports of the two pure approval/verdict builders from
//! `local_supply_chain.py` (RTM-019). Rust owns decision authority; the
//! Python oracles are the source of truth.
//!
//! - `package_approval_identity` ↔ `_package_approval_identity`
//!   (local_supply_chain.py:3127): the deterministic, secret-free approval
//!   preimage. It is a plain mapping consumed by `build_approval_context_token`
//!   and digested with CPython `json.dumps(sort_keys=True, separators=(",",":"),
//!   ensure_ascii=True, allow_nan=False)`; use
//!   `guard_contracts::canonical_json::write_canonical_json` for those bytes.
//! - `package_protect_verdict_context` ↔ `_package_protect_verdict_context`
//!   (local_supply_chain.py:1844): the verdict presentation + stored receipt
//!   for one package-protect projection.
//!
//! Dataclass inputs that do not map cleanly onto existing Rust value types are
//! carried as `serde_json::Value` (artifact `metadata`, `evaluation.packages`,
//! `evaluation.reasons`, `evaluation.user_copy`). The Python
//! `_package_approval_identity` reads `evaluation.packages` via
//! `getattr(evaluation, "packages", ())`; on the Rust mirror
//! `PackageRequestEvaluation` wraps the same shape as a `Value` mapping, so we
//! read `evaluation.packages()`.

use serde_json::{json, Map, Value};

use crate::effect_decision::GuardAction;
use crate::local_supply_chain::{
    stable_digest_hex, uuid4_hex, PackageRequestEvaluation, Timestamp,
};
use crate::package_execution_context::{
    PackageExecutionContext, PACKAGE_EXECUTION_CONTEXT_VERSION,
};
use crate::package_intent_common::{GuardArtifact, PackageIntent};

/// `_protect_action_for_policy_action` (:4373-4374): normalize the policy
/// action, unknown → "block".
fn protect_action_for_policy_action(policy_action: &Value) -> GuardAction {
    crate::action_lattice::normalize_guard_action(policy_action, GuardAction::Block)
}

/// `_string_value` — `Some(s)` iff `value` is a JSON string, else `None`.
fn string_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

/// `_string_items` — collect string items of a list (skips non-strings).
fn string_items(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `str(target.get("raw_spec") or "")` — `None`/non-string → `""`.
fn raw_spec_or_empty(target: &Value) -> String {
    match target.get("raw_spec") {
        Some(Value::String(s)) => s.clone(),
        Some(other) if !other.is_null() => other.to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// `_package_approval_identity` (local_supply_chain.py:3127)
// ---------------------------------------------------------------------------

/// Serde-able view of the inputs `_package_approval_identity` reads.
/// `artifact_metadata` is `artifact.metadata` (a mapping; non-dict Python
/// values degrade to `{}`, so callers pass a JSON object).
/// `evaluation` is the package-request evaluation mapping (the Rust mirror of
/// `PackageRequestEvaluation` holds it as `Value`; pass `&evaluation.value` or
/// any JSON object exposing `"packages"`).
#[derive(Debug, Clone)]
pub struct PackageApprovalIdentityInput<'a> {
    /// `artifact.metadata` mapping.
    pub artifact_metadata: &'a Value,
    /// Evaluation mapping (read via `.packages`).
    pub evaluation: &'a Value,
    /// Resolved package execution context.
    pub execution_context: &'a PackageExecutionContext,
}

/// `_package_approval_identity` (py:3127). Returns the exact dict shape and
/// key order the Python produces (canonical digests sort keys anyway).
pub fn package_approval_identity(input: &PackageApprovalIdentityInput<'_>) -> Value {
    let metadata = input.artifact_metadata;
    let raw_targets = metadata.get("targets");
    let targets: Vec<Value> = match raw_targets {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|t| t.is_object())
            .map(|target| {
                let source_url_hash = target
                    .get("source_url_hash")
                    .and_then(string_value)
                    .or_else(|| {
                        target
                            .get("source_url")
                            .and_then(string_value)
                            .map(|url| stable_digest_hex(url.as_bytes()))
                    });
                let get = |key: &str| -> Value {
                    target
                        .get(key)
                        .map(|v| string_value(v).map_or(Value::Null, Value::String))
                        .unwrap_or(Value::Null)
                };
                let mut entry = Map::new();
                // Insertion order mirrors the Python dict literal.
                entry.insert("alias".to_string(), get("alias"));
                entry.insert("ecosystem".to_string(), get("ecosystem"));
                entry.insert("package_name".to_string(), get("package_name"));
                entry.insert("raw_spec".to_string(), get("raw_spec"));
                entry.insert("raw_spec_hash".to_string(), get("raw_spec_hash"));
                entry.insert(
                    "requested_specifier".to_string(),
                    get("requested_specifier"),
                );
                entry.insert(
                    "source_url_hash".to_string(),
                    source_url_hash.map_or(Value::Null, Value::String),
                );
                Value::Object(entry)
            })
            .collect(),
        _ => Vec::new(),
    };

    let raw_packages = input.evaluation.get("packages");
    let packages: Vec<Value> = match raw_packages {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|p| p.is_object())
            .map(|package| {
                let get = |key: &str| -> Value {
                    package
                        .get(key)
                        .map(|v| string_value(v).map_or(Value::Null, Value::String))
                        .unwrap_or(Value::Null)
                };
                let mut entry = Map::new();
                entry.insert("dependency_path".to_string(), get("dependencyPath"));
                entry.insert("ecosystem".to_string(), get("ecosystem"));
                entry.insert("name".to_string(), get("name"));
                entry.insert("namespace".to_string(), get("namespace"));
                entry.insert("package_manager".to_string(), get("packageManager"));
                entry.insert("requested_version".to_string(), get("requestedVersion"));
                entry.insert("resolved_version".to_string(), get("resolvedVersion"));
                Value::Object(entry)
            })
            .collect(),
        _ => Vec::new(),
    };

    let mut out = Map::new();
    out.insert(
        "context_digest".to_string(),
        json!(input.execution_context.digest),
    );
    // `execution_context.version` — the Rust `PackageExecutionContext` mirror
    // fixes version at `PACKAGE_EXECUTION_CONTEXT_VERSION` (2), matching the
    // Python dataclass default and the only value `from_evidence` accepts.
    out.insert(
        "context_version".to_string(),
        json!(PACKAGE_EXECUTION_CONTEXT_VERSION),
    );
    out.insert(
        "manager".to_string(),
        metadata
            .get("package_manager")
            .map(|v| string_value(v).map_or(Value::Null, Value::String))
            .unwrap_or(Value::Null),
    );
    out.insert("packages".to_string(), Value::Array(packages));
    out.insert("targets".to_string(), Value::Array(targets));
    out.insert("version".to_string(), json!(1));
    Value::Object(out)
}

// ---------------------------------------------------------------------------
// `_package_protect_verdict_context` (local_supply_chain.py:1844)
// ---------------------------------------------------------------------------

/// `_PackageProtectAuthority` fields consumed by `_package_protect_verdict_context`.
/// Fields the Python body never touches (current_action, launch_*, etc.) are omitted.
#[derive(Debug, Clone)]
pub struct PackageProtectAuthority<'a> {
    pub intent: &'a PackageIntent,
    pub artifact: &'a GuardArtifact,
    pub execution_context: &'a PackageExecutionContext,
    pub artifact_hash: &'a str,
    pub additional_policy_context: Option<&'a Map<String, Value>>,
    pub observe_mode: bool,
    /// `invoking_harness` — Python resolves via `resolve_local_supply_chain_harness`
    /// (env markers → parent process → `"guard-cli"`); the caller computes it.
    pub invoking_harness: &'a str,
}

/// `PackageProtectVerdictContext` (runtime/package_protect_projection.py:33).
/// `receipt` mirrors `GuardReceipt.to_dict()`; `receipt_id`/`timestamp` are
/// generated per call (uuid4/now) and therefore not deterministic.
#[derive(Debug, Clone)]
pub struct PackageProtectVerdictContext {
    pub matched_advisories: Vec<Value>,
    pub observe_projected: bool,
    pub observed_policy_action: GuardAction,
    pub public_targets: Vec<Value>,
    /// `GuardReceipt.to_dict()`-shaped `Value` (all 18 dataclass keys).
    pub receipt: Value,
    pub receipt_policy_metadata: Value,
    pub risk_signals: Vec<String>,
    pub verdict_action: GuardAction,
    pub verdict_reason: String,
}

/// `_matched_advisories` (py:4515-4534) on a typed package-request evaluation.
fn matched_advisories(evaluation: &PackageRequestEvaluation) -> Vec<Value> {
    let mut advisories = Vec::new();
    for item in evaluation.packages() {
        let Some(map) = item.as_object() else {
            continue;
        };
        for advisory_id in string_items(map.get("related_advisory_ids").unwrap_or(&Value::Null)) {
            let mut entry = Map::new();
            entry.insert("advisory_id".to_string(), json!(advisory_id));
            entry.insert(
                "package_name".to_string(),
                map.get("name").cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "version".to_string(),
                map.get("version").cloned().unwrap_or(Value::Null),
            );
            entry.insert(
                "decision".to_string(),
                map.get("decision").cloned().unwrap_or(Value::Null),
            );
            advisories.push(Value::Object(entry));
        }
    }
    advisories
}

/// `_evaluation_risk_signals` (py:4537-4549) on a typed evaluation.
fn evaluation_risk_signals(evaluation: &PackageRequestEvaluation) -> Vec<String> {
    let mut signals = Vec::new();
    for item in evaluation.reasons() {
        if let Some(message) = item.get("message").and_then(Value::as_str) {
            if !message.is_empty() {
                signals.push(message.to_string());
            }
        }
    }
    if !signals.is_empty() {
        return signals;
    }
    evaluation
        .risk_summary()
        .filter(|s| !s.is_empty())
        .map(|s| vec![s.to_string()])
        .unwrap_or_default()
}

/// `_package_approval_reuse_evidence` (py:3211-3220).
fn package_approval_reuse_evidence(evaluation: &PackageRequestEvaluation) -> Vec<Value> {
    let mut items = Vec::new();
    for reason in evaluation.reasons() {
        let Some(reuse) = reason.get("approval_reuse") else {
            continue;
        };
        let Some(reuse_map) = reuse.as_object() else {
            continue;
        };
        let mut evidence = Map::new();
        evidence.insert("source".to_string(), json!("approval_reuse"));
        for (key, value) in reuse_map {
            evidence.insert(key.clone(), value.clone());
        }
        items.push(Value::Object(evidence));
    }
    items
}

/// `uuid.uuid4()` — dashed form (`8-4-4-4-12`); `uuid4_hex` undashed is the
/// crate's existing primitive.
fn uuid4_dashed() -> String {
    let hex = uuid4_hex();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `datetime.now(timezone.utc).isoformat()` — microsecond precision; the
/// fraction is dropped when it lands exactly on a second, matching CPython's
/// `timespec="auto"` default. `Timestamp::isoformat()` alone truncates to
/// seconds, so the fraction is spliced in here.
fn isoformat_now_utc() -> String {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    let base = Timestamp::from_unix_micros(micros).isoformat();
    let frac = micros.rem_euclid(1_000_000);
    if frac == 0 {
        return base;
    }
    base.replacen("+00:00", &format!(".{frac:06}+00:00"), 1)
}

/// `build_package_guard_receipt` → `GuardReceipt.to_dict()` (models.py:185).
/// `receipt_id`/`timestamp` are call-time values; all other fields are
/// deterministic. Key order matches `dataclasses.asdict`.
#[allow(clippy::too_many_arguments)]
fn build_package_guard_receipt_dict(
    harness: &str,
    artifact_id: &str,
    artifact_hash: &str,
    policy_decision: GuardAction,
    capabilities_summary: &str,
    changed_capabilities: &[String],
    provenance_summary: &str,
    artifact_name: Option<&str>,
    source_scope: Option<&str>,
    scanner_evidence: &[Value],
) -> Value {
    let diff_summary = if changed_capabilities.is_empty() {
        Value::Null
    } else {
        let sample: Vec<&str> = changed_capabilities
            .iter()
            .take(3)
            .map(String::as_str)
            .collect();
        let mut s = format!(
            "{} change(s): {}",
            changed_capabilities.len(),
            sample.join(", ")
        );
        if changed_capabilities.len() > 3 {
            s.push_str(" ...");
        }
        Value::String(s)
    };
    let mut receipt = Map::new();
    receipt.insert(
        "receipt_id".to_string(),
        json!(format!("guard-receipt-{}", uuid4_dashed())),
    );
    receipt.insert("timestamp".to_string(), json!(isoformat_now_utc()));
    receipt.insert("harness".to_string(), json!(harness));
    receipt.insert("artifact_id".to_string(), json!(artifact_id));
    receipt.insert("artifact_hash".to_string(), json!(artifact_hash));
    receipt.insert(
        "policy_decision".to_string(),
        json!(policy_decision.as_str()),
    );
    receipt.insert(
        "capabilities_summary".to_string(),
        json!(capabilities_summary),
    );
    receipt.insert(
        "changed_capabilities".to_string(),
        Value::Array(changed_capabilities.iter().map(|c| json!(c)).collect()),
    );
    receipt.insert("provenance_summary".to_string(), json!(provenance_summary));
    receipt.insert("user_override".to_string(), Value::Null);
    receipt.insert(
        "artifact_name".to_string(),
        artifact_name.map_or(Value::Null, |s| json!(s)),
    );
    receipt.insert(
        "source_scope".to_string(),
        source_scope.map_or(Value::Null, |s| json!(s)),
    );
    receipt.insert("diff_summary".to_string(), diff_summary);
    receipt.insert("approval_source".to_string(), Value::Null);
    receipt.insert("approval_request_id".to_string(), Value::Null);
    receipt.insert(
        "scanner_evidence".to_string(),
        Value::Array(scanner_evidence.to_vec()),
    );
    receipt.insert("browser_intent".to_string(), Value::Null);
    receipt.insert("raw_command_text".to_string(), Value::Null);
    Value::Object(receipt)
}

/// `_package_protect_verdict_context` (py:1844).
///
/// `execution_policy_action` is the executed decision override (`None` when the
/// projected action equals the observed policy action).
pub fn package_protect_verdict_context(
    authority: &PackageProtectAuthority<'_>,
    evaluation: &PackageRequestEvaluation,
    execution_policy_action: Option<GuardAction>,
) -> PackageProtectVerdictContext {
    let intent = authority.intent;
    let public_targets: Vec<Value> = intent.targets.iter().map(|t| t.to_dict()).collect();
    let artifact = authority.artifact;
    let observed_policy_action =
        protect_action_for_policy_action(&json!(evaluation.policy_action().unwrap_or_default()));
    let verdict_action = execution_policy_action.unwrap_or(observed_policy_action);
    let observe_projected = authority.observe_mode && verdict_action != observed_policy_action;
    let mut verdict_reason = evaluation
        .user_copy()
        .and_then(|uc| uc.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if observe_projected {
        verdict_reason = format!(
            "Watch only observed a `{}` package-policy decision. HOL Guard allowed the install to continue.",
            observed_policy_action.as_str()
        );
    }
    let risk_signals = evaluation_risk_signals(evaluation);
    let approval_reuse_evidence = package_approval_reuse_evidence(evaluation);

    let mut receipt_policy_metadata = Map::new();
    receipt_policy_metadata.insert(
        "matched_rule_id".to_string(),
        evaluation
            .matched_rule_id()
            .map_or(Value::Null, |s| json!(s)),
    );
    receipt_policy_metadata.insert(
        "package_execution_context".to_string(),
        authority.execution_context.to_evidence(),
    );
    receipt_policy_metadata.insert("package_manager".to_string(), json!(intent.package_manager));
    receipt_policy_metadata.insert(
        "package_targets".to_string(),
        Value::Array(
            public_targets
                .iter()
                .map(|t| json!(raw_spec_or_empty(t)))
                .collect(),
        ),
    );
    receipt_policy_metadata.insert("policy_action".to_string(), json!(verdict_action.as_str()));
    receipt_policy_metadata.insert(
        "policy_version".to_string(),
        evaluation
            .value
            .get("policy_version")
            .and_then(Value::as_str)
            .map_or(Value::Null, |s| json!(s)),
    );
    receipt_policy_metadata.insert(
        "redacted_command".to_string(),
        json!(intent.redacted_command),
    );
    if observe_projected {
        receipt_policy_metadata.insert("observe_mode".to_string(), json!(true));
        receipt_policy_metadata.insert(
            "observed_policy_action".to_string(),
            json!(observed_policy_action.as_str()),
        );
    }
    if let Some(bundle_version) = evaluation
        .value
        .get("bundle_version")
        .filter(|value| !value.is_null())
    {
        receipt_policy_metadata.insert("bundle_version".to_string(), bundle_version.clone());
    }
    if let Some(context) = authority.additional_policy_context {
        receipt_policy_metadata.insert(
            "additional_policy_context".to_string(),
            Value::Object(context.clone()),
        );
    }
    if !approval_reuse_evidence.is_empty() {
        receipt_policy_metadata.insert(
            "approval_reuse".to_string(),
            Value::Array(approval_reuse_evidence.clone()),
        );
    }
    if authority.invoking_harness != "guard-cli" {
        receipt_policy_metadata.insert(
            "invoking_harness".to_string(),
            json!(authority.invoking_harness),
        );
    }

    let changed_capabilities: Vec<String> = intent
        .targets
        .iter()
        .zip(public_targets.iter())
        .map(|(target, public_target)| {
            match target
                .package_name
                .as_deref()
                .filter(|name| !name.is_empty())
            {
                Some(name) => name.to_string(),
                None => raw_spec_or_empty(public_target),
            }
        })
        .collect();

    let provenance_summary = evaluation
        .user_copy()
        .and_then(|uc| uc.get("harness_message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let receipt = build_package_guard_receipt_dict(
        authority.invoking_harness,
        &artifact.artifact_id,
        authority.artifact_hash,
        verdict_action,
        &verdict_reason,
        &changed_capabilities,
        &provenance_summary,
        Some(artifact.name.as_str()),
        Some(artifact.source_scope.as_str()),
        &approval_reuse_evidence,
    );

    PackageProtectVerdictContext {
        matched_advisories: matched_advisories(evaluation),
        observe_projected,
        observed_policy_action,
        public_targets,
        receipt,
        receipt_policy_metadata: Value::Object(receipt_policy_metadata),
        risk_signals,
        verdict_action,
        verdict_reason,
    }
}

// ---------------------------------------------------------------------------
// Tests — Python oracle parity.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use crate::package_execution_context::PackageExecutionContextComponent;
    use crate::package_intent_common::{GuardArtifact, PackageIntent, PackageIntentTarget};

    fn ctx() -> PackageExecutionContext {
        PackageExecutionContext {
            digest: "d".repeat(64),
            portable: false,
            components: vec![PackageExecutionContextComponent {
                name: "workspace".to_string(),
                digest: "a".repeat(64),
            }],
            non_portable_reason: Some("no git remote".to_string()),
        }
    }

    fn artifact() -> GuardArtifact {
        GuardArtifact {
            artifact_id: "art-9".to_string(),
            name: "cli-artifact".to_string(),
            harness: "guard-cli".to_string(),
            artifact_type: "package-request".to_string(),
            source_scope: "workspace".to_string(),
            config_path: "/tmp/proj/.holguard".to_string(),
            command: None,
            args: vec![],
            url: None,
            transport: None,
            publisher: None,
            metadata: json!({}),
            runtime_private_metadata: json!({}),
        }
    }

    fn intent() -> PackageIntent {
        PackageIntent {
            package_manager: "npm".to_string(),
            intent_kind: "install",
            command_tokens: vec![
                "npm".into(),
                "install".into(),
                "lodash".into(),
                "--token=sec".into(),
            ],
            redacted_command: "npm install lodash --token=*****".into(),
            targets: vec![
                PackageIntentTarget {
                    ecosystem: "npm".into(),
                    package_name: Some("lodash".into()),
                    raw_spec: "lodash@4.17.21".into(),
                    requested_specifier: Some("^4.0.0".into()),
                    source_url: None,
                    source_kind: None,
                    source_repository: None,
                    source_revision_kind: None,
                    source_identity: None,
                    source_invalid_reason: None,
                    alias: None,
                    dependency_group: None,
                    extras: vec![],
                    editable: false,
                },
                PackageIntentTarget {
                    ecosystem: "pypi".into(),
                    package_name: None,
                    raw_spec: "https://user:tok@example.com/pkg-1.0.tar.gz".into(),
                    requested_specifier: None,
                    source_url: Some("https://user:tok@example.com/pkg-1.0.tar.gz".into()),
                    source_kind: Some("url".into()),
                    source_repository: None,
                    source_revision_kind: None,
                    source_identity: None,
                    source_invalid_reason: None,
                    alias: None,
                    dependency_group: None,
                    extras: vec![],
                    editable: false,
                },
            ],
            manifest_paths: vec!["package.json".into()],
            lockfile_paths: vec![],
            flags: vec![],
            notes: vec![],
            local_executions: vec![],
            execution_context_hashes: vec![],
            execution_context_cwds: vec![],
            execution_context_reason_codes: vec![],
        }
    }

    fn evaluation() -> PackageRequestEvaluation {
        PackageRequestEvaluation::new(json!({
            "decision": "require-approval",
            "policy_action": "review",
            "enforcement": "strict",
            "entitlement_state": "entitled",
            "cache_status": "miss",
            "package_intent_hash": "ih",
            "policy_version": "pv-1",
            "bundle_version": null,
            "workspace_fingerprint": null,
            "reasons": [
                {"code": "low_version", "message": "lodash has CVEs",
                 "approval_reuse": {"token": "t1", "age_seconds": 5}},
                {"code": "r2"},
            ],
            "packages": [
                {"name": "lodash", "version": "4.17.21", "decision": "review",
                 "related_advisory_ids": ["GHSA-x", "CVE-2024-1"]},
                {"name": "requests"},
                "skip",
            ],
            "risk_summary": "risk summary here",
            "user_copy": {
                "title": "t", "summary": "orig summary", "next_step": null,
                "dashboard_url": null, "harness_message": "hm",
            },
            "matched_rule_id": "rule-7",
        }))
    }

    fn canonical_sha256(value: &Value) -> String {
        let mut buf = Vec::new();
        guard_contracts::write_canonical_json(value, &mut buf).unwrap();
        format!("{:x}", Sha256::digest(&buf))
    }

    // --- _package_approval_identity -------------------------------------------

    #[test]
    fn approval_identity_oracle_parity() {
        let metadata = json!({
            "package_manager": "npm",
            "targets": [
                {"alias": "lodash-alias", "ecosystem": "npm", "package_name": "lodash",
                 "raw_spec": "lodash@4.17.21", "raw_spec_hash": "h1",
                 "requested_specifier": "^4.0.0", "source_url": "https://user:pass@github.com/x/y.git"},
                {"alias": 3, "ecosystem": "pypi", "package_name": "requests", "raw_spec": "requests"},
                "not-a-dict",
            ],
            "manifest_paths": ["package.json"],
        });
        let evaluation = json!({
            "policy_version": "v1.2.3",
            "packages": [
                {"dependencyPath": ["root"], "ecosystem": "npm", "name": "lodash", "namespace": "@acme",
                 "packageManager": "npm", "requestedVersion": "^4.0.0", "resolvedVersion": "4.17.21", "extra": 1},
                {"name": 42},
                "skip-me",
            ],
        });
        let input = PackageApprovalIdentityInput {
            artifact_metadata: &metadata,
            evaluation: &evaluation,
            execution_context: &ctx(),
        };
        let identity = package_approval_identity(&input);
        let canon = {
            let mut b = Vec::new();
            guard_contracts::write_canonical_json(&identity, &mut b).unwrap();
            String::from_utf8(b).unwrap()
        };
        let expected_canon = concat!(
            r#"{"context_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","context_version":2,"manager":"npm""#,
            r#","packages":[{"dependency_path":null,"ecosystem":"npm","name":"lodash","namespace":"@acme","package_manager":"npm","requ"#,
            r#"ested_version":"^4.0.0","resolved_version":"4.17.21"},{"dependency_path":null,"ecosystem":null,"name":null,"namespace":n"#,
            r#"ull,"package_manager":null,"requested_version":null,"resolved_version":null}],"targets":[{"alias":"lodash-alias","ecosys"#,
            r#"tem":"npm","package_name":"lodash","raw_spec":"lodash@4.17.21","raw_spec_hash":"h1","requested_specifier":"^4.0.0","sour"#,
            r#"ce_url_hash":"2b4cd605b40667078a8f965af94d37f288176e92e153c9288869c60f110b8030"},{"alias":null,"ecosystem":"pypi","packa"#,
            r#"ge_name":"requests","raw_spec":"requests","raw_spec_hash":null,"requested_specifier":null,"source_url_hash":null}],"vers"#,
            r#"ion":1}"#,
        );
        assert_eq!(canon, expected_canon);
        assert_eq!(
            canonical_sha256(&identity),
            "706775e9c4c672e7182a69ef54881f62e9b041a782885f8185b969990845ca25"
        );
    }

    #[test]
    fn approval_identity_key_order_matches_python() {
        let metadata = json!({"package_manager": "npm"});
        let evaluation = json!({"packages": []});
        let input = PackageApprovalIdentityInput {
            artifact_metadata: &metadata,
            evaluation: &evaluation,
            execution_context: &ctx(),
        };
        let identity = package_approval_identity(&input);
        let keys: Vec<String> = identity.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "context_digest",
                "context_version",
                "manager",
                "packages",
                "targets",
                "version"
            ]
        );
    }

    // --- _package_protect_verdict_context -------------------------------------

    #[test]
    fn verdict_context_observe_sentence_verbatim() {
        let authority = PackageProtectAuthority {
            intent: &intent(),
            artifact: &artifact(),
            execution_context: &ctx(),
            artifact_hash: &"a".repeat(64),
            additional_policy_context: None,
            observe_mode: true,
            invoking_harness: "codex",
        };
        let context =
            package_protect_verdict_context(&authority, &evaluation(), Some(GuardAction::Allow));
        assert_eq!(
            context.verdict_reason,
            "Watch only observed a `review` package-policy decision. HOL Guard allowed the install to continue."
        );
        assert!(context.observe_projected);
        assert_eq!(context.observed_policy_action, GuardAction::Review);
        assert_eq!(context.verdict_action, GuardAction::Allow);
    }

    #[test]
    fn verdict_context_full_oracle_parity() {
        let authority = PackageProtectAuthority {
            intent: &intent(),
            artifact: &artifact(),
            execution_context: &ctx(),
            artifact_hash: &"a".repeat(64),
            additional_policy_context: None,
            observe_mode: true,
            invoking_harness: "codex",
        };
        let vc =
            package_protect_verdict_context(&authority, &evaluation(), Some(GuardAction::Allow));

        // matched_advisories
        assert_eq!(
            vc.matched_advisories,
            vec![
                json!({"advisory_id": "GHSA-x", "package_name": "lodash", "version": "4.17.21", "decision": "review"}),
                json!({"advisory_id": "CVE-2024-1", "package_name": "lodash", "version": "4.17.21", "decision": "review"}),
            ]
        );

        // risk_signals
        assert_eq!(vc.risk_signals, vec!["lodash has CVEs".to_string()]);

        // receipt_policy_metadata
        assert_eq!(
            vc.receipt_policy_metadata,
            json!({
                "matched_rule_id": "rule-7",
                "package_execution_context": {
                    "kind": "package_execution_context",
                    "schema_version": 2,
                    "portable": false,
                    "context_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "components": [{"name": "workspace", "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
                    "portable_summary": "Bound to this retry because Guard could not prove a complete portable package context.",
                    "non_portable_reason": "no git remote",
                },
                "package_manager": "npm",
                "package_targets": ["lodash@4.17.21", "https://example.com/pkg-1.0.tar.gz"],
                "policy_action": "allow",
                "policy_version": "pv-1",
                "redacted_command": "npm install lodash --token=*****",
                "observe_mode": true,
                "observed_policy_action": "review",
                "approval_reuse": [{"source": "approval_reuse", "token": "t1", "age_seconds": 5}],
                "invoking_harness": "codex",
            })
        );

        // receipt (excluding non-deterministic receipt_id/timestamp)
        let receipt = vc.receipt.as_object().unwrap();
        // `receipt_id` = `f"guard-receipt-{uuid4()}"` — dashed 8-4-4-4-12.
        let receipt_id = receipt["receipt_id"].as_str().unwrap();
        assert!(receipt_id.starts_with("guard-receipt-"));
        let uuid_part = &receipt_id["guard-receipt-".len()..];
        assert_eq!(uuid_part.len(), 36);
        assert_eq!(
            uuid_part.chars().filter(|c| *c == '-').count(),
            4,
            "receipt_id must carry the dashed uuid4 form"
        );
        // `timestamp` = `datetime.now(timezone.utc).isoformat()` — ends
        // `+00:00` and carries a microsecond fraction when non-zero.
        let timestamp = receipt["timestamp"].as_str().unwrap();
        assert!(timestamp.ends_with("+00:00"));
        assert!(timestamp.contains('T'));
        for key in ["receipt_id", "timestamp"] {
            assert!(receipt.contains_key(key), "missing {key}");
        }
        let mut receipt_stable = receipt.clone();
        receipt_stable.remove("receipt_id");
        receipt_stable.remove("timestamp");
        assert_eq!(
            Value::Object(receipt_stable),
            json!({
                "harness": "codex",
                "artifact_id": "art-9",
                "artifact_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "policy_decision": "allow",
                "capabilities_summary": "Watch only observed a `review` package-policy decision. HOL Guard allowed the install to continue.",
                "changed_capabilities": ["lodash", "https://example.com/pkg-1.0.tar.gz"],
                "provenance_summary": "hm",
                "user_override": null,
                "artifact_name": "cli-artifact",
                "source_scope": "workspace",
                "diff_summary": "2 change(s): lodash, https://example.com/pkg-1.0.tar.gz",
                "approval_source": null,
                "approval_request_id": null,
                "scanner_evidence": [{"source": "approval_reuse", "token": "t1", "age_seconds": 5}],
                "browser_intent": null,
                "raw_command_text": null,
            })
        );

        // public_targets — sanitized + sha256'd exactly as Python to_dict.
        let t0 = &vc.public_targets[0];
        assert_eq!(
            t0["raw_spec_hash"],
            "adaac4144887ebc2c1b682380ff385210f681fc58b4bc1ef3986148cf8dcd28a"
        );
        let t1 = &vc.public_targets[1];
        assert_eq!(t1["raw_spec"], "https://example.com/pkg-1.0.tar.gz");
        assert_eq!(t1["source_url"], "https://example.com/pkg-1.0.tar.gz");
        assert_eq!(
            t1["raw_spec_hash"],
            "3aa1baf6fb52bd49f1a4fda1a5589db490c822a9263c0a32de6180f7901c29d4"
        );
        assert_eq!(
            t1["source_url_hash"],
            "3aa1baf6fb52bd49f1a4fda1a5589db490c822a9263c0a32de6180f7901c29d4"
        );
    }
}
