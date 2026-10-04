//! `command_decision_adapter.py` — bridge between extension evidence and the
//! central effect-decision evaluator.
//!
//! Faithful port:
//! - `extension_evidence_batch` re-derives each observation's evidence/floor.
//! - `decision_factors` = `factors_from_extension_evidence` + the
//!   compatibility floor factor.
//! - `factors_from_extension_evidence`/`_extension_evidence_digest` live here
//!   (imported from `effect_decision` in Python; kept in this module to keep
//!   `extension_evidence` free of decision-plane dependencies).
//! - `interaction_policy_factors`, `evaluate_extension_interaction`,
//!   `command_uncertainties`, `extension_uncertainties`, `effect_decision_to_dict`.
//!
//! `GuardAction` is the 6-rank canonical lattice; `_CANONICAL_FLOOR` maps the
//! 4-rank legacy floor onto it (`monitor`→`warn`).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::canonical_command::CanonicalCommand;
use crate::command_evaluation::NativeCommandExtensionObservation;
use crate::effect_decision::{
    evaluate_effect_decision, maximum_action_floor, DecisionBasis, DecisionFactor,
    DecisionFactorSource, DecisionReason, EffectDecision, EffectDecisionRequest, EffectKind,
    GuardAction, ProofRequirement, UncertaintyKind,
};
use crate::extension_evidence::{
    EvidenceSeverity, ExtensionEvidence, ExtensionEvidenceBatch, ExtensionMatchClass,
    ExtensionRuleIdentity, OwnedSafeVariant, SafeVariantOutcome, EXTENSION_EVIDENCE_SCHEMA_VERSION,
};

/// Python `tuple[extension, rule]` compat-rule — only the fields the adapter
/// reads: `extension.required`, `rule.severity`, `rule.default_mode`,
/// `rule.rule_id`.
#[derive(Debug, Clone)]
pub struct CompatRuleRef {
    pub extension_required: bool,
    pub rule_severity: String,
    pub rule_default_mode: String,
    pub rule_id: String,
}

/// `_MODE_FLOOR` (adapter.py:43). `None` = Python `KeyError`.
fn mode_floor(mode: &str) -> Option<&'static str> {
    match mode {
        "disabled" => Some("allow"),
        "monitor" => Some("monitor"),
        "review" => Some("review"),
        "enforce" => Some("block"),
        "required" => Some("review"),
        _ => None,
    }
}

/// `_CANONICAL_FLOOR` (adapter.py:50). `None` = Python `KeyError`.
fn canonical_floor(legacy: &str) -> Option<GuardAction> {
    match legacy {
        "allow" => Some(GuardAction::Allow),
        "monitor" => Some(GuardAction::Warn),
        "review" => Some(GuardAction::Review),
        "block" => Some(GuardAction::Block),
        _ => None,
    }
}

/// `_SEVERITY` (adapter.py:56). `None` = Python `KeyError`.
fn evidence_severity(severity: &str) -> Option<EvidenceSeverity> {
    match severity {
        "low" => Some(EvidenceSeverity::Low),
        "medium" => Some(EvidenceSeverity::Medium),
        "high" => Some(EvidenceSeverity::High),
        "critical" => Some(EvidenceSeverity::Critical),
        _ => None,
    }
}

/// `legacy_rule_floor` (adapter.py:64). `None` = Python `KeyError`.
fn legacy_rule_floor(
    extension_required: bool,
    rule_severity: &str,
    rule_default_mode: &str,
) -> Option<&'static str> {
    if extension_required && rule_severity == "critical" {
        return Some("block");
    }
    if rule_default_mode == "disabled" {
        return Some("allow");
    }
    if extension_required {
        return Some("review");
    }
    mode_floor(rule_default_mode)
}

/// `command_risk_effects` table (command_risk_effects.py:11); `None` = unknown.
fn command_risk_effects(risk_class: &str) -> Option<EffectKind> {
    Some(match risk_class {
        "credential_exfiltration" => EffectKind::CredentialOrSecretOperation,
        "data_flow_exfiltration" => EffectKind::NetworkWrite,
        "destructive_shell" => EffectKind::DestructiveOrIrreversibleOperation,
        "encoded_execution" => EffectKind::ProcessExecution,
        "execution" => EffectKind::ProcessExecution,
        "local_secret_read" => EffectKind::SensitiveRead,
        "network_egress" => EffectKind::NetworkWrite,
        "policy_bypass" => EffectKind::GuardControlOperation,
        "supply_chain" => EffectKind::PackageOrSourceInstallation,
        _ => return None,
    })
}

/// `_effect_claims` (adapter.py:267): mapped set, `PROCESS_EXECUTION`
/// fallback for unknown classes, non-empty.
fn effect_claims(risk_classes: &[String]) -> Vec<EffectKind> {
    let mut effects: BTreeSet<EffectKind> = BTreeSet::new();
    for risk_class in risk_classes {
        effects.insert(command_risk_effects(risk_class).unwrap_or(EffectKind::ProcessExecution));
    }
    if effects.is_empty() {
        effects.insert(EffectKind::ProcessExecution);
    }
    effects.into_iter().collect()
}

/// `_extension_proof_requirements` (adapter.py:257).
fn extension_proof_requirements() -> Vec<ProofRequirement> {
    vec![
        ProofRequirement::OperationAndTargets,
        ProofRequirement::ParserConfidence,
        ProofRequirement::ExpectedEffects,
    ]
}

/// `_rule_identity` (adapter.py:246).
fn rule_identity(observation: &NativeCommandExtensionObservation) -> ExtensionRuleIdentity {
    ExtensionRuleIdentity {
        extension_id: observation.extension_id.clone(),
        extension_version: observation.extension_version.clone(),
        rule_id: observation.rule_id.clone(),
        rule_version: observation.rule_version.clone(),
    }
}

/// `extension_evidence_batch` (adapter.py:74).
///
/// For each observation: an `uncertainty`-class `ExtensionEvidence` when
/// `uncertainty_reasons` is non-empty (floor = max uncertainty floor), then one
/// `unsafe`-class evidence per review-or-stronger match — one evidence entry
/// per observation carrying the *set* of effective segment indexes covered by
/// safe variants filtered by `segment_index`. Python builds one evidence per
/// segment_index in `effective_evidence` segment coverage; the safe-variant
/// list on each entry is the variants whose matcher evidence overlaps that
/// segment.
pub fn extension_evidence_batch(
    command: &CanonicalCommand,
    observations: &[NativeCommandExtensionObservation],
) -> Result<ExtensionEvidenceBatch, &'static str> {
    let mut evidence: Vec<ExtensionEvidence> = Vec::new();
    let operation_ref = command.operation_ref();
    for observation in observations {
        let Some(floor) = canonical_floor(
            legacy_rule_floor(
                observation.extension_required,
                &observation.rule_severity,
                &observation.rule_default_mode,
            )
            .ok_or("unsupported rule default_mode")?,
        ) else {
            return Err("unsupported legacy command floor");
        };
        if !observation.uncertainty_reasons.is_empty() {
            let floors: Vec<GuardAction> = observation
                .uncertainty_reasons
                .iter()
                .map(|item| item.floor())
                .collect();
            let item = ExtensionEvidence {
                identity: rule_identity(observation),
                match_class: ExtensionMatchClass::Uncertainty,
                severity: EvidenceSeverity::Critical,
                declared_floor: maximum_action_floor(floors.iter()),
                base_fact: "matcher-failure".to_owned(),
                segment_ref: "segment:unknown".to_owned(),
                operation_ref: operation_ref.clone(),
                effect_claims: effect_claims(&observation.rule_risk_classes),
                proof_requirements: extension_proof_requirements(),
                uncertainty_reasons: observation.uncertainty_reasons.clone(),
                safe_variant: None,
                schema_version: EXTENSION_EVIDENCE_SCHEMA_VERSION.to_owned(),
            };
            item.validate()?;
            evidence.push(item);
        }
        // adapter.py:101 — canonical {"allow","warn"} floors produce no
        // unsafe evidence. Note "warn" is the canonical action for legacy
        // "monitor"; GuardAction::Warn == "warn".
        if floor == GuardAction::Allow || floor == GuardAction::Warn {
            continue;
        }
        // adapter.py:104 — segments from ALL matcher_evidence (not the
        // effective set): segments fully covered by safe variants are still
        // emitted as owned-safe-variant evidence.
        let identity = rule_identity(observation);
        let segment_indexes: BTreeSet<u32> = observation
            .matcher_evidence
            .iter()
            .map(|item| item.segment_index)
            .collect();
        for segment_index in segment_indexes {
            // adapter.py:105-111 — sorted variant_ids covering this segment.
            let safe_variant_ids: BTreeSet<&str> = observation
                .safe_variants
                .iter()
                .filter(|variant| {
                    variant
                        .matcher_evidence
                        .iter()
                        .any(|item| item.segment_index == segment_index)
                })
                .map(|variant| variant.variant_id.as_str())
                .collect();
            // adapter.py:112-115 — one OwnedSafeVariant per id, or (None,).
            if safe_variant_ids.is_empty() {
                let item = ExtensionEvidence {
                    identity: identity.clone(),
                    match_class: ExtensionMatchClass::Unsafe,
                    severity: evidence_severity(&observation.rule_severity)
                        .ok_or("unsupported rule severity")?,
                    declared_floor: floor,
                    base_fact: "rule-match".to_owned(),
                    segment_ref: format!("segment:{segment_index}"),
                    operation_ref: operation_ref.clone(),
                    effect_claims: effect_claims(&observation.rule_risk_classes),
                    proof_requirements: extension_proof_requirements(),
                    uncertainty_reasons: Vec::new(),
                    safe_variant: None,
                    schema_version: EXTENSION_EVIDENCE_SCHEMA_VERSION.to_owned(),
                };
                item.validate()?;
                evidence.push(item);
            } else {
                for variant_id in safe_variant_ids {
                    let item = ExtensionEvidence {
                        identity: identity.clone(),
                        match_class: ExtensionMatchClass::Unsafe,
                        severity: evidence_severity(&observation.rule_severity)
                            .ok_or("unsupported rule severity")?,
                        declared_floor: floor,
                        base_fact: "rule-match".to_owned(),
                        segment_ref: format!("segment:{segment_index}"),
                        operation_ref: operation_ref.clone(),
                        effect_claims: effect_claims(&observation.rule_risk_classes),
                        proof_requirements: extension_proof_requirements(),
                        uncertainty_reasons: Vec::new(),
                        safe_variant: Some(OwnedSafeVariant {
                            identity: identity.clone(),
                            safe_variant_id: variant_id.to_owned(),
                            outcome: SafeVariantOutcome::OwnedRuleNotRaised,
                        }),
                        schema_version: EXTENSION_EVIDENCE_SCHEMA_VERSION.to_owned(),
                    };
                    item.validate()?;
                    evidence.push(item);
                }
            }
        }
    }
    ExtensionEvidenceBatch::new(evidence)
}

/// `decision_factors` (adapter.py:134) — the batch's match factors plus, when
/// `compatibility_action_class` is set, a POLICY `compatibility-action` factor
/// at max(review, rule floor) with producer_ref `legacy:{sha256(action_class)}`
/// or `rule:{rule_id}` when the owning rule is resolved.
pub fn decision_factors(
    batch: &ExtensionEvidenceBatch,
    compatibility_action_class: Option<&str>,
    compatibility_rule: Option<&CompatRuleRef>,
) -> Result<Vec<DecisionFactor>, &'static str> {
    let mut factors = factors_from_extension_evidence(batch)?;
    if let Some(action_class) = compatibility_action_class {
        let mut compatibility_floor = canonical_floor("review").unwrap_or(GuardAction::Review);
        let mut producer_ref: Option<String> = None;
        if let Some(rule) = compatibility_rule {
            let rule_floor = canonical_floor(
                legacy_rule_floor(
                    rule.extension_required,
                    &rule.rule_severity,
                    &rule.rule_default_mode,
                )
                .ok_or("unsupported rule default_mode")?,
            )
            .ok_or("unsupported legacy command floor")?;
            compatibility_floor = maximum_action_floor([GuardAction::Review, rule_floor].iter());
            producer_ref = Some(format!("rule:{}", rule.rule_id));
        }
        if producer_ref.is_none() {
            let mut hasher = Sha256::new();
            hasher.update(action_class.trim().to_lowercase().as_bytes());
            producer_ref = Some(format!("legacy:{:x}", hasher.finalize()));
        }
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Policy,
            reason_code: "compatibility-action".to_owned(),
            basis: DecisionBasis {
                action_floor: compatibility_floor,
                proof_route: None,
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref,
            evidence_digest: None,
            assessment: None,
            proof: None,
        });
    }
    Ok(factors)
}

/// `factors_from_extension_evidence` (effect_decision.py:254): one MATCH-source
/// factor per evidence entry with a non-None `effective_floor`, sorted by
/// `semantic_key`.
pub fn factors_from_extension_evidence(
    batch: &ExtensionEvidenceBatch,
) -> Result<Vec<DecisionFactor>, &'static str> {
    let mut factors: Vec<DecisionFactor> = Vec::new();
    for evidence in &batch.evidence {
        let Some(floor) = evidence.effective_floor() else {
            continue;
        };
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Match,
            reason_code: evidence.base_fact.clone(),
            basis: DecisionBasis {
                action_floor: floor,
                proof_route: None,
            },
            segment_ref: Some(evidence.segment_ref.clone()),
            operation_ref: Some(evidence.operation_ref.clone()),
            producer_ref: Some(format!(
                "extension:{}/{}",
                evidence.identity.extension_id, evidence.identity.rule_id
            )),
            evidence_digest: Some(extension_evidence_digest(&evidence.semantic_key())),
            assessment: None,
            proof: None,
        });
    }
    factors.sort_by_cached_key(DecisionFactor::semantic_key);
    Ok(factors)
}

/// `_extension_evidence_digest` (effect_decision.py:329):
/// sha256("guard-extension-evidence-factor-v1\x00" +
/// canonical_json({"schema": ..., "semantic_key": <key>})).
pub fn extension_evidence_digest(semantic_key: &Value) -> String {
    let payload = json!({
        "schema": "guard-extension-evidence-factor-v1",
        "semantic_key": semantic_key,
    });
    let mut out = Vec::new();
    // semantic_key is always CPython-encodable (strings/arrays/ints).
    let _ = guard_contracts::write_canonical_json(&payload, &mut out);
    let mut hasher = Sha256::new();
    hasher.update(b"guard-extension-evidence-factor-v1\x00");
    hasher.update(&out);
    format!("{:x}", hasher.finalize())
}

/// `interaction_policy_factors` (adapter.py:160).
pub fn interaction_policy_factors(
    observations: &[NativeCommandExtensionObservation],
) -> Result<Vec<DecisionFactor>, &'static str> {
    let mut factors: Vec<DecisionFactor> = Vec::new();
    for observation in observations {
        let effective = observation.effective_evidence();
        if effective.is_empty() || observation.rule_action_classes.is_empty() {
            continue;
        }
        let Some(floor) = legacy_rule_floor(
            observation.extension_required,
            &observation.rule_severity,
            &observation.rule_default_mode,
        ) else {
            return Err("unsupported rule default_mode"); // Python KeyError.
        };
        if floor == "allow" || floor == "monitor" {
            continue;
        }
        let segment_indexes: BTreeSet<u32> =
            effective.iter().map(|item| item.segment_index).collect();
        for segment_index in segment_indexes {
            factors.push(DecisionFactor {
                source: DecisionFactorSource::Policy,
                reason_code: "extension-interaction-floor".to_owned(),
                basis: DecisionBasis {
                    action_floor: GuardAction::Review,
                    proof_route: None,
                },
                segment_ref: Some(format!("segment:{segment_index}")),
                operation_ref: None,
                producer_ref: Some(format!("rule:{}", observation.rule_id)),
                evidence_digest: None,
                assessment: None,
                proof: None,
            });
        }
    }
    Ok(factors)
}

/// `evaluate_extension_interaction` (adapter.py:185): batch evidence factors +
/// interaction policy floors + extension uncertainties → `evaluate_effect_decision`.
pub fn evaluate_extension_interaction(
    command: &CanonicalCommand,
    observations: &[NativeCommandExtensionObservation],
) -> Result<EffectDecision, &'static str> {
    let batch = extension_evidence_batch(command, observations)?;
    let mut factors = decision_factors(&batch, None, None)?;
    factors.extend(interaction_policy_factors(observations)?);
    evaluate_effect_decision(&EffectDecisionRequest {
        factors,
        uncertainties: extension_uncertainties(observations),
        schema_version: crate::effect_decision::EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })
}

/// `command_uncertainties` (adapter.py:204).
pub fn command_uncertainties(command: &CanonicalCommand, sensitive: bool) -> Vec<UncertaintyKind> {
    if !sensitive || command.is_exact() {
        return Vec::new();
    }
    if command.confidence == "fallback" {
        return vec![UncertaintyKind::PartialParse];
    }
    vec![UncertaintyKind::DynamicInput]
}

/// `extension_uncertainties` (adapter.py:212): dedup across observations,
/// sort by `item.value` (the kebab-case string).
pub fn extension_uncertainties(
    observations: &[NativeCommandExtensionObservation],
) -> Vec<UncertaintyKind> {
    let mut items: Vec<UncertaintyKind> = Vec::new();
    for observation in observations {
        for item in &observation.uncertainty_reasons {
            if !items.contains(item) {
                items.push(*item);
            }
        }
    }
    items.sort_by_key(|item| item.as_str());
    items
}

/// `effect_decision_to_dict` (adapter.py:223).
pub fn effect_decision_to_dict(decision: &EffectDecision) -> Value {
    let mut proof_routes: Vec<&str> = decision
        .proof_routes
        .iter()
        .map(|route| route.as_str())
        .collect();
    proof_routes.sort_unstable();
    json!({
        "schema_version": decision.schema_version,
        "action": decision.action.as_str(),
        "disposition": decision.disposition.as_str(),
        "proof_routes": proof_routes,
        "controlling_reasons": decision
            .controlling_reasons
            .iter()
            .map(reason_to_dict)
            .collect::<Vec<Value>>(),
        "reasons": decision
            .reasons
            .iter()
            .map(reason_to_dict)
            .collect::<Vec<Value>>(),
    })
}

/// `_reason_to_dict` (adapter.py:234).
fn reason_to_dict(reason: &DecisionReason) -> Value {
    json!({
        "source": reason.source.as_str(),
        "reason_code": reason.reason_code,
        "action_floor": reason.action_floor.as_str(),
        "segment_ref": reason.segment_ref,
        "operation_ref": reason.operation_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_evidence::ExtensionRuleIdentity;

    fn unsafe_evidence() -> ExtensionEvidence {
        ExtensionEvidence {
            identity: ExtensionRuleIdentity {
                extension_id: "ext".to_owned(),
                extension_version: "1.0.0".to_owned(),
                rule_id: "ext.rule".to_owned(),
                rule_version: "1.0.0".to_owned(),
            },
            match_class: ExtensionMatchClass::Unsafe,
            severity: EvidenceSeverity::High,
            declared_floor: GuardAction::Review,
            base_fact: "rule-match".to_owned(),
            segment_ref: "segment:0".to_owned(),
            operation_ref: "operation:abc123".to_owned(),
            effect_claims: vec![EffectKind::ProcessExecution],
            proof_requirements: extension_proof_requirements(),
            uncertainty_reasons: Vec::new(),
            safe_variant: None,
            schema_version: EXTENSION_EVIDENCE_SCHEMA_VERSION.to_owned(),
        }
    }

    /// Parity vector: Python `ExtensionEvidence(...).semantic_key` for the
    /// identical value. Asserts the nested array shape + field order.
    #[test]
    fn semantic_key_matches_python_oracle() {
        let ev = unsafe_evidence();
        let key = ev.semantic_key();
        assert_eq!(
            key,
            json!([
                "ext",
                "1.0.0",
                "ext.rule",
                "1.0.0",
                "segment:0",
                "operation:abc123",
                "unsafe",
                "high",
                "review",
                "rule-match",
                ["process-execution"],
                [
                    "expected-effects",
                    "operation-and-targets",
                    "parser-confidence"
                ],
                [],
                ["0", "", "", "", "", "", ""],
                "1.0.0"
            ])
        );
    }

    /// `_extension_evidence_digest` cross-impl parity: sha256 over canonical
    /// JSON of `{schema, semantic_key}` must equal the Python oracle.
    #[test]
    fn evidence_digest_matches_python_oracle() {
        let ev = unsafe_evidence();
        let digest = extension_evidence_digest(&ev.semantic_key());
        assert_eq!(
            digest,
            "4849f09ea3a240eeb242414a51836e6d2877abd6e802c68b6d0ab83bd191b905"
        );
    }

    /// `factors_from_extension_evidence` produces a MATCH factor whose
    /// evidence_digest is the batch evidence digest.
    #[test]
    fn factor_from_evidence_matches_python_oracle() {
        let ev = unsafe_evidence();
        let batch = ExtensionEvidenceBatch::new(vec![ev]).expect("batch");
        let factors = factors_from_extension_evidence(&batch).expect("factors");
        assert_eq!(factors.len(), 1);
        let f = &factors[0];
        assert_eq!(f.source, DecisionFactorSource::Match);
        assert_eq!(f.reason_code, "rule-match");
        assert_eq!(f.basis.action_floor, GuardAction::Review);
        assert_eq!(f.segment_ref.as_deref(), Some("segment:0"));
        assert_eq!(f.operation_ref.as_deref(), Some("operation:abc123"));
        assert_eq!(f.producer_ref.as_deref(), Some("extension:ext/ext.rule"));
        assert_eq!(
            f.evidence_digest.as_deref(),
            Some("4849f09ea3a240eeb242414a51836e6d2877abd6e802c68b6d0ab83bd191b905")
        );
    }

    /// Evidence with a safe variant emits one evidence per owned safe variant
    /// per covered segment (adapter.py:104-130 cross-product).
    #[test]
    fn batch_cross_product_per_safe_variant_per_segment() {
        // One observation, one segment, two covering safe variants → two
        // unsafe evidence entries (one per variant_id).
        let command = crate::canonical_command::CanonicalCommand::from_v1(
            &crate::parse_command(&crate::CommandModelRequestV1 {
                command: "echo hi".to_owned(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "test".to_owned(),
            })
            .expect("parse"),
        );
        let obs = NativeCommandExtensionObservation {
            extension_id: "ext".to_owned(),
            extension_version: "1.0.0".to_owned(),
            extension_required: true,
            rule_id: "ext.rule".to_owned(),
            rule_version: "1.0.0".to_owned(),
            rule_severity: "high".to_owned(),
            rule_default_mode: "enforce".to_owned(),
            rule_risk_classes: vec!["execution".to_owned()],
            rule_action_classes: vec!["exec".to_owned()],
            matcher_evidence: vec![crate::command_evaluation::NativeMatcherEvidence {
                segment_index: 0,
                executable: None,
                detail: "d".to_owned(),
            }],
            safe_variants: vec![
                crate::command_evaluation::NativeSafeVariantObservation {
                    variant_id: "va".to_owned(),
                    matcher_evidence: vec![crate::command_evaluation::NativeMatcherEvidence {
                        segment_index: 0,
                        executable: None,
                        detail: "d".to_owned(),
                    }],
                },
                crate::command_evaluation::NativeSafeVariantObservation {
                    variant_id: "vb".to_owned(),
                    matcher_evidence: vec![crate::command_evaluation::NativeMatcherEvidence {
                        segment_index: 0,
                        executable: None,
                        detail: "d".to_owned(),
                    }],
                },
            ],
            uncertainty_reasons: Vec::new(),
        };
        let batch = extension_evidence_batch(&command, &[obs]).expect("batch");
        // required+enforce → legacy floor = max(review, enforce=block) via
        // legacy_rule_floor → "block"; unsafe class → one evidence per
        // covering safe variant (va, vb) for segment 0.
        assert_eq!(batch.evidence.len(), 2);
        let variant_ids: Vec<&str> = batch
            .evidence
            .iter()
            .filter_map(|e| e.safe_variant.as_ref().map(|s| s.safe_variant_id.as_str()))
            .collect();
        assert_eq!(variant_ids, ["va", "vb"]);
    }
}
