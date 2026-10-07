//! `evaluate_command` decision-floor lattice and composite type surface.
//!
//! Byte-parity port of the pure (no-IO) helpers in
//! `command_evaluation.py:60-168` and `:723-755` plus the
//! `CompositeCommandEvaluation` projection (`to_dict`). Producer functions that
//! construct the individual `DecisionFactor`s live in sibling modules and are
//! assembled by the resident `command_effect_decide` op.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::effect_decision::{
    effect_decision_to_payload, DecisionFactor, EffectDecision, UncertaintyKind,
};

/// `CommandDecisionFloor` — the 4-level minimum-action lattice.
///
/// Distinct from `GuardAction` (the 6-level action lattice): floors are the
/// *minimum* a factor/match can demand; the effect-decision reduction maps the
/// winning floor to a `GuardAction`. Wire values are kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandDecisionFloor {
    Allow,
    Monitor,
    Review,
    Block,
}

impl CommandDecisionFloor {
    /// `_FLOOR_RANK` (command_evaluation.py:66): allow=0 monitor=1 review=2 block=3.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Monitor => 1,
            Self::Review => 2,
            Self::Block => 3,
        }
    }

    /// The literal wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Monitor => "monitor",
            Self::Review => "review",
            Self::Block => "block",
        }
    }
}

/// `_SEVERITY_RANK` (command_evaluation.py:78): low=0 medium=1 high=2 critical=3.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    }
}

/// `_MODE_FLOOR` (command_evaluation.py:79): declared default_mode → floor.
/// `None` for an unrecognized mode.
pub fn mode_floor(default_mode: &str) -> Option<CommandDecisionFloor> {
    Some(match default_mode {
        "disabled" => CommandDecisionFloor::Allow,
        "monitor" => CommandDecisionFloor::Monitor,
        "review" => CommandDecisionFloor::Review,
        "enforce" => CommandDecisionFloor::Block,
        "required" => CommandDecisionFloor::Review,
        _ => return None,
    })
}

/// `_UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS` (command_evaluation.py:67).
pub const UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS: &[&str] = &[
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "encoded_exfiltration",
    "guard_bypass",
    "policy_bypass",
];

/// `NativeMatcherEvidence` (native_command_extension_evidence.py:20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeMatcherEvidence {
    pub segment_index: u32,
    #[serde(default)]
    pub executable: Option<String>,
    pub detail: String,
}

impl NativeMatcherEvidence {
    /// `to_dict` (native_command_extension_evidence.py).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        })
    }
}

/// `NativeSafeVariantObservation` (native_command_extension_evidence.py:29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeSafeVariantObservation {
    pub variant_id: String,
    #[serde(default)]
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
}

impl NativeSafeVariantObservation {
    /// `to_dict` adds the literal `match_class: "safe-variant"`.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "variant_id": self.variant_id,
            "match_class": "safe-variant",
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
        })
    }
}

/// `NativeCommandExtensionObservation` (native_command_extension_evidence.py:42).
///
/// The Python observation carries `.extension`/`.rule` objects; Rust flattens
/// the rule metadata the adapter reads (`severity`, `default_mode`,
/// `risk_classes`, `action_classes`) + `extension.required`/`extension.version`
/// so `legacy_rule_floor`, `_effect_claims`, and `interaction_policy_factors`
/// are byte-identical without a full registry round-trip at factor time.
/// These are resolved from the bound `CommandCatalog` when the observation is
/// materialized.
#[derive(Debug, Clone)]
pub struct NativeCommandExtensionObservation {
    pub extension_id: String,
    pub extension_version: String,
    pub extension_required: bool,
    pub rule_id: String,
    pub rule_version: String,
    /// `rule.severity` (catalog).
    pub rule_severity: String,
    /// `rule.default_mode` (catalog).
    pub rule_default_mode: String,
    /// `rule.risk_classes` (catalog) — feeds `_effect_claims`.
    pub rule_risk_classes: Vec<String>,
    /// `rule.action_classes` (catalog) — `interaction_policy_factors` gate.
    pub rule_action_classes: Vec<String>,
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
    pub safe_variants: Vec<NativeSafeVariantObservation>,
    pub uncertainty_reasons: Vec<UncertaintyKind>,
}

impl NativeCommandExtensionObservation {
    /// `effective_evidence` (native_command_extension_evidence.py:51):
    /// matcher_evidence minus segment_indexes covered by any safe variant.
    pub fn effective_evidence(&self) -> Vec<&NativeMatcherEvidence> {
        let covered: BTreeSet<u32> = self
            .safe_variants
            .iter()
            .flat_map(|v| v.matcher_evidence.iter().map(|e| e.segment_index))
            .collect();
        self.matcher_evidence
            .iter()
            .filter(|e| !covered.contains(&e.segment_index))
            .collect()
    }

    /// `match_class` — "uncertainty" if any uncertainty, else "unsafe".
    fn match_class(&self) -> &'static str {
        if self.uncertainty_reasons.is_empty() {
            "unsafe"
        } else {
            "uncertainty"
        }
    }

    /// `match_classes` — `["unsafe"]` when there is effective evidence, plus
    /// `"uncertainty"` when uncertainty_reasons non-empty.
    fn match_classes(&self) -> Vec<&'static str> {
        let mut classes = Vec::new();
        if !self.effective_evidence().is_empty() {
            classes.push("unsafe");
        }
        if !self.uncertainty_reasons.is_empty() {
            classes.push("uncertainty");
        }
        classes
    }

    /// `to_dict` (native_command_extension_evidence.py:59).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "extension_id": self.extension_id,
            "extension_version": self.extension_version,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "match_class": self.match_class(),
            "match_classes": self.match_classes(),
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
            "safe_variants": self
                .safe_variants
                .iter()
                .map(NativeSafeVariantObservation::to_payload)
                .collect::<Vec<_>>(),
            "uncertainty_reasons": self
                .uncertainty_reasons
                .iter()
                .map(|u| u.as_str())
                .collect::<Vec<_>>(),
            "effective_segment_indexes": self
                .effective_evidence()
                .iter()
                .map(|e| e.segment_index)
                .collect::<Vec<_>>(),
        })
    }
}

/// `CommandSafetyRule` projection — the fields the composition + `to_dict`
/// read (command_rules.py:290; evaluate_command uses `.rule_id`,`.severity`,
/// `.risk_classes`,`.action_classes`,`.safer_alternatives`,`.default_mode`,
/// `.compatibility_fallback`,`.description`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CommandSafetyRule {
    pub rule_id: String,
    pub severity: String,
    #[serde(default)]
    pub risk_classes: Vec<String>,
    /// `action_classes` — controlling-class candidates this rule owns.
    #[serde(default)]
    pub action_classes: Vec<String>,
    /// `description` — used as `reason` for non-fallback matches (:262).
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub safer_alternatives: Vec<String>,
    pub default_mode: String,
    #[serde(default)]
    pub compatibility_fallback: bool,
    /// `rule_version` — carried for observation payload parity.
    #[serde(default)]
    pub rule_version: String,
}

/// One rule match with its owning extension (command_evaluation.py:110).
///
/// `extension_id`/`required` are flattened here — Rust keeps the two fields
/// Python reads off `owned.extension`, avoiding a full `CommandSafetyExtension`
/// port for the composition lattice. `command.confidence` is carried as
/// `parse_confidence` for `to_dict` byte-parity.
#[derive(Debug, Clone)]
pub struct OwnedCommandRuleMatch {
    /// `extension.extension_id`.
    pub extension_id: String,
    /// `extension.required`.
    pub extension_required: bool,
    /// `extension.provenance_digest`.
    pub extension_provenance_digest: String,
    /// `extension.trust_class` — needed by `extension_is_active` filtering.
    pub extension_trust_class: String,
    /// `match.rule`.
    pub rule: CommandSafetyRule,
    /// `match.action_class` — the controlling-class candidate for this match.
    pub action_class: Option<String>,
    /// `match.reason` (= `rule.description`, or `compatibility_reason` when
    /// `rule.compatibility_fallback`).
    pub reason: String,
    /// `match.matcher_evidence`.
    pub matcher_evidence: Vec<NativeMatcherEvidence>,
    /// `command.confidence` at match time (`parse_confidence` in `to_dict`).
    pub parse_confidence: String,
}

impl OwnedCommandRuleMatch {
    /// `OwnedCommandRuleMatch.to_dict` (:116-120): `extension_id` merged over
    /// `match.to_dict()` (:96-106).
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "extension_id": self.extension_id,
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": self.rule.risk_classes,
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": self.rule.safer_alternatives,
            "matcher_evidence": self
                .matcher_evidence
                .iter()
                .map(NativeMatcherEvidence::to_payload)
                .collect::<Vec<_>>(),
            "parse_confidence": self.parse_confidence,
        })
    }
}

/// `_rule_floor` (command_evaluation.py:723): per-match minimum floor.
pub fn rule_floor(owned: &OwnedCommandRuleMatch) -> CommandDecisionFloor {
    if owned.extension_required && owned.rule.severity == "critical" {
        return CommandDecisionFloor::Block;
    }
    if owned.rule.default_mode == "disabled" {
        return CommandDecisionFloor::Allow;
    }
    if owned.extension_required {
        return CommandDecisionFloor::Review;
    }
    mode_floor(&owned.rule.default_mode).unwrap_or(CommandDecisionFloor::Review)
}

/// `_stronger_floor` (command_evaluation.py:736): max by `_FLOOR_RANK`.
pub fn stronger_floor(
    left: CommandDecisionFloor,
    right: CommandDecisionFloor,
) -> CommandDecisionFloor {
    if left.rank() >= right.rank() {
        left
    } else {
        right
    }
}

/// `_decision_action_floor` (command_evaluation.py:740).
pub fn decision_action_floor(action: &str) -> CommandDecisionFloor {
    match action {
        "allow" => CommandDecisionFloor::Allow,
        "warn" => CommandDecisionFloor::Monitor,
        "block" => CommandDecisionFloor::Block,
        _ => CommandDecisionFloor::Review,
    }
}

/// `_match_precedence_key` (command_evaluation.py:750): descending precedence.
pub fn match_precedence_key(owned: &OwnedCommandRuleMatch) -> (u8, u8, u8) {
    (
        rule_floor(owned).rank(),
        severity_rank(&owned.rule.severity),
        if owned.rule.compatibility_fallback {
            0
        } else {
            1
        },
    )
}

/// `CompositeCommandEvaluation` (command_evaluation.py:124) — the assembled
/// result the `command_effect_decide` op returns as `to_dict()`.
#[derive(Debug, Clone)]
pub struct CompositeCommandEvaluation {
    /// `command.security_identity`.
    pub security_identity: String,
    /// `command.confidence` (parse confidence string).
    pub parse_confidence: String,
    /// `command.uncertainty_reason`.
    pub uncertainty_reason: Option<String>,
    pub matches: Vec<OwnedCommandRuleMatch>,
    pub controlling_action_class: Option<String>,
    pub controlling_reason: Option<String>,
    pub controlling_rule_id: Option<String>,
    pub minimum_action: CommandDecisionFloor,
    /// `extension_observations` — typed projection.
    pub extension_observations: Vec<NativeCommandExtensionObservation>,
    pub decision_plane: EffectDecision,
    pub baseline_factors: Vec<DecisionFactor>,
    #[allow(dead_code)] // carried for risk_classes derivation
    pub baseline_uncertainties: Vec<UncertaintyKind>,
}

impl CompositeCommandEvaluation {
    /// `risk_classes` property (:141-149): union of match rule risk classes +
    /// controlling-action risk classes + the two local-critical sentinels.
    pub fn risk_classes(&self) -> Vec<String> {
        let mut risks: BTreeSet<String> = BTreeSet::new();
        for owned in &self.matches {
            risks.extend(owned.rule.risk_classes.iter().cloned());
        }
        if let Some(action) = &self.controlling_action_class {
            risks.extend(
                risk_classes_for_command_action(action)
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
        if self
            .baseline_factors
            .iter()
            .any(|f| f.reason_code == "critical.local-secret-read")
        {
            risks.insert("local_secret_read".to_owned());
        }
        if self
            .baseline_factors
            .iter()
            .any(|f| f.reason_code == "critical.local-script-execution")
        {
            risks.insert("execution".to_owned());
        }
        risks.into_iter().collect()
    }

    /// `matched` property (:152).
    pub fn matched(&self) -> bool {
        self.controlling_action_class.is_some() || !self.matches.is_empty()
    }

    /// `to_dict` (:155) — the exact op wire payload.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "security_identity": self.security_identity,
            "controlling_action_class": self.controlling_action_class,
            "controlling_reason": self.controlling_reason,
            "controlling_rule_id": self.controlling_rule_id,
            "minimum_action": self.minimum_action.as_str(),
            "risk_classes": self.risk_classes(),
            "matches": self
                .matches
                .iter()
                .map(OwnedCommandRuleMatch::to_payload)
                .collect::<Vec<_>>(),
            "extension_observations": self
                .extension_observations
                .iter()
                .map(NativeCommandExtensionObservation::to_payload)
                .collect::<Vec<_>>(),
            "decision_plane": effect_decision_to_payload(&self.decision_plane),
            "parse_confidence": self.parse_confidence,
            "uncertainty_reason": self.uncertainty_reason,
        })
    }
}

/// `risk_classes_for_command_action` (command_extensions.py:32):
/// `COMMAND_ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())`.
///
/// The table is `_BASE_COMMAND_ACTION_RISK_CLASSES` +
/// `BLITCP_ACTION_RISK_CLASSES` + `GITHUB_ACTION_RISK_CLASSES` +
/// `OLLAMA_ACTION_RISK_CLASSES` (command_action_risk_metadata.py:12-112).
pub fn risk_classes_for_command_action(action_class: &str) -> &'static [&'static str] {
    let key = action_class.trim().to_lowercase();
    for (k, v) in COMMAND_ACTION_RISK_CLASSES {
        if *k == key {
            return v;
        }
    }
    &[]
}

/// `COMMAND_ACTION_RISK_CLASSES` — the merged table. Ordered; linear scan is
/// fine (84 entries, called once per composition).
pub static COMMAND_ACTION_RISK_CLASSES: &[(&str, &[&str])] = &[
    ("local secret read shell command", &["local_secret_read"]),
    ("local script execution shell command", &["execution"]),
    (
        "credential exfiltration shell command",
        &[
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress",
        ],
    ),
    ("guard-managed config write", &["destructive_shell"]),
    (
        "docker-sensitive command",
        &["network_egress", "destructive_shell"],
    ),
    ("docker client config access", &["local_secret_read"]),
    ("encoded or encrypted shell command", &["encoded_execution"]),
    ("kubernetes secret read command", &["local_secret_read"]),
    ("process environment secret read", &["local_secret_read"]),
    (
        "shell file upload command",
        &["credential_exfiltration", "network_egress"],
    ),
    (
        "sensitive local file write",
        &["destructive_shell", "local_secret_read"],
    ),
    ("destructive shell command", &["destructive_shell"]),
    ("pytest repository-code execution", &["execution"]),
    ("untrusted python interpreter", &["execution"]),
    (
        "guard approval self-authorization command",
        &["policy_bypass"],
    ),
    ("github pr body shell substitution", &["execution"]),
    ("filesystem destructive command", &["destructive_shell"]),
    ("git destructive command", &["destructive_shell"]),
    ("git origin refresh", &["network_egress"]),
    ("git index inspection", &["local_secret_read"]),
    (
        "git workspace command",
        &["destructive_shell", "network_egress"],
    ),
    ("git read command", &["local_secret_read"]),
    (
        "skill sunset configuration audit command",
        &["local_secret_read"],
    ),
    ("system destructive command", &["destructive_shell"]),
    ("windows destructive command", &["destructive_shell"]),
    (
        "kubernetes destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "infrastructure destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google cloud destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure dns destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "aws storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "google storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "azure storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "minio storage destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rclone destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "restic destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "borg destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "velero destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "ssh remote execution command",
        &["execution", "network_egress"],
    ),
    (
        "ssh configured execution command",
        &["execution", "network_egress"],
    ),
    (
        "scp overwrite command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rsync destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "postgresql destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "mysql destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "mongodb destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "redis destructive command",
        &["destructive_shell", "network_egress"],
    ),
    ("sqlite destructive command", &["destructive_shell"]),
    (
        "supabase destructive command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "rsync remote shell command",
        &["execution", "network_egress"],
    ),
    (
        "essh group execution command",
        &["execution", "network_egress"],
    ),
    ("essh cache removal command", &["destructive_shell"]),
    (
        "noodle request execution command",
        &["execution", "network_egress"],
    ),
    (
        "probe request execution command",
        &["execution", "network_egress"],
    ),
    ("probe workspace mutation command", &["destructive_shell"]),
    ("probe destructive command", &["destructive_shell"]),
    // BLITCP_ACTION_RISK_CLASSES
    ("blitcp remote destination command", &["network_egress"]),
    ("blitcp privilege escalation command", &["execution"]),
    (
        "blitcp self-update command",
        &["execution", "network_egress"],
    ),
    ("blitcp unverified copy command", &["destructive_shell"]),
    // GITHUB_ACTION_RISK_CLASSES
    (
        "github routine pull-request merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github workflow rerun",
        &["destructive_shell", "network_egress"],
    ),
    ("github local configuration write", &["destructive_shell"]),
    (
        "github bounded maintenance command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github content mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github administrator pull-request merge command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github release publication command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github workflow mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github force mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github delete command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github secret mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github access mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "github remote mutation command",
        &["destructive_shell", "network_egress"],
    ),
    (
        "unverified github command capability",
        &["destructive_shell", "network_egress"],
    ),
    // OLLAMA_ACTION_RISK_CLASSES
    ("ollama model publication command", &["network_egress"]),
    ("ollama model removal command", &["destructive_shell"]),
];

// ---------------------------------------------------------------------------
// `evaluate_command` (command_evaluation.py:171-557) + its module-local
// helpers `_native_classification_factors`, `_explicit_permission_allow_factors`,
// `_direct_github_permission_ids` (:560-719). Composition only — the individual
// `DecisionFactor` producers live in sibling modules; `read_factors` arrive as
// a request input because `shell_read_floor_factors` owns the filesystem read
// model (cwd/home_dir) on the host.
// ---------------------------------------------------------------------------

use crate::command_contained_routine_candidates::contained_routine_candidate_factor;
use crate::command_critical_floors::command_critical_floor_factors;
use crate::command_decision_adapter::{
    command_uncertainties, decision_factors, extension_evidence_batch, extension_uncertainties,
    CompatRuleRef,
};
use crate::command_verified_read_candidates::verified_read_candidate_factor;
use crate::command_workspace_write_candidates::workspace_write_candidate_factors;
use crate::effect_decision::{
    evaluate_effect_decision, DecisionBasis, DecisionFactorSource, EffectDecisionRequest,
    PositiveProof, ProofRequirement, ProofRoute,
};
use crate::extension_control::{
    resolve_extension_controls, ControlSurface, ExtensionControlLayer, ResolverFailureCode,
};
use crate::extension_trust::filter_inert_external_observations;
use crate::github_capability_contract::{github_capability_contract, GitHubCommandCapability};
use crate::github_command_capabilities::classify_github_cli;
use crate::github_workflow_authorization::{
    github_workflow_authorization_evidence, GitHubWorkflowAuthorizationV1,
};
use crate::native_command_catalog::CommandCatalog;
use crate::native_command_extension_evidence::observations_from_native_evidence;
use guard_contracts::NativeCommandControlBindingV1;

/// `evaluate_command` (:171-557).
///
/// Pure over its inputs. `native_extension_evidence` is the validated
/// `NativeCommandObservationsV1` wire `Value`; `control_snapshot` is the
/// authenticated `NativeCommandControlBindingV1`; `control_layers` are the
/// snapshot's `ExtensionControlLayer`s; `read_factors` are the host-computed
/// `shell_read_floor_factors` output (deferred shell-read model); `write_redirect`
/// is the caller-computed `command.redirects` write flag (Rust `CanonicalCommand`
/// intentionally drops redirects).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_command(
    command: &crate::canonical_command::CanonicalCommand,
    native_extension_evidence: &serde_json::Value,
    registry: &CommandCatalog,
    control_snapshot: &NativeCommandControlBindingV1,
    control_layers: &[ExtensionControlLayer],
    compatibility_action_class: Option<&str>,
    compatibility_reason: Option<&str>,
    workflow_authorization: Option<&GitHubWorkflowAuthorizationV1>,
    read_factors: &[DecisionFactor],
    write_redirect: bool,
) -> Result<CompositeCommandEvaluation, &'static str> {
    // `runtime_snapshot` is the authenticated binding; `control_layers` its layers.
    // observations + filter_inert (:201-211).
    let observations = filter_inert_external_observations(
        registry,
        &observations_from_native_evidence(
            native_extension_evidence,
            registry,
            command,
            control_snapshot,
        )?,
        control_layers,
    );
    // structured: (extension, rule, effective_evidence) for obs with evidence.
    // Rust keeps `NativeCommandExtensionObservation` (which carries
    // extension_id/rule_id) + resolves the catalog rule for floor/metadata.
    let selected: Vec<(
        &NativeCommandExtensionObservation,
        &crate::native_command_catalog::CatalogRule,
        Vec<crate::command_evaluation::NativeMatcherEvidence>,
    )> = {
        let mut out = Vec::new();
        for item in &observations {
            let effective = item.effective_evidence();
            if effective.is_empty() {
                continue;
            }
            let extension = registry
                .get(&item.extension_id)
                .ok_or("native_command_extension_evidence_unknown_identity")?;
            let rule = extension
                .rules
                .iter()
                .find(|rule| rule.rule_id == item.rule_id)
                .ok_or("native_command_extension_evidence_unknown_identity")?;
            out.push((
                item,
                rule,
                effective.into_iter().cloned().collect::<Vec<_>>(),
            ));
        }
        out
    };
    // compatibility_rule (:217-224) — first selected rule owning the compat class.
    let compatibility_rule = selected
        .iter()
        .find(|(_item, rule, _evidence)| {
            compatibility_action_class
                .map(|klass| rule.action_classes.iter().any(|c| c == klass))
                .unwrap_or(false)
        })
        .map(|(item, rule, _)| (*item, *rule));
    // effective_compatibility_class (:225-230).
    let effective_compatibility_class = if compatibility_rule.is_some()
        || (compatibility_action_class.is_some()
            && registry
                .rule_for_action_class(compatibility_action_class.unwrap())
                .is_none())
    {
        compatibility_action_class
    } else {
        None
    };

    // owned_matches (:233-249).
    let mut owned_matches: Vec<OwnedCommandRuleMatch> = Vec::new();
    for (item, rule, evidence) in &selected {
        let action_class = if !rule.action_classes.is_empty() {
            Some(rule.action_classes[0].clone())
        } else {
            effective_compatibility_class.map(str::to_owned)
        };
        let mut reason = rule.description.clone();
        if rule.compatibility_fallback {
            if let Some(compat) = compatibility_reason {
                reason = compat.to_owned();
            }
        }
        let extension = registry
            .get(&item.extension_id)
            .ok_or("native_command_extension_evidence_unknown_identity")?;
        owned_matches.push(OwnedCommandRuleMatch {
            extension_id: extension.extension_id.clone(),
            extension_required: extension.required,
            extension_provenance_digest: String::new(),
            extension_trust_class: extension.trust_class.clone(),
            rule: CommandSafetyRule {
                rule_id: rule.rule_id.clone(),
                severity: rule.severity.clone(),
                risk_classes: rule.risk_classes.clone(),
                action_classes: rule.action_classes.clone(),
                description: rule.description.clone(),
                safer_alternatives: rule.safer_alternatives.clone(),
                default_mode: rule.default_mode.clone(),
                compatibility_fallback: rule.compatibility_fallback,
                rule_version: rule.rule_version.clone(),
            },
            action_class,
            reason,
            matcher_evidence: evidence.clone(),
            parse_confidence: command.confidence.clone(),
        });
    }

    // extension_ids + permission_ids (:251-260).
    let extension_ids: Vec<String> = {
        let mut ids: Vec<String> = observations
            .iter()
            .map(|obs| obs.extension_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    };
    let permission_ids: Vec<String> = {
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for owned in &owned_matches {
            if let Some(permission) = registry.permission_for_rule_id(&owned.rule.rule_id) {
                ids.insert(permission.permission_id.clone());
            }
        }
        for id in direct_github_permission_ids(command) {
            ids.insert(id);
        }
        ids.into_iter().collect()
    };
    // control_resolution (:261-274).
    let control_resolution = resolve_extension_controls(
        control_layers,
        Some(registry),
        &extension_ids,
        &permission_ids,
        ControlSurface::CommandEvaluation,
        &observations
            .iter()
            .map(|obs| format!("{}:{}", obs.extension_id, obs.rule_id))
            .collect::<Vec<_>>(),
        None,
    );
    // explicitly_enabled_* (:275-282) from resolution.composed.
    // `effective_control_states` — project composed.controls into the Python
    // `(kind, target_id) -> enabled` map.
    let effective_control_states: std::collections::BTreeMap<(String, String), bool> =
        control_resolution
            .composed
            .controls
            .iter()
            .map(|control| {
                (
                    (
                        control.target.kind.as_str().to_owned(),
                        control.target.target_id.clone(),
                    ),
                    control.state == crate::extension_control::ControlState::Enabled,
                )
            })
            .collect();
    let explicitly_enabled_extensions: BTreeSet<String> = {
        let mut out = BTreeSet::new();
        for obs in &observations {
            // `effective_control_states[("extension", ext_id)] is True` → explicitly enabled.
            if effective_control_states
                .get(&("extension".to_owned(), obs.extension_id.clone()))
                .copied()
                .unwrap_or(false)
            {
                out.insert(obs.extension_id.clone());
            }
        }
        out
    };
    let explicitly_enabled_permissions: BTreeSet<String> = {
        let mut out = BTreeSet::new();
        for owned in &owned_matches {
            if let Some(permission) = registry.permission_for_rule_id(&owned.rule.rule_id) {
                if effective_control_states
                    .get(&("permission".to_owned(), permission.permission_id.clone()))
                    .copied()
                    .unwrap_or(false)
                {
                    out.insert(permission.permission_id.clone());
                }
            }
        }
        out
    };
    let explicitly_enabled_rule_ids: BTreeSet<String> = {
        let mut ids = explicitly_enabled_extensions.clone();
        for permission_id in &explicitly_enabled_permissions {
            if let Some(permission) = registry.permission(permission_id) {
                for rule_id in &permission.rule_ids {
                    ids.insert(rule_id.clone());
                }
            }
        }
        ids
    };
    // relaxable_enabled_permissions (:283-292): permission whose rule_ids ⊆
    // {allow-floor owned rule_ids ∪ explicitly_enabled_rule_ids}.
    let allow_floor_owned_rule_ids: BTreeSet<String> = owned_matches
        .iter()
        .filter(|owned| rule_floor(owned) == CommandDecisionFloor::Allow)
        .map(|owned| owned.rule.rule_id.clone())
        .collect();
    let relaxable_enabled_permissions: Vec<String> = explicitly_enabled_permissions
        .iter()
        .filter(|permission_id| {
            registry
                .permission(permission_id)
                .map(|permission| {
                    permission.rule_ids.iter().all(|rule_id| {
                        allow_floor_owned_rule_ids.contains(rule_id)
                            || explicitly_enabled_rule_ids.contains(rule_id)
                    })
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    controlling_parts(
        &owned_matches,
        effective_compatibility_class,
        compatibility_reason,
        &mut (),
    );
    // controlling_match / controlling_action_class / controlling_reason (:296-301).
    let controlling_match = owned_matches
        .iter()
        .max_by_key(|owned| match_precedence_key(owned));
    let mut controlling_action_class: Option<String> =
        effective_compatibility_class.map(str::to_owned);
    let mut controlling_reason: Option<String> = if effective_compatibility_class.is_some() {
        compatibility_reason.map(str::to_owned)
    } else {
        None
    };
    if controlling_action_class.is_none() {
        if let Some(controlling_match) = controlling_match {
            controlling_action_class = controlling_match.action_class.clone();
            controlling_reason = Some(controlling_match.reason.clone());
        }
    }
    // authorization (:302-307).
    let authorization_evidence =
        github_workflow_authorization_evidence(workflow_authorization, &command.security_identity);
    let authorized_action_class = authorization_evidence
        .as_ref()
        .map(|(_proof, action_class)| *action_class);
    let workflow_authorized_rule_ids: BTreeSet<String> = observations
        .iter()
        .filter(|obs| {
            authorized_action_class.is_some()
                && obs.uncertainty_reasons.is_empty()
                && obs
                    .rule_action_classes
                    .iter()
                    .any(|klass| Some(klass.as_str()) == authorized_action_class)
        })
        .map(|obs| obs.rule_id.clone())
        .collect();
    // minimum_action (:308-335).
    let mut minimum_action = CommandDecisionFloor::Allow;
    let native_explicitly_benign = native_extension_evidence.is_object()
        && command.confidence == "exact"
        && native_extension_evidence.get("minimum_action")
            == Some(&serde_json::Value::String("allow".to_owned()))
        && native_extension_evidence.get("explicitly_benign")
            == Some(&serde_json::Value::Bool(true));
    let native_benign_rule_ids: BTreeSet<String> = if native_explicitly_benign {
        owned_matches
            .iter()
            .filter(|owned| {
                rule_floor(owned) == CommandDecisionFloor::Allow
                    && observations.iter().any(|obs| {
                        obs.rule_id == owned.rule.rule_id && obs.uncertainty_reasons.is_empty()
                    })
            })
            .map(|owned| owned.rule.rule_id.clone())
            .collect()
    } else {
        BTreeSet::new()
    };
    let contained_routine_candidate = contained_routine_candidate_factor(command);
    let verified_read_candidate = verified_read_candidate_factor(command);
    let workspace_write_candidates = workspace_write_candidate_factors(command);
    let execution_proof_required = contained_routine_candidate.is_some()
        || verified_read_candidate.is_some()
        || !workspace_write_candidates.is_empty();
    let native_host_floor_exempt = native_explicitly_benign && !execution_proof_required;
    for owned in &owned_matches {
        if native_benign_rule_ids.contains(&owned.rule.rule_id)
            || explicitly_enabled_rule_ids.contains(&owned.rule.rule_id)
            || workflow_authorized_rule_ids.contains(&owned.rule.rule_id)
        {
            continue;
        }
        minimum_action = stronger_floor(minimum_action, rule_floor(owned));
    }
    let compatibility_owned_rule_ids: BTreeSet<String> = owned_matches
        .iter()
        .filter(|owned| owned.action_class.as_deref() == effective_compatibility_class)
        .map(|owned| owned.rule.rule_id.clone())
        .collect();
    let compatibility_explicitly_enabled = (!compatibility_owned_rule_ids.is_empty()
        && compatibility_owned_rule_ids.is_subset(&explicitly_enabled_rule_ids))
        || compatibility_rule
            .map(|(_, rule)| explicitly_enabled_rule_ids.contains(&rule.rule_id))
            .unwrap_or(false);
    let compatibility_workflow_authorized = !compatibility_owned_rule_ids.is_empty()
        && compatibility_owned_rule_ids.is_subset(&workflow_authorized_rule_ids);
    if effective_compatibility_class.is_some()
        && !compatibility_explicitly_enabled
        && !compatibility_workflow_authorized
    {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    if command.confidence != "exact"
        && (effective_compatibility_class.is_some() || !owned_matches.is_empty())
    {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    // observation_uncertainties (:364-366).
    let observation_uncertainties = extension_uncertainties(&observations);
    if !observation_uncertainties.is_empty() {
        minimum_action = CommandDecisionFloor::Block;
    }
    // evidence batch + effective batch (:367-376).
    let evidence_batch = extension_evidence_batch(command, &observations)?;
    let effective_evidence_batch = crate::extension_evidence::ExtensionEvidenceBatch {
        evidence: evidence_batch
            .evidence
            .iter()
            .filter(|evidence| {
                !native_benign_rule_ids.contains(&evidence.identity.rule_id)
                    && (!explicitly_enabled_rule_ids.contains(&evidence.identity.rule_id)
                        || !evidence.uncertainty_reasons.is_empty())
            })
            .cloned()
            .collect(),
    };
    // read_factors (:380-389) — host-supplied shell-read floor factors.
    let mut read_factors: Vec<DecisionFactor> = read_factors.to_vec();
    if native_host_floor_exempt {
        read_factors.retain(|f| f.reason_code == "critical.local-secret-read");
    }
    if authorization_evidence.is_some() {
        read_factors.retain(|f| f.reason_code == "critical.local-secret-read");
    }
    if !read_factors.is_empty() {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    // explicitly_allowed_github_capabilities (:391-397).
    let explicitly_allowed_github_capabilities: Vec<GitHubCommandCapability> =
        relaxable_enabled_permissions
            .iter()
            .filter_map(|permission_id| registry.permission(permission_id))
            .flat_map(|permission| permission.typed_capabilities.iter())
            .filter_map(|cap| github_capability_from_str(cap))
            .collect();
    // critical_floor_factors (:398-406).
    let critical_floor_factors: Vec<DecisionFactor> = if native_host_floor_exempt {
        Vec::new()
    } else {
        command_critical_floor_factors(
            command,
            workflow_authorization,
            &explicitly_allowed_github_capabilities,
        )
    };
    if critical_floor_factors
        .iter()
        .any(|factor| factor.basis.action_floor == crate::effect_decision::GuardAction::Block)
    {
        minimum_action = CommandDecisionFloor::Block;
    }
    // baseline factors + uncertainties (:407-452).
    let native_classification_factors =
        native_classification_factors(native_extension_evidence, command, native_explicitly_benign);
    let baseline_decision_factors = decision_factors(&effective_evidence_batch, None, None)?;
    // (:411) baseline_critical_floor_factors = critical_floor_factors + read_factors.
    let mut baseline_factors = native_classification_factors.clone();
    baseline_factors.extend(baseline_decision_factors.iter().cloned());
    if let Some(candidate) = &contained_routine_candidate {
        baseline_factors.push(candidate.clone());
    }
    if let Some(candidate) = &verified_read_candidate {
        baseline_factors.push(candidate.clone());
    }
    baseline_factors.extend(workspace_write_candidates.iter().cloned());
    baseline_factors.extend(critical_floor_factors.iter().cloned());
    baseline_factors.extend(read_factors.iter().cloned());
    let baseline_uncertainties = command_uncertainties(
        command,
        !baseline_factors.is_empty() || minimum_action == CommandDecisionFloor::Block,
    );
    let decision_uncertainties = {
        let mut u = baseline_uncertainties.clone();
        for item in observation_uncertainties {
            if !u.contains(&item) {
                u.push(item);
            }
        }
        u
    };
    let decision_compatibility_action_class = if effective_compatibility_class.is_some()
        && !compatibility_explicitly_enabled
        && !compatibility_workflow_authorized
    {
        effective_compatibility_class
    } else {
        None
    };
    let mut current_decision_factors = decision_factors(
        &effective_evidence_batch,
        decision_compatibility_action_class,
        compatibility_rule
            .map(|(item, rule)| CompatRuleRef {
                extension_required: item.extension_required,
                rule_severity: rule.severity.clone(),
                rule_default_mode: rule.default_mode.clone(),
                rule_id: rule.rule_id.clone(),
            })
            .as_ref(),
    )?;
    // authorization factor (:453-463).
    if let Some((proof, _action_class)) = &authorization_evidence {
        current_decision_factors.push(DecisionFactor {
            source: DecisionFactorSource::Authorization,
            reason_code: "github-workflow-capability".to_owned(),
            basis: DecisionBasis {
                action_floor: crate::effect_decision::GuardAction::Allow,
                proof_route: Some(ProofRoute::WorkflowAuthorized),
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref: Some("runtime:github-workflow-authorization-v1".to_owned()),
            evidence_digest: None,
            assessment: None,
            proof: Some(proof.clone()),
        });
    }
    // native benign authorizations (:464-476).
    if native_explicitly_benign {
        for owned in &owned_matches {
            if !native_benign_rule_ids.contains(&owned.rule.rule_id) {
                continue;
            }
            let proof = PositiveProof {
                route: ProofRoute::Verified,
                binding_digest: format!("native-benign:{}", command.security_identity),
                satisfied_requirements: vec![
                    ProofRequirement::ParserConfidence,
                    ProofRequirement::OperationAndTargets,
                    ProofRequirement::ExpectedEffects,
                ],
                enforced: false,
            };
            current_decision_factors.push(DecisionFactor {
                source: DecisionFactorSource::Assurance,
                reason_code: "runtime.native-benign-allow".to_owned(),
                basis: DecisionBasis {
                    action_floor: crate::effect_decision::GuardAction::Allow,
                    proof_route: Some(ProofRoute::Verified),
                },
                segment_ref: None,
                operation_ref: Some(format!("operation:{}", owned.rule.rule_id)),
                producer_ref: Some("runtime:native-benign-allow".to_owned()),
                evidence_digest: Some(format!("native-benign:{}", command.security_identity)),
                assessment: None,
                proof: Some(proof),
            });
        }
    }
    // explicit_permission_allow_factors (:477-481).
    let explicit_permission_allow_factors = explicit_permission_allow_factors(
        command,
        control_layers,
        &explicitly_enabled_permissions,
        control_snapshot,
    );
    // control fail-closed (:484-517).
    // apply_control_fail_closed (:490-517) — only when control_resolution.blocked.
    // Unavailable authority still fail-closes cataloged, destructive, or write
    // commands; secret reads and unmatched PATH tools keep their review floor.
    let mut apply_control_fail_closed = false;
    if control_resolution.blocked {
        let authority_unavailable_only = !control_resolution.failures.is_empty()
            && control_resolution
                .failures
                .iter()
                .all(|failure| failure.code == ResolverFailureCode::AuthorityUnavailable);
        apply_control_fail_closed = !authority_unavailable_only
            || !extension_ids.is_empty()
            || minimum_action == CommandDecisionFloor::Block
            || !workspace_write_candidates.is_empty()
            || write_redirect;
        if !apply_control_fail_closed {
            for owned in &owned_matches {
                if owned
                    .rule
                    .risk_classes
                    .iter()
                    .any(|risk| UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.contains(&risk.as_str()))
                {
                    apply_control_fail_closed = true;
                    break;
                }
            }
        }
        if !apply_control_fail_closed {
            if let Some(action_class) = effective_compatibility_class {
                if risk_classes_for_command_action(action_class)
                    .iter()
                    .any(|risk| UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.contains(risk))
                {
                    apply_control_fail_closed = true;
                }
            }
        }
        if apply_control_fail_closed {
            minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Block);
        }
    }
    // decision_plane (:518-532).
    let mut factors: Vec<DecisionFactor> = Vec::new();
    factors.extend(native_classification_factors);
    factors.extend(current_decision_factors);
    if let Some(candidate) = &contained_routine_candidate {
        factors.push(candidate.clone());
    }
    if let Some(candidate) = &verified_read_candidate {
        factors.push(candidate.clone());
    }
    factors.extend(workspace_write_candidates);
    factors.extend(critical_floor_factors);
    factors.extend(read_factors);
    if apply_control_fail_closed {
        factors.extend(control_resolution.factors.iter().cloned());
    }
    factors.extend(explicit_permission_allow_factors);
    let decision_plane = evaluate_effect_decision(&EffectDecisionRequest {
        factors,
        uncertainties: decision_uncertainties,
        schema_version: crate::effect_decision::EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })?;
    // final floor merge (:538-539).
    minimum_action = stronger_floor(
        minimum_action,
        decision_action_floor(decision_plane.action.as_str()),
    );
    Ok(CompositeCommandEvaluation {
        security_identity: command.security_identity.clone(),
        parse_confidence: command.confidence.clone(),
        uncertainty_reason: command.uncertainty_reason.clone(),
        controlling_rule_id: controlling_match.map(|owned| owned.rule.rule_id.clone()),
        matches: owned_matches,
        controlling_action_class,
        controlling_reason,
        minimum_action,
        extension_observations: observations,
        decision_plane,
        baseline_factors,
        baseline_uncertainties,
    })
}

/// `controlling_parts` is folded inline; retained as a no-op to keep the
/// port's statement order explicit.
fn controlling_parts(
    _owned: &[OwnedCommandRuleMatch],
    _compat: Option<&str>,
    _reason: Option<&str>,
    _sink: &mut (),
) {
}

#[allow(dead_code)]
fn extension_control_target_kind_extension() -> &'static str {
    "extension"
}

#[allow(dead_code)]
fn extension_control_target_kind_permission() -> &'static str {
    "permission"
}

/// `github_capability_from_str` — map a permission `typed_capabilities`
/// string back to the `GitHubCommandCapability` for the relaxable allow set.
fn github_capability_from_str(capability: &str) -> Option<GitHubCommandCapability> {
    // The contract table key is the capability enum; typed_capabilities stores
    // `capability.as_str()` (snake_case). Match by round-tripping over ALL.
    GitHubCommandCapability::ALL
        .iter()
        .find(|cap| cap.as_str() == capability)
        .copied()
}

/// `_native_classification_factors` (:560-637).
fn native_classification_factors(
    value: &serde_json::Value,
    command: &crate::canonical_command::CanonicalCommand,
    allow_benign_proof: bool,
) -> Vec<DecisionFactor> {
    if !value.is_object() {
        return Vec::new();
    }
    let blocked =
        value.get("minimum_action") == Some(&serde_json::Value::String("block".to_owned()));
    let privileged_wrapper_reapproval = value.get("minimum_action")
        == Some(&serde_json::Value::String("require-reapproval".to_owned()))
        && value.get("reason_code")
            == Some(&serde_json::Value::String(
                "native_privileged_wrapper_reapproval".to_owned(),
            ));
    let explicitly_benign = allow_benign_proof
        && command.confidence == "exact"
        && value.get("minimum_action") == Some(&serde_json::Value::String("allow".to_owned()))
        && value.get("explicitly_benign") == Some(&serde_json::Value::Bool(true));
    let mut factors: Vec<DecisionFactor> = Vec::new();
    if blocked || privileged_wrapper_reapproval || explicitly_benign {
        let digest = sha256_hex(
            serde_json::to_string(&serde_json::json!({
                "schema": "guard.native-classification-projection.v1",
                "command_security_identity": command.security_identity,
                "command_extensions": value.get("command_extensions"),
                "minimum_action": if blocked {
                    "block"
                } else if privileged_wrapper_reapproval {
                    "require-reapproval"
                } else {
                    "allow"
                },
            }))
            .unwrap_or_default()
            .as_bytes(),
        );
        let floor = if blocked {
            crate::effect_decision::GuardAction::Block
        } else if privileged_wrapper_reapproval {
            crate::effect_decision::GuardAction::RequireReapproval
        } else {
            crate::effect_decision::GuardAction::Allow
        };
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Assurance,
            reason_code: "native-classification".to_owned(),
            basis: DecisionBasis {
                action_floor: floor,
                proof_route: if explicitly_benign {
                    Some(ProofRoute::Verified)
                } else {
                    None
                },
            },
            segment_ref: None,
            operation_ref: Some(format!("operation:{}", command.security_identity)),
            producer_ref: Some("runtime:native-classification-v1".to_owned()),
            evidence_digest: Some(digest.clone()),
            assessment: None,
            proof: if explicitly_benign {
                Some(PositiveProof {
                    route: ProofRoute::Verified,
                    binding_digest: digest.clone(),
                    satisfied_requirements: vec![
                        ProofRequirement::ParserConfidence,
                        ProofRequirement::OperationAndTargets,
                        ProofRequirement::ExpectedEffects,
                    ],
                    enforced: true,
                })
            } else {
                None
            },
        });
    }
    factors
}

/// `_explicit_permission_allow_factors` (:639-707).
fn explicit_permission_allow_factors(
    command: &crate::canonical_command::CanonicalCommand,
    layers: &[ExtensionControlLayer],
    permission_ids: &BTreeSet<String>,
    _authority_evidence: &NativeCommandControlBindingV1,
) -> Vec<DecisionFactor> {
    if command.confidence != "exact" || permission_ids.is_empty() {
        return Vec::new();
    }
    let mut canonical_layers: Vec<serde_json::Value> = layers
        .iter()
        .map(|layer| {
            let mut controls = layer.controls.clone();
            controls.sort_by(|a, b| {
                (a.target.kind.as_str(), &a.target.target_id)
                    .cmp(&(b.target.kind.as_str(), &b.target.target_id))
            });
            serde_json::json!({
                "kind": layer.kind.as_str(),
                "catalog_digest": layer.catalog_digest,
                "global_lockdown": layer.global_lockdown,
                "controls": controls
                    .iter()
                    .map(|control| serde_json::json!({
                        "kind": control.target.kind.as_str(),
                        "target_id": control.target.target_id,
                        "state": control.state.as_str(),
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    canonical_layers.sort_by(|a, b| {
        a.get("kind")
            .and_then(|v| v.as_str())
            .cmp(&b.get("kind").and_then(|v| v.as_str()))
    });
    let requirements = vec![
        ProofRequirement::ConfigurationIdentity,
        ProofRequirement::ParserConfidence,
        ProofRequirement::CapabilityConstraints,
    ];
    let mut factors: Vec<DecisionFactor> = Vec::new();
    let mut sorted: Vec<&String> = permission_ids.iter().collect();
    sorted.sort();
    for permission_id in sorted {
        let binding_digest = sha256_hex(
            serde_json::to_string(&serde_json::json!({
                "command_security_identity": command.security_identity,
                "permission_id": permission_id,
                "layers": canonical_layers,
            }))
            .unwrap_or_default()
            .as_bytes(),
        );
        let proof = PositiveProof {
            route: ProofRoute::Verified,
            binding_digest: binding_digest.clone(),
            satisfied_requirements: requirements.clone(),
            enforced: true,
        };
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Control,
            reason_code: "control.explicitly-enabled-permission".to_owned(),
            basis: DecisionBasis {
                action_floor: crate::effect_decision::GuardAction::Allow,
                proof_route: Some(ProofRoute::Verified),
            },
            segment_ref: None,
            operation_ref: None,
            producer_ref: Some(format!("control:{permission_id}")),
            evidence_digest: Some(binding_digest),
            assessment: None,
            proof: Some(proof),
        });
    }
    factors
}

/// `_direct_github_permission_ids` (:708-719).
fn direct_github_permission_ids(
    command: &crate::canonical_command::CanonicalCommand,
) -> Vec<String> {
    let mut permission_ids: BTreeSet<String> = BTreeSet::new();
    for segment in &command.segments {
        let executable = segment
            .executable
            .as_deref()
            .unwrap_or("")
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let stripped = executable.strip_suffix(".exe").unwrap_or(&executable);
        if stripped != "gh" {
            continue;
        }
        let assessment = classify_github_cli(&segment.arguments);
        for capability in &assessment.capabilities {
            permission_ids.insert(
                github_capability_contract(*capability)
                    .permission_id
                    .clone(),
            );
        }
    }
    permission_ids.into_iter().collect()
}

impl crate::extension_control::ControlRegistry for CommandCatalog {
    fn catalog_digest(&self) -> &str {
        self.catalog_digest.as_str()
    }
    fn extension(&self, extension_id: &str) -> Option<crate::extension_control::RegistryExtension> {
        CommandCatalog::get(self, extension_id).map(|extension| {
            crate::extension_control::RegistryExtension {
                extension_id: extension.extension_id.clone(),
                dependencies: extension.dependencies.clone(),
            }
        })
    }
    fn permission(
        &self,
        permission_id: &str,
    ) -> Option<crate::extension_control::RegistryPermission> {
        CommandCatalog::permission(self, permission_id).map(|permission| {
            crate::extension_control::RegistryPermission {
                permission_id: permission.permission_id.clone(),
                extension_id: permission.extension_id.clone(),
                dependencies: permission.dependencies.clone(),
                implied_permissions: permission.implied_permissions.clone(),
            }
        })
    }
    fn permission_for_rule_id(&self, rule_id: &str) -> Option<String> {
        CommandCatalog::permission_for_rule_id(self, rule_id)
            .map(|permission| permission.permission_id.clone())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(severity: &str, mode: &str, compat: bool) -> CommandSafetyRule {
        CommandSafetyRule {
            rule_id: "r".to_owned(),
            severity: severity.to_owned(),
            risk_classes: vec![],
            action_classes: vec![],
            description: "desc".to_owned(),
            safer_alternatives: vec![],
            default_mode: mode.to_owned(),
            compatibility_fallback: compat,
            rule_version: "1".to_owned(),
        }
    }

    fn owned(rule: CommandSafetyRule, required: bool) -> OwnedCommandRuleMatch {
        OwnedCommandRuleMatch {
            extension_id: "ext".to_owned(),
            extension_required: required,
            extension_provenance_digest: String::new(),
            extension_trust_class: "internal".to_owned(),
            rule,
            action_class: None,
            reason: "r".to_owned(),
            matcher_evidence: vec![],
            parse_confidence: "exact".to_owned(),
        }
    }

    #[test]
    fn rule_floor_required_critical_blocks() {
        assert_eq!(
            rule_floor(&owned(rule("critical", "review", false), true)),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn rule_floor_required_noncritical_reviews() {
        assert_eq!(
            rule_floor(&owned(rule("high", "enforce", false), true)),
            CommandDecisionFloor::Review
        );
    }

    #[test]
    fn rule_floor_disabled_allows() {
        assert_eq!(
            rule_floor(&owned(rule("low", "disabled", false), true)),
            CommandDecisionFloor::Allow
        );
    }

    #[test]
    fn rule_floor_maps_mode() {
        assert_eq!(
            rule_floor(&owned(rule("low", "monitor", false), false)),
            CommandDecisionFloor::Monitor
        );
        assert_eq!(
            rule_floor(&owned(rule("low", "enforce", false), false)),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn stronger_floor_takes_higher_rank() {
        assert_eq!(
            stronger_floor(CommandDecisionFloor::Monitor, CommandDecisionFloor::Block),
            CommandDecisionFloor::Block
        );
        assert_eq!(
            stronger_floor(CommandDecisionFloor::Block, CommandDecisionFloor::Allow),
            CommandDecisionFloor::Block
        );
    }

    #[test]
    fn decision_action_floor_maps_classes() {
        assert_eq!(decision_action_floor("allow"), CommandDecisionFloor::Allow);
        assert_eq!(decision_action_floor("warn"), CommandDecisionFloor::Monitor);
        assert_eq!(decision_action_floor("block"), CommandDecisionFloor::Block);
        assert_eq!(
            decision_action_floor("review"),
            CommandDecisionFloor::Review
        );
        assert_eq!(decision_action_floor("other"), CommandDecisionFloor::Review);
    }

    #[test]
    fn precedence_prefers_floor_then_severity_then_noncompat() {
        let a = owned(rule("critical", "enforce", false), false);
        let b = owned(rule("low", "enforce", false), false);
        assert!(match_precedence_key(&a) > match_precedence_key(&b));
        let c = owned(rule("critical", "enforce", true), false);
        assert!(match_precedence_key(&a) > match_precedence_key(&c));
    }

    #[test]
    fn risk_table_matches_python_entries() {
        assert_eq!(
            risk_classes_for_command_action("destructive shell command"),
            &["destructive_shell"]
        );
        assert_eq!(
            risk_classes_for_command_action("credential exfiltration shell command"),
            &[
                "data_flow_exfiltration",
                "credential_exfiltration",
                "network_egress"
            ]
        );
        // Normalization: strip + lowercase.
        assert_eq!(
            risk_classes_for_command_action("  Git Destructive Command "),
            &["destructive_shell"]
        );
        assert_eq!(
            risk_classes_for_command_action("unknown class"),
            &[] as &[&str]
        );
    }

    #[test]
    fn observation_effective_evidence_excludes_safe_variant_segments() {
        let obs = NativeCommandExtensionObservation {
            extension_id: "e".to_owned(),
            extension_version: "1".to_owned(),
            extension_required: true,
            rule_id: "r".to_owned(),
            rule_version: "1".to_owned(),
            rule_severity: "high".to_owned(),
            rule_default_mode: "review".to_owned(),
            rule_risk_classes: vec![],
            rule_action_classes: vec![],
            matcher_evidence: vec![
                NativeMatcherEvidence {
                    segment_index: 0,
                    executable: None,
                    detail: "d0".to_owned(),
                },
                NativeMatcherEvidence {
                    segment_index: 1,
                    executable: None,
                    detail: "d1".to_owned(),
                },
            ],
            safe_variants: vec![NativeSafeVariantObservation {
                variant_id: "v".to_owned(),
                matcher_evidence: vec![NativeMatcherEvidence {
                    segment_index: 1,
                    executable: None,
                    detail: "d1".to_owned(),
                }],
            }],
            uncertainty_reasons: vec![],
        };
        let eff = obs.effective_evidence();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].segment_index, 0);
        assert_eq!(obs.match_class(), "unsafe");
        assert_eq!(obs.match_classes(), vec!["unsafe"]);
    }
}
