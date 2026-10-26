//! `HookArtifactCompose` — wire contract for the resident hook-artifact
//! decision composition op.
//!
//! Python gathers evidence (policy config, store rows, scanner results) and the
//! resident decides: it composes the action lattice over the gathered inputs,
//! settles local grants, evaluates saved/claimed approval reuse, decides the
//! trusted-request override, and selects the decision copy. Every query is
//! pure: no IO, no SQLite. Python must send every field explicitly (nulls
//! included) so the request digest it binds matches the resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::hook_artifact_compose_policy_tail::PolicyCompositionQueryV1;
use crate::is_python_space;

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA: &str = "guard-hook-artifact-compose-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA: &str = "guard-hook-artifact-compose-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_COMPOSE_FEATURE: &str = "hook-artifact-compose-v1";
/// Capability advertised when the `policy_lookup_select` query is served. A
/// runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_POLICY_LOOKUP_FEATURE: &str =
    "hook-artifact-compose-policy-lookup-v1";
/// Capability advertised when the `prompt_request_reason` query is served.
/// A runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_PROMPT_REASON_FEATURE: &str =
    "hook-artifact-compose-prompt-reason-v1";
/// Capability advertised when the `remembered_rule_reason` query is served.
/// A runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_REMEMBERED_RULE_FEATURE: &str =
    "hook-artifact-compose-remembered-rule-v1";
/// Capability advertised when the `package_reuse_settle` query is served. A
/// runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE: &str =
    "hook-artifact-compose-package-reuse-v1";
/// Capability advertised when the `package_firewall_entitlement` query is
/// served. A runtime that predates the query rejects it as an unknown kind, so
/// the caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ENTITLEMENT_FEATURE: &str =
    "hook-artifact-compose-package-firewall-entitlement-v1";
/// Capability advertised when the `package_firewall_access` query is served.
pub const HOOK_ARTIFACT_COMPOSE_PACKAGE_FIREWALL_ACCESS_FEATURE: &str =
    "hook-artifact-compose-package-firewall-access-v1";
/// Capability advertised when the `signal_composition` query is served. A
/// runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_SIGNAL_COMPOSITION_FEATURE: &str =
    "hook-artifact-compose-signal-composition-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: HookArtifactComposeQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookArtifactComposeQueryV1 {
    /// Current action composition, local-grant eligibility, and risk copy.
    PolicyStack(Box<PolicyStackQueryV1>),
    /// Configured policy action of one artifact (no lattice composition).
    ConfigAction(Box<ConfigActionQueryV1>),
    /// A matched local tool grant settles the current review as an allow.
    ToolGrantApply,
    /// Settle a local CLI grant result and the native floor.
    GrantSettle(GrantSettleQueryV1),
    /// What observe mode records as the action that would have executed.
    ObserveExecutableAction(Box<ObserveExecutableActionQueryV1>),
    /// Non-package saved-approval reuse composition.
    SavedReuse(Box<SavedReuseQueryV1>),
    /// A saved block selected for a package request.
    SavedBlockReuse {
        current_action: Value,
        policy_action: Value,
        stored_artifact_hash: Value,
    },
    /// The trusted-request override decision.
    TrustedOverride(Box<TrustedOverrideQueryV1>),
    /// Reuse composition after an atomic saved-approval claim.
    ClaimedReuse(Box<ClaimedReuseQueryV1>),
    /// Decision copy overlay for the composed action.
    DecisionCopy(Box<DecisionCopyQueryV1>),
    /// Build the canonical decision and its copy in the same resident request.
    DecisionBuildCopy(Box<DecisionBuildCopyQueryV1>),
    /// Which of the non-consuming policy lookups the hook is answered from.
    PolicyLookupSelect(PolicyLookupSelectQueryV1),
    /// What a flagged prompt request tells the user, before any harness copy.
    PromptRequestReason(PromptRequestReasonQueryV1),
    /// Why a remembered local rule was refused while local trust is degraded.
    RememberedRuleReason(RememberedRuleReasonQueryV1),
    /// Settle a package request's saved-approval reuse from the reasons the
    /// evaluation carries, folding the saved-block reuse of the same request.
    PackageReuseSettle(Box<PackageReuseSettleQueryV1>),
    /// Resolve what package-firewall access this home is entitled to.
    PackageFirewallEntitlement(Box<PackageFirewallEntitlementQueryV1>),
    /// What a resolved package-firewall entitlement permits on this machine.
    PackageFirewallAccess(PackageFirewallAccessQueryV1),
    /// Calibrate a base policy action against a detector run's risk and
    /// false-positive signals.
    SignalComposition(Box<SignalCompositionQueryV1>),
    /// The settled verdict's `policy_composition` trace and receipt
    /// `approval_source`.
    PolicyComposition(Box<PolicyCompositionQueryV1>),
}

/// The store rows the package-firewall entitlement is resolved from.
///
/// Every field is read as the store returned it; the resident re-derives the
/// entitlement from them, so nothing here is a verdict the caller composed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageFirewallEntitlementQueryV1 {
    /// The `supply_chain_bundle_entitlement` sync payload, `null` when unset.
    pub bundle_payload: Value,
    /// The `oauth_local_credentials` sync payload, `null` when unset.
    pub oauth_payload: Value,
    /// The OAuth local-credential health record, `null` when unavailable.
    pub oauth_health: Value,
    /// The effective Guard connect state at `now`, `null` when there is none.
    pub connect_state: Value,
    /// A cloud sync profile exists for this home.
    pub has_cloud_sync_profile: bool,
    /// The instant to resolve against as an ISO-8601 UTC string, `null` for
    /// the resident's own clock.
    pub now: Option<String>,
}

/// The resolved entitlement and the local protection a package-firewall
/// control request is answered against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageFirewallAccessQueryV1 {
    /// The entitlement as `resolve_package_firewall_entitlement` returned it.
    pub entitlement: Value,
    /// The operation to answer for, `null` to answer only the states, the
    /// offered actions, and the block copy.
    pub operation: Option<String>,
    /// A package manager is already shimmed on this machine, so existing local
    /// protection stays repairable and removable.
    pub has_installed_managers: bool,
}

/// The detector run a composition is calibrated from. `signals` are
/// `RiskSignalV2` payloads exactly as the detector registry emits them, and
/// `base_action` is the policy action the composition starts from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignalCompositionQueryV1 {
    pub signals: Vec<Value>,
    pub base_action: Value,
}

/// The package-request facts the reuse settlement reads. `reasons` is the
/// evaluation's reason list as it stands after the stored-policy override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageReuseSettleQueryV1 {
    pub reasons: Vec<Value>,
    /// The caller claims a saved approval on this pass.
    pub claim_saved_approval: bool,
    /// The composed action before any reuse is applied.
    pub current_action: Value,
    /// The evaluation's own action after the stored-policy override.
    pub evaluation_policy_action: Value,
    /// The saved decision's action, `null` when nothing is saved.
    pub stored_policy_action: Value,
    /// The saved decision's artifact hash, `null` when nothing is saved.
    pub stored_artifact_hash: Value,
    /// The source already named for this request's reuse evidence, if any.
    pub approval_reuse_source: Value,
}

/// Guard configuration facts the native policy-config action reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigFactsV1 {
    pub default_action: String,
    pub risk_actions: BTreeMap<String, String>,
    pub harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
    pub security_level: String,
    pub protection_posture: String,
    pub protection_posture_explicit: bool,
    /// Managed policy locks `security_level`.
    pub managed_locks_level: bool,
    /// Canonical harness every action is resolved for.
    pub harness: String,
    /// Per-harness posture override for `harness`, `null` when none.
    pub harness_posture_override: Option<String>,
}

/// Facts of one artifact the native policy-config action reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifactFactsV1 {
    /// The prompt asks to bypass Guard.
    pub hard_block: bool,
    /// Artifact, publisher, or harness action override.
    pub configured_override: Option<String>,
    /// Normalized command-action floor.
    pub command_action_floor: Option<String>,
    /// A verified explicit catalog-permission allow.
    pub explicit_permission_allow: bool,
    pub risk_classes: Vec<String>,
    /// A restricted pytest sandbox profile is already in force.
    pub pytest_restricted_sandbox: bool,
    /// The shell local-script execution review detector fired.
    pub shell_local_script_review: bool,
    /// `guard_default_action` metadata; non-strings arrive as `""`.
    pub guard_default_action: Option<String>,
    /// `str(confidence or "")` of the artifact risk confidence. Whether that
    /// confidence is strong enough to stop a posture is read off this text
    /// here, so no caller decides it.
    pub confidence_text: String,
    /// A caller that already knows the artifact installs a boot or login
    /// item says so here; the resident reads `action_class` for the rest.
    pub writes_launch_agent: bool,
    /// `action_class` metadata; absent or non-string arrives as `null`.
    #[serde(default)]
    pub action_class: Option<String>,
    pub skill_is_known_bad: bool,
    /// The native command floor does not run for this artifact: a package
    /// request is decided by the package evaluator, and a verified
    /// explicit-permission allow was already adjudicated against the
    /// published control layer. The artifact facts answer it so the caller
    /// need not read the artifact to decide whether to ask for the floor.
    #[serde(default)]
    pub skip_native_floor: bool,
    /// The digest a saved approval for this artifact is keyed by, present
    /// only when the caller asked the facts op for it.
    ///
    /// No composition reads this: it is the artifact's approval identity, not
    /// a fact a verdict turns on. It rides with the facts because the caller
    /// that needs the digest is the hook that already asks for them, and a
    /// second request for one SHA-256 would put the resident on the hook's
    /// critical path again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
}

impl PolicyArtifactFactsV1 {
    /// The artifact risk confidence is one a protection posture stops on.
    #[must_use]
    pub fn confidence_strong(&self) -> bool {
        self.confidence_text
            .trim_matches(is_python_space)
            .eq_ignore_ascii_case("strong")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigActionQueryV1 {
    pub policy_config: PolicyConfigFactsV1,
    pub artifact: PolicyArtifactFactsV1,
}

/// The native edge result fields the policy stack floors on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeEdgeFactsV1 {
    pub event_name: Option<String>,
    pub policy_action: Value,
    pub minimum_action: Value,
    pub decision: Value,
    pub reason_code: Value,
    /// The runtime artifact is a `package_request`.
    pub package_request: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyStackQueryV1 {
    /// The hook event this evaluation runs for.
    pub event_name: String,
    /// The runtime artifact's type.
    pub artifact_type: String,
    /// The request carries a raw shell command a local tool grant could name.
    pub has_raw_command: bool,
    pub policy_config: PolicyConfigFactsV1,
    pub runtime: PolicyArtifactFactsV1,
    pub approval_context: PolicyArtifactFactsV1,
    /// A data-flow signal carries strong confidence.
    pub data_flow_strong: bool,
    /// Trusted CLI action; `null` means none was supplied.
    pub cli_action: Value,
    pub payload_action_present: bool,
    pub payload_action: Value,
    pub native_floor: Value,
    /// The native edge verdict for this hook; the op derives its floor.
    pub native_edge: Option<NativeEdgeFactsV1>,
    pub current_action_override_present: bool,
    pub has_package: bool,
    pub package_policy_action: Value,
    pub has_data_flow: bool,
    pub has_scanner: bool,
    pub scanner_action: Value,
    pub has_compound_findings: bool,
    pub artifact_risk_signals: Vec<String>,
    pub data_flow_reasons: Vec<String>,
    pub artifact_risk_summary: String,
    pub data_flow_summary: Option<String>,
    pub package_risk_signals: Vec<String>,
    pub package_risk_summary: Option<String>,
    pub scanner_risk_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantSettleQueryV1 {
    pub current_action: Value,
    pub policy_action: Value,
    pub approval_context_action: Value,
    pub granted_action: Value,
    pub native_floor: Value,
}

/// The composed sources observe mode re-reads to name the action that would
/// have run.
///
/// Each field carries one source's action, or null when that source said
/// nothing. They arrive as raw values rather than as `GuardAction` because an
/// unrecognized source name must be ignored here, not normalized into a
/// verdict: observe mode reports what the harness would have done, so a source
/// this build cannot read contributes nothing instead of a guess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObserveExecutableActionQueryV1 {
    pub current_config_action: Value,
    pub current_action_override: Value,
    pub trusted_cli_override: Value,
    pub untrusted_hook_payload_hint: Value,
    pub package_action: Value,
    pub data_flow_action: Value,
    pub scanner_action: Value,
    /// The package evaluation's own action, which the composition trace does
    /// not always carry.
    pub package_evaluation_action: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SavedReuseQueryV1 {
    pub current_action: Value,
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_artifact_hash: Value,
    pub integrity_failure: bool,
    pub stored_validation_reason: Option<String>,
    pub cursor_native_present: bool,
    pub cursor_validation_reason: Option<String>,
    pub diagnostic_reason: Option<String>,
    pub diagnostic_stored_hash: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedOverrideQueryV1 {
    pub token_validation_reason: Option<String>,
    pub policy_action: Value,
    pub remembered_rule_rejected: bool,
    pub prior_reuse_reason_code: Option<String>,
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_source: Value,
    pub stored_validation_reason: Option<String>,
    /// `null` before the caller has attempted the claim.
    pub claim_succeeded: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PriorReuseV1 {
    pub action: Value,
    pub saved_action: Value,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimedReuseQueryV1 {
    pub claimed_hash: Value,
    pub token_validation_reason: Option<String>,
    pub post_claim_refresh_failed: bool,
    pub remembered_rule_rejected: bool,
    pub prior_reuse: Option<PriorReuseV1>,
    pub package_reuse_saved_action: Value,
    pub workflow_capability_required: bool,
    pub workflow_authorization_claimed: bool,
    pub policy_action: Value,
    pub current_policy_action: Value,
    pub claimed_trusted_request_override: bool,
    pub claimed_package_approval_consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyPackageV1 {
    pub reason_codes: Vec<String>,
    pub user_title: String,
    pub user_summary: String,
    pub user_harness_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyQueryV1 {
    pub policy_action: Value,
    pub package: Option<DecisionCopyPackageV1>,
    pub package_policy_action: Value,
    pub has_compound_findings: bool,
    pub compound_finding_count: Option<u64>,
    pub risk_summary: String,
    pub scanner_raised_to_block: bool,
    pub has_scanner_evidence: bool,
    pub scanner_primary_signal: Option<String>,
    pub base_user_body: Value,
    pub base_harness_message: Value,
    pub base_dashboard_primary_detail: Value,
    pub remembered_rule_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupSelectQueryV1 {
    /// The lookups in probe order, the direct artifact first. Each is a saved
    /// decision lookup result: `decision`, `ignored_local_integrity`,
    /// `trust_status` and `authority_revision`.
    pub lookups: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptRequestReasonQueryV1 {
    /// The harness that submitted the prompt, when one was reported.
    pub harness: Option<String>,
    /// Request classes the prompt was classified into.
    pub prompt_classes: Vec<String>,
    /// Summary of what the prompt asks for, when one was recorded.
    pub prompt_summary: Option<String>,
    /// Composed action for the prompt, when one was reported.
    pub policy_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RememberedRuleReasonQueryV1 {
    /// Reported state of remembered local rules, `unknown` when absent.
    pub remembered_rules: String,
    /// Integrity detail to append to the reason, when one was reported.
    pub integrity_message: Option<String>,
    /// How the request is named in the reason.
    pub artifact_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionBuildCopyQueryV1 {
    pub copy: DecisionCopyQueryV1,
    pub reason: String,
    pub signals: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_hook_artifact_compose_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[cfg(test)]
mod confidence_tests {
    use super::PolicyArtifactFactsV1;
    use serde_json::json;

    fn facts(confidence_text: &str) -> PolicyArtifactFactsV1 {
        serde_json::from_value(json!({
            "hard_block": false,
            "configured_override": null,
            "command_action_floor": null,
            "explicit_permission_allow": false,
            "risk_classes": [],
            "pytest_restricted_sandbox": false,
            "shell_local_script_review": false,
            "guard_default_action": null,
            "confidence_text": confidence_text,
            "writes_launch_agent": false,
            "skill_is_known_bad": false,
        }))
        .expect("artifact facts decode")
    }

    #[test]
    fn a_strong_confidence_is_read_off_the_confidence_text() {
        assert!(facts("strong").confidence_strong());
        assert!(facts("  Strong  ").confidence_strong());
    }

    #[test]
    fn any_other_confidence_text_is_not_strong() {
        for text in ["", "weak", "moderate", "strongly"] {
            assert!(!facts(text).confidence_strong(), "{text:?} read as strong");
        }
    }

    #[test]
    fn padding_a_strong_confidence_does_not_weaken_it() {
        // The reporting side strips with `str.strip()`, which also removes the
        // information separators and the C1 space that Rust's `trim` keeps.
        for text in [
            "\u{1c}strong\u{1f}",
            "\u{1d}\u{1e}Strong",
            "\u{85}strong\u{a0}",
            "\u{2028}strong\u{3000}",
        ] {
            assert!(facts(text).confidence_strong(), "{text:?} read as weaker");
        }
    }

    #[test]
    fn the_caller_may_not_send_its_own_strength() {
        let mut value = serde_json::to_value(facts("strong")).expect("encode");
        value["confidence_strong"] = json!(false);
        serde_json::from_value::<PolicyArtifactFactsV1>(value)
            .expect_err("a caller-sent strength must be rejected");
    }
}
