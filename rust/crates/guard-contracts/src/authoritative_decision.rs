//! Authoritative Guard decision: value types, build, artifact projection, and
//! the full validator graph.
//!
//! Port of `runtime/decisions.py` — the sole decision from which display,
//! storage, and launch fields derive. Preserves:
//!   * the `_ACTION_MESSAGES` copy table (guard_action -> decision action +
//!     user_title/user_body/harness_message/dashboard_primary_detail)
//!   * `decision_from_legacy_policy_action` incl. the data-flow exfiltration
//!     copy overrides and `highest_confidence`/`strongest-signal` fallbacks
//!   * `GuardDecisionEnforcementState` derivation + `_validate_authoritative_decision`
//!   * `build_authoritative_decision` / `authoritative_decision_from_artifact`
//!   * `_validate_composition_trace` (recursive unknown-action-bearing-field
//!     reject, terminal-action weakening, override gates)
//!   * `_validate_artifact_projection` + `_validate_artifact_approval_projection`
//!     + `_validate_saved_approval_claim` + `_require_scanner_evidence`
//!   * `_validate_run_decision_projection`, `_merge_signals`,
//!     `authoritative_decision_from_artifact`, `evaluation_authority_error`,
//!     `rebuild_artifact_authority`
//!
//! Every validator returns the Python `ValueError` message verbatim so callers
//! surface identical reasons.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::decision_lattice::{
    is_action_bearing_key, most_restrictive_guard_action, GuardAction, DEFAULT_UNKNOWN_GUARD_ACTION,
};
use crate::signal_contract::{RiskConfidenceLabel, RiskSignalV2};

pub const AUTHORITATIVE_DECISION_SCHEMA_VERSION: i64 = 1;
pub const AUTHORITATIVE_DECISION_INCONSISTENT: &str = "authoritative_decision_inconsistent";

const APPROVAL_REUSE_ACCEPTED_REASON: &str = "approval_reuse_accepted";
const TRUSTED_REQUEST_OVERRIDE_REASON: &str = "trusted_request_override_exact_context";

type VErr = Value;

fn verr(msg: &str) -> Value {
    Value::String(msg.to_string())
}

macro_rules! bail {
    ($msg:literal) => {
        return Err(verr($msg))
    };
}
macro_rules! bailf {
    ($($arg:tt)*) => {
        return Err(verr(&format!($($arg)*)))
    };
}

fn is_blocking(a: GuardAction) -> bool {
    matches!(
        a,
        GuardAction::Review
            | GuardAction::RequireReapproval
            | GuardAction::SandboxRequired
            | GuardAction::Block
    )
}

const COMPOSITION_ACTION_FIELDS: [&str; 5] = [
    "configured_action",
    "current_action",
    "saved_action",
    "scanner_action",
    "runtime_detector_action",
];

fn is_known_composition_action_field(k: &str) -> bool {
    COMPOSITION_ACTION_FIELDS.contains(&k) || k == "final_action"
}

fn is_terminal_composition_action(a: GuardAction) -> bool {
    matches!(a, GuardAction::SandboxRequired | GuardAction::Block)
}

// ---------------------------------------------------------------------------
// _ACTION_MESSAGES copy table
// ---------------------------------------------------------------------------

/// `(decision_action, user_title, user_body, harness_message)`.
fn action_messages(a: GuardAction) -> (&'static str, &'static str, &'static str, &'static str) {
    match a {
        GuardAction::Allow => (
            "allow",
            "Allowed by policy",
            "Policy allows this action.",
            "HOL Guard allowed this action because policy already trusts it.",
        ),
        GuardAction::Warn => (
            "warn",
            "Risk signals found",
            "HOL Guard noticed risk signals, but policy allows the harness to continue.",
            "Review the warning if this action was unexpected.",
        ),
        GuardAction::Review => (
            "ask",
            "Approval required",
            "HOL Guard needs your approval before this action can run.",
            "Choose an approval scope, then retry in the harness.",
        ),
        GuardAction::SandboxRequired => (
            "ask",
            "Sandbox review required",
            "HOL Guard wants this action reviewed and run in a sandboxed path.",
            "Run this action in an approved sandbox, then retry.",
        ),
        GuardAction::RequireReapproval => (
            "ask",
            "Fresh approval required",
            "HOL Guard needs a fresh approval before this action can run.",
            "Choose the smallest approval scope that matches your intent, then retry.",
        ),
        GuardAction::Block => (
            "block",
            "Blocked by policy",
            "HOL Guard blocked this action.",
            "Review the details before retrying this action.",
        ),
    }
}

// ---------------------------------------------------------------------------
// data_flow_sink_type  (port of runtime/data_flow_sink.py)
// ---------------------------------------------------------------------------

/// `data_flow_sink_type` — stable user-facing sink label.
pub fn data_flow_sink_type(signals: &[RiskSignalV2]) -> &'static str {
    let has_id = |needle: &str| signals.iter().any(|s| s.signal_id == needle);
    if signals
        .iter()
        .any(|s| s.category == crate::signal_contract::RiskSignalCategory::Network)
    {
        return "network host";
    }
    if has_id("data-flow:clipboard-secret") {
        return "clipboard";
    }
    if has_id("data-flow:world-readable-temp-secret") {
        return "world-readable temp file";
    }
    if has_id("data-flow:git-remote-token") {
        return "git remote configuration";
    }
    "external sink"
}

fn has_data_flow_exfiltration_signal(signals: &[RiskSignalV2]) -> bool {
    signals
        .iter()
        .any(|s| s.detector == "data_flow.exfiltration" || s.signal_id.starts_with("data-flow:"))
}

fn confidence_rank(c: RiskConfidenceLabel) -> i32 {
    match c {
        RiskConfidenceLabel::Strong => 3,
        RiskConfidenceLabel::Likely => 2,
        RiskConfidenceLabel::Weak => 1,
    }
}

fn highest_confidence(signals: &[RiskSignalV2]) -> RiskConfidenceLabel {
    signals
        .iter()
        .map(|s| s.confidence)
        .max_by_key(|c| confidence_rank(*c))
        .unwrap_or(RiskConfidenceLabel::Likely)
}

fn dashboard_detail_from_signals(signals: &[RiskSignalV2], fallback: &str) -> String {
    if signals.is_empty() {
        return fallback.to_string();
    }
    if has_data_flow_exfiltration_signal(signals) {
        let sink = data_flow_sink_type(signals);
        return format!(
            "Source-to-sink route: local secret -> {sink}. This command sends local secret to {sink} without exposing the raw secret in Guard evidence."
        );
    }
    let strongest = signals
        .iter()
        .max_by_key(|s| confidence_rank(s.confidence))
        .unwrap();
    strongest.plain_reason.clone()
}

fn harness_message_from_signals(
    signals: &[RiskSignalV2],
    fallback: &str,
    policy_action: GuardAction,
) -> String {
    if has_data_flow_exfiltration_signal(signals) {
        let sink = data_flow_sink_type(signals);
        return match policy_action {
            GuardAction::Allow => format!(
                "HOL Guard allowed this action after noting that it sends local secret to {sink}."
            ),
            GuardAction::Warn => format!(
                "HOL Guard allowed this action with a warning because it sends local secret to {sink}."
            ),
            GuardAction::SandboxRequired => format!(
                "HOL Guard requires a sandbox because this action sends local secret to {sink}."
            ),
            GuardAction::Block => format!(
                "HOL Guard blocked this action because it sends local secret to {sink}."
            ),
            GuardAction::Review | GuardAction::RequireReapproval => format!(
                "HOL Guard paused this action because it sends local secret to {sink}."
            ),
        };
    }
    fallback.to_string()
}

// ---------------------------------------------------------------------------
// GuardDecisionV2
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct GuardDecisionV2 {
    pub guard_action: GuardAction,
    pub action: String, // GuardDecisionAction literal
    pub reason: String,
    pub user_title: String,
    pub user_body: String,
    pub harness_message: String,
    pub dashboard_primary_detail: String,
    pub approval_scopes: Vec<String>,
    pub retry_instruction: Option<String>,
    pub signals: Vec<RiskSignalV2>,
    pub confidence: RiskConfidenceLabel,
    pub package_review_cloud_reason_code: Option<String>,
}

impl GuardDecisionV2 {
    pub fn to_value(&self) -> Value {
        let mut payload = json!({
            "guard_action": self.guard_action.as_str(),
            "action": self.action,
            "reason": self.reason,
            "user_title": self.user_title,
            "user_body": self.user_body,
            "harness_message": self.harness_message,
            "dashboard_primary_detail": self.dashboard_primary_detail,
            "approval_scopes": self.approval_scopes,
            "retry_instruction": self.retry_instruction,
            "signals": self.signals.iter().map(|s| s.to_value()).collect::<Vec<_>>(),
            "confidence": self.confidence.as_str(),
        });
        if let Some(code) = &self.package_review_cloud_reason_code {
            payload["package_review_cloud_reason_code"] = json!(code);
        }
        payload
    }
}

/// `decision_from_legacy_policy_action` — derive the product-facing decision
/// from a guard action + reason + signals.
pub fn decision_from_legacy_policy_action(
    action: GuardAction,
    reason: &str,
    signals: &[RiskSignalV2],
) -> GuardDecisionV2 {
    let (decision_action, title, body, harness) = action_messages(action);
    let (approval_scopes, retry_instruction): (Vec<String>, Option<String>) = match action {
        GuardAction::Review | GuardAction::RequireReapproval => (
            vec!["once".into(), "task".into(), "always".into()],
            Some("Ask for approval again after choosing a scope.".into()),
        ),
        GuardAction::SandboxRequired => (
            vec!["once".into(), "task".into()],
            Some("Ask again after running this in a sandbox.".into()),
        ),
        _ => (vec![], None),
    };
    let (user_body, harness_message): (String, String) =
        if action == GuardAction::Block && signals.is_empty() {
            (
                "HOL Guard blocked this action because runtime policy denied it.".into(),
                "HOL Guard blocked this action before launch.".into(),
            )
        } else {
            (body.to_string(), harness.to_string())
        };
    let (user_body, harness_message) = if action == GuardAction::Warn && signals.is_empty() {
        (
            "HOL Guard warned about this action.".into(),
            "HOL Guard recorded a warning for this action.".into(),
        )
    } else {
        (user_body, harness_message)
    };
    let plain_reason = if reason.trim().is_empty() {
        title.to_string()
    } else {
        reason.to_string()
    };
    let harness_message = harness_message_from_signals(signals, &harness_message, action);
    let dashboard_detail = dashboard_detail_from_signals(signals, &user_body);
    GuardDecisionV2 {
        guard_action: action,
        action: decision_action.to_string(),
        reason: plain_reason.clone(),
        user_title: title.to_string(),
        user_body,
        harness_message,
        dashboard_primary_detail: dashboard_detail,
        approval_scopes,
        retry_instruction,
        signals: signals.to_vec(),
        confidence: highest_confidence(signals),
        package_review_cloud_reason_code: None,
    }
}

// ---------------------------------------------------------------------------
// GuardDecisionEnforcementState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardDecisionEnforcementState {
    pub blocking: bool,
    pub authority_finalized: bool,
    pub launch_permitted: bool,
    pub prompt_required: bool,
    pub sandbox_required: bool,
    pub snapshot_permitted: bool,
}

impl GuardDecisionEnforcementState {
    pub fn to_value(&self) -> Value {
        json!({
            "blocking": self.blocking,
            "authority_finalized": self.authority_finalized,
            "launch_permitted": self.launch_permitted,
            "prompt_required": self.prompt_required,
            "sandbox_required": self.sandbox_required,
            "snapshot_permitted": self.snapshot_permitted,
        })
    }
}

// ---------------------------------------------------------------------------
// AuthoritativeGuardDecision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct AuthoritativeGuardDecision {
    pub schema_version: i64,
    pub action: GuardAction,
    pub source: String,
    pub reason: String,
    pub composition_trace: Map<String, Value>,
    pub signals: Vec<RiskSignalV2>,
    pub enforcement: GuardDecisionEnforcementState,
    pub decision_v2: GuardDecisionV2,
}

impl AuthoritativeGuardDecision {
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "action": self.action.as_str(),
            "source": self.source,
            "reason": self.reason,
            "composition_trace": self.composition_trace,
            "signals": self.signals.iter().map(|s| s.to_value()).collect::<Vec<_>>(),
            "enforcement": self.enforcement.to_value(),
            "decision_v2": self.decision_v2.to_value(),
        })
    }

    /// `to_artifact_projection` — every compatibility field, never raw scoring.
    pub fn to_artifact_projection(&self) -> Value {
        json!({
            "authoritative_decision": self.to_value(),
            "policy_action": self.action.as_str(),
            "decision_v2_json": self.decision_v2.to_value(),
            "policy_composition": self.composition_trace,
            "verdict_action": self.action.as_str(),
            "decision_action": self.decision_v2.action,
            "policy_reason": self.reason,
            "decision_reason": self.reason,
        })
    }

    /// `to_run_decision_projection` — raw session-level persistence; the sole
    /// place scoring persists.
    pub fn to_run_decision_projection(&self) -> Value {
        json!({
            "authoritative_decision": self.to_value(),
            "policy_action": self.action.as_str(),
            "policy_composition": self.composition_trace,
            "decision_v2_json": self.decision_v2.to_value(),
            "verdict_action": self.action.as_str(),
        })
    }
}

/// `build_authoritative_decision` — build the sole decision after all policy
/// and approval composition, then run `_validate_authoritative_decision`.
pub fn build_authoritative_decision(
    action: GuardAction,
    reason: &str,
    mut composition_trace: Map<String, Value>,
    signals: &[RiskSignalV2],
    authority_finalized: bool,
    source: &str,
) -> Result<AuthoritativeGuardDecision, VErr> {
    if reason.trim().is_empty() {
        bail!("reason must be a non-empty string");
    }
    composition_trace.insert("final_action".into(), json!(action.as_str()));
    let blocking = is_blocking(action);
    let enforcement = GuardDecisionEnforcementState {
        blocking,
        authority_finalized,
        launch_permitted: !blocking && authority_finalized,
        prompt_required: matches!(action, GuardAction::Review | GuardAction::RequireReapproval),
        sandbox_required: action == GuardAction::SandboxRequired,
        snapshot_permitted: !blocking && authority_finalized,
    };
    let decision = AuthoritativeGuardDecision {
        schema_version: AUTHORITATIVE_DECISION_SCHEMA_VERSION,
        action,
        source: source.to_string(),
        reason: reason.to_string(),
        composition_trace,
        signals: signals.to_vec(),
        enforcement,
        decision_v2: decision_from_legacy_policy_action(action, reason, signals),
    };
    validate_authoritative_decision(&decision)?;
    Ok(decision)
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// `_validate_authoritative_decision` — cross-check enforcement + decision_v2
/// derive entirely from action/reason/signals.
pub fn validate_authoritative_decision(decision: &AuthoritativeGuardDecision) -> Result<(), VErr> {
    validate_composition_trace(decision.action, &decision.composition_trace)?;
    let expected_blocking = is_blocking(decision.action);
    let expected_launch = !expected_blocking && decision.enforcement.authority_finalized;
    let expected_prompt = matches!(
        decision.action,
        GuardAction::Review | GuardAction::RequireReapproval
    );
    let expected_sandbox = decision.action == GuardAction::SandboxRequired;
    if decision.enforcement.blocking != expected_blocking {
        bail!("enforcement.blocking must derive from action");
    }
    if decision.enforcement.launch_permitted != expected_launch {
        bail!("enforcement.launch_permitted must derive from action and authority state");
    }
    if decision.enforcement.prompt_required != expected_prompt {
        bail!("enforcement.prompt_required must derive from action");
    }
    if decision.enforcement.sandbox_required != expected_sandbox {
        bail!("enforcement.sandbox_required must derive from action");
    }
    if decision.enforcement.snapshot_permitted != expected_launch {
        bail!("enforcement.snapshot_permitted must derive from action and authority state");
    }
    let expected_decision_v2 =
        decision_from_legacy_policy_action(decision.action, &decision.reason, &decision.signals);
    if decision.decision_v2 != expected_decision_v2 {
        bail!("decision_v2 must derive entirely from action, reason, and signals");
    }
    Ok(())
}

fn parse_guard_action_value(value: &Value) -> Result<GuardAction, VErr> {
    match value {
        Value::String(s) => GuardAction::from_canonical(s)
            .ok_or_else(|| verr("action must be a known Guard action")),
        _ => Err(verr("action must be a known Guard action")),
    }
}

fn is_guard_action_value(value: &Value) -> bool {
    matches!(value, Value::String(s) if GuardAction::from_canonical(s).is_some())
}

/// `_validate_composition_trace` — reject action-bearing trace data that could
/// conceal stronger authority.
pub fn validate_composition_trace(
    action: GuardAction,
    trace: &Map<String, Value>,
) -> Result<(), VErr> {
    if trace.get("final_action") != Some(&json!(action.as_str())) {
        bail!("composition_trace.final_action must match action");
    }
    reject_unknown_composition_action_fields(trace)?;
    let mut parsed: Map<String, Value> = Map::new();
    for key in COMPOSITION_ACTION_FIELDS {
        match trace.get(key) {
            None => {
                parsed.insert(key.to_string(), Value::Null);
                continue;
            }
            Some(Value::Null)
                if matches!(key, "configured_action" | "saved_action" | "scanner_action") =>
            {
                parsed.insert(key.to_string(), Value::Null);
                continue;
            }
            Some(v) => {
                if !is_guard_action_value(v) {
                    bailf!("composition_trace.{key} must be a known Guard action or null");
                }
                parsed.insert(key.to_string(), v.clone());
            }
        }
    }

    let trusted_override = match trace.get("trusted_request_override") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => bail!("composition_trace.trusted_request_override must be a boolean"),
    };
    let saved_state_present = match trace.get("saved_state_present") {
        None => false,
        Some(Value::Bool(b)) => *b,
        _ => bail!("composition_trace.saved_state_present must be a boolean"),
    };

    let runtime_action = parsed.get("runtime_detector_action");
    let runtime_block = matches!(runtime_action, Some(Value::String(s)) if s=="block");
    if runtime_block && action != GuardAction::Block {
        bail!("runtime detector block cannot be overridden");
    }
    let current_action = parsed.get("current_action");

    for (key, candidate) in &parsed {
        let Some(cand_str) = candidate.as_str() else {
            continue;
        };
        let Some(cand) = GuardAction::from_canonical(cand_str) else {
            continue;
        };
        if !is_terminal_composition_action(cand) {
            continue;
        }
        if action.severity() < cand.severity() {
            bailf!("composition_trace.{key} cannot be weakened by the final action");
        }
    }

    for key in ["configured_action", "scanner_action"] {
        let candidate = parsed.get(key);
        if let (Some(cur), Some(cand)) = (current_action, candidate) {
            if let (Value::String(cs), Value::String(cands)) = (cur, cand) {
                if let (Some(ca), Some(cb)) = (
                    GuardAction::from_canonical(cs),
                    GuardAction::from_canonical(cands),
                ) {
                    if ca.severity() < cb.severity() {
                        bailf!("composition_trace.current_action cannot be weaker than {key}");
                    }
                }
            }
        }
    }

    let saved_allow_override = matches!(current_action, Some(Value::String(s)) if s=="review")
        && matches!(parsed.get("saved_action"), Some(Value::String(s)) if s=="allow")
        && saved_state_present
        && matches!(action, GuardAction::Allow | GuardAction::Warn);
    let explicit_approval_override = (trusted_override
        && matches!(action, GuardAction::Allow | GuardAction::Warn))
        || saved_allow_override;
    let runtime_warn = matches!(runtime_action, Some(Value::String(s)) if s=="warn");
    if runtime_warn && action.severity() < GuardAction::Warn.severity() {
        bail!("runtime detector warning cannot be erased by the final action");
    }
    let runtime_review = matches!(runtime_action, Some(Value::String(s)) if s=="review");
    if runtime_review
        && action.severity() < GuardAction::Review.severity()
        && !explicit_approval_override
    {
        bail!("runtime detector review requires an explicit allowed override");
    }

    let authority_inputs: Vec<GuardAction> = parsed
        .iter()
        .filter(|(k, _)| k.as_str() != "runtime_detector_action")
        .filter_map(|(_, v)| v.as_str())
        .filter_map(GuardAction::from_canonical)
        .collect();
    let strongest_input = authority_inputs
        .iter()
        .copied()
        .max_by_key(|a| a.severity());
    match strongest_input {
        None => return Ok(()),
        Some(si) if action.severity() >= si.severity() => return Ok(()),
        _ => {}
    }
    if explicit_approval_override {
        return Ok(());
    }
    bail!("composition_trace final action weakens authority without an explicit allowed override")
}

/// `_reject_unknown_composition_action_fields` — reject hidden action aliases
/// at any nesting depth.
fn reject_unknown_composition_action_fields(trace: &Map<String, Value>) -> Result<(), VErr> {
    fn visit(value: &Value, path: &str, top_level: bool) -> Result<(), VErr> {
        if let Value::Object(m) = value {
            for (raw_key, nested) in m {
                let key_path = format!("{path}.{raw_key}");
                let known_top = top_level && is_known_composition_action_field(raw_key);
                if is_action_bearing_key(raw_key) && !known_top {
                    bailf!("composition_trace contains unknown action-bearing field: {key_path}");
                }
                visit(nested, &key_path, false)?;
            }
            return Ok(());
        }
        if let Value::Array(a) = value {
            for (i, nested) in a.iter().enumerate() {
                visit(nested, &format!("{path}[{i}]"), false)?;
            }
        }
        Ok(())
    }
    visit(&Value::Object(trace.clone()), "composition_trace", true)
}

// ---------------------------------------------------------------------------
// _merge_signals / artifact projection / authority error / rebuild
// ---------------------------------------------------------------------------

/// `_merge_signals` — dedupe by signal_id, preserving order.
pub fn merge_signals(existing: &[RiskSignalV2], additional: &[RiskSignalV2]) -> Vec<RiskSignalV2> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for signal in existing.iter().chain(additional.iter()) {
        if seen.insert(signal.signal_id.clone()) {
            merged.push(signal.clone());
        }
    }
    merged
}

/// `_validate_artifact_projection` — reject alternate action authority in the
/// stored/loaded artifact before it can finalize launch authority.
pub fn validate_artifact_projection(
    payload: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Result<(), VErr> {
    reject_unknown_action_bearing_fields(
        payload,
        &["policy_action", "verdict_action", "action_envelope_json"],
        "artifact projection",
    )?;
    if payload.get("policy_action") != Some(&json!(decision.action.as_str())) {
        bail!("policy_action must match authoritative action");
    }
    if let Some(verdict) = payload.get("verdict_action") {
        if verdict != &json!(decision.action.as_str()) {
            bail!("verdict_action must match authoritative action");
        }
    }
    if let Some(raw_composition) = payload.get("policy_composition") {
        let comp = raw_composition
            .as_object()
            .ok_or_else(|| verr("policy_composition must be an object"))?;
        if comp.get("final_action") != Some(&json!(decision.action.as_str())) {
            bail!("policy_composition.final_action must match authoritative action");
        }
        if payload.contains_key("authoritative_decision") && comp != &decision.composition_trace {
            bail!("policy_composition must match authoritative composition_trace");
        }
    }
    if let Some(raw_dv2) = payload.get("decision_v2_json") {
        let dv2 = raw_dv2
            .as_object()
            .ok_or_else(|| verr("decision_v2_json must be an object"))?;
        if dv2.get("action") != Some(&json!(decision.decision_v2.action)) {
            bail!("decision_v2_json.action must match authoritative action");
        }
        if let Some(ga) = dv2.get("guard_action") {
            let parsed = parse_guard_action_value(ga)?;
            if parsed != decision.action {
                bail!("decision_v2_json.guard_action must match authoritative action");
            }
        }
        if payload.contains_key("authoritative_decision")
            && dv2
                != &decision
                    .decision_v2
                    .to_value()
                    .as_object()
                    .cloned()
                    .unwrap_or_default()
        {
            bail!("decision_v2_json must match authoritative decision_v2");
        }
    }
    if let Some(env) = payload.get("action_envelope_json") {
        let envelope = env
            .as_object()
            .ok_or_else(|| verr("action_envelope_json must be an object or null"))?;
        reject_unknown_action_bearing_fields(
            envelope,
            &[
                "action_id",
                "action_type",
                "policy_action",
                "pre_execution_result",
                "actionId",
                "actionType",
                "policyAction",
                "preExecutionResult",
            ],
            "action_envelope_json",
        )?;
        require_matching_alias(envelope, "action_id", "actionId", "action_envelope_json")?;
        require_matching_alias(
            envelope,
            "action_type",
            "actionType",
            "action_envelope_json",
        )?;
        require_matching_alias(
            envelope,
            "policy_action",
            "policyAction",
            "action_envelope_json",
        )?;
        require_matching_alias(
            envelope,
            "pre_execution_result",
            "preExecutionResult",
            "action_envelope_json",
        )?;
        for (key, alias) in [
            ("policy_action", "policyAction"),
            ("pre_execution_result", "preExecutionResult"),
        ] {
            let envelope_action = envelope
                .get(key)
                .or_else(|| envelope.get(alias))
                .cloned()
                .unwrap_or(Value::Null);
            if envelope_action.is_null() {
                continue;
            }
            if !is_guard_action_value(&envelope_action) {
                bailf!("action_envelope_json.{key} must be a known Guard action");
            }
            if envelope_action != json!(decision.action.as_str()) {
                bailf!("action_envelope_json.{key} must match authoritative action");
            }
        }
    }
    validate_artifact_approval_projection(payload, decision)
}

fn require_matching_alias(
    payload: &Map<String, Value>,
    snake: &str,
    camel: &str,
    context: &str,
) -> Result<(), VErr> {
    if payload.contains_key(snake)
        && payload.contains_key(camel)
        && payload.get(snake) != payload.get(camel)
    {
        bailf!("{context}.{camel} must match {snake}");
    }
    Ok(())
}

const ARTIFACT_ACTION_FIELDS: [&str; 3] =
    ["policy_action", "verdict_action", "action_envelope_json"];

/// `_reject_unknown_action_bearing_fields` — reject keys that can smuggle a
/// second action authority, except the explicitly allowed ones.
fn reject_unknown_action_bearing_fields(
    payload: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), VErr> {
    let _ = ARTIFACT_ACTION_FIELDS;
    for key in payload.keys() {
        if is_action_bearing_key(key) && !allowed.contains(&key.as_str()) {
            bailf!("{context} contains unknown action-bearing field: {key}");
        }
    }
    Ok(())
}

/// `_validate_artifact_approval_projection` — cross-check approval evidence
/// before it can finalize launch authority.
fn validate_artifact_approval_projection(
    payload: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Result<(), VErr> {
    let trace = &decision.composition_trace;
    let approval_fields_present = [
        "approval_reuse",
        "approval_reuse_status",
        "approval_reuse_reason_code",
        "trusted_request_override",
    ]
    .iter()
    .any(|k| payload.contains_key(*k));
    if !approval_fields_present
        && ![
            "saved_state_present",
            "trusted_request_override",
            "saved_approval_claim",
        ]
        .iter()
        .any(|k| trace.contains_key(*k))
    {
        return Ok(());
    }

    let raw_reuse = payload
        .get("approval_reuse")
        .and_then(Value::as_object)
        .ok_or_else(|| verr("approval_reuse must be an object"))?;
    let reuse_action = parse_guard_action_value(raw_reuse.get("action").unwrap_or(&Value::Null))?;
    let current_action =
        parse_guard_action_value(raw_reuse.get("current_action").unwrap_or(&Value::Null))?;
    let saved_action = match raw_reuse.get("saved_action") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_guard_action_value(v)?),
    };
    let reuse_status = raw_reuse
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| verr("approval_reuse.status must be a known status"))?;
    if !["accepted", "rejected", "not-applicable"].contains(&reuse_status) {
        bail!("approval_reuse.status must be a known status");
    }
    let reuse_reason = match raw_reuse.get("reason_code") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        _ => bail!("reason_code must be a non-empty string"),
    };
    let reuse_should_claim = match raw_reuse.get("should_claim") {
        Some(Value::Bool(b)) => *b,
        _ => bail!("approval_reuse.should_claim must be a boolean"),
    };
    if payload.get("approval_reuse_status") != Some(&json!(reuse_status)) {
        bail!("approval_reuse_status must match approval_reuse.status");
    }
    if payload.get("approval_reuse_reason_code") != Some(&json!(reuse_reason)) {
        bail!("approval_reuse_reason_code must match approval_reuse.reason_code");
    }
    if trace.get("current_action") != Some(&json!(current_action.as_str())) {
        bail!("composition_trace.current_action must match approval_reuse.current_action");
    }
    let saved_action_json = saved_action
        .map(|a| json!(a.as_str()))
        .unwrap_or(Value::Null);
    if trace.get("saved_action").cloned().unwrap_or(Value::Null) != saved_action_json
        && !(trace.get("saved_action").is_none() && saved_action.is_none())
    {
        bail!("composition_trace.saved_action must match approval_reuse.saved_action");
    }
    let saved_state_present = match trace.get("saved_state_present") {
        Some(Value::Bool(b)) => *b,
        _ => bail!("composition_trace.saved_state_present must be a boolean"),
    };
    if saved_state_present != saved_action.is_some() {
        bail!("composition_trace.saved_state_present must match saved approval evidence");
    }

    let raw_trusted = payload
        .get("trusted_request_override")
        .and_then(Value::as_object)
        .ok_or_else(|| verr("trusted_request_override must be an object"))?;
    let trusted_applied = match raw_trusted.get("applied") {
        Some(Value::Bool(b)) => *b,
        _ => bail!("trusted_request_override.applied must be a boolean"),
    };
    let trusted_reason = raw_trusted
        .get("reason_code")
        .cloned()
        .unwrap_or(Value::Null);
    let expected_trusted_reason = if trusted_applied {
        json!(TRUSTED_REQUEST_OVERRIDE_REASON)
    } else {
        Value::Null
    };
    if trusted_reason != expected_trusted_reason {
        bail!("trusted_request_override.reason_code must match applied state");
    }
    if trace.get("trusted_request_override") != Some(&json!(trusted_applied)) {
        bail!("composition_trace.trusted_request_override must match outer evidence");
    }

    let saved_allow_reuse = current_action == GuardAction::Review
        && saved_action == Some(GuardAction::Allow)
        && reuse_action == GuardAction::Allow
        && reuse_status == "accepted"
        && reuse_reason == APPROVAL_REUSE_ACCEPTED_REASON
        && reuse_should_claim;
    let saved_block_reuse = saved_action == Some(GuardAction::Block)
        && reuse_action == GuardAction::Block
        && reuse_status == "accepted"
        && reuse_reason == "approval_reuse_saved_block"
        && !reuse_should_claim;
    if reuse_status == "accepted" && !(saved_allow_reuse || saved_block_reuse) {
        bail!("accepted approval reuse must be an exact saved allow or block");
    }
    if reuse_should_claim && !saved_allow_reuse {
        bail!("approval_reuse.should_claim requires accepted exact saved allow reuse");
    }

    let mut expected_action = if trusted_applied {
        GuardAction::Allow
    } else {
        reuse_action
    };
    if let Some(runtime_action) = trace.get("runtime_detector_action") {
        let parsed = parse_guard_action_value(runtime_action)?;
        let detector_review_approved =
            parsed == GuardAction::Review && (trusted_applied || saved_allow_reuse);
        if !detector_review_approved {
            expected_action = most_restrictive_guard_action(
                &[json!(expected_action.as_str()), runtime_action.clone()],
                DEFAULT_UNKNOWN_GUARD_ACTION,
            );
        }
    }
    if decision.action != expected_action {
        bail!("authoritative action must derive from approval reuse and runtime authority");
    }

    let raw_trace_claim = trace.get("saved_approval_claim");
    let raw_outer_claim = payload.get("approval_claim");
    if raw_trace_claim.is_none() != raw_outer_claim.is_none() {
        bail!("saved approval claim must match its authoritative trace");
    }
    let mut claim: Option<&Map<String, Value>> = None;
    if let Some(tclaim) = raw_trace_claim {
        let tclaim_obj = tclaim
            .as_object()
            .ok_or_else(|| verr("saved approval claim must be an object"))?;
        let oclaim_obj = raw_outer_claim
            .and_then(Value::as_object)
            .ok_or_else(|| verr("saved approval claim must be an object"))?;
        if tclaim_obj != oclaim_obj {
            bail!("saved approval claim must match its authoritative trace");
        }
        claim = Some(tclaim_obj);
        validate_saved_approval_claim(payload, tclaim_obj)?;
    }

    if trusted_applied {
        if claim.is_some() {
            bail!("trusted request and saved approval claim cannot both finalize authority");
        }
        if !matches!(
            reuse_action,
            GuardAction::Review | GuardAction::RequireReapproval
        ) {
            bail!("trusted request override must satisfy a review action");
        }
        if !decision.enforcement.authority_finalized {
            bail!("trusted request override must finalize authority");
        }
        if decision.action == GuardAction::Allow
            && decision.reason != TRUSTED_REQUEST_OVERRIDE_REASON
        {
            bail!("trusted request allow reason must match its evidence");
        }
        require_scanner_evidence(
            payload,
            "trusted_request_override",
            "accepted",
            TRUSTED_REQUEST_OVERRIDE_REASON,
            payload.get("approval_context_hash"),
        )?;
    }

    if let Some(_c) = claim {
        if !decision.enforcement.authority_finalized {
            bail!("saved approval claim must finalize authority");
        }
        if !saved_allow_reuse {
            bail!("saved approval claim must match accepted exact allow reuse");
        }
        require_scanner_evidence(
            payload,
            "approval_reuse",
            "accepted",
            APPROVAL_REUSE_ACCEPTED_REASON,
            None,
        )?;
    } else if reuse_should_claim && decision.enforcement.authority_finalized && !trusted_applied {
        bail!("finalized saved approval reuse requires an atomic claim proof");
    }
    Ok(())
}

fn validate_saved_approval_claim(
    payload: &Map<String, Value>,
    claim: &Map<String, Value>,
) -> Result<(), VErr> {
    let expected: BTreeSet<&str> = ["status", "approval_context_hash", "reason_code"].into();
    let actual: BTreeSet<&str> = claim.keys().map(String::as_str).collect();
    if actual != expected {
        bail!("saved approval claim has an invalid schema");
    }
    if !["consumed", "retained"]
        .contains(&claim.get("status").and_then(Value::as_str).unwrap_or(""))
    {
        bail!("saved approval claim status must be consumed or retained");
    }
    let context_hash = payload.get("approval_context_hash").and_then(Value::as_str);
    match context_hash {
        Some(h) if !h.is_empty() && claim.get("approval_context_hash") == Some(&json!(h)) => {}
        _ => bail!("saved approval claim must match approval_context_hash"),
    }
    if claim.get("reason_code") != Some(&json!(APPROVAL_REUSE_ACCEPTED_REASON)) {
        bail!("saved approval claim must carry the accepted reuse reason");
    }
    Ok(())
}

fn require_scanner_evidence(
    payload: &Map<String, Value>,
    source: &str,
    status: &str,
    reason_code: &str,
    artifact_hash: Option<&Value>,
) -> Result<(), VErr> {
    let raw = match payload.get("scanner_evidence") {
        Some(Value::Array(a)) => a,
        _ => bail!("scanner_evidence must be a list"),
    };
    for entry in raw {
        let Some(e) = entry.as_object() else { continue };
        if e.get("source") == Some(&json!(source))
            && e.get("status") == Some(&json!(status))
            && e.get("reason_code") == Some(&json!(reason_code))
            && (artifact_hash.is_none() || e.get("artifact_hash") == artifact_hash)
        {
            return Ok(());
        }
    }
    bailf!("scanner_evidence must contain matching {source} evidence")
}

// ---------------------------------------------------------------------------
// authoritative_decision_from_artifact / run projection / evaluation / rebuild
// ---------------------------------------------------------------------------

/// `authoritative_decision_from_artifact` — parse + cross-check a serialized
/// artifact decision. Older callers without `authoritative_decision` are
/// adapted only when every action field they provide agrees; new payloads get
/// strict schema validation.
pub fn authoritative_decision_from_artifact(
    payload: &Map<String, Value>,
    require_authoritative: bool,
) -> Result<AuthoritativeGuardDecision, VErr> {
    let decision = match payload.get("authoritative_decision") {
        Some(Value::Object(m)) => decode_authoritative_decision(m)?,
        Some(_) => bail!("authoritative_decision must be an object"),
        None => {
            if require_authoritative {
                bail!("authoritative_decision is required at the launch boundary");
            }
            let action =
                parse_guard_action_value(payload.get("policy_action").unwrap_or(&Value::Null))?;
            let mut composition = payload
                .get("policy_composition")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            composition.insert("final_action".into(), json!(action.as_str()));
            let reason = payload
                .get("decision_v2_json")
                .and_then(Value::as_object)
                .and_then(|d| d.get("reason"))
                .and_then(Value::as_str)
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| action.as_str());
            build_authoritative_decision(
                action,
                reason,
                composition,
                &[],
                true,
                "legacy-compatible-projection",
            )?
        }
    };
    validate_artifact_projection(payload, &decision)?;
    Ok(decision)
}

/// `evaluation_authority_error` — detect authoritative-vs-legacy divergence.
pub fn evaluation_authority_error(evaluation: &Map<String, Value>) -> Option<&'static str> {
    let authority = evaluation.get("authoritative_decision")?.as_object()?;
    let action = authority.get("action")?.as_str()?;
    if evaluation.get("policy_action") != Some(&json!(action)) {
        return Some("policy_action diverges from authoritative_decision.action");
    }
    if let Some(verdict) = evaluation.get("verdict_action") {
        if verdict != &json!(action) {
            return Some("verdict_action diverges from authoritative_decision.action");
        }
    }
    None
}

/// `rebuild_artifact_authority` — re-parse the artifact and confirm launch
/// authority survives byte-identical.
pub fn rebuild_artifact_authority(
    payload: &Map<String, Value>,
    require_authoritative: bool,
) -> Result<AuthoritativeGuardDecision, VErr> {
    let decision = authoritative_decision_from_artifact(payload, require_authoritative)?;
    if payload.contains_key("authoritative_decision")
        && payload
            .get("authoritative_decision")
            .and_then(Value::as_object)
            != Some(&decision.to_value().as_object().cloned().unwrap_or_default())
    {
        bail!("authoritative decision authority is inconsistent");
    }
    Ok(decision)
}

/// `_validate_run_decision_projection` — confirm run authority matches the
/// runtime detector composition + signals.
pub fn validate_run_decision_projection(
    evaluation: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Result<(), VErr> {
    let composition = evaluation
        .get("runtime_detector_composition")
        .and_then(Value::as_object)
        .ok_or_else(|| verr("run authority requires runtime_detector_composition"))?;
    if composition.get("action") != Some(&json!(decision.action.as_str()))
        || composition.get("reason") != Some(&json!(decision.reason))
    {
        bail!("runtime detector composition must match run authority");
    }
    if decision.composition_trace.get("runtime_detector_action")
        != Some(&json!(decision.action.as_str()))
    {
        bail!("run authority trace must match the runtime detector action");
    }
    let raw_signals = evaluation
        .get("runtime_detector_signals_v2")
        .and_then(Value::as_array)
        .ok_or_else(|| verr("run authority requires runtime detector signals"))?;
    let projected: Vec<Value> = decision.signals.iter().map(|s| s.to_value()).collect();
    if &projected != raw_signals {
        bail!("runtime detector signals must match run authority");
    }
    let blocked_reason = evaluation.get("blocked_by_detector");
    if decision.enforcement.blocking && blocked_reason != Some(&json!(decision.reason)) {
        bail!("blocked_by_detector must match run authority reason");
    }
    Ok(())
}

/// Strict decode of an `authoritative_decision` payload — requires exact field
/// set, all sub-objects validated, then runs `validate_authoritative_decision`.
fn decode_authoritative_decision(
    payload: &Map<String, Value>,
) -> Result<AuthoritativeGuardDecision, VErr> {
    const FIELDS: [&str; 8] = [
        "schema_version",
        "action",
        "source",
        "reason",
        "composition_trace",
        "signals",
        "enforcement",
        "decision_v2",
    ];
    let actual: BTreeSet<&str> = payload.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = FIELDS.into();
    if actual != expected {
        bail!("authoritative_decision fields must match schema");
    }
    let schema_version = match payload.get("schema_version") {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(-1),
        _ => bail!("schema_version must be an integer"),
    };
    let action = parse_guard_action_value(payload.get("action").unwrap_or(&Value::Null))?;
    let source = payload
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let composition_trace = payload
        .get("composition_trace")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| verr("composition_trace must be an object"))?;
    let signals: Vec<RiskSignalV2> = payload
        .get("signals")
        .and_then(Value::as_array)
        .ok_or_else(|| verr("signals must be a list"))?
        .iter()
        .map(RiskSignalV2::decode)
        .collect::<Result<_, _>>()
        .map_err(|_| verr("signals must be a list of valid signal objects"))?;
    let enforcement_raw = payload
        .get("enforcement")
        .and_then(Value::as_object)
        .ok_or_else(|| verr("enforcement fields must match schema"))?;
    const EF: [&str; 6] = [
        "blocking",
        "authority_finalized",
        "launch_permitted",
        "prompt_required",
        "sandbox_required",
        "snapshot_permitted",
    ];
    if enforcement_raw
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != EF.into_iter().collect::<BTreeSet<_>>()
    {
        bail!("enforcement fields must match schema");
    }
    let rb = |k: &str| -> Result<bool, VErr> {
        match enforcement_raw.get(k) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => bailf!("{k} must be a boolean"),
        }
    };
    let enforcement = GuardDecisionEnforcementState {
        blocking: rb("blocking")?,
        authority_finalized: rb("authority_finalized")?,
        launch_permitted: rb("launch_permitted")?,
        prompt_required: rb("prompt_required")?,
        sandbox_required: rb("sandbox_required")?,
        snapshot_permitted: rb("snapshot_permitted")?,
    };
    let dv2_raw = payload
        .get("decision_v2")
        .and_then(Value::as_object)
        .ok_or_else(|| verr("decision_v2 fields must match schema"))?;
    const DVF: [&str; 11] = [
        "guard_action",
        "action",
        "reason",
        "user_title",
        "user_body",
        "harness_message",
        "dashboard_primary_detail",
        "approval_scopes",
        "retry_instruction",
        "signals",
        "confidence",
    ];
    // decision_v2 may also carry the optional cloud reason code.
    let mut dv_expected: BTreeSet<&str> = DVF.into();
    if dv2_raw.contains_key("package_review_cloud_reason_code") {
        dv_expected.insert("package_review_cloud_reason_code");
    }
    if dv2_raw.keys().map(String::as_str).collect::<BTreeSet<_>>() != dv_expected {
        bail!("decision_v2 fields must match schema");
    }
    let rs = |k: &str| -> Result<String, VErr> {
        match dv2_raw.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
            _ => bailf!("{k} must be a non-empty string"),
        }
    };
    let dv2_signals: Vec<RiskSignalV2> = dv2_raw
        .get("signals")
        .and_then(Value::as_array)
        .ok_or_else(|| verr("signals must be a list"))?
        .iter()
        .map(RiskSignalV2::decode)
        .collect::<Result<_, _>>()
        .map_err(|_| verr("decision_v2.signals must be a list of valid signal objects"))?;
    let dv2 = GuardDecisionV2 {
        guard_action: parse_guard_action_value(
            dv2_raw.get("guard_action").unwrap_or(&Value::Null),
        )?,
        action: match dv2_raw.get("action").and_then(Value::as_str) {
            Some("allow") | Some("warn") | Some("ask") | Some("block") => dv2_raw
                .get("action")
                .and_then(Value::as_str)
                .unwrap()
                .to_string(),
            _ => bail!("action must be a known Guard decision action"),
        },
        reason: rs("reason")?,
        user_title: rs("user_title")?,
        user_body: rs("user_body")?,
        harness_message: rs("harness_message")?,
        dashboard_primary_detail: rs("dashboard_primary_detail")?,
        approval_scopes: dv2_raw
            .get("approval_scopes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        retry_instruction: dv2_raw
            .get("retry_instruction")
            .and_then(Value::as_str)
            .map(str::to_string),
        signals: dv2_signals,
        confidence: crate::signal_contract::parse_risk_confidence(
            dv2_raw.get("confidence").unwrap_or(&Value::Null),
        )
        .map_err(|_| verr("confidence must be a known confidence label"))?,
        package_review_cloud_reason_code: dv2_raw
            .get("package_review_cloud_reason_code")
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    let decision = AuthoritativeGuardDecision {
        schema_version,
        action,
        source,
        reason,
        composition_trace,
        signals,
        enforcement,
        decision_v2: dv2,
    };
    validate_authoritative_decision(&decision)?;
    Ok(decision)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal_contract::{RiskRedactionLevel, RiskSeverityLabel, RiskSignalCategory};
    use serde_json::json;

    fn sig(
        cat: RiskSignalCategory,
        sev: RiskSeverityLabel,
        conf: RiskConfidenceLabel,
        det: &str,
        id: &str,
    ) -> RiskSignalV2 {
        RiskSignalV2 {
            signal_id: id.into(),
            category: cat,
            severity: sev,
            confidence: conf,
            detector: det.into(),
            title: "t".into(),
            plain_reason: format!("reason-{id}"),
            technical_detail: None,
            evidence_ref: None,
            redaction_level: RiskRedactionLevel::Summary,
            false_positive_hint: None,
            advisory_id: None,
        }
    }

    fn allow_decision() -> AuthoritativeGuardDecision {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("allow"));
        build_authoritative_decision(
            GuardAction::Allow,
            "policy allows",
            trace,
            &[],
            true,
            "composed-consumer-policy",
        )
        .unwrap()
    }

    #[test]
    fn build_allow_derives_non_blocking() {
        let d = allow_decision();
        assert!(!d.enforcement.blocking);
        assert!(d.enforcement.launch_permitted);
        assert!(d.enforcement.snapshot_permitted);
        assert!(!d.enforcement.prompt_required);
        assert_eq!(d.decision_v2.action, "allow");
        assert_eq!(d.decision_v2.user_title, "Allowed by policy");
        assert_eq!(d.composition_trace["final_action"], "allow");
    }

    #[test]
    fn build_review_is_blocking_and_prompt_required() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("review"));
        let d = build_authoritative_decision(
            GuardAction::Review,
            "needs approval",
            trace,
            &[],
            false,
            "composed-consumer-policy",
        )
        .unwrap();
        assert!(d.enforcement.blocking);
        assert!(!d.enforcement.launch_permitted); // blocking -> not permitted
        assert!(d.enforcement.prompt_required);
        assert_eq!(d.decision_v2.action, "ask");
        assert_eq!(
            d.decision_v2.approval_scopes,
            vec!["once", "task", "always"]
        );
    }

    #[test]
    fn build_block_derives_block_copy() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("block"));
        let sigs = vec![sig(
            RiskSignalCategory::Secret,
            RiskSeverityLabel::Critical,
            RiskConfidenceLabel::Strong,
            "d",
            "s",
        )];
        let d = build_authoritative_decision(
            GuardAction::Block,
            "denied",
            trace,
            &sigs,
            true,
            "composed-consumer-policy",
        )
        .unwrap();
        assert!(d.enforcement.blocking);
        assert_eq!(d.decision_v2.action, "block");
        assert_eq!(d.decision_v2.user_title, "Blocked by policy");
    }

    #[test]
    fn empty_reason_rejected() {
        let trace = Map::new();
        assert!(
            build_authoritative_decision(GuardAction::Allow, "   ", trace, &[], true, "s").is_err()
        );
    }

    #[test]
    fn data_flow_copy_overrides_block() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("block"));
        let sigs = vec![RiskSignalV2 {
            detector: "data_flow.exfiltration".into(),
            category: RiskSignalCategory::Network,
            severity: RiskSeverityLabel::Critical,
            confidence: RiskConfidenceLabel::Strong,
            signal_id: "data-flow:network".into(),
            title: "t".into(),
            plain_reason: "r".into(),
            technical_detail: None,
            evidence_ref: None,
            redaction_level: RiskRedactionLevel::Summary,
            false_positive_hint: None,
            advisory_id: None,
        }];
        let d = build_authoritative_decision(
            GuardAction::Block,
            "denied",
            trace,
            &sigs,
            true,
            "composed-consumer-policy",
        )
        .unwrap();
        assert_eq!(data_flow_sink_type(&d.signals), "network host");
        assert!(d.decision_v2.harness_message.contains("network host"));
        assert!(d
            .decision_v2
            .dashboard_primary_detail
            .contains("Source-to-sink route"));
    }

    #[test]
    fn artifact_projection_keys_present() {
        let d = allow_decision();
        let proj = d.to_artifact_projection();
        assert_eq!(proj["policy_action"], "allow");
        assert_eq!(proj["verdict_action"], "allow");
        assert_eq!(proj["decision_action"], "allow");
        assert!(proj["authoritative_decision"].is_object());
    }

    #[test]
    fn merge_signals_dedupes_by_id() {
        let a = sig(
            RiskSignalCategory::Network,
            RiskSeverityLabel::Low,
            RiskConfidenceLabel::Likely,
            "d1",
            "id-1",
        );
        let b = sig(
            RiskSignalCategory::Secret,
            RiskSeverityLabel::High,
            RiskConfidenceLabel::Strong,
            "d2",
            "id-2",
        );
        let b2 = sig(
            RiskSignalCategory::Secret,
            RiskSeverityLabel::High,
            RiskConfidenceLabel::Strong,
            "d2",
            "id-2",
        );
        let merged = merge_signals(
            &[a.clone(), b.clone()],
            &[
                b2,
                sig(
                    RiskSignalCategory::Policy,
                    RiskSeverityLabel::Info,
                    RiskConfidenceLabel::Weak,
                    "d3",
                    "id-3",
                ),
            ],
        );
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].signal_id, "id-1");
        assert_eq!(merged[2].signal_id, "id-3");
    }

    #[test]
    fn composition_trace_rejects_runtime_block_override() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("allow"));
        trace.insert("runtime_detector_action".into(), json!("block"));
        // build would fail at validate; call the validator directly
        let r = validate_composition_trace(GuardAction::Allow, &trace);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().as_str().unwrap(),
            "runtime detector block cannot be overridden"
        );
    }

    #[test]
    fn composition_trace_rejects_unknown_action_field_nested() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("allow"));
        let mut nested = Map::new();
        nested.insert("sneakyAction".into(), json!("block")); // action-bearing nested
        trace.insert("meta".into(), Value::Object(nested));
        let r = validate_composition_trace(GuardAction::Allow, &trace);
        assert!(r
            .unwrap_err()
            .as_str()
            .unwrap()
            .contains("unknown action-bearing field"));
    }

    #[test]
    fn composition_trace_allows_known_action_fields() {
        let mut trace = Map::new();
        trace.insert("final_action".into(), json!("review"));
        trace.insert("configured_action".into(), json!("allow"));
        trace.insert("current_action".into(), json!("review"));
        let r = validate_composition_trace(GuardAction::Review, &trace);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn evaluation_authority_error_detects_divergence() {
        let mut eval = Map::new();
        eval.insert("authoritative_decision".into(), allow_decision().to_value());
        eval.insert("policy_action".into(), json!("block")); // divergent
        assert!(evaluation_authority_error(&eval).is_some());
        eval.insert("policy_action".into(), json!("allow"));
        assert!(evaluation_authority_error(&eval).is_none());
    }

    #[test]
    fn artifact_roundtrip_validate() {
        let d = allow_decision();
        // `to_artifact_projection` emits `decision_action`, which
        // `_reject_unknown_action_bearing_fields` rejects (not in
        // _ARTIFACT_ACTION_FIELDS) — Python behaves identically, so the
        // stored artifact drops it before validation.
        let mut proj = d.to_artifact_projection().as_object().cloned().unwrap();
        proj.remove("decision_action");
        let d2 = authoritative_decision_from_artifact(&proj, true).unwrap();
        assert_eq!(d2.action, GuardAction::Allow);
        assert_eq!(d2, d);
        // parity check: decision_action-bearing projection is rejected
        let mut bad = d.to_artifact_projection().as_object().cloned().unwrap();
        let r = authoritative_decision_from_artifact(&bad, true);
        assert!(r
            .unwrap_err()
            .as_str()
            .unwrap()
            .contains("unknown action-bearing field: decision_action"));
        let _ = bad.remove("policy_reason");
    }
}
