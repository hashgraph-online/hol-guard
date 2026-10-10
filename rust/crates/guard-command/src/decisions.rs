//! `runtime/decisions.py` — authoritative Guard decision and strict validators.
//!
//! Byte-parity port of the staged Python (30 fns). Value types and the action
//! lattice are reused from `guard-contracts` (RTM-023): `GuardAction`,
//! `RiskSignalV2`, `RiskConfidenceLabel`, `compose_action_from_signals`,
//! `data_flow_sink_type`, `guard_action_severity`, `most_restrictive_of`,
//! `is_action_bearing_key`, `is_guard_action`.
//!
//! `ValueError` -> `DecisionError` (a `String` carrying the verbatim Python
//! exception message). `_parse_confidence` is the `parse_risk_confidence` alias.

use guard_contracts::{
    compose_action_from_signals, data_flow_sink_type, is_action_bearing_key, is_guard_action,
    most_restrictive_of, GuardAction, RiskConfidenceLabel, RiskSignalV2,
};
use serde_json::{json, Map, Value};

pub use crate::signals::parse_risk_confidence;

// ---------------------------------------------------------------------------
// Error type — ValueError analogue
// ---------------------------------------------------------------------------

/// `ValueError`-equivalent. Carries the exact Python exception message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionError(pub String);

impl std::fmt::Display for DecisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DecisionError {}

type Res<T> = Result<T, DecisionError>;

fn err<T>(m: &str) -> Res<T> {
    Err(DecisionError(m.to_string()))
}

// ---------------------------------------------------------------------------
// Constants + literal field sets
// ---------------------------------------------------------------------------

/// `GuardDecisionAction` literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDecisionAction {
    Allow,
    Warn,
    Ask,
    Block,
}
impl GuardDecisionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Ask => "ask",
            Self::Block => "block",
        }
    }
}

pub const AUTHORITATIVE_DECISION_SCHEMA_VERSION: i64 = 1;
pub const AUTHORITATIVE_DECISION_INCONSISTENT: &str = "authoritative_decision_inconsistent";

const APPROVAL_REUSE_ACCEPTED_REASON: &str = "approval_reuse_accepted";
const TRUSTED_REQUEST_OVERRIDE_REASON: &str = "trusted_request_override_exact_context";

fn blocking_actions() -> BTreeSetWrap {
    BTreeSetWrap(&[
        GuardAction::Review,
        GuardAction::RequireReapproval,
        GuardAction::SandboxRequired,
        GuardAction::Block,
    ])
}
struct BTreeSetWrap(&'static [GuardAction]);
impl BTreeSetWrap {
    fn contains(&self, a: GuardAction) -> bool {
        self.0.contains(&a)
    }
}

fn composition_action_fields() -> [&'static str; 5] {
    [
        "configured_action",
        "current_action",
        "saved_action",
        "scanner_action",
        "runtime_detector_action",
    ]
}
fn known_composition_action_fields() -> std::collections::HashSet<&'static str> {
    composition_action_fields()
        .into_iter()
        .chain(std::iter::once("final_action"))
        .collect()
}
fn terminal_composition_actions() -> [GuardAction; 2] {
    [GuardAction::SandboxRequired, GuardAction::Block]
}
fn saved_approval_claim_dispositions() -> [&'static str; 2] {
    ["consumed", "retained"]
}
fn decision_v2_fields() -> std::collections::HashSet<&'static str> {
    [
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
    ]
    .into_iter()
    .collect()
}
fn decision_v2_action_fields() -> std::collections::HashSet<&'static str> {
    ["guard_action", "action"].into_iter().collect()
}
fn enforcement_fields() -> std::collections::HashSet<&'static str> {
    [
        "blocking",
        "authority_finalized",
        "launch_permitted",
        "prompt_required",
        "sandbox_required",
        "snapshot_permitted",
    ]
    .into_iter()
    .collect()
}
fn authoritative_decision_fields() -> std::collections::HashSet<&'static str> {
    [
        "schema_version",
        "action",
        "source",
        "reason",
        "composition_trace",
        "signals",
        "enforcement",
        "decision_v2",
    ]
    .into_iter()
    .collect()
}
fn artifact_action_fields() -> std::collections::HashSet<&'static str> {
    ["policy_action", "verdict_action", "action_envelope_json"]
        .into_iter()
        .collect()
}
fn action_envelope_action_fields() -> std::collections::HashSet<&'static str> {
    [
        "action_id",
        "action_type",
        "policy_action",
        "pre_execution_result",
        "actionId",
        "actionType",
        "policyAction",
        "preExecutionResult",
    ]
    .into_iter()
    .collect()
}

/// `_ACTION_MESSAGES[guard_action]` -> `(action, user_title, harness_message,
/// retry_instruction)`.
fn action_messages(
    a: GuardAction,
) -> (
    GuardDecisionAction,
    &'static str,
    &'static str,
    &'static str,
) {
    match a {
        GuardAction::Allow => (
            GuardDecisionAction::Allow,
            "Allowed by policy",
            "Policy allows this action.",
            "HOL Guard allowed this action because policy already trusts it.",
        ),
        GuardAction::Warn => (
            GuardDecisionAction::Warn,
            "Risk signals found",
            "HOL Guard noticed risk signals, but policy allows the harness to continue.",
            "Review the warning if this action was unexpected.",
        ),
        GuardAction::Review => (
            GuardDecisionAction::Ask,
            "Approval required",
            "HOL Guard needs your approval before this action can run.",
            "Choose an approval scope, then retry in the harness.",
        ),
        GuardAction::SandboxRequired => (
            GuardDecisionAction::Ask,
            "Sandbox review required",
            "HOL Guard wants this action reviewed and run in a sandboxed path.",
            "Run this action in an approved sandbox, then retry.",
        ),
        GuardAction::RequireReapproval => (
            GuardDecisionAction::Ask,
            "Fresh approval required",
            "HOL Guard needs a fresh approval before this action can run.",
            "Choose the smallest approval scope that matches your intent, then retry.",
        ),
        GuardAction::Block => (
            GuardDecisionAction::Block,
            "Blocked by policy",
            "HOL Guard blocked this action.",
            "Review the details before changing policy or retrying.",
        ),
    }
}

// ---------------------------------------------------------------------------
// Coercion helpers (payload_coercion.py) + strict field-set parsers
// ---------------------------------------------------------------------------

/// `required_string` — non-empty string.
fn required_string(payload: &Map<String, Value>, key: &str) -> Res<String> {
    match payload.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        _ => err(&format!("{key} must be a non-empty string")),
    }
}
/// `optional_string`.
fn optional_string(payload: &Map<String, Value>, key: &str) -> Res<Option<String>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => err(&format!("{key} must be a string or null")),
    }
}
/// `_required_bool`.
fn required_bool(payload: &Map<String, Value>, key: &str) -> Res<bool> {
    match payload.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => err(&format!("{key} must be a boolean")),
    }
}

/// `_parse_action`.
fn parse_action(v: &Value) -> Res<GuardDecisionAction> {
    match v.as_str() {
        Some("allow") => Ok(GuardDecisionAction::Allow),
        Some("warn") => Ok(GuardDecisionAction::Warn),
        Some("ask") => Ok(GuardDecisionAction::Ask),
        Some("block") => Ok(GuardDecisionAction::Block),
        _ => err("action must be a known Guard decision action"),
    }
}
/// `_parse_guard_action`.
fn parse_guard_action(v: &Value) -> Res<GuardAction> {
    if !is_guard_action(v) {
        return err("action must be a known Guard action");
    }
    Ok(GuardAction::from_canonical(v.as_str().unwrap()).unwrap())
}
/// `_parse_confidence` == `parse_risk_confidence`.
fn parse_confidence(v: &Value) -> Res<RiskConfidenceLabel> {
    parse_risk_confidence(v).map_err(|e| DecisionError(e.0.to_string()))
}
/// `_parse_signals`.
fn parse_signals(v: &Value) -> Res<Vec<RiskSignalV2>> {
    let arr = match v {
        Value::Array(a) => a,
        _ => return err("signals must be a list"),
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if !item.is_object() {
            let tname = match item {
                Value::Null => "NoneType",
                Value::Bool(_) => "bool",
                Value::Number(_) => "int",
                Value::String(_) => "str",
                Value::Array(_) => "list",
                _ => "object",
            };
            return err(&format!("signal item must be an object, got {tname}"));
        }
        out.push(RiskSignalV2::decode(item).map_err(|e| DecisionError(e.0.to_string()))?);
    }
    Ok(out)
}
/// `_parse_string_tuple`.
fn parse_string_tuple(v: &Value, key: &str) -> Res<Vec<String>> {
    let arr = match v {
        Value::Array(a) => a,
        _ => return err(&format!("{key} must be a list of non-empty strings")),
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        match item {
            Value::String(s) if !s.trim().is_empty() => out.push(s.clone()),
            _ => return err(&format!("{key} must be a list of non-empty strings")),
        }
    }
    Ok(out)
}

/// `_require_exact_fields` — exact key set.
fn require_exact_fields(
    payload: &Map<String, Value>,
    expected: &std::collections::HashSet<&'static str>,
    context: &str,
) -> Res<()> {
    let actual: std::collections::HashSet<&str> = payload.keys().map(|k| k.as_str()).collect();
    let expected_set: std::collections::HashSet<&str> = expected.iter().copied().collect();
    if actual == expected_set {
        return Ok(());
    }
    let mut missing: Vec<&str> = expected_set.difference(&actual).copied().collect();
    missing.sort();
    let mut extra: Vec<&str> = actual.difference(&expected_set).copied().collect();
    extra.sort();
    err(&format!(
        "{context} fields must match schema; missing={missing:?}, extra={extra:?}"
    ))
}
/// `_reject_unknown_action_bearing_fields`.
fn reject_unknown_action_bearing_fields(
    payload: &Map<String, Value>,
    allowed: &std::collections::HashSet<&'static str>,
    context: &str,
) -> Res<()> {
    for key in payload.keys() {
        if is_action_bearing_key(key) && !allowed.contains(key.as_str()) {
            return err(&format!(
                "{context} contains unknown action-bearing field: {key}"
            ));
        }
    }
    Ok(())
}
/// `_require_matching_alias`.
fn require_matching_alias(
    payload: &Map<String, Value>,
    snake_key: &str,
    camel_key: &str,
    context: &str,
) -> Res<()> {
    if let (Some(s), Some(c)) = (payload.get(snake_key), payload.get(camel_key)) {
        if s != c {
            return err(&format!("{context}.{camel_key} must match {snake_key}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GuardDecisionV2
// ---------------------------------------------------------------------------

/// `GuardDecisionV2` — product-facing decision.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardDecisionV2 {
    pub guard_action: GuardAction,
    pub action: GuardDecisionAction,
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
    /// `to_dict` — key order matches the Python literal.
    pub fn to_value(&self) -> Value {
        let mut payload = json!({
            "guard_action": self.guard_action.as_str(),
            "action": self.action.as_str(),
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

    /// `from_dict`.
    pub fn decode(payload: &Value) -> Res<Self> {
        let p = match payload {
            Value::Object(m) => m,
            _ => return err("decision_v2 must be an object"),
        };
        reject_unknown_action_bearing_fields(p, &decision_v2_action_fields(), "decision_v2")?;
        let guard_action = parse_guard_action(p.get("guard_action").unwrap_or(&Value::Null))?;
        let action = parse_action(p.get("action").unwrap_or(&Value::Null))?;
        if action != action_messages(guard_action).0 {
            return err("decision_v2.action must match guard_action");
        }
        Ok(Self {
            guard_action,
            action,
            reason: required_string(p, "reason")?,
            user_title: required_string(p, "user_title")?,
            user_body: required_string(p, "user_body")?,
            harness_message: required_string(p, "harness_message")?,
            dashboard_primary_detail: required_string(p, "dashboard_primary_detail")?,
            approval_scopes: parse_string_tuple(
                p.get("approval_scopes").unwrap_or(&Value::Null),
                "approval_scopes",
            )?,
            retry_instruction: optional_string(p, "retry_instruction")?,
            signals: parse_signals(p.get("signals").unwrap_or(&Value::Null))?,
            confidence: parse_confidence(p.get("confidence").unwrap_or(&Value::Null))?,
            package_review_cloud_reason_code: optional_string(
                p,
                "package_review_cloud_reason_code",
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// GuardDecisionEnforcementState
// ---------------------------------------------------------------------------

/// `GuardDecisionEnforcementState`.
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
    /// `to_dict`.
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
    /// `from_dict`.
    pub fn decode(payload: &Value) -> Res<Self> {
        let p = match payload {
            Value::Object(m) => m,
            _ => return err("enforcement must be an object"),
        };
        require_exact_fields(p, &enforcement_fields(), "enforcement")?;
        Ok(Self {
            blocking: required_bool(p, "blocking")?,
            authority_finalized: required_bool(p, "authority_finalized")?,
            launch_permitted: required_bool(p, "launch_permitted")?,
            prompt_required: required_bool(p, "prompt_required")?,
            sandbox_required: required_bool(p, "sandbox_required")?,
            snapshot_permitted: required_bool(p, "snapshot_permitted")?,
        })
    }
}

// ---------------------------------------------------------------------------
// AuthoritativeGuardDecision
// ---------------------------------------------------------------------------

/// `AuthoritativeGuardDecision`.
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
    /// `to_dict`.
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
    /// `to_artifact_projection`.
    pub fn to_artifact_projection(&self) -> Value {
        json!({
            "authoritative_decision": self.to_value(),
            "policy_action": self.action.as_str(),
            "decision_v2_json": self.decision_v2.to_value(),
            "policy_composition": self.composition_trace,
            "verdict_action": self.action.as_str(),
        })
    }
    /// `from_dict` — exact field set, validated, then cross-checked.
    pub fn decode(payload: &Value) -> Res<Self> {
        let p = match payload {
            Value::Object(m) => m,
            _ => return err("authoritative_decision must be an object"),
        };
        require_exact_fields(
            p,
            &authoritative_decision_fields(),
            "authoritative_decision",
        )?;
        let schema_version = match p.get("schema_version").and_then(Value::as_i64) {
            Some(v) => v,
            None => return err("schema_version must be an integer"),
        };
        if schema_version != AUTHORITATIVE_DECISION_SCHEMA_VERSION {
            return err("schema_version must match the authoritative schema version");
        }
        let action = parse_guard_action(p.get("action").unwrap_or(&Value::Null))?;
        let source = required_string(p, "source")?;
        let reason = required_string(p, "reason")?;
        let composition_trace = match p.get("composition_trace") {
            Some(Value::Object(m)) => m.clone(),
            _ => return err("composition_trace must be an object"),
        };
        let signals = parse_signals(p.get("signals").unwrap_or(&Value::Null))?;
        let enforcement = match p.get("enforcement") {
            Some(Value::Object(m)) => {
                GuardDecisionEnforcementState::decode(&Value::Object(m.clone()))?
            }
            _ => return err("enforcement must be an object"),
        };
        let decision_v2 = match p.get("decision_v2") {
            Some(Value::Object(m)) => {
                require_exact_fields(m, &decision_v2_fields(), "decision_v2")?;
                GuardDecisionV2::decode(&Value::Object(m.clone()))?
            }
            _ => return err("decision_v2 must be an object"),
        };
        let decision = Self {
            schema_version: AUTHORITATIVE_DECISION_SCHEMA_VERSION,
            action,
            source,
            reason,
            composition_trace,
            signals,
            enforcement,
            decision_v2,
        };
        validate_authoritative_decision(&decision)?;
        Ok(decision)
    }
}

// ---------------------------------------------------------------------------
// decision_from_legacy_policy_action + signal derivations
// ---------------------------------------------------------------------------

/// `_confidence_rank`.
fn confidence_rank(confidence: RiskConfidenceLabel) -> i32 {
    match confidence {
        RiskConfidenceLabel::Strong => 3,
        RiskConfidenceLabel::Likely => 2,
        RiskConfidenceLabel::Weak => 1,
    }
}

/// `_highest_confidence` — `"likely"` on empty.
fn highest_confidence(signals: &[RiskSignalV2]) -> RiskConfidenceLabel {
    signals
        .iter()
        .map(|s| s.confidence)
        .max_by_key(|c| confidence_rank(*c))
        .unwrap_or(RiskConfidenceLabel::Likely)
}

/// `_has_data_flow_exfiltration_signal`.
fn has_data_flow_exfiltration_signal(signals: &[RiskSignalV2]) -> bool {
    signals
        .iter()
        .any(|s| s.detector == "data_flow.exfiltration" || s.signal_id.starts_with("data-flow:"))
}

/// `_approval_scopes_for_action`.
fn approval_scopes_for_action(action: GuardAction) -> Vec<String> {
    if !matches!(action, GuardAction::Review | GuardAction::RequireReapproval) {
        return Vec::new();
    }
    ["artifact", "workspace", "publisher", "harness"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `_dashboard_detail_from_signals` — fallback / data-flow copy / strongest
/// `plain_reason`.
fn dashboard_detail_from_signals(signals: &[RiskSignalV2], fallback: &str) -> String {
    if signals.is_empty() {
        return fallback.to_string();
    }
    if has_data_flow_exfiltration_signal(signals) {
        let sink_type = data_flow_sink_type(signals);
        return format!(
            "Source-to-sink route: local secret -> {sink_type}. \
This command sends local secret to {sink_type} without exposing the raw secret in Guard evidence."
        );
    }
    let strongest = signals
        .iter()
        .max_by_key(|item| confidence_rank(item.confidence))
        .unwrap();
    strongest.plain_reason.clone()
}

/// `_harness_message_from_signals` — data-flow copy overrides, else fallback.
fn harness_message_from_signals(
    signals: &[RiskSignalV2],
    fallback: &str,
    policy_action: GuardAction,
) -> String {
    if has_data_flow_exfiltration_signal(signals) {
        let sink_type = data_flow_sink_type(signals);
        return match policy_action {
            GuardAction::Allow => format!(
                "HOL Guard allowed this action after noting that it sends local secret to {sink_type}."
            ),
            GuardAction::Warn => format!(
                "HOL Guard allowed this action with a warning because it sends local secret to {sink_type}."
            ),
            GuardAction::SandboxRequired => format!(
                "HOL Guard requires a sandbox because this action sends local secret to {sink_type}."
            ),
            GuardAction::Block => format!(
                "HOL Guard blocked this action because it sends local secret to {sink_type}."
            ),
            GuardAction::Review | GuardAction::RequireReapproval => format!(
                "HOL Guard paused this action because it sends local secret to {sink_type}."
            ),
        };
    }
    fallback.to_string()
}

/// `decision_from_legacy_policy_action` — derive the public product decision
/// from the internal lattice action.
pub fn decision_from_legacy_policy_action(
    policy_action: GuardAction,
    reason: &str,
    signals: &[RiskSignalV2],
) -> GuardDecisionV2 {
    let (action, user_title, harness_message, retry_instruction) = action_messages(policy_action);
    let confidence = highest_confidence(signals);
    let dashboard_detail = dashboard_detail_from_signals(signals, harness_message);
    let harness_detail = harness_message_from_signals(signals, harness_message, policy_action);
    GuardDecisionV2 {
        guard_action: policy_action,
        action,
        reason: reason.to_string(),
        user_title: user_title.to_string(),
        user_body: dashboard_detail.clone(),
        harness_message: harness_detail,
        dashboard_primary_detail: dashboard_detail,
        approval_scopes: approval_scopes_for_action(policy_action),
        retry_instruction: if matches!(
            action,
            GuardDecisionAction::Allow | GuardDecisionAction::Warn
        ) {
            None
        } else {
            Some(retry_instruction.to_string())
        },
        signals: signals.to_vec(),
        confidence,
        package_review_cloud_reason_code: None,
    }
}

// ---------------------------------------------------------------------------
// build_authoritative_decision / authoritative_decision_from_artifact
// ---------------------------------------------------------------------------

/// `build_authoritative_decision` — sole decision after policy + approval
/// composition. `final_action` is forced to `action`.
pub fn build_authoritative_decision(
    action: GuardAction,
    reason: &str,
    composition_trace: &Map<String, Value>,
    signals: &[RiskSignalV2],
    authority_finalized: bool,
    source: &str,
) -> Res<AuthoritativeGuardDecision> {
    if reason.trim().is_empty() {
        return err("reason must be a non-empty string");
    }
    let mut trace = composition_trace.clone();
    trace.insert("final_action".into(), Value::String(action.as_str().into()));
    let blocking = blocking_actions().contains(action);
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
        composition_trace: trace,
        signals: signals.to_vec(),
        enforcement,
        decision_v2: decision_from_legacy_policy_action(action, reason, signals),
    };
    validate_authoritative_decision(&decision)?;
    Ok(decision)
}

/// `authoritative_decision_from_artifact` — parse + cross-check a serialized
/// artifact decision. `require_authoritative=true` demands `authoritative_decision`.
pub fn authoritative_decision_from_artifact(
    payload: &Value,
    require_authoritative: bool,
) -> Res<AuthoritativeGuardDecision> {
    let p = match payload {
        Value::Object(m) => m,
        _ => return err("artifact decision must be an object"),
    };
    let decision = match p.get("authoritative_decision") {
        Some(v) if v.is_object() => AuthoritativeGuardDecision::decode(v)?,
        Some(_) => return err("authoritative_decision must be an object"),
        None => {
            if require_authoritative {
                return err("authoritative_decision is required at the launch boundary");
            }
            let action = parse_guard_action(p.get("policy_action").unwrap_or(&Value::Null))?;
            let mut composition = match p.get("policy_composition") {
                Some(Value::Object(c)) => c.clone(),
                _ => Map::new(),
            };
            composition.insert("final_action".into(), Value::String(action.as_str().into()));
            let reason = match p.get("decision_v2_json") {
                Some(Value::Object(dv2)) => match dv2.get("reason") {
                    Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
                    _ => action.as_str().to_string(),
                },
                _ => action.as_str().to_string(),
            };
            build_authoritative_decision(
                action,
                &reason,
                &composition,
                &[],
                true,
                "legacy-compatible-projection",
            )?
        }
    };
    validate_artifact_projection(p, &decision)?;
    Ok(decision)
}

// ---------------------------------------------------------------------------
// Authoritative / composition / run-projection validators
// ---------------------------------------------------------------------------

/// `_validate_authoritative_decision` — every enforcement + decision_v2 field
/// must derive from `action`, `reason`, and `signals`.
pub fn validate_authoritative_decision(decision: &AuthoritativeGuardDecision) -> Res<()> {
    validate_composition_trace(decision.action, &decision.composition_trace)?;
    let expected_blocking = blocking_actions().contains(decision.action);
    let expected_launch = !expected_blocking && decision.enforcement.authority_finalized;
    let expected_prompt = matches!(
        decision.action,
        GuardAction::Review | GuardAction::RequireReapproval
    );
    let expected_sandbox = decision.action == GuardAction::SandboxRequired;
    if decision.enforcement.blocking != expected_blocking {
        return err("enforcement.blocking must derive from action");
    }
    if decision.enforcement.launch_permitted != expected_launch {
        return err("enforcement.launch_permitted must derive from action and authority state");
    }
    if decision.enforcement.prompt_required != expected_prompt {
        return err("enforcement.prompt_required must derive from action");
    }
    if decision.enforcement.sandbox_required != expected_sandbox {
        return err("enforcement.sandbox_required must derive from action");
    }
    if decision.enforcement.snapshot_permitted != expected_launch {
        return err("enforcement.snapshot_permitted must derive from action and authority state");
    }
    let expected_decision_v2 =
        decision_from_legacy_policy_action(decision.action, &decision.reason, &decision.signals);
    if decision.decision_v2 != expected_decision_v2 {
        return err("decision_v2 must derive entirely from action, reason, and signals");
    }
    Ok(())
}

/// `_validate_composition_trace` — reject action-bearing trace data that could
/// conceal stronger authority.
pub fn validate_composition_trace(action: GuardAction, trace: &Map<String, Value>) -> Res<()> {
    if trace.get("final_action").and_then(Value::as_str) != Some(action.as_str()) {
        return err("composition_trace.final_action must match action");
    }
    reject_unknown_composition_action_fields(trace)?;

    let mut parsed: Map<String, Value> = Map::new();
    for key in composition_action_fields() {
        match trace.get(key) {
            None => {
                parsed.insert(key.to_string(), Value::Null);
            }
            Some(Value::Null)
                if matches!(key, "configured_action" | "saved_action" | "scanner_action") =>
            {
                parsed.insert(key.to_string(), Value::Null);
            }
            Some(v) if is_guard_action(v) => {
                parsed.insert(key.to_string(), v.clone());
            }
            Some(_) => {
                return err(&format!(
                    "composition_trace.{key} must be a known Guard action or null"
                ))
            }
        }
    }

    let trusted_override = match trace.get("trusted_request_override") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return err("composition_trace.trusted_request_override must be a boolean"),
    };
    let saved_state_present = match trace.get("saved_state_present") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return err("composition_trace.saved_state_present must be a boolean"),
    };

    let runtime_action = parsed["runtime_detector_action"]
        .as_str()
        .and_then(GuardAction::from_canonical);
    if runtime_action == Some(GuardAction::Block) && action != GuardAction::Block {
        return err("runtime detector block cannot be overridden");
    }
    let current_action = parsed["current_action"]
        .as_str()
        .and_then(GuardAction::from_canonical);

    // Terminal candidates cannot be weakened by the final action.
    for (key, cand_v) in &parsed {
        let Some(candidate) = cand_v.as_str().and_then(GuardAction::from_canonical) else {
            continue;
        };
        if !terminal_composition_actions().contains(&candidate) {
            continue;
        }
        if action.severity() < candidate.severity() {
            return err(&format!(
                "composition_trace.{key} cannot be weakened by the final action"
            ));
        }
    }
    // current_action cannot be weaker than configured/scanner.
    for key in ["configured_action", "scanner_action"] {
        let candidate = parsed[key].as_str().and_then(GuardAction::from_canonical);
        if let (Some(cur), Some(cand)) = (current_action, candidate) {
            if cur.severity() < cand.severity() {
                return err(&format!(
                    "composition_trace.current_action cannot be weaker than {key}"
                ));
            }
        }
    }
    let saved_allow_override = matches!(
        current_action,
        Some(GuardAction::Review | GuardAction::RequireReapproval)
    ) && parsed["saved_action"]
        .as_str()
        .and_then(GuardAction::from_canonical)
        == Some(GuardAction::Allow)
        && saved_state_present
        && matches!(action, GuardAction::Allow | GuardAction::Warn);
    let explicit_approval_override = (trusted_override
        && matches!(action, GuardAction::Allow | GuardAction::Warn))
        || saved_allow_override;
    if runtime_action == Some(GuardAction::Warn) && action.severity() < GuardAction::Warn.severity()
    {
        return err("runtime detector warning cannot be erased by the final action");
    }
    if runtime_action == Some(GuardAction::Review)
        && action.severity() < GuardAction::Review.severity()
        && !explicit_approval_override
    {
        return err("runtime detector review requires an explicit allowed override");
    }

    let strongest_input = parsed
        .iter()
        .filter(|(k, _)| k.as_str() != "runtime_detector_action")
        .filter_map(|(_, v)| v.as_str().and_then(GuardAction::from_canonical))
        .max_by_key(|a| a.severity());
    let Some(strongest) = strongest_input else {
        return Ok(());
    };
    if action.severity() >= strongest.severity() || explicit_approval_override {
        return Ok(());
    }
    err("composition_trace final action weakens authority without an explicit allowed override")
}

/// `_reject_unknown_composition_action_fields` — recursive unknown-key walk at
/// every nesting depth.
fn reject_unknown_composition_action_fields(trace: &Map<String, Value>) -> Res<()> {
    fn visit(v: &Value, path: &str, top_level: bool) -> Res<()> {
        match v {
            Value::Object(m) => {
                for (raw_key, nested) in m {
                    let key_path = format!("{path}.{raw_key}");
                    let known_top_level_action =
                        top_level && known_composition_action_fields().contains(raw_key.as_str());
                    if is_action_bearing_key(raw_key) && !known_top_level_action {
                        return err(&format!(
                            "composition_trace contains unknown action-bearing field: {key_path}"
                        ));
                    }
                    visit(nested, &key_path, false)?;
                }
                Ok(())
            }
            Value::Array(a) => {
                for (index, nested) in a.iter().enumerate() {
                    visit(nested, &format!("{path}[{index}]"), false)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    visit(&Value::Object(trace.clone()), "composition_trace", true)
}

/// `_validate_run_decision_projection`.
fn validate_run_decision_projection(
    evaluation: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Res<()> {
    let composition = match evaluation.get("runtime_detector_composition") {
        Some(Value::Object(c)) => c,
        _ => return err("run authority requires runtime_detector_composition"),
    };
    if composition.get("action").and_then(Value::as_str) != Some(decision.action.as_str())
        || composition.get("reason").and_then(Value::as_str) != Some(decision.reason.as_str())
    {
        return err("runtime detector composition must match run authority");
    }
    if decision
        .composition_trace
        .get("runtime_detector_action")
        .and_then(Value::as_str)
        != Some(decision.action.as_str())
    {
        return err("run authority trace must match the runtime detector action");
    }
    let raw_signals = match evaluation.get("runtime_detector_signals_v2") {
        Some(Value::Array(a)) => a,
        _ => return err("run authority requires runtime detector signals"),
    };
    let expected: Vec<Value> = decision.signals.iter().map(|s| s.to_value()).collect();
    if expected.as_slice() != raw_signals.as_slice() {
        return err("runtime detector signals must match run authority");
    }
    let blocked_reason = evaluation.get("blocked_by_detector");
    if decision.enforcement.blocking
        && blocked_reason.and_then(Value::as_str) != Some(decision.reason.as_str())
    {
        return err("blocked_by_detector must match run authority reason");
    }
    Ok(())
}

/// `_merge_signals` — dedup by `signal_id`, preserving order.
fn merge_signals(existing: &[RiskSignalV2], additional: &[RiskSignalV2]) -> Vec<RiskSignalV2> {
    let mut merged = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for signal in existing.iter().chain(additional.iter()) {
        if seen.contains(&signal.signal_id) {
            continue;
        }
        seen.insert(signal.signal_id.clone());
        merged.push(signal.clone());
    }
    merged
}

// ---------------------------------------------------------------------------
// Artifact projection + approval-evidence validators
// ---------------------------------------------------------------------------

/// `_validate_artifact_projection`.
fn validate_artifact_projection(
    payload: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Res<()> {
    reject_unknown_action_bearing_fields(
        payload,
        &artifact_action_fields(),
        "artifact projection",
    )?;
    let policy_action = payload.get("policy_action");
    if policy_action.and_then(Value::as_str) != Some(decision.action.as_str()) {
        return err("policy_action must match authoritative action");
    }
    if let Some(v) = payload.get("verdict_action") {
        if !v.is_null() && v.as_str() != Some(decision.action.as_str()) {
            return err("verdict_action must match authoritative action");
        }
    }
    if let Some(raw) = payload.get("policy_composition") {
        let rc = match raw {
            Value::Object(m) => m,
            _ => return err("policy_composition must be an object"),
        };
        if rc.get("final_action").and_then(Value::as_str) != Some(decision.action.as_str()) {
            return err("policy_composition.final_action must match authoritative action");
        }
        if payload.contains_key("authoritative_decision") && *rc != decision.composition_trace {
            return err("policy_composition must match authoritative composition_trace");
        }
    }
    if let Some(raw) = payload.get("decision_v2_json") {
        let rd = match raw {
            Value::Object(m) => m,
            _ => return err("decision_v2_json must be an object"),
        };
        if rd.get("action").and_then(Value::as_str) != Some(decision.decision_v2.action.as_str()) {
            return err("decision_v2_json.action must match authoritative action");
        }
        if let Some(ga) = rd.get("guard_action") {
            let exact = parse_guard_action(ga)?;
            if exact != decision.action {
                return err("decision_v2_json.guard_action must match authoritative action");
            }
        }
        if payload.contains_key("authoritative_decision") && *raw != decision.decision_v2.to_value()
        {
            return err("decision_v2_json must match authoritative decision_v2");
        }
    }
    if let Some(raw) = payload.get("action_envelope_json") {
        let env = match raw {
            Value::Object(m) => m,
            _ => return err("action_envelope_json must be an object or null"),
        };
        reject_unknown_action_bearing_fields(
            env,
            &action_envelope_action_fields(),
            "action_envelope_json",
        )?;
        require_matching_alias(env, "action_id", "actionId", "action_envelope_json")?;
        require_matching_alias(env, "action_type", "actionType", "action_envelope_json")?;
        require_matching_alias(env, "policy_action", "policyAction", "action_envelope_json")?;
        require_matching_alias(
            env,
            "pre_execution_result",
            "preExecutionResult",
            "action_envelope_json",
        )?;
        for (key, alias) in [
            ("policy_action", "policyAction"),
            ("pre_execution_result", "preExecutionResult"),
        ] {
            let envelope_action = env.get(key).or_else(|| env.get(alias));
            let Some(ea) = envelope_action else { continue };
            if ea.is_null() {
                continue;
            }
            if !is_guard_action(ea) {
                return err(&format!(
                    "action_envelope_json.{key} must be a known Guard action"
                ));
            }
            if ea.as_str() != Some(decision.action.as_str()) {
                return err(&format!(
                    "action_envelope_json.{key} must match authoritative action"
                ));
            }
        }
    }
    validate_artifact_approval_projection(payload, decision)
}

/// `_validate_artifact_approval_projection` — cross-check approval evidence
/// before it can finalize launch authority.
fn validate_artifact_approval_projection(
    payload: &Map<String, Value>,
    decision: &AuthoritativeGuardDecision,
) -> Res<()> {
    let trace = &decision.composition_trace;
    let approval_fields_present = [
        "approval_reuse",
        "approval_reuse_status",
        "approval_reuse_reason_code",
        "trusted_request_override",
    ]
    .iter()
    .any(|k| payload.contains_key(*k));
    let trace_keys = [
        "saved_state_present",
        "trusted_request_override",
        "saved_approval_claim",
    ];
    if !approval_fields_present && !trace_keys.iter().any(|k| trace.contains_key(*k)) {
        return Ok(());
    }

    let raw_reuse = match payload.get("approval_reuse") {
        Some(Value::Object(m)) => m,
        _ => return err("approval_reuse must be an object"),
    };
    let reuse_action = parse_guard_action(raw_reuse.get("action").unwrap_or(&Value::Null))?;
    let current_action =
        parse_guard_action(raw_reuse.get("current_action").unwrap_or(&Value::Null))?;
    let saved_action = match raw_reuse.get("saved_action") {
        Some(Value::Null) | None => None,
        Some(v) => Some(parse_guard_action(v)?),
    };
    let reuse_status = raw_reuse.get("status").and_then(Value::as_str);
    if !matches!(
        reuse_status,
        Some("accepted") | Some("rejected") | Some("not-applicable")
    ) {
        return err("approval_reuse.status must be a known status");
    }
    let reuse_reason = required_string(raw_reuse, "reason_code")?;
    let reuse_should_claim = match raw_reuse.get("should_claim") {
        Some(Value::Bool(b)) => *b,
        _ => return err("approval_reuse.should_claim must be a boolean"),
    };
    if payload.get("approval_reuse_status").and_then(Value::as_str) != reuse_status {
        return err("approval_reuse_status must match approval_reuse.status");
    }
    if payload
        .get("approval_reuse_reason_code")
        .and_then(Value::as_str)
        != Some(reuse_reason.as_str())
    {
        return err("approval_reuse_reason_code must match approval_reuse.reason_code");
    }
    if trace.get("current_action").and_then(Value::as_str) != Some(current_action.as_str()) {
        return err("composition_trace.current_action must match approval_reuse.current_action");
    }
    let trace_saved = trace.get("saved_action").and_then(Value::as_str);
    if trace_saved != saved_action.map(|a| a.as_str()) {
        return err("composition_trace.saved_action must match approval_reuse.saved_action");
    }
    let saved_state_present = match trace.get("saved_state_present") {
        Some(Value::Bool(b)) => *b,
        _ => return err("composition_trace.saved_state_present must be a boolean"),
    };
    if saved_state_present != saved_action.is_some() {
        return err("composition_trace.saved_state_present must match saved approval evidence");
    }

    let raw_trusted = match payload.get("trusted_request_override") {
        Some(Value::Object(m)) => m,
        _ => return err("trusted_request_override must be an object"),
    };
    let trusted_applied = match raw_trusted.get("applied") {
        Some(Value::Bool(b)) => *b,
        _ => return err("trusted_request_override.applied must be a boolean"),
    };
    let trusted_reason = raw_trusted.get("reason_code");
    let matches = if trusted_applied {
        trusted_reason.and_then(Value::as_str) == Some(TRUSTED_REQUEST_OVERRIDE_REASON)
    } else {
        matches!(trusted_reason, None | Some(Value::Null))
    };
    if !matches {
        return err("trusted_request_override.reason_code must match applied state");
    }
    if trace
        .get("trusted_request_override")
        .and_then(Value::as_bool)
        != Some(trusted_applied)
    {
        return err("composition_trace.trusted_request_override must match outer evidence");
    }

    let saved_allow_reuse = matches!(
        current_action,
        GuardAction::Review | GuardAction::RequireReapproval
    ) && saved_action == Some(GuardAction::Allow)
        && reuse_action == GuardAction::Allow
        && reuse_status == Some("accepted")
        && reuse_reason == APPROVAL_REUSE_ACCEPTED_REASON
        && reuse_should_claim;
    let saved_block_reuse = saved_action == Some(GuardAction::Block)
        && reuse_action == GuardAction::Block
        && reuse_status == Some("accepted")
        && reuse_reason == "approval_reuse_saved_block"
        && !reuse_should_claim;
    if reuse_status == Some("accepted") && !(saved_allow_reuse || saved_block_reuse) {
        return err("accepted approval reuse must be an exact saved allow or block");
    }
    if reuse_should_claim && !saved_allow_reuse {
        return err("approval_reuse.should_claim requires accepted exact saved allow reuse");
    }

    let mut expected_action = if trusted_applied {
        GuardAction::Allow
    } else {
        reuse_action
    };
    if let Some(rt) = trace.get("runtime_detector_action") {
        if !rt.is_null() {
            let parsed_runtime_action = parse_guard_action(rt)?;
            let detector_review_was_approved = (parsed_runtime_action == GuardAction::Review
                && trusted_applied)
                || (matches!(
                    parsed_runtime_action,
                    GuardAction::Review | GuardAction::RequireReapproval
                ) && saved_allow_reuse);
            if !detector_review_was_approved {
                expected_action = most_restrictive_of(expected_action, parsed_runtime_action);
            }
        }
    }
    if decision.action != expected_action {
        return err("authoritative action must derive from approval reuse and runtime authority");
    }

    let raw_trace_claim = trace.get("saved_approval_claim");
    let raw_outer_claim = payload.get("approval_claim");
    if raw_trace_claim.is_none() != raw_outer_claim.is_none() {
        return err("saved approval claim must match its authoritative trace");
    }
    let mut claim: Option<&Map<String, Value>> = None;
    if let Some(tc) = raw_trace_claim {
        let (tc_m, oc_m) = match (tc, raw_outer_claim) {
            (Value::Object(t), Some(Value::Object(o))) => (t, o),
            _ => return err("saved approval claim must be an object"),
        };
        if tc_m != oc_m {
            return err("saved approval claim must match its authoritative trace");
        }
        claim = Some(tc_m);
        validate_saved_approval_claim(payload, tc_m)?;
    }

    if trusted_applied {
        if claim.is_some() {
            return err("trusted request and saved approval claim cannot both finalize authority");
        }
        if !matches!(
            reuse_action,
            GuardAction::Review | GuardAction::RequireReapproval
        ) {
            return err("trusted request override must satisfy a review action");
        }
        if !decision.enforcement.authority_finalized {
            return err("trusted request override must finalize authority");
        }
        if decision.action == GuardAction::Allow
            && decision.reason != TRUSTED_REQUEST_OVERRIDE_REASON
        {
            return err("trusted request allow reason must match its evidence");
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
            return err("saved approval claim must finalize authority");
        }
        if !saved_allow_reuse {
            return err("saved approval claim must match accepted exact allow reuse");
        }
        require_scanner_evidence(
            payload,
            "approval_reuse",
            "accepted",
            APPROVAL_REUSE_ACCEPTED_REASON,
            None,
        )?;
    } else if reuse_should_claim && decision.enforcement.authority_finalized && !trusted_applied {
        return err("finalized saved approval reuse requires an atomic claim proof");
    }
    Ok(())
}

/// `_validate_saved_approval_claim`.
fn validate_saved_approval_claim(
    payload: &Map<String, Value>,
    claim: &Map<String, Value>,
) -> Res<()> {
    let expected: std::collections::HashSet<&str> =
        ["status", "approval_context_hash", "reason_code"]
            .into_iter()
            .collect();
    let actual: std::collections::HashSet<&str> = claim.keys().map(|k| k.as_str()).collect();
    if actual != expected {
        return err("saved approval claim has an invalid schema");
    }
    let status = claim.get("status").and_then(Value::as_str);
    if !status
        .map(|s| saved_approval_claim_dispositions().contains(&s))
        .unwrap_or(false)
    {
        return err("saved approval claim status must be consumed or retained");
    }
    let context_hash = payload.get("approval_context_hash");
    let valid_hash = matches!(context_hash, Some(Value::String(s)) if !s.is_empty());
    if !valid_hash || claim.get("approval_context_hash") != context_hash {
        return err("saved approval claim must match approval_context_hash");
    }
    if claim.get("reason_code").and_then(Value::as_str) != Some(APPROVAL_REUSE_ACCEPTED_REASON) {
        return err("saved approval claim must carry the accepted reuse reason");
    }
    Ok(())
}

/// `_require_scanner_evidence`.
fn require_scanner_evidence(
    payload: &Map<String, Value>,
    source: &str,
    status: &str,
    reason_code: &str,
    artifact_hash: Option<&Value>,
) -> Res<()> {
    let raw_evidence = match payload.get("scanner_evidence") {
        Some(Value::Array(a)) => a,
        _ => return err("scanner_evidence must be a list"),
    };
    for entry in raw_evidence {
        let Some(e) = entry.as_object() else { continue };
        let matches = e.get("source").and_then(Value::as_str) == Some(source)
            && e.get("status").and_then(Value::as_str) == Some(status)
            && e.get("reason_code").and_then(Value::as_str) == Some(reason_code)
            && (artifact_hash.is_none() || e.get("artifact_hash") == artifact_hash);
        if matches {
            return Ok(());
        }
    }
    err(&format!(
        "scanner_evidence must contain matching {source} evidence"
    ))
}

/// `_is_disabled_codex_skill_inventory` — only a disabled Codex skill inventory
/// row may omit launch authority.
fn is_disabled_codex_skill_inventory(
    raw_item: &Value,
    decision: &AuthoritativeGuardDecision,
) -> bool {
    let Some(m) = raw_item.as_object() else {
        return false;
    };
    let artifact_id = m.get("artifact_id").and_then(Value::as_str);
    m.get("inventory_only") == Some(&Value::Bool(true))
        && m.get("artifact_type").and_then(Value::as_str) == Some("skill")
        && artifact_id
            .map(|s| s.starts_with("codex:"))
            .unwrap_or(false)
        && decision.action == GuardAction::Allow
        && decision.reason == "inventory_only"
        && decision.composition_trace.get("inventory_only") == Some(&Value::Bool(true))
        && !decision.enforcement.authority_finalized
}

// ---------------------------------------------------------------------------
// evaluation_authority_error / rebuild_artifact_authority
// ---------------------------------------------------------------------------

/// `evaluation_authority_error` — return the stable fail-closed code when an
/// evaluation contradicts itself, else `None`.
pub fn evaluation_authority_error(
    evaluation: &Value,
    require_launch_permitted: bool,
) -> Option<String> {
    match inner_eval(evaluation, require_launch_permitted) {
        Ok(()) => None,
        Err(_) => Some(AUTHORITATIVE_DECISION_INCONSISTENT.to_string()),
    }
}

fn inner_eval(evaluation: &Value, require_launch_permitted: bool) -> Res<()> {
    let eval_map = match evaluation {
        Value::Object(m) => m,
        _ => return err(AUTHORITATIVE_DECISION_INCONSISTENT),
    };
    if eval_map.get("decision_contract_error").is_some() {
        return err(AUTHORITATIVE_DECISION_INCONSISTENT);
    }
    let raw_artifacts = match eval_map.get("artifacts") {
        Some(Value::Array(a)) => a.clone(),
        _ => return err(AUTHORITATIVE_DECISION_INCONSISTENT),
    };
    let mut artifact_decisions: Vec<AuthoritativeGuardDecision> = Vec::new();
    let mut decisions: Vec<AuthoritativeGuardDecision> = Vec::new();
    for raw_item in &raw_artifacts {
        if !raw_item.is_object() {
            return err("artifact decision must be an object");
        }
        if raw_item.get("decision_contract_error").is_some() {
            return err("artifact decision carries a contract error");
        }
        let artifact_decision =
            authoritative_decision_from_artifact(raw_item, require_launch_permitted)?;
        artifact_decisions.push(artifact_decision.clone());
        decisions.push(artifact_decision);
    }
    if let Some(raw_run) = eval_map.get("run_authoritative_decision") {
        if !raw_run.is_null() {
            if !raw_run.is_object() {
                return err("run_authoritative_decision must be an object");
            }
            let run_decision = AuthoritativeGuardDecision::decode(raw_run)?;
            validate_run_decision_projection(eval_map, &run_decision)?;
            decisions.push(run_decision);
        }
    }

    let raw_runtime_signals = eval_map.get("runtime_detector_signals_v2");
    let runtime_composition = eval_map.get("runtime_detector_composition");
    let has_runtime_result = raw_runtime_signals.is_some() || runtime_composition.is_some();
    if has_runtime_result {
        if raw_runtime_signals.is_none() || !matches!(runtime_composition, Some(Value::Object(_))) {
            return err("runtime detector signals and composition must be projected together");
        }
        let runtime_signals = parse_signals(raw_runtime_signals.unwrap())?;
        let comp = match runtime_composition {
            Some(Value::Object(c)) => c,
            _ => unreachable!(),
        };
        let recomposed = compose_action_from_signals(&runtime_signals, &json!("allow"));
        if comp.get("action").and_then(Value::as_str) != Some(recomposed.action.as_str())
            || comp.get("reason").and_then(Value::as_str) != Some(recomposed.reason.as_str())
            || comp.get("downgraded").and_then(Value::as_bool) != Some(recomposed.downgraded)
            || comp.get("upgraded").and_then(Value::as_bool) != Some(recomposed.upgraded)
        {
            return err("runtime detector composition must derive from its signals");
        }
        for artifact_decision in &artifact_decisions {
            if runtime_signals
                .iter()
                .any(|s| !artifact_decision.signals.contains(s))
            {
                return err("artifact authority must include every runtime detector signal");
            }
        }
        if artifact_decisions.is_empty() && eval_map.get("run_authoritative_decision").is_none() {
            return err("zero-artifact detector results require run authority");
        }
    }
    let runtime_action = match runtime_composition {
        Some(Value::Object(c)) => c.get("action").and_then(Value::as_str),
        _ => None,
    };
    if has_runtime_result {
        for artifact_decision in &artifact_decisions {
            if artifact_decision
                .composition_trace
                .get("runtime_detector_action")
                .and_then(Value::as_str)
                != runtime_action
            {
                return err("artifact trace must include the runtime detector action");
            }
        }
    }

    let blocked = match eval_map.get("blocked") {
        Some(Value::Bool(b)) => *b,
        _ => return err(AUTHORITATIVE_DECISION_INCONSISTENT),
    };
    if blocked != decisions.iter().any(|d| d.enforcement.blocking) {
        return err(AUTHORITATIVE_DECISION_INCONSISTENT);
    }
    if require_launch_permitted {
        for (raw_item, decision) in raw_artifacts.iter().zip(artifact_decisions.iter()) {
            if decision.enforcement.launch_permitted {
                continue;
            }
            if is_disabled_codex_skill_inventory(raw_item, decision) {
                continue;
            }
            return err(AUTHORITATIVE_DECISION_INCONSISTENT);
        }
        if decisions[artifact_decisions.len()..]
            .iter()
            .any(|d| !d.enforcement.launch_permitted)
        {
            return err(AUTHORITATIVE_DECISION_INCONSISTENT);
        }
    }
    Ok(())
}

/// `rebuild_artifact_authority` — synchronize runner-added trace/reason across
/// every projection. Returns `{**payload, **rebuilt.to_artifact_projection()}`.
pub fn rebuild_artifact_authority(
    payload: &Value,
    reason: Option<&str>,
    composition_updates: Option<&Map<String, Value>>,
    additional_signals: &[RiskSignalV2],
) -> Res<Map<String, Value>> {
    let decision = authoritative_decision_from_artifact(payload, true)?;
    let mut composition = decision.composition_trace.clone();
    if let Some(upd) = composition_updates {
        for (k, v) in upd {
            composition.insert(k.clone(), v.clone());
        }
    }
    let merged_signals = merge_signals(&decision.signals, additional_signals);
    let rebuilt = build_authoritative_decision(
        decision.action,
        reason.unwrap_or(&decision.reason),
        &composition,
        &merged_signals,
        decision.enforcement.authority_finalized,
        &decision.source,
    )?;
    let mut out = match payload {
        Value::Object(o) => o.clone(),
        _ => Map::new(),
    };
    if let Value::Object(proj) = rebuilt.to_artifact_projection() {
        for (k, v) in proj {
            out.insert(k, v);
        }
    }
    Ok(out)
}
