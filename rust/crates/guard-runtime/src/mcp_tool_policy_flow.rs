//! The observation-driven MCP tool-call policy pass.
//!
//! One pass is a pure function of the subject and the effect results observed
//! so far. When it needs an effect that has not been observed it stops with
//! [`Stop::Need`]; the caller runs the effect and re-enters with the result.
//! Every pass decides from scratch, so nothing here can be skipped or replayed
//! by the caller choosing which observations to send.

use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CLAIM_FAILED,
};
use guard_command::effect_decision::GuardAction;
use guard_command::mcp_tool_policy::evaluate_tool_policy;
use guard_command::mcp_tool_signals::{evaluate_risk_evidence, risk_arguments};
use guard_contracts::{
    BrowserAutomationIntentV1, McpToolPolicyObservationV1, McpToolPolicyRequestV1,
    McpToolPolicySubjectV1, McpToolRiskInputV1,
};
use serde_json::{json, Map, Value};

use crate::approval_proof_op::{claim_disposition, fresh_tool_approval, Disposition};
use crate::mcp_tool_policy_composio::{provider_floor_blocks, requires_action_review};
use crate::mcp_tool_policy_decision::{with_reuse, Current, Decision};
use crate::mcp_tool_policy_grants::{browser_intent, exact_match_context, grant_selectors};

pub(crate) const ERR_OBSERVATION: &str = "native_mcp_tool_policy_decide_observation_invalid";
const ERR_ACTION: &str = "native_mcp_tool_policy_decide_action_invalid";

/// Why a pass stopped before producing a decision.
#[derive(Debug)]
pub(crate) enum Stop {
    Need(Value),
    Fail(&'static str),
}

impl From<&'static str> for Stop {
    fn from(code: &'static str) -> Self {
        Self::Fail(code)
    }
}

pub(crate) type Flow<T> = Result<T, Stop>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Initial,
    Fresh,
}

impl Phase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Fresh => "fresh",
        }
    }
}

pub(crate) struct Ctx<'a> {
    pub(crate) observations: &'a [McpToolPolicyObservationV1],
}

impl Ctx<'_> {
    /// The observed result of `need`, or a stop asking the caller for it.
    pub(crate) fn ask(&self, need: Value) -> Flow<&Value> {
        self.observations
            .iter()
            .find(|observation| observation.need == need)
            .map(|observation| &observation.result)
            .ok_or(Stop::Need(need))
    }
}

pub(crate) enum Pass {
    Final(Box<Decision>),
    Claimed {
        row: Map<String, Value>,
        disposition: Option<Disposition>,
    },
}

fn invalid<T>() -> Flow<T> {
    Err(Stop::Fail(ERR_OBSERVATION))
}

pub(crate) fn parse_action(value: &Value) -> Flow<GuardAction> {
    serde_json::from_value(value.clone()).map_err(|_| Stop::Fail(ERR_ACTION))
}

pub(crate) fn action_value(action: GuardAction) -> Value {
    Value::String(action.as_str().to_owned())
}

pub(crate) fn most_restrictive(left: GuardAction, right: GuardAction) -> GuardAction {
    guard_command::effect_decision::maximum_action_floor([&left, &right])
}

fn row_of(value: &Value) -> Flow<Option<Map<String, Value>>> {
    match value {
        Value::Null => Ok(None),
        Value::Object(row) => Ok(Some(row.clone())),
        _ => invalid(),
    }
}

fn field<'a>(result: &'a Value, key: &str) -> Flow<&'a Value> {
    match result.as_object().and_then(|object| object.get(key)) {
        Some(value) => Ok(value),
        None => invalid(),
    }
}

fn strings(value: &Value) -> Flow<Vec<String>> {
    let Some(items) = value.as_array() else {
        return invalid();
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(Stop::Fail(ERR_OBSERVATION))
        })
        .collect()
}

/// The native recommendation for this call; saved approvals are separate.
pub(crate) fn evaluate_current(subject: &McpToolPolicySubjectV1) -> Flow<Current> {
    let policy = evaluate_tool_policy(&McpToolPolicyRequestV1 {
        artifact: subject.artifact.clone(),
        arguments: risk_arguments(&subject.arguments),
        config: subject.config.clone(),
        harness: subject.harness.clone(),
        artifact_id: subject.artifact_id.clone(),
        publisher: subject.publisher.clone(),
    })?;
    let evidence = evaluate_risk_evidence(&McpToolRiskInputV1 {
        artifact: subject.artifact.clone(),
        arguments: subject.arguments.clone(),
        risk_categories: Some(policy.risk_categories.clone()),
        summary_code: Some(policy.summary_code.clone()),
    })?;
    let summary = field(&evidence, "summary")?;
    Ok(Current {
        action: parse_action(&Value::String(policy.action))?,
        source: policy.source,
        signals: strings(field(&evidence, "signals")?)?,
        summary: summary
            .as_str()
            .ok_or(Stop::Fail(ERR_OBSERVATION))?
            .to_owned(),
        risk_categories: strings(field(&evidence, "risk_categories")?)?,
    })
}

fn replaced(current: Current, action: GuardAction, source: &str, summary: &str) -> Current {
    Current {
        action,
        source: source.to_owned(),
        summary: summary.to_owned(),
        ..current
    }
}

/// Provider floor, extension choice, then bounded temporary grants.
fn apply_temporary_grant(
    ctx: &Ctx,
    phase: Phase,
    subject: &McpToolPolicySubjectV1,
    intent: Option<&BrowserAutomationIntentV1>,
    current: Current,
) -> Flow<Current> {
    let original = current.action;
    let command = subject.artifact.command.as_deref().unwrap_or("");
    let composio = requires_action_review(command);
    if composio {
        let choices = ctx.ask(json!({"kind": "provider_choices", "phase": phase.as_str()}))?;
        let Some(choices) = choices.as_object() else {
            return invalid();
        };
        let arguments = risk_arguments(&subject.arguments);
        if provider_floor_blocks(choices, &subject.harness, command, &arguments) {
            return Ok(replaced(
                current,
                GuardAction::Block,
                "composio-action-deny",
                "A denied app action blocks this execution. No batch member may run.",
            ));
        }
    }
    let granted = ctx.ask(json!({
        "kind": "extension_decision",
        "phase": phase.as_str(),
        "action": original.as_str(),
    }))?;
    if !granted.is_null() {
        let action = parse_action(field(granted, "action")?)?;
        if matches!(action, GuardAction::Block | GuardAction::Review)
            || current.action != GuardAction::Allow
        {
            let text = |key| -> Flow<String> {
                field(granted, key)?
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Stop::Fail(ERR_OBSERVATION))
            };
            return Ok(Current {
                action,
                source: text("source")?,
                summary: text("summary")?,
                ..current
            });
        }
    }
    let mut current = current;
    if original == GuardAction::Review {
        let selectors = grant_selectors(
            intent,
            &current.risk_categories,
            &subject.artifact_id,
            &subject.artifact_hash,
        );
        for selector in selectors {
            let lookup = ctx.ask(json!({
                "kind": "grant_lookup",
                "phase": phase.as_str(),
                "harness": subject.harness,
                "selector": selector,
            }))?;
            if let Some(row) = row_of(field(lookup, "decision")?)? {
                if row.get("action").and_then(Value::as_str) == Some("allow")
                    && row.get("source").and_then(Value::as_str) == Some("approval-gate")
                {
                    current = replaced(
                        current,
                        GuardAction::Allow,
                        "temporary-mcp-grant",
                        "A time-bounded approval covers this routine MCP capability.",
                    );
                    break;
                }
            }
        }
    }
    if composio {
        let action = most_restrictive(current.action, GuardAction::Review);
        return Ok(replaced(
            current,
            action,
            "composio-action-review",
            "Review the underlying actions and account. A wrapper grant does not authorize execution.",
        ));
    }
    Ok(current)
}

/// What the saved evidence for this call says, before composition.
struct Saved {
    row: Option<Map<String, Value>>,
    action: Value,
    validation_reason: Option<String>,
}

fn saved_evidence(
    ctx: &Ctx,
    phase: Phase,
    subject: &McpToolPolicySubjectV1,
    intent: Option<&BrowserAutomationIntentV1>,
) -> Flow<Option<Saved>> {
    let lookup = ctx.ask(json!({
        "kind": "policy_lookup",
        "phase": phase.as_str(),
        "harness": subject.harness,
        "artifact_id": subject.artifact_id,
        "artifact_hash": subject.artifact_hash,
        "workspace": subject.workspace,
        "publisher": subject.publisher,
        "runtime_exact_match_context": exact_match_context(intent),
        "memory_command": subject.artifact.command,
        "memory_artifact_type": subject.artifact_type,
        "memory_artifact_name": subject.artifact.name,
    }))?;
    let row = row_of(field(lookup, "decision")?)?;
    let Some(ignored) = field(lookup, "ignored_local_integrity")?.as_bool() else {
        return invalid();
    };
    if row.is_none() && !ignored {
        let diagnosed = ctx.ask(json!({
            "kind": "reuse_diagnostic",
            "phase": phase.as_str(),
            "harness": subject.harness,
            "artifact_id": subject.artifact_id,
            "artifact_hash": subject.artifact_hash,
            "workspace": subject.workspace,
            "publisher": subject.publisher,
        }))?;
        return Ok(match field(diagnosed, "reason")? {
            Value::Null => None,
            Value::String(reason) => Some(Saved {
                row: None,
                action: Value::String("allow".to_owned()),
                validation_reason: Some(reason.clone()),
            }),
            _ => return invalid(),
        });
    }
    let action = match &row {
        Some(row) => row.get("action").cloned().unwrap_or(Value::Null),
        None => Value::String("require-reapproval".to_owned()),
    };
    let allow = row
        .as_ref()
        .is_some_and(|row| row.get("action") == Some(&json!("allow")));
    let validation_reason = if ignored {
        Some("approval_reuse_integrity_failure".to_owned())
    } else if let (true, Some(row)) = (allow, &row) {
        let saved_token = row.get("artifact_hash").unwrap_or(&Value::Null);
        crate::context_digest::validate_context_tokens(
            saved_token,
            &Value::String(subject.artifact_hash.clone()),
        )
    } else {
        None
    };
    Ok(Some(Saved {
        row,
        action,
        validation_reason,
    }))
}

pub(crate) fn compose(
    current: GuardAction,
    saved: &Value,
    validation_reason: Option<&str>,
    fresh_local: bool,
) -> ApprovalReuseDecision {
    evaluate_approval_reuse(
        &action_value(current),
        Some(saved),
        Some(true),
        validation_reason,
        fresh_local,
        false,
    )
}

/// One full pass. With `claim` false a claimable approval stays pending.
pub(crate) fn evaluate_pass(
    ctx: &Ctx,
    subject: &McpToolPolicySubjectV1,
    phase: Phase,
    claim: bool,
) -> Flow<Pass> {
    let intent = browser_intent(subject)?;
    let current = evaluate_current(subject)?;
    let current = apply_temporary_grant(ctx, phase, subject, intent.as_ref(), current)?;
    let command = subject.artifact.command.as_deref().unwrap_or("");
    let composio = requires_action_review(command);
    let finish = |decision: Decision| Ok(Pass::Final(Box::new(decision)));
    if composio && current.action != GuardAction::Block {
        let observed =
            ctx.ask(json!({"kind": "provider_authority_hash", "phase": phase.as_str()}))?;
        let observed = field(observed, "hash")?;
        let expected = subject.artifact.metadata.get("mcp_provider_catalog_hash");
        if observed != expected.unwrap_or(&Value::Null) {
            let action = most_restrictive(current.action, GuardAction::RequireReapproval);
            return finish(Decision::plain(replaced(
                current,
                action,
                "composio-schema-reapproval",
                "The app action inventory changed. Rebuild this call and review it again.",
            )));
        }
    }
    let Some(saved) = saved_evidence(ctx, phase, subject, intent.as_ref())? else {
        return finish(Decision::plain(current));
    };
    let allow = saved
        .row
        .as_ref()
        .is_some_and(|row| row.get("action") == Some(&json!("allow")));
    let disposition = saved.row.as_ref().and_then(claim_disposition);
    let mut validation_reason = saved.validation_reason.clone();
    if validation_reason.is_none() && allow && disposition.is_none() {
        // No authoritative disposition: never reach the claim, which could
        // consume the approval without launching.
        validation_reason = Some(APPROVAL_REUSE_CLAIM_FAILED.to_owned());
    }
    if validation_reason.is_none()
        && allow
        && composio
        && disposition != Some(Disposition::Consumed)
    {
        // No supported account resolver exists for this profile: a retained
        // wrapper approval could follow a changed default account.
        validation_reason = Some("approval_reuse_provider_account_unverified".to_owned());
    }
    let fresh_local = validation_reason.is_none()
        && disposition == Some(Disposition::Consumed)
        && fresh_tool_approval(
            saved.row.as_ref(),
            &subject.harness,
            &subject.artifact_id,
            &subject.artifact_hash,
        );
    let mut reuse = compose(
        current.action,
        &saved.action,
        validation_reason.as_deref(),
        fresh_local,
    );
    let mut pending = None;
    let mut claimed_disposition = None;
    if let (true, Some(row)) = (reuse.should_claim, saved.row.as_ref()) {
        claimed_disposition = disposition;
        if claim {
            let outcome = ctx.ask(json!({"kind": "claim", "decision": row}))?;
            match field(outcome, "outcome")?.as_str() {
                Some("claimed") => {
                    return Ok(Pass::Claimed {
                        row: row.clone(),
                        disposition,
                    });
                }
                Some(result @ ("declined" | "uncertain")) => {
                    reuse = compose(
                        current.action,
                        &saved.action,
                        Some(APPROVAL_REUSE_CLAIM_FAILED),
                        false,
                    );
                    if result == "uncertain" {
                        // The claim may have committed: no retry, no launch.
                        reuse.action =
                            most_restrictive(reuse.action, GuardAction::RequireReapproval);
                    }
                }
                _ => return invalid(),
            }
        } else {
            pending = Some(row.clone());
        }
    }
    let mut decision = with_reuse(&current, &reuse, pending);
    decision.claim_disposition = claimed_disposition;
    finish(decision)
}
