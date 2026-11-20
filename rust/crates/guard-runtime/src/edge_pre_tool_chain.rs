//! The pre-tool verdict chain, shared by the hook and by the steps of a
//! chained command judged one at a time.

use crate::policy_enforcement::AdmittedPolicySnapshot;
use crate::{git_rules, runtime_known_vulnerable as runtime_risk};
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use serde_json::{Map, Value};
use std::time::{Duration, Instant};

/// The `PreToolUse` and `UserPromptSubmit` verdict before the per-session
/// stop: the native review, then every policy layer joined over it. It holds
/// no session state, so it also judges one step of a chained command alone
/// (`edge_local_cli_compound.rs`).
pub(super) fn evaluate_pre_tool_chain(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
) -> Result<PreToolResultV1, String> {
    let unavailable_environment = guard_contracts::GuardExecutionEnvironmentV1::unavailable();
    crate::edge_git_push::install();
    let native = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        harness,
        event_name,
        &envelope.raw_payload,
        policy_snapshot.and_then(|snapshot| snapshot.command_extensions.as_ref()),
        Some(
            Instant::now()
                + Duration::from_millis(envelope.deadline_budget_ms.unwrap_or(9_000).min(9_000)),
        ),
        // The envelope carries only the roots. Every proof a context
        // holds is set by a caller with the command, so all stay false.
        guard_command::pretool::PathContext {
            home_dir: Some(envelope.source.home_dir.as_str()),
            guard_home: Some(envelope.source.guard_home.as_str()),
            cwd: envelope.source.cwd.as_deref(),
            ..Default::default()
        },
        Some(
            envelope
                .source
                .execution_environment
                .as_ref()
                .unwrap_or(&unavailable_environment),
        ),
    );
    let native = crate::omp_yield_input_scan::scan(
        &envelope.raw_payload,
        envelope.deadline_budget_ms,
        native,
    )?;
    let evaluated = if let Some(snapshot) = policy_snapshot {
        crate::policy_enforcement::apply_pre_tool_policy_for_hook(snapshot, envelope, native)?
    } else {
        native
    };
    let evaluated =
        crate::native_exact_action_op::require_bash_owner(envelope, policy_snapshot, evaluated);
    let evaluated = crate::network_protection::apply_to_envelope(envelope, evaluated);
    let evaluated = runtime_risk::apply_to_envelope(envelope, policy_snapshot, evaluated);
    let evaluated = git_rules::after_exact_review(envelope, policy_snapshot, evaluated);
    let evaluated = crate::policy_enforcement::deferred_prompt_review(evaluated);
    Ok(evaluated)
}

/// One step of a chained command, judged as a command of its own: the hook's
/// envelope with the step's payload and the time left for it.
pub(super) fn step(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    payload: &Value,
    budget_ms: u64,
) -> Option<Map<String, Value>> {
    let mut alone = envelope.clone();
    alone.raw_payload = payload.clone();
    alone.deadline_budget_ms = Some(budget_ms);
    let verdict = evaluate_pre_tool_chain(&alone, harness, event_name, policy_snapshot).ok()?;
    match serde_json::to_value(verdict).ok()? {
        Value::Object(verdict) => Some(verdict),
        _ => None,
    }
}
