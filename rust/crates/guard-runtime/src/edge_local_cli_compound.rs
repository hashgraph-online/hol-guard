//! A chained command whose script steps the user allowed.
//!
//! A custom CLI grant reads one launch, so `./approve.sh 12 ; gh pr view 12`
//! stayed under review even when the user allowed the script and the command
//! choices it uses, and the other step passes on its own. Each step is judged
//! here as a command of its own, through the same verdict chain the hook runs
//! (`evaluate_pre_tool_chain`). The chain is allowed only when every step
//! passes alone or is a script whose grant lifts its own review, and at least
//! one step is such a script.
//!
//! Only a plain list of simple commands is split. A step that changes what
//! the next one runs under (`cd`, `export`, `source`, a `VAR=` prefix), a
//! redirect, a command substitution or a wrapper leaves the review standing:
//! a step judged alone would not run the way it runs in the chain. The chain
//! itself must be reviewed only because Guard did not recognize a step, and
//! every grant read follows the single-launch rules, so a blocked script, a
//! script allowed only for an earlier version or a choice set to review keeps
//! the review.

use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use guard_contracts::{GuardHookEnvelopeV2, HookLocalCliRuleRequestV1};
use serde_json::{Map, Value};

use crate::hook_direct::local_cli::rule_op::{self, RuleVerdict};

/// The most steps a chain may have. Each is evaluated once.
const MAX_STEPS: usize = 8;
/// How long judging every step alone may take, on the edge's own thread.
const STEPS_BUDGET: Duration = Duration::from_secs(2);
/// How long the grant reads wait for a writer's exclusive storage hold.
const STORAGE_GATE_WAIT: Duration = Duration::from_secs(2);
/// Steps that change the shell the next step runs in.
const STATE_STEPS: [&str; 24] = [
    "cd", "pushd", "popd", "export", "source", ".", "eval", "exec", "alias", "unalias", "set",
    "unset", "shopt", "hash", "trap", "umask", "ulimit", "builtin", "command", "declare",
    "typeset", "local", "readonly", "enable",
];

/// One step judged alone: its payload and a time budget in, its verdict out.
pub(super) type Step<'a> = dyn Fn(&Value, u64) -> Option<Map<String, Value>> + 'a;

/// Whether the reviewed chain in `envelope` runs because every step passes
/// alone or is a script the user allowed.
pub(super) fn lifts(
    envelope: &GuardHookEnvelopeV2,
    result: &Map<String, Value>,
    step: &Step<'_>,
    deadline: Instant,
) -> bool {
    if !crate::connector_setup::is_non_recognition(
        result.get("reason_code").and_then(Value::as_str),
    ) || !crate::hook_direct::saved_decision::overridable(result)
    {
        return false;
    }
    let Some(payload) = envelope.raw_payload.as_object() else {
        return false;
    };
    let Some(command) = crate::local_store_read::pre_tool_command(payload) else {
        return false;
    };
    let Some(texts) = step_texts(
        command,
        envelope.source.cwd.as_deref(),
        &envelope.source.home_dir,
    ) else {
        return false;
    };
    let steps_deadline = deadline.min(Instant::now() + STEPS_BUDGET);
    let mut steps = Vec::with_capacity(texts.len());
    for text in texts {
        let remaining = steps_deadline.saturating_duration_since(Instant::now());
        let Some(alone) = with_command(payload, &text) else {
            return false;
        };
        let budget = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        if budget == 0 {
            return false;
        }
        let Some(verdict) = step(&Value::Object(alone.clone()), budget) else {
            return false;
        };
        steps.push((alone, verdict));
    }
    // A chain whose every step passes alone was reviewed for something no
    // single step shows; no grant answers that.
    if steps.iter().all(|(_, verdict)| allowed(verdict)) {
        return false;
    }
    granted(envelope, steps, deadline)
}

/// Whether a step runs alone with nothing more asked of it. A step that runs
/// only inside the sandbox does not pass: the chain would run it outside.
fn allowed(verdict: &Map<String, Value>) -> bool {
    let text = |key: &str| verdict.get(key).and_then(Value::as_str);
    text("minimum_action") == Some("allow") && text("policy_action") != Some("sandbox-required")
}

/// The text of each step of a plain list of simple commands, or `None` when
/// a step judged alone would not run as it runs in the chain.
fn step_texts(command: &str, cwd: Option<&str>, home_dir: &str) -> Option<Vec<String>> {
    if command.trim().is_empty() {
        return None;
    }
    let model = guard_command::command_model::parse_shell_command(
        command,
        cwd.map(Path::new),
        Some(Path::new(home_dir)),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if model.confidence != "exact"
        || !model.redirects.is_empty()
        || !model.embedded_commands.is_empty()
        || !model.wrapper_chain.is_empty()
        || model.path_overridden()
        || !(2..=MAX_STEPS).contains(&model.segments.len())
    {
        return None;
    }
    model
        .segments
        .iter()
        .map(|segment| {
            let executable = segment.executable.as_deref()?;
            let simple = segment.wrapper_chain.is_empty()
                && segment.pipeline_index == 0
                && !segment.path_overridden
                && segment.environment_names.is_empty()
                && !STATE_STEPS.contains(&executable)
                && !segment.text.trim().is_empty();
            simple.then(|| segment.text.trim().to_owned())
        })
        .collect()
}

/// `payload` with the command the hook reads replaced by `text`, or `None`
/// when the replaced payload would not read back as `text`.
fn with_command(payload: &Map<String, Value>, text: &str) -> Option<Map<String, Value>> {
    let current = crate::local_store_read::pre_tool_command(payload)?;
    let mut alone = payload.clone();
    let input = ["tool_input", "toolInput"]
        .into_iter()
        .find(|key| alone.get(*key).is_some_and(Value::is_object));
    let containers = [input, Some("arguments"), None];
    let replaced = containers.into_iter().any(|container| {
        let target = match container {
            Some(key) => match alone.get_mut(key).and_then(Value::as_object_mut) {
                Some(object) => object,
                None => return false,
            },
            None => &mut alone,
        };
        let field = ["command", "cmd", "shell_command", "shellCommand"]
            .into_iter()
            .find(|key| target.get(*key).and_then(Value::as_str) == Some(current));
        field.is_some_and(|key| {
            target.insert(key.to_owned(), Value::String(text.to_owned()));
            true
        })
    });
    (replaced && crate::local_store_read::pre_tool_command(&alone) == Some(text)).then_some(alone)
}

/// Whether every reviewed step is a script whose grant lifts its review and
/// no allowed step is a script the user blocked, read under the shared
/// storage hold. A hold or read that does not finish by `deadline` keeps the
/// review.
fn granted(
    envelope: &GuardHookEnvelopeV2,
    steps: Vec<(Map<String, Value>, Map<String, Value>)>,
    deadline: Instant,
) -> bool {
    let Some(rules) = envelope.local_cli_rules.as_ref() else {
        return false;
    };
    let guard_home = envelope.source.guard_home.clone();
    let requests: Vec<(bool, HookLocalCliRuleRequestV1)> = steps
        .into_iter()
        .map(|(payload, verdict)| {
            let reviewed = !allowed(&verdict);
            let request = HookLocalCliRuleRequestV1 {
                schema: guard_contracts::HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA.to_owned(),
                request_id: "edge-local-cli-compound".to_owned(),
                store_path: rules.store_path.clone(),
                guard_home: guard_home.clone(),
                mode: if reviewed { "review" } else { "allowed" }.to_owned(),
                payload,
                native_result: verdict,
                workspace: envelope.source.cwd.clone(),
                home_dir: envelope.source.home_dir.clone(),
                user_home: Some(rules.user_home.clone()),
                env: Some(rules.env.clone()),
            };
            (reviewed, request)
        })
        .collect();
    let (sender, receiver) = mpsc::sync_channel(1);
    // An abandoned read finishes on its own and its answer is dropped.
    let spawned = std::thread::Builder::new()
        .name("edge-local-cli-compound".to_owned())
        .spawn(move || {
            let Ok(_hold) = crate::hook_evidence_store_gate::hold_storage_gate(
                Path::new(&guard_home),
                STORAGE_GATE_WAIT,
            ) else {
                return;
            };
            let _ = sender.send(requests.iter().all(|(reviewed, request)| {
                if *reviewed {
                    rule_op::review_verdict(request) == RuleVerdict::Allowed
                } else {
                    matches!(
                        rule_op::allowed_verdict(request),
                        RuleVerdict::None | RuleVerdict::Allowed
                    )
                }
            }));
        });
    let wait = deadline.saturating_duration_since(Instant::now());
    spawned.is_ok() && receiver.recv_timeout(wait).unwrap_or(false)
}
