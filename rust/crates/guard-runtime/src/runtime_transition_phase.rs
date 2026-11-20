//! The runtime transition phase rules: which step each phase allows, who may
//! take it, until when, and what the journal records once it is taken.
//!
//! `step_check` reads the journal and answers whether a step may run, with
//! the file and install comparisons the caller must make before committing
//! it. `step_commit` reads the journal again, repeats the same checks and
//! writes the journal the step leaves behind. The caller passes its process
//! identity, its monotonic clock reading and any verified admission
//! observation; the journal itself never leaves this module unsigned.

use serde_json::{json, Map, Value};

use super::shape::{record_number, record_objects, Refusal};
use super::{no, read_record, write_record, Request};

const AUTHORIZED: &str = "AuthorizedForExactTransition";
const HOOKS: &str = "HooksPrepared";
const SWITCHING: &str = "Switching";
const CANDIDATE: &str = "CandidateFunctional";
const RESTORING: &str = "RestoringPrevious";
const PREVIOUS: &str = "PreviousFunctional";
const ROLLED_BACK: &str = "FailedWithVerifiedRollback";
const COMMITTED: &str = "Committed";
const RECOVERY: &str = "RecoveryRequired";
const MAX_FILES: usize = 128;
const MAX_CAUSES: usize = 8;
const MAX_FIRST_CAUSE: usize = 512;

/// `_FORWARD`: the one phase each forward step leads to.
fn forward(phase: &str) -> Option<&'static str> {
    match phase {
        AUTHORIZED => Some(HOOKS),
        HOOKS => Some(SWITCHING),
        SWITCHING => Some(CANDIDATE),
        CANDIDATE => Some(COMMITTED),
        _ => None,
    }
}

fn text<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn owner(request: &Request) -> Value {
    request.owner.clone().unwrap_or(Value::Null)
}

fn now(request: &Request) -> Result<f64, Refusal> {
    request
        .now
        .filter(|now| now.is_finite())
        .ok_or_else(|| no("invalid"))
}

fn expected(request: &Request) -> Result<&str, Refusal> {
    request
        .expected_phase
        .as_deref()
        .ok_or_else(|| no("phase_changed"))
}

fn owned_forward(payload: &Map<String, Value>, request: &Request) -> Result<(), Refusal> {
    if payload.get("owner") != Some(&owner(request)) {
        return Err(no("forward_owner_changed"));
    }
    Ok(())
}

fn forward_live(payload: &Map<String, Value>, request: &Request) -> Result<(), Refusal> {
    if now(request)? >= record_number(payload, "forward_expires_monotonic")? {
        return Err(no("forward_authorization_expired"));
    }
    Ok(())
}

/// The planned files of one kind, or all of them.
fn files(payload: &Map<String, Value>, kind: Option<&str>) -> Result<Vec<Value>, Refusal> {
    Ok(record_objects(payload, "files", MAX_FILES)?
        .into_iter()
        .filter(|change| kind.is_none_or(|kind| text(change, "kind") == Some(kind)))
        .map(|change| Value::Object(change.clone()))
        .collect())
}

fn compare(files: Vec<Value>, generation: &str) -> Value {
    json!({"files": files, "generation": generation})
}

/// `_validate_functional_proof`: the observation names this operation, this
/// home, the side's artifact generation and its pinned native runtime, and
/// was seen after the functional window opened and not after `now`.
fn functional_proof(
    payload: &Map<String, Value>,
    request: &Request,
    side: &str,
) -> Result<Value, Refusal> {
    let missing = || no("functional_proof_missing");
    let observation = request
        .observation
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(missing)?;
    let observed = record_number(observation, "observed_monotonic")?;
    let native = payload
        .get("native_runtimes")
        .and_then(Value::as_object)
        .and_then(|bindings| bindings.get(side));
    let generation = payload
        .get(side)
        .and_then(Value::as_object)
        .and_then(|artifact| artifact.get("generation"));
    let matches = native.is_some()
        && observation.get("runtime_identity") == native
        && observation.get("operation_id") == payload.get("operation_id")
        && generation.is_some()
        && observation.get("generation") == generation
        && observation.get("guard_home").and_then(Value::as_str)
            == Some(request.guard_home.as_str())
        && observed >= record_number(payload, "functional_started_monotonic")?
        && observed <= now(request)?;
    if !matches {
        return Err(missing());
    }
    Ok(Value::Object(observation.clone()))
}

/// `advance` up to its comparisons: the expected forward phase, its owner,
/// the overall deadline and, before the switch, the live authorization.
fn advance_checks(
    payload: &Map<String, Value>,
    request: &Request,
) -> Result<&'static str, Refusal> {
    let expected = expected(request)?;
    let next = forward(expected).ok_or_else(|| no("phase_changed"))?;
    if text(payload, "phase") != Some(expected) {
        return Err(no("phase_changed"));
    }
    owned_forward(payload, request)?;
    if now(request)? >= record_number(payload, "deadline_monotonic")? {
        return Err(no("deadline_exceeded"));
    }
    if matches!(expected, AUTHORIZED | HOOKS) {
        forward_live(payload, request)?;
    }
    Ok(next)
}

/// `authorize_runtime_step`: a live, owned grant for the stop or switch.
fn runtime_step(
    payload: &Map<String, Value>,
    request: &Request,
    phase: &str,
) -> Result<(), Refusal> {
    if !matches!(phase, HOOKS | SWITCHING) || text(payload, "phase") != Some(phase) {
        return Err(no("phase_changed"));
    }
    owned_forward(payload, request)?;
    forward_live(payload, request)
}

fn recovery_owned(payload: &Map<String, Value>, request: &Request) -> Result<(), Refusal> {
    if payload.get("recovery_owner") != Some(&owner(request)) {
        return Err(no("recovery_owner_changed"));
    }
    Ok(())
}

fn rollback_checks(payload: &Map<String, Value>, request: &Request) -> Result<Value, Refusal> {
    if !matches!(text(payload, "phase"), Some(RESTORING | PREVIOUS)) {
        return Err(no("phase_changed"));
    }
    recovery_owned(payload, request)?;
    functional_proof(payload, request, "predecessor")
}

/// What a step needs before it may commit: a fresh grant check, the managed
/// install rows at one generation and the planned files at another.
struct Plan {
    grant: bool,
    installs: Option<&'static str>,
    compare: Vec<Value>,
    extra: Map<String, Value>,
}

impl Plan {
    fn new(grant: bool, installs: Option<&'static str>, compare: Vec<Value>) -> Self {
        Self {
            grant,
            installs,
            compare,
            extra: Map::new(),
        }
    }
}

fn daemon_step(payload: &Map<String, Value>, request: &Request) -> Result<Plan, Refusal> {
    if text(payload, "authorized_subject") != request.subject.as_deref() {
        return Err(no("plan_context_mismatch"));
    }
    let side = request.side.as_deref().unwrap_or_default();
    let action = request.action.as_deref().unwrap_or_default();
    let planned = match (side, action) {
        ("predecessor", "stop") => Some(HOOKS),
        ("candidate", "start" | "observe") => Some(SWITCHING),
        _ => None,
    };
    if let Some(phase) = planned.filter(|phase| text(payload, "phase") == Some(phase)) {
        runtime_step(payload, request, phase)?;
        return Ok(Plan::new(true, None, Vec::new()));
    }
    let inverse = matches!(
        (side, action),
        ("candidate", "stop") | ("predecessor", "start" | "observe")
    );
    if text(payload, "phase") != Some(RESTORING)
        || payload.get("recovery_owner") != Some(&owner(request))
        || !inverse
    {
        return Err(no("daemon_step_not_authorized"));
    }
    if action == "stop" {
        return Ok(Plan::new(false, None, Vec::new()));
    }
    if payload.get("inverse_files_restored") != Some(&Value::Bool(true)) {
        return Err(no("inverse_not_restored"));
    }
    Ok(Plan::new(
        false,
        Some("before"),
        vec![compare(files(payload, None)?, "before")],
    ))
}

fn plan(payload: &Map<String, Value>, request: &Request) -> Result<Plan, Refusal> {
    match request.step.as_deref() {
        Some("advance") => {
            advance_checks(payload, request)?;
            let expected = expected(request)?;
            let compare = match expected {
                AUTHORIZED => vec![
                    compare(files(payload, Some("binding"))?, "after"),
                    compare(files(payload, Some("selection"))?, "before"),
                ],
                HOOKS => vec![compare(files(payload, None)?, "after")],
                _ => {
                    functional_proof(payload, request, "candidate")?;
                    vec![compare(files(payload, None)?, "after")]
                }
            };
            Ok(Plan::new(
                matches!(expected, AUTHORIZED | HOOKS),
                Some("after"),
                compare,
            ))
        }
        Some("runtime_step") => {
            runtime_step(payload, request, expected(request)?)?;
            Ok(Plan::new(true, None, Vec::new()))
        }
        Some("daemon_step") => daemon_step(payload, request),
        Some("mutation_scope") => {
            if !matches!(text(payload, "phase"), Some(AUTHORIZED | HOOKS)) {
                return Err(no("phase_changed"));
            }
            owned_forward(payload, request)?;
            forward_live(payload, request)?;
            let mut plan = Plan::new(true, None, Vec::new());
            let expires = record_number(payload, "forward_expires_monotonic")?;
            let deadline = record_number(payload, "deadline_monotonic")?.min(expires);
            plan.extra.insert("forward_expires".into(), json!(expires));
            plan.extra.insert("sqlite_deadline".into(), json!(deadline));
            Ok(plan)
        }
        Some("publish") => {
            let expected = expected(request)?;
            if text(payload, "phase") != Some(expected) || !matches!(expected, AUTHORIZED | HOOKS) {
                return Err(no("phase_changed"));
            }
            let (kind, installs) = if expected == AUTHORIZED {
                ("binding", "before")
            } else {
                ("selection", "after")
            };
            let mut plan = Plan::new(false, None, Vec::new());
            plan.extra
                .insert("selected".into(), Value::Array(files(payload, Some(kind))?));
            plan.extra
                .insert("installs_expected".into(), json!(installs));
            Ok(plan)
        }
        Some("finish_rollback") => {
            rollback_checks(payload, request)?;
            Ok(Plan::new(
                false,
                Some("before"),
                vec![compare(files(payload, None)?, "before")],
            ))
        }
        _ => Err(no("invalid")),
    }
}

/// `step_check`: whether the step may run and what to compare first.
pub(super) fn check(request: &Request) -> Result<Value, Refusal> {
    let payload = read_record(request)?;
    let plan = plan(&payload, request)?;
    let mut answer = plan.extra;
    answer.insert("payload".into(), Value::Object(payload));
    answer.insert("grant".into(), Value::Bool(plan.grant));
    answer.insert("installs".into(), json!(plan.installs));
    answer.insert("compare".into(), Value::Array(plan.compare));
    Ok(Value::Object(answer))
}

fn terminal(payload: &Map<String, Value>) -> Result<(), Refusal> {
    if matches!(text(payload, "phase"), Some(COMMITTED | ROLLED_BACK)) {
        return Err(no("terminal_transition"));
    }
    Ok(())
}

/// `payload.get("first_cause") or first_cause[:512]`.
fn keep_first_cause(payload: &mut Map<String, Value>, request: &Request) {
    let present = payload
        .get("first_cause")
        .is_some_and(|value| !value.is_null() && value != &json!(""));
    if !present {
        let cause: String = request
            .first_cause
            .as_deref()
            .unwrap_or_default()
            .chars()
            .take(MAX_FIRST_CAUSE)
            .collect();
        payload.insert("first_cause".into(), Value::String(cause));
    }
}

/// Append one `{code, errno}` cause and keep the last eight.
fn add_cause(payload: &mut Map<String, Value>, request: &Request) -> Result<(), Refusal> {
    let cause = request
        .cause
        .as_ref()
        .filter(|cause| cause.is_object())
        .ok_or_else(|| no("invalid"))?;
    let mut causes: Vec<Value> = record_objects(payload, "recovery_causes", MAX_CAUSES)?
        .into_iter()
        .map(|item| Value::Object(item.clone()))
        .collect();
    causes.push(cause.clone());
    let skip = causes.len().saturating_sub(MAX_CAUSES);
    payload.insert(
        "recovery_causes".into(),
        Value::Array(causes.into_iter().skip(skip).collect()),
    );
    payload.insert("phase".into(), json!(RECOVERY));
    Ok(())
}

/// `step_commit`: repeat the step's checks and write what it leaves behind.
pub(super) fn commit(request: &Request) -> Result<Value, Refusal> {
    let mut payload = read_record(request)?;
    match request.step.as_deref() {
        Some("advance") => {
            let next = advance_checks(&payload, request)?;
            match expected(request)? {
                HOOKS => {
                    payload.insert("functional_started_monotonic".into(), json!(now(request)?));
                }
                SWITCHING | CANDIDATE => {
                    let observation = functional_proof(&payload, request, "candidate")?;
                    payload.insert("functional_proof".into(), observation);
                }
                _ => {}
            }
            payload.insert("phase".into(), json!(next));
        }
        Some("prepare_recovery") => {
            terminal(&payload)?;
            keep_first_cause(&mut payload, request);
            payload.insert("phase".into(), json!(RESTORING));
            let owner = owner(request);
            if owner.is_null() {
                return Err(no("owner_identity_unavailable"));
            }
            payload.insert("recovery_owner".into(), owner);
            payload.insert("inverse_files_restored".into(), Value::Bool(false));
        }
        Some("restore_failed") => add_cause(&mut payload, request)?,
        Some("restored") => {
            payload.insert("functional_started_monotonic".into(), json!(now(request)?));
            payload.insert("inverse_files_restored".into(), Value::Bool(true));
        }
        Some("recovery_failure") => {
            terminal(&payload)?;
            let owner = owner(request);
            let known = [payload.get("owner"), payload.get("recovery_owner")]
                .into_iter()
                .any(|known| known == Some(&owner));
            if owner.is_null() || !known {
                return Err(no("recovery_owner_changed"));
            }
            keep_first_cause(&mut payload, request);
            add_cause(&mut payload, request)?;
        }
        Some("finish_rollback") => {
            // Two commits, so a crash between them leaves PreviousFunctional.
            let observation = rollback_checks(&payload, request)?;
            if text(&payload, "phase") == Some(PREVIOUS) {
                payload.insert("phase".into(), json!(ROLLED_BACK));
            } else {
                payload.insert("phase".into(), json!(PREVIOUS));
                payload.insert("rollback_functional_proof".into(), observation);
            }
        }
        _ => return Err(no("invalid")),
    }
    write_record(request, &payload)?;
    Ok(json!({"phase": payload.get("phase")}))
}
