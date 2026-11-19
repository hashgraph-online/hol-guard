use serde_json::{json, Value};

use super::{Clock, Outcome, State};

fn clock(now: f64) -> Clock {
    Clock {
        deadline: Some(100.0),
        now: Some(now),
    }
}

/// What the action asks the caller to run, as one word.
fn label(action: &Value) -> String {
    let text = |key: &str| action.get(key).and_then(Value::as_str).unwrap_or("");
    match text("do") {
        "call" => text("method").to_owned(),
        "drive" => format!("{}:{}", text("op"), text("side")),
        other => other.to_owned(),
    }
}

/// Run a coordinator loop the way the caller does, failing the one step named.
fn run(recover: bool, fail: Option<&str>, now: f64) -> Vec<String> {
    let mut state = State {
        recover,
        cause: "interrupted".to_owned(),
        ..State::default()
    };
    let mut outcome: Option<Outcome> = None;
    let mut seen = Vec::new();
    for _ in 0..40 {
        let action = state.advance(outcome.as_ref(), &clock(now)).expect("step");
        let step = label(&action);
        seen.push(step.clone());
        if step == "done" || step == "raise" {
            break;
        }
        let failed = fail == Some(step.as_str());
        outcome = Some(Outcome {
            ok: !failed,
            id: u64::from(failed),
            cause: failed.then(|| "boom".to_owned()),
            phase: Some("Rolled".to_owned()),
        });
    }
    seen
}

#[test]
fn an_activation_runs_forward_to_a_functional_candidate() {
    assert_eq!(
        run(false, None, 1.0),
        [
            "publish",
            "authorize",
            "stop:predecessor",
            "publish",
            "authorize",
            "start:candidate",
            "observe:candidate",
            "advance",
            "advance",
            "done",
        ]
    );
}

#[test]
fn a_candidate_that_fails_its_observation_is_retired_and_the_predecessor_restored() {
    assert_eq!(
        run(false, Some("observe:candidate"), 1.0),
        [
            "publish",
            "authorize",
            "stop:predecessor",
            "publish",
            "authorize",
            "start:candidate",
            "observe:candidate",
            "prepare_recovery",
            "stop:candidate",
            "restore_files",
            "start:predecessor",
            "observe:predecessor",
            "finish_rollback",
            "done",
        ]
    );
}

#[test]
fn a_recovery_runs_only_the_inverse() {
    assert_eq!(
        run(true, None, 1.0),
        [
            "prepare_recovery",
            "stop:candidate",
            "restore_files",
            "start:predecessor",
            "observe:predecessor",
            "finish_rollback",
            "done",
        ]
    );
}

#[test]
fn a_passed_deadline_records_the_failure_without_touching_a_runtime() {
    assert_eq!(
        run(false, None, 200.0),
        ["publish", "prepare_recovery", "record_failure", "done"]
    );
}

#[test]
fn the_state_survives_a_round_trip_between_calls() {
    let mut state = State::default();
    state.advance(None, &clock(1.0)).expect("first step");
    let sent = serde_json::to_value(&state).expect("serialize");
    let back: State = serde_json::from_value(sent.clone()).expect("deserialize");
    assert_eq!(serde_json::to_value(&back).expect("again"), sent);
    assert_eq!(sent["at"], json!("authorized"));
}
