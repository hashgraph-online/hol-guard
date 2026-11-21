//! The runtime transition coordinator's step protocol, ported from the Python
//! `RuntimeTransitionCoordinator.activate` and `recover` loops.
//!
//! The caller holds the process-local effects: the lifecycle driver that stops,
//! starts and observes runtimes, and the journal methods that write the planned
//! files. The runtime owns the order. Each call carries the last outcome and the
//! state the previous call returned; the answer is the next action to run, with
//! the state to send back. The deadline is judged here from the caller's
//! monotonic clock, which every call reports in `now`.
//!
//! An `activate` runs forward to a committed candidate; any failure retires the
//! candidate, restores the predecessor and records what could not be undone. A
//! `recover` runs only that inverse. Errors travel by the caller's identifier,
//! so the caller can chain the exact exceptions it caught.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::publication::Call;
use super::publication_authorize::{ahead, number};
use super::{Fault, Step};

const INVALID: Fault = Fault::Transition("record_invalid");
const DEADLINE: &str = "deadline_exceeded";
/// Ids at or above this are errors the runtime itself raised, which the
/// caller spells as `TransitionError(deadline_exceeded)`.
const SYNTHETIC: u64 = 1 << 32;
const AUTHORIZED: &str = "AuthorizedForExactTransition";
const HOOKS: &str = "HooksPrepared";
const SWITCHING: &str = "Switching";
const CANDIDATE: &str = "CandidateFunctional";
const RECOVERY_REQUIRED: &str = "RecoveryRequired";

/// What the last action was, so the next outcome is read for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum At {
    Authorized,
    HooksAuthorized,
    PredecessorStopped,
    HooksPublished,
    SwitchingAuthorized,
    CandidateStarted,
    CandidateObserved,
    Switching,
    Functional,
    Prepared,
    CandidateRetired,
    Restored,
    PredecessorStarted,
    PredecessorObserved,
    Finished,
    Recording,
    Phase,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    at: Option<At>,
    recover: bool,
    cause: String,
    may_run: bool,
    attempted: bool,
    completed: bool,
    decided: bool,
    persistence: Option<u64>,
    retirement: Option<u64>,
    recovery: Option<u64>,
    pending: Vec<u64>,
    synthetic: u64,
}

/// One outcome the caller reports: success, or the error it caught.
struct Outcome {
    ok: bool,
    id: u64,
    cause: Option<String>,
    phase: Option<String>,
}

impl Outcome {
    fn parse(value: &Value) -> Step<Self> {
        let ok = value.get("ok").and_then(Value::as_bool).ok_or(INVALID)?;
        Ok(Self {
            ok,
            id: value.get("id").and_then(Value::as_u64).unwrap_or(0),
            cause: value
                .get("cause")
                .and_then(Value::as_str)
                .map(str::to_owned),
            phase: value
                .get("phase")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }
}

/// The caller's clocks, as the deadline checks read them.
struct Clock {
    deadline: Option<f64>,
    now: Option<f64>,
}

impl Clock {
    fn live(&self) -> bool {
        ahead(self.deadline, self.now).is_ok()
    }
}

fn call(method: &str, extra: Value) -> Value {
    let mut action = json!({ "do": "call", "method": method });
    if let (Some(base), Some(more)) = (action.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    action
}

fn drive(op: &str, side: &str) -> Value {
    json!({ "do": "drive", "op": op, "side": side })
}

impl State {
    fn issue(&mut self, at: At, action: Value) -> Value {
        self.at = Some(at);
        action
    }

    /// A deadline check: the error the runtime raises when it has passed.
    fn expired(&mut self, clock: &Clock) -> Option<u64> {
        if clock.live() {
            return None;
        }
        self.synthetic += 1;
        Some(SYNTHETIC + self.synthetic)
    }

    fn begin(&mut self) -> Value {
        if self.recover {
            return self.prepare();
        }
        self.issue(
            At::Authorized,
            call("publish", json!({ "phase": AUTHORIZED })),
        )
    }

    fn prepare(&mut self) -> Value {
        let cause = self.cause.clone();
        self.issue(
            At::Prepared,
            call("prepare_recovery", json!({ "cause": cause })),
        )
    }

    /// A forward step failed: retire what started and restore the predecessor.
    fn fail_forward(&mut self, cause: Option<String>) -> Value {
        self.cause = cause.unwrap_or_else(|| DEADLINE.to_owned());
        self.prepare()
    }

    fn forward_error(&mut self, id: Option<u64>, cause: Option<String>) -> Value {
        let cause = if id.is_some_and(|id| id >= SYNTHETIC) {
            Some(DEADLINE.to_owned())
        } else {
            cause
        };
        self.fail_forward(cause)
    }

    /// A check inside the forward block: `Err` is the failure action.
    fn forward_check(&mut self, clock: &Clock) -> Option<Value> {
        self.expired(clock)
            .map(|id| self.forward_error(Some(id), None))
    }

    fn after_prepare(&mut self, clock: &Clock) -> Value {
        if self.recover {
            if let Some(id) = self.expired(clock) {
                return self.record_failures(id);
            }
            return self.issue(At::PredecessorStopped, drive("stop", "candidate"));
        }
        if self.may_run {
            if let Some(id) = self.expired(clock) {
                self.retirement = Some(id);
                return self.inverse(clock);
            }
            return self.issue(At::CandidateRetired, drive("stop", "candidate"));
        }
        self.inverse(clock)
    }

    /// The inverse attempt: restore the files, then start and prove the
    /// predecessor again.
    fn inverse(&mut self, clock: &Clock) -> Value {
        if let Some(id) = self.persistence.or(self.retirement) {
            return self.record_failures(id);
        }
        if let Some(id) = self.expired(clock) {
            return self.record_failures(id);
        }
        self.attempted = true;
        let cause = self.cause.clone();
        self.issue(
            At::Restored,
            call("restore_files", json!({ "cause": cause })),
        )
    }

    /// The error that ended the inverse, and what must be recorded for it.
    fn record_failures(&mut self, error: u64) -> Value {
        self.recovery = Some(error);
        let mut pending = Vec::new();
        for kept in [self.retirement, self.persistence].into_iter().flatten() {
            if kept != error && !pending.contains(&kept) {
                pending.push(kept);
            }
        }
        self.pending = pending;
        self.decided = false;
        self.next_record()
    }

    fn next_record(&mut self) -> Value {
        if !self.pending.is_empty() {
            let id = self.pending.remove(0);
            let cause = self.cause.clone();
            return self.issue(
                At::Recording,
                call("record_failure", json!({ "error": id, "cause": cause })),
            );
        }
        if self.decided {
            return json!({ "do": "done" });
        }
        self.decided = true;
        if !self.attempted || self.completed {
            self.pending.extend(self.recovery);
            return self.next_record();
        }
        self.issue(At::Phase, call("phase", json!({})))
    }

    /// Recording failed: the first error stays the one raised.
    fn raise(&self, recording: u64) -> Value {
        match self.persistence {
            Some(persistence) => json!({ "do": "raise", "error": persistence, "cause": recording }),
            None => json!({ "do": "raise", "error": recording, "cause": null }),
        }
    }

    fn failed(&mut self, at: At, outcome: &Outcome, clock: &Clock) -> Value {
        match at {
            At::Authorized
            | At::HooksAuthorized
            | At::PredecessorStopped
            | At::HooksPublished
            | At::SwitchingAuthorized
            | At::CandidateStarted
            | At::CandidateObserved
            | At::Switching
            | At::Functional
                if !self.recover =>
            {
                self.forward_error(Some(outcome.id), outcome.cause.clone())
            }
            At::Prepared => {
                self.persistence = Some(outcome.id);
                self.after_prepare(clock)
            }
            At::CandidateRetired => {
                self.retirement = Some(outcome.id);
                self.inverse(clock)
            }
            At::Recording | At::Phase => self.raise(outcome.id),
            _ => self.record_failures(outcome.id),
        }
    }

    fn succeeded(&mut self, at: At, outcome: &Outcome, clock: &Clock) -> Value {
        match at {
            At::Authorized => {
                if let Some(failure) = self.forward_check(clock) {
                    return failure;
                }
                self.issue(
                    At::HooksAuthorized,
                    call("authorize", json!({ "phase": HOOKS })),
                )
            }
            At::HooksAuthorized => self.issue(At::PredecessorStopped, drive("stop", "predecessor")),
            At::PredecessorStopped if self.recover => self.inverse(clock),
            At::PredecessorStopped => {
                if let Some(failure) = self.forward_check(clock) {
                    return failure;
                }
                self.issue(
                    At::HooksPublished,
                    call("publish", json!({ "phase": HOOKS })),
                )
            }
            At::HooksPublished => {
                if let Some(failure) = self.forward_check(clock) {
                    return failure;
                }
                self.issue(
                    At::SwitchingAuthorized,
                    call("authorize", json!({ "phase": SWITCHING })),
                )
            }
            At::SwitchingAuthorized => {
                self.may_run = true;
                self.issue(At::CandidateStarted, drive("start", "candidate"))
            }
            At::CandidateStarted => {
                if let Some(failure) = self.forward_check(clock) {
                    return failure;
                }
                self.issue(At::CandidateObserved, drive("observe", "candidate"))
            }
            At::CandidateObserved => {
                if let Some(failure) = self.forward_check(clock) {
                    return failure;
                }
                self.issue(
                    At::Switching,
                    call("advance", json!({ "phase": SWITCHING, "proof": true })),
                )
            }
            At::Switching => self.issue(
                At::Functional,
                call("advance", json!({ "phase": CANDIDATE, "proof": true })),
            ),
            At::Functional => json!({ "do": "done" }),
            At::Prepared => self.after_prepare(clock),
            At::CandidateRetired => self.inverse(clock),
            At::Restored => {
                self.completed = true;
                if let Some(id) = self.expired(clock) {
                    return self.record_failures(id);
                }
                self.issue(At::PredecessorStarted, drive("start", "predecessor"))
            }
            At::PredecessorStarted if self.recover => {
                if let Some(id) = self.expired(clock) {
                    return self.record_failures(id);
                }
                self.issue(At::PredecessorObserved, drive("observe", "predecessor"))
            }
            At::PredecessorStarted => {
                self.issue(At::PredecessorObserved, drive("observe", "predecessor"))
            }
            At::PredecessorObserved => {
                if let Some(id) = self.expired(clock) {
                    return self.record_failures(id);
                }
                self.issue(
                    At::Finished,
                    call("finish_rollback", json!({ "proof": true })),
                )
            }
            At::Finished => json!({ "do": "done" }),
            At::Recording => self.next_record(),
            At::Phase => {
                if outcome.phase.as_deref() != Some(RECOVERY_REQUIRED) {
                    self.pending.extend(self.recovery);
                }
                self.next_record()
            }
        }
    }

    fn advance(&mut self, outcome: Option<&Outcome>, clock: &Clock) -> Step<Value> {
        let Some(at) = self.at else {
            return Ok(self.begin());
        };
        let outcome = outcome.ok_or(INVALID)?;
        Ok(if outcome.ok {
            self.succeeded(at, outcome, clock)
        } else {
            self.failed(at, outcome, clock)
        })
    }
}

/// `publication_coordinate`: the next action of a coordinator loop.
///
/// `flow` is `activate` or `recover`; `cause` names the interrupted
/// transition a `recover` starts from. The first call carries no `state` and
/// no `outcome`.
pub(super) fn coordinate(call: &mut Call<'_>) -> Step<Value> {
    let recover = match call.text("flow")? {
        "activate" => false,
        "recover" => true,
        _ => return Err(INVALID),
    };
    let clock = Clock {
        deadline: number(call, "deadline"),
        now: number(call, "now"),
    };
    let mut state = match call.args.get("state").filter(|state| !state.is_null()) {
        Some(state) => {
            let carried: State = serde_json::from_value(state.clone()).map_err(|_| INVALID)?;
            // State from the other flow would override the one requested.
            if carried.recover != recover {
                return Err(INVALID);
            }
            carried
        }
        None => State {
            recover,
            cause: call
                .args
                .get("cause")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            ..State::default()
        },
    };
    let outcome = match call
        .args
        .get("outcome")
        .filter(|outcome| !outcome.is_null())
    {
        Some(outcome) => Some(Outcome::parse(outcome)?),
        None => None,
    };
    let action = state.advance(outcome.as_ref(), &clock)?;
    Ok(json!({ "action": action, "state": state }))
}

#[cfg(test)]
#[path = "publication_coordinate_tests.rs"]
mod tests;
