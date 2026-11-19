//! Runaway-session stops at the hook edge.
//!
//! An agent that is stuck repeats itself. Two shapes are stopped here, both
//! measured per harness session and kept under the Guard home, so the counts
//! outlive any one resident runtime process:
//!
//! * a loop: the exact same shell command, already allowed five times in a
//!   row within [`LOOP_WINDOW`] with no other tool call in between, made a
//!   sixth time;
//! * a fan-out: a ninth subagent started within [`FANOUT_WINDOW`], counting
//!   every subagent a batched call starts.
//!
//! The stop denies that one call and says why, then starts the count again,
//! so a repeat the agent makes on purpose runs on its next try. Ordinary work
//! never reaches the threshold: an edit, a read, a different command or a new
//! user prompt between two runs of the same command breaks the streak.
//!
//! Only calls Guard already let through are counted or stopped. A call Guard
//! reviews or blocks keeps its own verdict and resets the loop streak, so this
//! step never touches an approval round trip. The stop is an added block, so
//! it never lowers a sandbox route or any other floor. It applies only to
//! harnesses whose hooks see every tool call (so an edit between two test runs
//! is visible) and only when the hook names its session. Watch mode,
//! recording-only calls and a sandbox's recheck of a routed call are left
//! alone.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy_enforcement::{ActionFloor, AdmittedPolicySnapshot};

const LOOP_STOP: &str = "native_session_repeated_call_stopped";
const FANOUT_STOP: &str = "native_session_subagent_fanout_stopped";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";

/// Identical allowed calls in a row before the next one is stopped.
pub(crate) const LOOP_PRIORS: usize = 5;
/// Subagents started before the next one is stopped.
pub(crate) const FANOUT_PRIORS: usize = 8;
/// A model takes several seconds to choose each call, so six calls in a row
/// from a stuck agent span about a minute. The window must hold that pace.
pub(crate) const LOOP_WINDOW: Duration = Duration::from_secs(120);
pub(crate) const FANOUT_WINDOW: Duration = Duration::from_secs(60);

/// Harnesses whose `PreToolUse` hook sees every tool the agent calls.
/// Oh My Pi and Pi share one extension, which hooks every tool call.
const HARNESSES: &[&str] = &["claude-code", "omp", "pi"];
const SUBAGENT_TOOLS: &[&str] = &["Agent", "Task", "task"];
/// Only a shell command can loop into a stop. A wait, poll or read tool
/// repeats by design, so it only ends a streak.
const SHELL_TOOLS: &[&str] = &["Bash", "PowerShell", "bash"];
/// Shell input fields that label a call or bound its run time without
/// changing the command.
const SHELL_LABEL_FIELDS: &[&str] = &["description", "timeout", "title", "i", "intent"];

/// Sessions kept, and how long an idle one is remembered.
const MAX_SESSIONS: usize = 512;
const SESSION_IDLE: Duration = Duration::from_secs(600);
const MAX_CALLS: usize = LOOP_PRIORS + 1;
const MAX_REQUESTS: usize = 16;

/// What the edge saw for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stop {
    Loop,
    Fanout,
}

#[derive(Debug)]
struct Call {
    digest: [u8; 32],
    at: Instant,
    allowed: bool,
}

#[derive(Debug)]
struct Session {
    calls: VecDeque<Call>,
    spawns: VecDeque<Instant>,
    /// Requests already answered, with the stop each one got, so a hook
    /// delivered twice gets the same answer twice.
    requests: VecDeque<(String, Option<Stop>)>,
    touched: Instant,
}

impl Session {
    fn new(now: Instant) -> Self {
        Self {
            calls: VecDeque::new(),
            spawns: VecDeque::new(),
            requests: VecDeque::new(),
            touched: now,
        }
    }
}

/// Per-session call history.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    sessions: HashMap<String, Session>,
}

/// One `PreToolUse` call as the tracker sees it.
pub(crate) struct Observed<'a> {
    pub(crate) session: &'a str,
    pub(crate) request: Option<&'a str>,
    pub(crate) digest: [u8; 32],
    pub(crate) kind: Kind,
    pub(crate) allowed: bool,
}

/// Which stop a call can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Shell,
    /// A call that starts this many subagents.
    Subagent(usize),
    Other,
}

impl Tracker {
    /// Records a call and says whether it must be stopped. A request already
    /// seen (the same hook delivered twice) is not counted again and gets the
    /// answer it got the first time.
    pub(crate) fn observe(&mut self, call: &Observed<'_>, now: Instant) -> Option<Stop> {
        self.prune(now, call.session);
        let session = self
            .sessions
            .entry(call.session.to_owned())
            .or_insert_with(|| Session::new(now));
        session.touched = now;
        let request = call.request.filter(|request| !request.is_empty());
        if let Some(request) = request {
            if let Some((_, stop)) = session.requests.iter().find(|(seen, _)| seen == request) {
                return *stop;
            }
        }
        let stop = Self::stop(session, call, now);
        if let Some(request) = request {
            if session.requests.len() >= MAX_REQUESTS {
                session.requests.pop_front();
            }
            session.requests.push_back((request.to_owned(), stop));
        }
        stop
    }

    fn stop(session: &mut Session, call: &Observed<'_>, now: Instant) -> Option<Stop> {
        let mut stop = None;
        if call.allowed {
            let streak = session
                .calls
                .iter()
                .rev()
                .take_while(|prior| {
                    prior.allowed
                        && prior.digest == call.digest
                        && now.saturating_duration_since(prior.at) <= LOOP_WINDOW
                })
                .count();
            if call.kind == Kind::Shell && streak >= LOOP_PRIORS {
                stop = Some(Stop::Loop);
            } else if let Kind::Subagent(count) = call.kind {
                while session
                    .spawns
                    .front()
                    .is_some_and(|at| now.saturating_duration_since(*at) > FANOUT_WINDOW)
                {
                    session.spawns.pop_front();
                }
                // A batch counts every subagent it starts. One call's own
                // batch is the agent's plan for the task, so it is checked
                // against the subagents already running, never on its own.
                let started = session.spawns.len();
                if started >= FANOUT_PRIORS || (started > 0 && started + count > FANOUT_PRIORS) {
                    session.spawns.clear();
                    stop = Some(Stop::Fanout);
                } else {
                    for _ in 0..count.min(FANOUT_PRIORS - started) {
                        session.spawns.push_back(now);
                    }
                }
            }
        }
        if session.calls.len() >= MAX_CALLS {
            session.calls.pop_front();
        }
        session.calls.push_back(Call {
            digest: call.digest,
            at: now,
            // A stopped call ends the streak, so the next try runs.
            allowed: call.allowed && stop.is_none(),
        });
        stop
    }

    /// A new user prompt starts the session's counts again.
    pub(crate) fn prompt(&mut self, session: &str) {
        self.sessions.remove(session);
    }

    /// Observes `call` against the counts `store` holds for its session, and
    /// saves them back. The saved counts win over this process's memory, since
    /// another runtime process may have seen later calls.
    fn observe_saved(
        &mut self,
        store: Option<&store::Store>,
        call: &Observed<'_>,
        now: Instant,
    ) -> Option<Stop> {
        let Some(store) = store else {
            return self.observe(call, now);
        };
        let mut created = false;
        match store.load(call.session, now) {
            Ok(Some(saved)) => {
                self.sessions.insert(call.session.to_owned(), saved);
            }
            Ok(None) => {
                self.sessions.remove(call.session);
                created = true;
            }
            Err(()) => {}
        }
        let stop = self.observe(call, now);
        if let Some(session) = self.sessions.get(call.session) {
            if store.save(call.session, session, now) && created {
                store.prune();
            }
        }
        stop
    }

    /// Forgets idle sessions, then the oldest beyond [`MAX_SESSIONS`]. The
    /// session being observed (`current`) is never the one evicted.
    fn prune(&mut self, now: Instant, current: &str) {
        self.sessions
            .retain(|_, session| now.saturating_duration_since(session.touched) <= SESSION_IDLE);
        let room = if self.sessions.contains_key(current) {
            MAX_SESSIONS
        } else {
            MAX_SESSIONS - 1
        };
        while self.sessions.len() > room {
            let Some(oldest) = self
                .sessions
                .iter()
                .filter(|(key, _)| key.as_str() != current)
                .min_by_key(|(_, session)| session.touched)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.sessions.remove(&oldest);
        }
    }
}

fn tracker() -> &'static Mutex<Tracker> {
    static TRACKER: OnceLock<Mutex<Tracker>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(Tracker::default()))
}

/// The session a hook names, keyed with its harness and folder.
fn session_key(harness: &str, envelope: &GuardHookEnvelopeV2) -> Option<String> {
    let session = envelope
        .raw_payload
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|session| !session.is_empty())?;
    let folder = envelope.source.cwd.as_deref().unwrap_or("");
    let digest = Sha256::digest(format!("{harness}\0{folder}\0{session}").as_bytes());
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The call's identity: the tool and its exact input. For a shell command,
/// fields that only describe the call or bound how long it may take are left
/// out, since they do not change what runs.
fn call_digest(payload: &Value) -> Option<([u8; 32], Kind)> {
    let tool = payload.get("tool_name").and_then(Value::as_str)?;
    let mut input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
    let kind = if SHELL_TOOLS.contains(&tool) {
        if let Value::Object(fields) = &mut input {
            fields.retain(|key, _| !SHELL_LABEL_FIELDS.contains(&key.as_str()));
        }
        Kind::Shell
    } else if SUBAGENT_TOOLS.contains(&tool) {
        Kind::Subagent(subagents(&input))
    } else {
        Kind::Other
    };
    let text = serde_json::to_string(&input).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    hasher.update([0]);
    hasher.update(text.as_bytes());
    Some((hasher.finalize().into(), kind))
}

/// How many subagents one call starts: each entry of a batched `tasks` list,
/// or one.
fn subagents(input: &Value) -> usize {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .map_or(1, |tasks| tasks.len().max(1))
}

/// Whether Guard let the call through: allowed, warned or sent to a sandbox.
/// A sandbox route carries a deny decision because the harness runs the
/// rewritten call instead of the original, so only the floor decides it.
fn let_through(result: &PreToolResultV1) -> bool {
    match ActionFloor::parse(&result.minimum_action) {
        Some(ActionFloor::SandboxRequired) => true,
        Some(ActionFloor::Allow | ActionFloor::Warn) => result.decision != "deny",
        _ => false,
    }
}

/// [`Tracker::observe`] for a hook envelope, after every other edge step.
/// `call` is the hook's event name and canonical harness.
pub(crate) fn apply(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    (event_name, harness): (&str, &str),
    result: PreToolResultV1,
) -> PreToolResultV1 {
    let observe = policy_snapshot.is_some_and(|snapshot| snapshot.mode == "observe");
    // A sandbox asks again about a call its hook already routed there; that
    // second question is the same call, so it is never counted twice.
    let sink_recheck = envelope.raw_payload.get(RECEIPT_ONLY_FIELD) == Some(&Value::Bool(true));
    if envelope.recording_only || observe || sink_recheck || !HARNESSES.contains(&harness) {
        return result;
    }
    let Some(session) = session_key(harness, envelope) else {
        return result;
    };
    if event_name != "UserPromptSubmit" && event_name != "PreToolUse" {
        return result;
    }
    let Ok(mut tracker) = tracker().lock() else {
        return result;
    };
    let store = store::Store::open(&envelope.source.guard_home);
    if event_name == "UserPromptSubmit" {
        tracker.prompt(&session);
        if let Some(store) = &store {
            store.remove(&session);
        }
        return result;
    }
    let Some((digest, kind)) = call_digest(&envelope.raw_payload) else {
        return result;
    };
    let call = Observed {
        session: &session,
        request: envelope.request_id.as_deref(),
        digest,
        kind,
        allowed: let_through(&result),
    };
    match tracker.observe_saved(store.as_ref(), &call, Instant::now()) {
        Some(stop) => stopped(result, &stop),
        None => result,
    }
}

/// Denies the call for `stop`.
pub(crate) fn stopped(mut result: PreToolResultV1, stop: &Stop) -> PreToolResultV1 {
    let (code, reason) = match stop {
        Stop::Loop => (
            LOOP_STOP,
            "Guard stopped this command: the exact same command already ran five times in a row in the \
             last two minutes with nothing else in between, which looks like a stuck loop. Read the \
             earlier results before trying again. If the repeat is intended, run the command again \
             and it runs.",
        ),
        Stop::Fanout => (
            FANOUT_STOP,
            "Guard stopped this subagent: eight subagents already started in this session in the \
             last minute, which looks like a runaway task. Check that the task needs more. If it \
             does, start this subagent again and it runs.",
        ),
    };
    result.minimum_action = "block".into();
    result.policy_action = "block".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = code.into();
    result.reason = reason.into();
    result
}

#[path = "edge_session_cascade_store.rs"]
mod store;

#[cfg(test)]
#[path = "edge_session_cascade_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "edge_session_cascade_pace_tests.rs"]
mod pace_tests;
