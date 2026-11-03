//! Records the CLIs an answered `PreToolUse` launches, off the answer path.
//!
//! The daemon used to queue each answered `PreToolUse` command for a Python
//! worker that asked this resident to record the CLI it launches. The
//! resident now does that itself, for the edge answers the daemon asks it to
//! observe ([`EDGE_LOCAL_CLI_OBSERVATION_FEATURE`]) and for the hooks it
//! answers directly. The semantics are the daemon's:
//!
//! - the same command, launch directory and `PATH` is skipped for
//!   [`RECENT_TTL`], and at most [`MAX_RECENT`] keys are remembered;
//! - the queue holds [`MAX_PENDING`] entries for one process-wide worker, and
//!   a full queue drops the entry without remembering its key, so the next
//!   hook may queue it again;
//! - nothing here blocks or fails the answer: the hook only resolves its
//!   launch directory, checks the recent keys and offers the entry.
//!
//! The worker records through `local_cli_hook_op::observe_only` under the
//! shared storage gate and puts the store files back into private mode, as
//! the daemon's store call did. A failed record is dropped.
//!
//! The launch resolves against the daemon's home and environment, as it did
//! when the daemon recorded it: an edge envelope carries both in its
//! `local_cli_rules`. The resident runs in an isolated environment without
//! the user's `PATH`, so its own is used only for a direct answer, which the
//! direct lane's rule check resolves the same way.

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use guard_contracts::{GuardHookEnvelopeV2, LocalCliHookRequestV1, LOCAL_CLI_HOOK_REQUEST_SCHEMA};
use serde_json::{Map, Value};

use crate::hook_direct::local_cli::{launch_dir_candidate, pre_tool_command, resolve_launch_dir};
use crate::local_store_read::STORE_FILE_NAME;

/// The resident observes an edge `PreToolUse` whose envelope asks for it.
pub(crate) const EDGE_LOCAL_CLI_OBSERVATION_FEATURE: &str = "edge-local-cli-observation-v1";
const MAX_PENDING: usize = 64;
/// Repeats of the same command in the same folder add nothing new, so they
/// are skipped for a while to keep the observer from competing with hooks.
const RECENT_TTL: Duration = Duration::from_secs(120);
const MAX_RECENT: usize = 512;
const WORKER_NAME: &str = "hol-guard-cli-observer";
/// `GuardStore.guard_source` is not read by the observation writes.
const STORE_SOURCE: &str = "default";
const REQUEST_ID: &str = "local-cli-observation";

/// The launch an answered hook names, before its directory is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    command: String,
    launch_dir: String,
    home_dir: String,
    guard_home: String,
    path: Option<String>,
    launch_env: Option<LaunchEnvironment>,
}

/// The daemon's home and environment, which a launch resolves `~` and
/// `PATH` against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchEnvironment {
    pub(crate) user_home: String,
    pub(crate) env: BTreeMap<String, String>,
}

/// One queued observation: the command, its resolved launch directory, and
/// the `PATH` the agent runs it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) command: String,
    pub(crate) cwd: String,
    pub(crate) home_dir: String,
    pub(crate) guard_home: String,
    pub(crate) path: Option<String>,
    pub(crate) launch_env: Option<LaunchEnvironment>,
}

type Key = (String, String, Option<String>);

impl Observation {
    fn key(&self) -> Key {
        (self.command.clone(), self.cwd.clone(), self.path.clone())
    }
}

/// The launch a `PreToolUse` payload names: its command, the payload's `cwd`
/// or else the workspace, and the agent's `PATH` when it is a usable one.
/// `None` when it names no command.
pub(crate) fn candidate(
    payload: &Map<String, Value>,
    workspace: Option<&str>,
    home_dir: &str,
    guard_home: &str,
    path: Option<&str>,
) -> Option<Candidate> {
    let command = pre_tool_command(payload).ok()??;
    let launch_dir = launch_dir_candidate(payload, workspace.unwrap_or_default()).ok()?;
    Some(Candidate {
        command: command.to_owned(),
        launch_dir: launch_dir.to_owned(),
        home_dir: home_dir.to_owned(),
        guard_home: guard_home.to_owned(),
        path: path
            .filter(|path| !path.is_empty() && !path.contains('\0'))
            .map(str::to_owned),
        launch_env: None,
    })
}

/// The launch a directly answered `PreToolUse` names. Its payload keeps the
/// execution environment the hook stamped, which the daemon read the `PATH`
/// from when it drained the record, over the home and environment the
/// daemon published (`launch_env`).
///
/// Without a published environment it keeps resolving against the resident's
/// own home and variables, as every direct observation did before the daemon
/// published one. An observation only records which local CLI a launch named,
/// never a decision, so a resident-resolved record stays better than no record
/// at all, and the `PATH` the hook stamped wins either way.
pub(crate) fn direct_candidate(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
    guard_home: &str,
    launch_env: Option<LaunchEnvironment>,
) -> Option<Candidate> {
    let path = payload
        .get(crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD)
        .and_then(|environment| environment.get("path"))
        .and_then(Value::as_str);
    candidate(payload, Some(workspace), home_dir, guard_home, path).map(|found| Candidate {
        launch_env,
        ..found
    })
}

/// The launch an edge envelope names, when the daemon asked the resident to
/// observe it and it is a `PreToolUse`, with the daemon's home and
/// environment when the envelope carries them.
pub(crate) fn edge_candidate(envelope: &GuardHookEnvelopeV2) -> Option<Candidate> {
    if !envelope.observe_local_cli
        || crate::edge::canonical_event(&envelope.event).ok()? != "PreToolUse"
    {
        return None;
    }
    candidate(
        envelope.raw_payload.as_object()?,
        envelope.source.cwd.as_deref(),
        &envelope.source.home_dir,
        &envelope.source.guard_home,
        envelope
            .source
            .execution_environment
            .as_ref()
            .map(|environment| environment.path.as_str()),
    )
    .map(|found| Candidate {
        launch_env: envelope
            .local_cli_rules
            .as_ref()
            .map(|rules| LaunchEnvironment {
                user_home: rules.user_home.clone(),
                env: rules.env.clone(),
            }),
        ..found
    })
}

/// Resolve the candidate's launch directory and offer it to the process-wide
/// observer. Returns whether it was queued.
pub(crate) fn offer(candidate: Option<Candidate>) -> bool {
    // Unit tests drive an `Observer` of their own; the process-wide worker
    // would write into other tests' stores after they assert on them.
    if cfg!(test) {
        return false;
    }
    let Some(observation) = candidate.and_then(resolve) else {
        return false;
    };
    static OBSERVER: OnceLock<Observer> = OnceLock::new();
    OBSERVER
        .get_or_init(|| Observer::start(MAX_PENDING, record))
        .offer(observation)
}

fn resolve(candidate: Candidate) -> Option<Observation> {
    let cwd = resolve_launch_dir(&candidate.launch_dir).ok()??;
    Some(Observation {
        command: candidate.command,
        cwd,
        home_dir: candidate.home_dir,
        guard_home: candidate.guard_home,
        path: candidate.path,
        launch_env: candidate.launch_env,
    })
}

/// A bounded queue drained by one worker, with the keys it queued recently.
pub(crate) struct Observer {
    recent: Mutex<VecDeque<(Key, Instant)>>,
    sender: SyncSender<Observation>,
}

impl Observer {
    /// Start the worker that runs `run` for each queued observation. A panic
    /// in `run` drops that observation and keeps the worker alive.
    pub(crate) fn start(capacity: usize, run: impl Fn(Observation) + Send + 'static) -> Self {
        let (sender, receiver) = sync_channel::<Observation>(capacity);
        // A worker that cannot start leaves the queue disconnected, so every
        // offer is dropped; the answer path is never affected.
        let _ = std::thread::Builder::new()
            .name(WORKER_NAME.to_owned())
            .spawn(move || {
                for observation in receiver {
                    let _ = catch_unwind(AssertUnwindSafe(|| run(observation)));
                }
            });
        Self {
            recent: Mutex::new(VecDeque::new()),
            sender,
        }
    }

    /// Queue `observation` unless its key was queued recently. A full queue
    /// drops it, and a dropped key stays eligible for the next offer.
    pub(crate) fn offer(&self, observation: Observation) -> bool {
        self.offer_at(observation, Instant::now())
    }

    fn offer_at(&self, observation: Observation, now: Instant) -> bool {
        let key = observation.key();
        if self.seen_recently(&key, now) {
            return false;
        }
        if self.sender.try_send(observation).is_err() {
            return false;
        }
        self.remember(key, now);
        true
    }

    fn seen_recently(&self, key: &Key, now: Instant) -> bool {
        let recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent
            .iter()
            .find(|(seen, _)| seen == key)
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) < RECENT_TTL)
    }

    fn remember(&self, key: Key, now: Instant) {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent.retain(|(seen, _)| *seen != key);
        recent.push_back((key, now));
        while recent.len() > MAX_RECENT {
            recent.pop_front();
        }
    }
}

/// Record one observation as the daemon's store call did: under the shared
/// storage gate, then with the store files put back into private mode.
/// A home without a store has nothing to record into, and its gate file is
/// left uncreated.
fn record(observation: Observation) {
    let guard_home = Path::new(&observation.guard_home);
    if !guard_home.join(STORE_FILE_NAME).is_file() {
        return;
    }
    let request = request(&observation);
    let timeout_ms = crate::hook_evidence_store_timeout::sqlite_timeout_ms();
    {
        let Ok(_gate) = crate::hook_evidence_store_gate::hold_storage_gate(
            guard_home,
            Duration::from_millis(timeout_ms.into()),
        ) else {
            return;
        };
        let _ = crate::local_cli_hook_op::observe_only(&request);
    }
    crate::hook_direct::saved_decision::consume::repair_store_permissions(guard_home);
}

/// The `LocalCliHook` request the daemon sent for an observation: its own
/// home and environment, with the agent's `PATH` when the hook stamped one.
fn request(observation: &Observation) -> LocalCliHookRequestV1 {
    let (user_home, mut env) = match &observation.launch_env {
        Some(daemon) => (daemon.user_home.clone(), daemon.env.clone()),
        None => (
            account_home(|name| std::env::var(name).ok(), &observation.home_dir),
            std::env::vars_os()
                .filter_map(|(name, value)| {
                    Some((name.into_string().ok()?, value.into_string().ok()?))
                })
                .collect(),
        ),
    };
    if let Some(path) = &observation.path {
        env.insert("PATH".to_owned(), path.clone());
    }
    let timeout_ms = crate::hook_evidence_store_timeout::sqlite_timeout_ms();
    LocalCliHookRequestV1 {
        schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        store_path: Path::new(&observation.guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: observation.guard_home.clone(),
        source: STORE_SOURCE.to_owned(),
        busy_timeout_ms: u64::from(timeout_ms).clamp(1, crate::guard_store_op::MAX_BUSY_TIMEOUT_MS),
        command: observation.command.clone(),
        cwd: observation.cwd.clone(),
        home_dir: Some(observation.home_dir.clone()),
        user_home,
        env,
        current_action: "allow".to_owned(),
        current_reason_code: None,
        grant_allowed: false,
    }
}

/// The account home a launch without the daemon's resolves `~` against:
/// `HOME`, else `USERPROFILE`, else the home the hook reported, which is the
/// same account's when a service runs without either variable.
fn account_home(lookup: impl Fn(&str) -> Option<String>, hook_home: &str) -> String {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .find_map(|name| lookup(name).filter(|home| !home.is_empty()))
        .unwrap_or_else(|| hook_home.to_owned())
}

#[cfg(test)]
#[path = "local_cli_observer_tests.rs"]
mod tests;
