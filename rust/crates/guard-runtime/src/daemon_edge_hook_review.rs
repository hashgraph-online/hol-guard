//! `POST /v1/hooks/<harness>` and `POST /v1/hooks/<harness>/readiness`: the
//! daemon's own review of a hook the resident's direct lane did not answer.
//!
//! The edge owns the caller check: a Codex or Claude Code hook must present
//! the identity proof it redeemed on this connection, and every other hook
//! the daemon's token. The hook worker reviews it through the
//! `route.hook_post` library call, which admits it under its deadline and the
//! scheduler's capacity and answers the harness's response. A call that
//! cannot run answers the harness's fail-safe instead, so a hook is never
//! left without a decision.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::http::{query_value, Request};
use super::super::library;
use super::{authorize_token, hook_scheduler, json_response, refusals, NativeReads, ReadConfig};
use crate::claude_hook_bridge_render::py_strip;
use crate::pyjson::PyVal;
use admission::{
    client_key, exec_workdir, expires_at, lane, missing_workdir, payload, payload_reference,
    reply_event, runtime_event, take_hint, Directories, Rejection, MAX_PAYLOAD_REFERENCE_BYTES,
    MISSING_WORKDIR_CODE,
};

#[path = "daemon_edge_hook_admission.rs"]
mod admission;
#[path = "daemon_edge_hook_counters.rs"]
mod counters;
#[path = "daemon_edge_hook_cursor_sink.rs"]
mod cursor_sink;
#[path = "daemon_edge_hook_envelopes.rs"]
mod envelopes;
#[path = "daemon_edge_hook_lifecycle.rs"]
mod lifecycle;
#[path = "daemon_edge_hook_managed.rs"]
mod managed;
#[path = "daemon_edge_hook_readiness.rs"]
mod readiness;
use envelopes::{capacity_reason, envelope, fail_safe, prepare_refusal, refusal};
#[cfg(test)]
use envelopes::{event_kind, fill, ENVELOPES};

/// `availability_harness_response`'s reason for a hook the worker never reviewed.
const WORKER_UNAVAILABLE_REASON: &str =
    "HOL Guard could not complete the native hook decision safely.";
const WORKER_UNAVAILABLE_CODE: &str = "native_hook_worker_unavailable";
/// The refusal for a payload reference Guard's writer could not have left.
const REFERENCE_REASON: &str = "HOL Guard could not authenticate the local hook payload.";
const REFERENCE_CODE: &str = "invalid_hook_payload_reference";

/// How long a readiness step may take: it prepares a workspace's policy
/// under its own setup budget.
const READINESS_WAIT: Duration = Duration::from_secs(60);
/// How long past its deadline a hook still waits for a review to finish.
const LATE_ANSWER_GRACE: Duration = Duration::from_millis(400);

/// What is left of a hook's deadline, plus the grace a late answer still
/// counts within.
fn budget(expires: f64) -> Duration {
    let remaining = (expires - hook_scheduler::shared().now()).max(0.0);
    Duration::from_secs_f64(remaining) + LATE_ANSWER_GRACE
}

/// What is left of the deadline and its grace together, so a step after a
/// late one does not get a fresh grace of its own.
fn budget_left(expires: f64) -> Duration {
    let deadline = expires + LATE_ANSWER_GRACE.as_secs_f64();
    Duration::from_secs_f64((deadline - hook_scheduler::shared().now()).max(0.0))
}
/// How long a refused-directory audit waits for a store another writer
/// holds, as the Python daemon's one inline attempt did.
const AUDIT_BUSY_MS: u64 = 250;
/// The longest a hook waits for the start-time worker warm-up.
const WARM_WAIT: Duration = Duration::from_secs(20);

/// `CHALLENGE_HOOK_PATHS`: the hooks only an identity proof admits.
const CHALLENGE_PATHS: [&str; 2] = ["/v1/hooks/codex", "/v1/hooks/claude-code"];

/// The harness a hook path names, and whether it is the readiness route.
fn route(path: &str) -> Option<(&str, bool)> {
    let rest = path.strip_prefix("/v1/hooks/")?;
    let (harness, readiness) = match rest.split_once('/') {
        None => (rest, false),
        Some((harness, "readiness")) => (harness, true),
        Some(_) => return None,
    };
    (!harness.is_empty()).then_some((harness, readiness))
}

/// Whether the daemon reviews `POST path` here.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    route(path).is_some()
}

/// The response to the hook, or `None` for a path that is not a hook route.
pub(in crate::daemon_edge) fn respond(
    request: &Request<'_>,
    body: &[u8],
    port: u16,
    config: &ReadConfig,
    reads: &NativeReads,
    proof_verified: bool,
) -> Option<Vec<u8>> {
    let (harness, readiness) = route(request.path)?;
    if request.has_header("Transfer-Encoding") {
        return None;
    }
    let challenge = CHALLENGE_PATHS.contains(&request.path);
    let proven = challenge && proof_verified;
    if !proven && authorize_token(request, &config.token).is_none() {
        // No handler sits behind the edge for a hook, so the refusal and its
        // audit row are written here.
        let refusal = refusals::refusal(request, body, &config.token)
            .unwrap_or(refusals::Refusal::Unauthorized);
        let (status, body, cors_origin) = refusals::respond(request, &refusal, None, config, reads);
        return Some(json_response(
            status,
            &body,
            config.dashboard_build.as_deref(),
            cors_origin.as_deref(),
            false,
        ));
    }
    let answer = |status: u16, body: &Value, no_store: bool| {
        json_response(
            status,
            body,
            config.dashboard_build.as_deref(),
            None,
            no_store,
        )
    };
    if challenge && !proven {
        return Some(answer(
            401,
            &json!({
                "error": "daemon_identity_required",
                "repair": "Run `hol-guard daemon repair`.",
            }),
            false,
        ));
    }
    let payload = match payload(request, body)? {
        Ok(payload) => payload,
        Err(()) => {
            return Some(answer(
                400,
                &json!({ "error": "invalid_request_body" }),
                false,
            ))
        }
    };
    reads.report_activity();
    let hook = Hook {
        config,
        reads,
        port,
        daemon_pid: reads.daemon_pid(),
        path: request.path,
        query: request.query,
        harness,
    };
    let (status, body, no_store) = if readiness {
        hook.readiness(&payload)
    } else {
        let direct_miss = request.single_header("X-Guard-Direct-Miss");
        (200, hook.runtime(payload, direct_miss), false)
    };
    Some(answer(status, &body, no_store))
}

/// One hook request, and the resident library steps it calls.
struct Hook<'a> {
    config: &'a ReadConfig,
    reads: &'a NativeReads,
    port: u16,
    daemon_pid: u32,
    path: &'a str,
    query: &'a str,
    harness: &'a str,
}

impl Hook<'_> {
    /// `_optional_string` of a query parameter's last value.
    fn param(&self, key: &str) -> Option<String> {
        self.raw_param(key)
            .map(|value| py_strip(&value).to_owned())
            .filter(|value| !value.is_empty())
    }

    /// A query parameter's last value as the request spelled it.
    fn raw_param(&self, key: &str) -> Option<String> {
        query_value(self.query, key).ok().flatten()
    }

    /// The home this daemon was configured with.
    fn home(&self) -> String {
        self.config
            .user_home
            .clone()
            .or_else(|| std::env::var("HOME").ok())
            .unwrap_or_default()
    }

    /// Runs one library step in the resident process.
    fn call(&self, name: &str, extra: Value) -> Option<Map<String, Value>> {
        self.call_within(name, extra, READINESS_WAIT)
    }

    /// A library step bounded by the hook's own deadline, plus the grace a
    /// review that finishes late is still answered within.
    fn call_by(&self, name: &str, extra: Value, expires: f64) -> Option<Map<String, Value>> {
        self.call_within(name, extra, budget(expires))
    }

    fn call_within(&self, name: &str, extra: Value, wait: Duration) -> Option<Map<String, Value>> {
        let mut args = Map::new();
        args.insert("port".to_owned(), self.port.into());
        args.insert("daemon_pid".to_owned(), self.daemon_pid.into());
        args.insert("home_dir".to_owned(), self.config.user_home.clone().into());
        args.insert("path".to_owned(), self.path.into());
        args.insert("query".to_owned(), self.query.into());
        args.insert("harness".to_owned(), self.harness.into());
        if let Value::Object(extra) = extra {
            args.extend(extra);
        }
        match library::call_resident_within(self.config, name, Value::Object(args), wait) {
            Ok(Value::Object(answer)) => Some(answer),
            _ => None,
        }
    }

    /// The app this hook route belongs to, as the managed-install table names it.
    fn managed_harness(&self) -> String {
        guard_command::harness_identity::canonical_harness_id(self.harness).map_or_else(
            || self.harness.trim().to_lowercase().replace('_', "-"),
            str::to_owned,
        )
    }

    /// Whether the hook belongs to an app Guard is not protecting: its own
    /// managed-install row is inactive or, with no row, another app's is
    /// active. A store that cannot be read keeps the hook reviewed.
    /// Hooks that arrived together share one read (see `managed`).
    fn unmanaged(&self, harness: &str, arrived: std::time::Instant) -> bool {
        let guard_home = &self.config.guard_home;
        managed::shared().unmanaged(&format!("{guard_home}\0{harness}"), arrived, || {
            crate::local_store_read::hook_store_probe(Path::new(guard_home), harness, None)
                .is_ok_and(|probe| probe.harness_unmanaged)
        })
    }

    /// Audits a directory the request named and the daemon refused. The
    /// row is best effort: a store held past the audit's short wait loses
    /// it rather than delaying the hook.
    fn audit_rejection(&self, rejection: &Value) {
        let text = |key: &str| {
            PyVal::Str(
                rejection
                    .get(key)
                    .and_then(Value::as_str)
                    .map(py_strip)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        let payload = PyVal::Dict(vec![
            ("method".to_owned(), PyVal::Str("POST".to_owned())),
            ("path".to_owned(), PyVal::Str(self.path.to_owned())),
            ("parameter".to_owned(), text("parameter")),
            ("reason".to_owned(), text("reason")),
        ]);
        let _ = refusals::record_within(
            "daemon.hook.path_rejected",
            &payload,
            self.config,
            self.reads,
            AUDIT_BUSY_MS,
        );
    }

    /// Settles the directories a request named against this daemon's homes.
    fn settle(&self, candidates: &[(&str, Option<String>, Option<&str>)]) -> Directories {
        Directories::settle(&self.config.guard_home, &self.home(), candidates)
    }

    /// `POST /v1/hooks/<harness>`: admits the hook under its deadline and the
    /// scheduler's capacity, and answers the worker's review or a fail-safe.
    fn runtime(&self, mut payload: Map<String, Value>, direct_miss: Option<&str>) -> Value {
        let arrived = std::time::Instant::now();
        let event = runtime_event(&payload);
        let (hint, missing) = take_hint(&mut payload);
        // A hook with no time hint has a client that waits for its answer;
        // one with a hint keeps its own clock from the moment it arrived.
        if missing {
            hook_scheduler::wait_for_warm(WARM_WAIT);
        }
        let scheduler = hook_scheduler::shared();
        let expires = expires_at(scheduler.now(), hint, missing, event == "UserPromptSubmit");
        payload.remove("hook_env");
        let remaining = || (expires - scheduler.now()).max(0.0);
        let runtime_harness = self.param("runtime-harness");
        let reply_harness = runtime_harness
            .as_deref()
            .unwrap_or(self.harness)
            .trim()
            .to_lowercase()
            .replace('_', "-");
        let reply_event = reply_event(&payload);
        let fail = |reason: &str, code: &str| fail_safe(&reply_harness, &reply_event, reason, code);
        let unavailable = || fail(WORKER_UNAVAILABLE_REASON, WORKER_UNAVAILABLE_CODE);

        // The daemon's direct lane (`direct_hook`) already asked the resident
        // before this route ran; what reaches here is the daemon's own review.
        let guard_home_query = self.param("guard-home");
        counters::note_received(
            Path::new(&self.config.guard_home),
            runtime_harness.as_deref().unwrap_or(self.harness),
            direct_miss,
        );
        let capacity_harness = counters::capacity_harness(&reply_harness);

        let (workdir_named, workdir) = exec_workdir(&payload);
        let payload_cwd = payload
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let query_workspace = self.raw_param("workspace");
        let named = [
            workdir.clone(),
            payload_cwd.clone(),
            query_workspace.clone(),
        ];
        let directories = self.settle(&[
            ("home", self.param("home"), None),
            ("guard-home", guard_home_query, None),
            ("exec-workdir", workdir, Some("exec-workdir")),
            ("workspace-payload", payload_cwd, Some("hook-workspace")),
            ("workspace-query", query_workspace, Some("hook-workspace")),
        ]);
        let settled = (|| {
            let home_dir = directories.require("home")?;
            let guard_home = directories.require("guard-home")?;
            let action = directories.require("exec-workdir")?;
            if workdir_named && action.is_none() {
                return Err(Rejection {
                    parameter: "workspace".to_owned(),
                    reason: "invalid_action_workdir".to_owned(),
                });
            }
            let workspace = match action {
                Some(action) => Some(action),
                None => match directories.require("workspace-payload")? {
                    Some(workspace) => Some(workspace),
                    None => directories.require("workspace-query")?,
                },
            };
            Ok((home_dir, guard_home, workspace))
        })();
        let mut missing = None;
        let (home_dir, guard_home, workspace, rejection) = match settled {
            Ok((home_dir, guard_home, workspace)) => (home_dir, guard_home, workspace, None),
            Err(rejection) => {
                let named = named.each_ref().map(Option::as_deref);
                missing = missing_workdir(&event, &rejection, &named);
                (
                    Some(self.home()),
                    Some(self.config.guard_home.clone()),
                    None,
                    Some(rejection.to_value()),
                )
            }
        };

        if let Some(rejection) = &rejection {
            self.audit_rejection(rejection);
        }
        // Leftover hooks of an app Guard is not protecting pass through.
        let managed_harness = self.managed_harness();
        if self.unmanaged(&managed_harness, arrived) {
            return envelope("unmanaged", &managed_harness, &[]);
        }
        // A command whose working directory does not exist cannot run; say so
        // now rather than send it for approval with no workspace.
        if let Some(reason) = missing {
            return fail(&reason, MISSING_WORKDIR_CODE);
        }
        // A referenced payload is read only where Guard's own writer could
        // have put it, and reserves the most a reference may carry.
        let bytes = match payload_reference(&payload) {
            Ok(None) => serde_json::to_vec(&payload).map_or(0, |body| body.len() as u64),
            Ok(Some(path)) => match self
                .settle(&[("payload-reference", Some(path), None)])
                .require("payload-reference")
            {
                Ok(Some(_)) => MAX_PAYLOAD_REFERENCE_BYTES,
                _ => return fail(REFERENCE_REASON, REFERENCE_CODE),
            },
            Err(()) => return fail(REFERENCE_REASON, REFERENCE_CODE),
        };

        let client = client_key(&payload, workspace.as_deref());
        let admitted = scheduler
            .reserve_bytes(bytes, expires)
            .and_then(|reservation| {
                scheduler.acquire(
                    capacity_harness,
                    &client,
                    hook_scheduler::lane_index(lane(&event)),
                    reservation,
                    expires,
                )
            });
        let mut permit = match admitted {
            Ok(permit) => permit,
            Err(code) => {
                scheduler.record_harness_rejection(capacity_harness);
                return fail(
                    &capacity_reason(code, Path::new(&self.config.guard_home), &self.home()),
                    code,
                );
            }
        };
        // The policy barrier runs inside the admitted slot: it can hold a
        // library worker for most of the hook's deadline, so a burst must
        // queue for it here, bounded, rather than all at once in the library.
        let Some(prepared) = self.call_by(
            "hook.prepare",
            json!({
                "workspace": workspace,
                "remaining_seconds": remaining(),
            }),
            expires,
        ) else {
            return unavailable();
        };
        if let Some(refused) = prepared.get("fail_safe") {
            return prepare_refusal(&reply_harness, &reply_event, refused)
                .unwrap_or_else(unavailable);
        }
        if let Some(answer) = self.lifecycle(&reply_harness, &event, &payload, expires) {
            permit.release();
            return answer;
        }
        if let Some(answer) = self.cursor_sink(
            &reply_harness,
            &event,
            &payload,
            (
                workspace.as_deref(),
                home_dir.as_deref(),
                guard_home.as_deref(),
            ),
            expires,
        ) {
            permit.release();
            return answer;
        }
        let review = self.call_by(
            "hook.review",
            json!({
                "payload": payload,
                "workspace": workspace,
                "home_dir_effective": home_dir,
                "guard_home_effective": guard_home,
                "remaining_seconds": remaining(),
            }),
            expires,
        );
        // The decision is final: free its slot before the answer is written,
        // so a slow reader never holds review capacity.
        permit.release();
        let Some(review) = review else {
            return unavailable();
        };
        if let Some(answer) = review.get("answer").filter(|answer| answer.is_object()) {
            return answer.clone();
        }
        review
            .get("fail_safe")
            .and_then(refusal)
            .map_or_else(unavailable, |(reason, code)| fail(reason, code))
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_review_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "daemon_edge_hook_policy_tests.rs"]
mod policy_tests;
