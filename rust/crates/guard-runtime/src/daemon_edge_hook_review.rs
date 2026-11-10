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

use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::http::{query_value, Request};
use super::super::library;
use super::{authorize_token, hook_scheduler, json_response, refusals, NativeReads, ReadConfig};
use crate::claude_hook_bridge_render::py_strip;
use admission::{
    client_key, exec_workdir, expanduser, expires_at, lane, normpath, payload_reference,
    reply_event, runtime_event, take_hint, truthy, Directories, Rejection,
    MAX_PAYLOAD_REFERENCE_BYTES,
};

#[path = "daemon_edge_hook_admission.rs"]
mod admission;

/// The daemon's fixed hook replies, declared once for every harness.
const ENVELOPES: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/contracts/hook-fail-closed-envelopes.v1.json"
);
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
const LATE_ANSWER_GRACE: Duration = Duration::from_secs(5);

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

/// The request body as the daemon's handler reads it, or `None` for a body it
/// reads some other way.
fn payload(request: &Request<'_>, body: &[u8]) -> Option<Result<Map<String, Value>, ()>> {
    if body.is_empty() {
        return Some(Ok(Map::new()));
    }
    if !request
        .single_header("Content-Type")?
        .contains("application/json")
    {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    // A body serde rejects may still be one `json.loads` reads (`NaN`, a lone
    // surrogate escape); only a body neither reads is refused here.
    Some(match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(payload)) => Ok(payload),
        Ok(_) => Ok(Map::new()),
        Err(_) => Err(()),
    })
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
        let remaining = (expires - hook_scheduler::shared().now()).max(0.0);
        self.call_within(
            name,
            extra,
            Duration::from_secs_f64(remaining) + LATE_ANSWER_GRACE,
        )
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

    /// Settles the directories a request named against this daemon's homes.
    fn settle(&self, candidates: &[(&str, Option<String>, Option<&str>)]) -> Directories {
        Directories::settle(&self.config.guard_home, &self.home(), candidates)
    }

    /// `POST /v1/hooks/<harness>/readiness`: prepares the workspace's policy
    /// before a host's timed hook starts.
    fn readiness(&self, payload: &Map<String, Value>) -> (u16, Value, bool) {
        let not_ready = (
            503,
            json!({ "ready": false, "reason_code": "native_policy_not_ready" }),
            true,
        );
        let invalid = |rejection: &Rejection| {
            (
                400,
                json!({
                    "ready": false,
                    "reason_code": format!("invalid_{}", rejection.parameter.replace('-', "_")),
                }),
                true,
            )
        };
        let guard_home = self.settle(&[("guard-home", self.param("guard-home"), None)]);
        if let Err(rejection) = guard_home.require("guard-home") {
            let _ = self.call("hook.ready", json!({ "rejection": rejection.to_value() }));
            return invalid(&rejection);
        }
        let candidate = self.raw_param("workspace").or_else(|| {
            let named = payload.get("workspace");
            if truthy(named) {
                named
            } else {
                payload.get("cwd")
            }
            .and_then(Value::as_str)
            .map(str::to_owned)
        });
        let directories = self.settle(&[("workspace", candidate, Some("hook-workspace"))]);
        let (workspace, rejection) = match directories.require("workspace") {
            Ok(workspace) => (workspace, None),
            Err(rejection) => (None, Some(rejection)),
        };
        let Some(ready) = self.call(
            "hook.ready",
            json!({
                "workspace": workspace,
                "late_rejection": rejection.as_ref().map(Rejection::to_value),
            }),
        ) else {
            return not_ready;
        };
        if ready.get("unmanaged") == Some(&Value::Bool(true)) {
            return (
                200,
                json!({
                    "ready": true,
                    "native_required": false,
                    "workspace_acknowledged": false,
                    "worker_ready": true,
                }),
                true,
            );
        }
        if let Some(rejection) = rejection {
            return invalid(&rejection);
        }
        if workspace.is_none() {
            return (
                400,
                json!({ "ready": false, "reason_code": "workspace_required" }),
                true,
            );
        }
        if ready.get("prepared") != Some(&Value::Bool(true)) {
            return not_ready;
        }
        (
            200,
            json!({
                "ready": true,
                "native_required": true,
                "native_route": "native_resident",
                "workspace_acknowledged": true,
                "worker_ready": true,
            }),
            true,
        )
    }

    /// `POST /v1/hooks/<harness>`: admits the hook under its deadline and the
    /// scheduler's capacity, and answers the worker's review or a fail-safe.
    fn runtime(&self, mut payload: Map<String, Value>, direct_miss: Option<&str>) -> Value {
        let scheduler = hook_scheduler::shared();
        let event = runtime_event(&payload);
        let (hint, missing) = take_hint(&mut payload);
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

        // Oh My Pi has no bridge to ask the resident first, so its direct
        // lane is asked here, unless the request claims another Guard home:
        // the lane answers out of the home it bound.
        let guard_home_query = self.param("guard-home");
        let try_direct = guard_home_query.as_deref().is_none_or(|claimed| {
            let user = std::env::var("HOME").unwrap_or_else(|_| self.home());
            normpath(&expanduser(claimed, &user)) == normpath(&self.config.guard_home)
        });
        let Some(begin) = self.call_by(
            "hook.begin",
            json!({
                "count_harness": runtime_harness.as_deref().unwrap_or(self.harness),
                "direct_miss": direct_miss,
                "payload": payload,
                "remaining_seconds": remaining(),
                "try_direct": try_direct,
                "capacity_harness": reply_harness,
            }),
            expires,
        ) else {
            return unavailable();
        };
        if let Some(answer) = begin.get("answer").filter(|answer| answer.is_object()) {
            return answer.clone();
        }
        let capacity_harness = begin
            .get("capacity_harness")
            .and_then(Value::as_str)
            .unwrap_or("other")
            .to_owned();

        let (workdir_named, workdir) = exec_workdir(&payload);
        let directories = self.settle(&[
            ("home", self.param("home"), None),
            ("guard-home", guard_home_query, None),
            ("exec-workdir", workdir, Some("exec-workdir")),
            (
                "workspace-payload",
                payload
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                Some("hook-workspace"),
            ),
            (
                "workspace-query",
                self.raw_param("workspace"),
                Some("hook-workspace"),
            ),
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
        let (home_dir, guard_home, workspace, rejection) = match settled {
            Ok((home_dir, guard_home, workspace)) => (home_dir, guard_home, workspace, None),
            Err(rejection) => (
                Some(self.home()),
                Some(self.config.guard_home.clone()),
                None,
                Some(rejection.to_value()),
            ),
        };

        let Some(prepared) = self.call_by(
            "hook.prepare",
            json!({
                "payload": payload,
                "workspace": workspace,
                "remaining_seconds": remaining(),
                "rejection": rejection,
            }),
            expires,
        ) else {
            return unavailable();
        };
        if let Some(answer) = prepared.get("answer").filter(|answer| answer.is_object()) {
            return answer.clone();
        }
        if let Some(refused) = prepared.get("fail_safe") {
            return refusal(refused).map_or_else(unavailable, |(reason, code)| fail(reason, code));
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
                    &capacity_harness,
                    &client,
                    hook_scheduler::lane_index(lane(&event)),
                    reservation,
                    expires,
                )
            });
        let mut permit = match admitted {
            Ok(permit) => permit,
            Err(code) => {
                scheduler.record_harness_rejection(&capacity_harness);
                return fail(capacity_reason(code), code);
            }
        };
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

/// The reason and code a library step's `fail_safe` carries.
fn refusal(refused: &Value) -> Option<(&str, &str)> {
    Some((
        refused.get("reason")?.as_str()?,
        refused.get("reason_code")?.as_str()?,
    ))
}

/// The message a capacity refusal carries.
fn capacity_reason(code: &str) -> &'static str {
    if code == hook_scheduler::DEADLINE_EXHAUSTED {
        "HOL Guard could not complete local review within the hook deadline. Retry this action."
    } else {
        "HOL Guard is safely queueing the maximum local review workload. Retry this action."
    }
}

/// The harness's answer when the hook worker could not review the hook:
/// `fail_closed_response` with `native_hook_worker_unavailable`. Tool,
/// permission and prompt events get a constant deny in the harness envelope;
/// other events a constant payload that carries no verdict.
fn fail_safe(harness: &str, event: &str, reason: &str, code: &str) -> Value {
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let kind = event_kind(&contract, event);
    let reason = if kind == "prompt" {
        contract["defaults"]["prompt_reason"]
            .as_str()
            .unwrap_or(reason)
    } else {
        reason
    };
    let table = &contract["envelopes"][kind.as_str()];
    let harness = harness.trim().to_lowercase().replace('_', "-");
    let template = table
        .get(harness.as_str())
        .or_else(|| table.get("*"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    fill(
        template,
        &[
            ("$reason", reason),
            ("$reason_code", code),
            ("$event_name", event),
        ],
    )
}

/// `_event_kind`: the envelope family an event name belongs to.
fn event_kind(contract: &Value, event: &str) -> String {
    let compact: String = event
        .trim()
        .to_lowercase()
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect();
    if let Some(kind) = contract["events"]
        .get(compact.as_str())
        .and_then(Value::as_str)
    {
        return kind.to_owned();
    }
    contract["event_prefixes"]
        .as_object()
        .into_iter()
        .flatten()
        .find(|(prefix, _)| compact.starts_with(prefix.as_str()))
        .and_then(|(_, kind)| kind.as_str())
        .unwrap_or("lifecycle")
        .to_owned()
}

/// The envelope with its whole-string placeholders filled.
fn fill(template: Value, values: &[(&str, &str)]) -> Value {
    match template {
        Value::String(text) => values
            .iter()
            .find(|(placeholder, _)| *placeholder == text)
            .map_or(Value::String(text), |(_, value)| json!(value)),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, fill(value, values)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| fill(item, values)).collect())
        }
        other => other,
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_review_tests.rs"]
mod tests;
