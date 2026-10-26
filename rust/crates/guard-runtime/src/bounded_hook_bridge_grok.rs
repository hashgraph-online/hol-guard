//! Native answers for Grok's generated bounded hook client.
//!
//! Grok runs `guard-runtime bounded-hook-bridge <python> -I <script>
//! <config>`. When `<script>` is the client this module was ported from
//! (see [`crate::bounded_hook_bridge_grok_script`]), the bridge does what the
//! client's `main` does: read the hook, ask the daemon, wait for a pending
//! approval and write Grok's answer. A live resident that answers the hook
//! exactly as the daemon would is asked first, and its answer is rendered
//! as the daemon's would be. The resident answers a prompt only for a
//! workspace whose published policy it holds, so the daemon's readiness
//! check runs only for a prompt the resident leaves to the daemon.
//!
//! A hook the bridge cannot read, and a home with no daemon to ask, get the
//! client's own fail-closed answer, and so does every failure once the
//! daemon has been asked. Python runs only when the client's configuration
//! cannot be read.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::bounded_hook_bridge::{read_hook_input, write_stdout, Input, MAX_HOOK_INPUT_BYTES};
use crate::bounded_hook_bridge_grok_render::{
    approval_request_ids, approval_wait_seconds, dump_object, event_labels_are_ascii, event_name,
    failure_stdout, failure_stdout_for, is_observe_event, json_object, pretool_event_conflict,
    quote_component, rewrite_decision, to_native, WAITING_ACTIONS,
};
use crate::bounded_hook_bridge_grok_script::{invocation, read_client_constants, Invocation};
use crate::bounded_hook_bridge_render::member;
use crate::claude_hook_bridge_auth::{private_file_raw, LOOPBACK_HOSTS};
use crate::claude_hook_bridge_http::{LoopbackConnection, MAX_DAEMON_RESPONSE_BYTES};
use crate::claude_hook_bridge_render::py_strip;
use crate::claude_hook_bridge_url::assert_loopback_http_url;
use crate::codex_hook_bridge_direct::grok_direct_answer;
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::hook_env_stamp::{current_environment, dumps, set_member, stamp_hook_input_text, Stamp};
use crate::pyjson::PyVal;

const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 4096;
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;
const STATE_FILE: &str = "daemon-state.json";
const TOKEN_FILE: &str = "daemon-auth-token";
const SETTINGS_FILE: &str = "config.toml";
const HOOK_PATH: &str = "/v1/hooks/grok";
/// Why the resident did not answer a hook the daemon now reviews.
const DIRECT_MISS_HEADER: &str = "X-Guard-Direct-Miss";
const READINESS_PATH: &str = "/v1/hooks/grok/readiness";
const PROMPT_EVENT: &str = "UserPromptSubmit";
const PRETOOL_EVENT: &str = "PreToolUse";
const HOOK_DEADLINE: &str = "daemon hook deadline exhausted";
const POLL_SECONDS: f64 = 1.0;
const POLL_INTERVAL_SECONDS: f64 = 0.2;
const OVERSIZE_REASON: &str =
    "HOL Guard blocked this action because hook input exceeded the safe size limit.";
const CONFLICT_REASON: &str = "HOL Guard blocked this action because hook event labels conflict.";

/// Seconds left before `deadline`, never negative.
fn seconds_left(deadline: Instant) -> f64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_secs_f64()
}

/// `min(cap, now + seconds)`.
fn capped(now: Instant, seconds: f64, cap: Instant) -> Instant {
    Duration::try_from_secs_f64(seconds.max(0.0))
        .ok()
        .and_then(|duration| now.checked_add(duration))
        .map_or(cap, |end| end.min(cap))
}

/// `_read_private_text(path, max_bytes=max)`.
fn read_private(path: &Path, max: u64) -> Option<String> {
    if std::fs::symlink_metadata(path).ok()?.len() > max {
        return None;
    }
    private_file_raw(path, "Guard file").ok()
}

/// The daemon `_daemon_auth` names, with a token urllib sends as is.
#[derive(Debug)]
struct Daemon {
    host: String,
    port: u16,
    token: String,
}

/// What the bridge does with one Grok hook.
#[derive(Debug, PartialEq)]
pub(crate) enum Route {
    /// Write `stdout` and exit with `exit_code`.
    Respond { stdout: String, exit_code: i32 },
}

/// The client's state after `_configure_grok_invocation`.
pub(crate) struct Client {
    pub(crate) guard_home: PathBuf,
    pub(crate) timeout_seconds: f64,
    pub(crate) invocation: Invocation,
    /// `_HOOK_DEADLINE_MONOTONIC`.
    pub(crate) deadline: Instant,
}

impl Client {
    /// `_fail(prefix)`: the client's fail-closed answer.
    fn fail(prefix: &str) -> Route {
        Route::Respond {
            stdout: failure_stdout(prefix),
            exit_code: 0,
        }
    }

    /// `_fail(prefix, reason=reason)`, answered as PreToolUse when the
    /// hook's labels conflict, as `_fail` does.
    fn refuse(prefix: &str, reason: &str) -> Route {
        let conflict = json_object(prefix).is_some_and(|payload| pretool_event_conflict(&payload));
        Route::Respond {
            stdout: failure_stdout_for(if conflict { "{}" } else { prefix }, reason),
            exit_code: 0,
        }
    }

    fn spent(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// `_daemon_auth`.
    fn daemon_auth(&self) -> Option<Daemon> {
        if self.spent() {
            return None;
        }
        let state = read_private(&self.guard_home.join(STATE_FILE), MAX_STATE_BYTES)
            .filter(|_| !self.spent())?;
        let token = read_private(&self.guard_home.join(TOKEN_FILE), MAX_TOKEN_BYTES)
            .filter(|_| !self.spent())?;
        let state = json_object(&state)?;
        let host = member(&state, "host")?.as_str()?;
        if !LOOPBACK_HOSTS.contains(&host) {
            return None;
        }
        let Some(PyVal::Int(digits)) = member(&state, "port") else {
            return None;
        };
        let port = digits.parse::<u16>().ok().filter(|port| *port >= 1)?;
        let token = py_strip(&token);
        let sendable = token
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
        (!token.is_empty() && sendable).then(|| Daemon {
            host: host.to_owned(),
            port,
            token: token.to_owned(),
        })
    }

    /// `_http_json(_loopback_url(host, port, path), token, data=body,
    /// timeout=timeout)`, naming the resident's miss when there was one.
    fn http_json(
        &self,
        daemon: &Daemon,
        path: &str,
        body: Option<&[u8]>,
        timeout: f64,
        miss: Option<DirectMiss>,
    ) -> Option<Vec<(String, PyVal)>> {
        let now = Instant::now();
        let deadline = capped(now, timeout, self.deadline);
        if now >= deadline {
            return None;
        }
        let target = format!("{path}?home={}", quote_component(&self.invocation.home));
        let rendered_host = if daemon.host == "::1" {
            "[::1]"
        } else {
            daemon.host.as_str()
        };
        assert_loopback_http_url(&format!("http://{rendered_host}:{}{target}", daemon.port))
            .ok()?;
        let mut headers = vec![("X-Guard-Token", daemon.token.as_str())];
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        if let Some(miss) = miss {
            headers.push((DIRECT_MISS_HEADER, miss.code()));
        }
        headers.push(("Connection", "close"));
        let mut connection = LoopbackConnection::new(&daemon.host, daemon.port);
        let head = match body {
            Some(body) => connection.post(&target, &headers, body, deadline),
            None => connection.get(&target, &headers, deadline),
        }
        .ok()?;
        if head.status != 200 {
            return None;
        }
        let raw = connection
            .read_body(&head, deadline, HOOK_DEADLINE, HOOK_DEADLINE)
            .ok()?;
        if Instant::now() >= deadline || raw.len() > MAX_DAEMON_RESPONSE_BYTES {
            return None;
        }
        let text = py_strip(std::str::from_utf8(&raw).ok()?);
        if text.starts_with('\u{feff}') {
            return None;
        }
        json_object(text)
    }

    /// `_prepare_grok_prompt`: wait for the workspace to be ready, then stamp
    /// the time left. `None` fails the prompt closed.
    fn prepare_prompt(
        &self,
        daemon: &Daemon,
        payload: &mut Vec<(String, PyVal)>,
        deadline: Instant,
    ) -> Option<()> {
        let left = seconds_left(deadline);
        if left <= 0.0 {
            return None;
        }
        let workspace = match member(payload, "cwd") {
            Some(PyVal::Str(workspace)) if !py_strip(workspace).is_empty() => {
                Some(workspace.clone())
            }
            _ => None,
        };
        if let Some(workspace) = workspace {
            let mut request = String::new();
            let body = PyVal::Dict(vec![("cwd".to_owned(), PyVal::Str(workspace))]);
            dumps(&body, true, false, &mut request);
            let ready =
                self.http_json(daemon, READINESS_PATH, Some(request.as_bytes()), left, None)?;
            let is =
                |key: &str, expected: bool| member(&ready, key) == Some(&PyVal::Bool(expected));
            if !is("ready", true) {
                return None;
            }
            if !is("native_required", false)
                && (!is("workspace_acknowledged", true) || !is("worker_ready", true))
            {
                return None;
            }
        }
        stamp_remaining(payload, deadline)
    }

    /// The resident's answer for a prompt stamped with the time left, asked
    /// before any readiness check. The resident answers only from the
    /// published policy it holds for the prompt's workspace with a current
    /// acknowledgement, which is the state the readiness check waits for.
    fn prompt_direct_answer(
        &self,
        payload: &[(String, PyVal)],
        deadline: Instant,
    ) -> Result<String, DirectMiss> {
        let mut stamped = payload.to_vec();
        stamp_remaining(&mut stamped, deadline).ok_or(DirectMiss::Late)?;
        self.direct_answer(PROMPT_EVENT, &dump_object(&stamped), seconds_left(deadline))
    }

    /// `_apply_grok_wait`: hold a PreToolUse review open until every
    /// approval it names is resolved, then answer with the resolution.
    fn apply_wait(
        &self,
        event: &str,
        native: Vec<(String, PyVal)>,
        exit_code: i32,
    ) -> (Vec<(String, PyVal)>, i32) {
        if event != PRETOOL_EVENT {
            return (native, exit_code);
        }
        let waiting = matches!(
            member(&native, "policy_action"),
            Some(PyVal::Str(action)) if WAITING_ACTIONS.contains(&action.as_str())
        );
        let request_ids = approval_request_ids(&native);
        if !waiting || request_ids.is_empty() {
            return (native, exit_code);
        }
        let Some(daemon) = self.daemon_auth() else {
            return (native, exit_code);
        };
        let settings = read_private(&self.guard_home.join(SETTINGS_FILE), MAX_SETTINGS_BYTES);
        let wait = approval_wait_seconds(settings.as_deref(), self.timeout_seconds);
        if wait <= 0.0 {
            return (native, exit_code);
        }
        let deadline = capped(Instant::now(), wait, self.deadline);
        let mut resolved: Vec<(String, String)> = Vec::new();
        while Instant::now() < deadline && resolved.len() < request_ids.len() {
            for request_id in &request_ids {
                if resolved.iter().any(|(id, _)| id == request_id) {
                    continue;
                }
                let left = seconds_left(deadline);
                if left <= 0.0 {
                    break;
                }
                let path = format!("/v1/requests/{}", quote_component(request_id));
                let Some(status) =
                    self.http_json(&daemon, &path, None, left.min(POLL_SECONDS), None)
                else {
                    continue;
                };
                if let Some(PyVal::Str(action)) = member(&status, "resolution_action") {
                    let action = py_strip(action);
                    if !action.is_empty() {
                        resolved.push((request_id.clone(), action.to_lowercase()));
                    }
                }
            }
            if resolved.len() < request_ids.len() {
                let left = seconds_left(deadline);
                if left <= 0.0 {
                    break;
                }
                std::thread::sleep(Duration::from_secs_f64(left.min(POLL_INTERVAL_SECONDS)));
            }
        }
        // A repeated id is never counted twice, so the client never
        // completes such a wait either.
        if resolved.len() != request_ids.len() {
            return (native, exit_code);
        }
        let allowed = resolved.iter().all(|(_, action)| action == "allow");
        let rewritten = rewrite_decision(&native, allowed);
        (rewritten, if allowed { 0 } else { exit_code })
    }

    /// The resident's answer for a hook it reviews as the daemon would, asked
    /// within half the daemon's timeout so a slow resident leaves the daemon
    /// time to answer.
    fn direct_answer(&self, event: &str, text: &str, timeout: f64) -> Result<String, DirectMiss> {
        let deadline = capped(Instant::now(), timeout * 0.5, self.deadline);
        grok_direct_answer(
            &self.guard_home,
            &self.invocation.home,
            event,
            text,
            deadline,
        )
    }

    /// `main` after the hook was read: the client's answer.
    pub(crate) fn route(&self, raw: &[u8]) -> Route {
        if raw.len() > MAX_HOOK_INPUT_BYTES {
            // `_HookInputError.prefix`: the first bytes, decoded leniently.
            let prefix = String::from_utf8_lossy(&raw[..MAX_HOOK_INPUT_BYTES]);
            return Self::refuse(&prefix, OVERSIZE_REASON);
        }
        let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
        let Ok(prefix) = std::str::from_utf8(body) else {
            // Undecodable input is `_fail("{}")`.
            return Self::fail("{}");
        };
        let Some(original) = json_object(prefix) else {
            return Self::fail(prefix);
        };
        if pretool_event_conflict(&original) {
            return Self::refuse(prefix, CONFLICT_REASON);
        }
        // Labels outside ASCII are never Grok's own, and this bridge cannot
        // read them as Python's `str.strip` would: they are refused as a
        // PreToolUse.
        if !event_labels_are_ascii(&original) {
            return Self::fail("{}");
        }
        let Stamp::Text(mut text) = stamp_hook_input_text(prefix, &current_environment()) else {
            return Self::fail(prefix);
        };
        let Some(mut payload) = json_object(&text) else {
            return Self::fail(prefix);
        };
        // `_grok_invocation_payload`.
        if let Some(workspace) = &self.invocation.workspace {
            let missing = match member(&payload, "cwd") {
                None | Some(PyVal::Null) => true,
                Some(PyVal::Str(cwd)) => py_strip(cwd).is_empty(),
                Some(_) => false,
            };
            if missing {
                set_member(&mut payload, "cwd", PyVal::Str(workspace.clone()));
                text = dump_object(&payload);
            }
        }
        let event = event_name(&payload);
        if self.spent() {
            return Self::fail(prefix);
        }
        let Some(daemon) = self.daemon_auth() else {
            return Self::fail(prefix);
        };
        let cap = if event == PROMPT_EVENT { 10.0 } else { 5.0 };
        let mut timeout = (self.timeout_seconds * 0.5)
            .min(cap)
            .min(seconds_left(self.deadline));
        if is_observe_event(&event) {
            timeout = timeout.min(1.0);
        }
        if timeout <= 0.0 {
            return Self::fail(prefix);
        }
        let resident = if event == PROMPT_EVENT {
            let deadline = capped(Instant::now(), timeout, self.deadline);
            let resident = self.prompt_direct_answer(&payload, deadline);
            if resident.is_err() {
                if self
                    .prepare_prompt(&daemon, &mut payload, deadline)
                    .is_none()
                {
                    return Self::fail(prefix);
                }
                text = dump_object(&payload);
                timeout = seconds_left(deadline);
                if timeout <= 0.0 {
                    return Self::fail(prefix);
                }
            }
            resident
        } else {
            self.direct_answer(&event, &text, timeout)
        };
        let answer = match resident {
            Ok(answer) => json_object(&answer),
            Err(miss) => {
                timeout = timeout.min(seconds_left(self.deadline));
                if timeout <= 0.0 {
                    return Self::fail(prefix);
                }
                self.http_json(
                    &daemon,
                    HOOK_PATH,
                    Some(text.as_bytes()),
                    timeout,
                    Some(miss),
                )
            }
        };
        let Some((native, exit_code)) = answer.and_then(|response| to_native(&response, &event))
        else {
            return Self::fail(prefix);
        };
        let (native, exit_code) = self.apply_wait(&event, native, exit_code);
        if self.spent() {
            return Self::fail(prefix);
        }
        let mut stdout = dump_object(&native);
        stdout.push('\n');
        Route::Respond { stdout, exit_code }
    }
}

/// How long a hook whose client this bridge cannot read waits for its input.
const UNREADABLE_CLIENT_INPUT: Duration = Duration::from_secs(5);

/// `_fail("{}")`: the answer when the hook could not be read at all.
fn fail_closed() -> i32 {
    write_stdout(&failure_stdout("{}"));
    0
}

/// The failure answer for a hook whose client this bridge cannot read,
/// rendered for the hook's own event so an observer stays non-blocking.
/// Input `route` would answer as a PreToolUse still fails as one.
fn client_unreadable_stdout(raw: &[u8]) -> String {
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body)
        .ok()
        .filter(|_| raw.len() <= MAX_HOOK_INPUT_BYTES)
        .filter(|text| {
            json_object(text).is_some_and(|payload| {
                !pretool_event_conflict(&payload) && event_labels_are_ascii(&payload)
            })
        });
    failure_stdout(text.unwrap_or("{}"))
}

/// Answer one Grok hook. `python_argv` is `[python, "-I", script, config]`.
pub(crate) fn run(python_argv: &[String], started: Instant) -> i32 {
    let client = read_client_constants(Path::new(&python_argv[2])).and_then(|constants| {
        let invocation = invocation(&python_argv[3], &constants.guard_home)?;
        let budget = Duration::try_from_secs_f64(constants.timeout_seconds).ok()?;
        Some(Client {
            guard_home: PathBuf::from(&constants.guard_home),
            timeout_seconds: constants.timeout_seconds,
            invocation,
            deadline: started.checked_add(budget)?,
        })
    });
    let Some(client) = client else {
        // No install writes a client this bridge cannot read, so the hook
        // fails closed rather than running Python.
        let Input::Read(raw) = read_hook_input(started + UNREADABLE_CLIENT_INPUT) else {
            return fail_closed();
        };
        write_stdout(&client_unreadable_stdout(&raw));
        return 0;
    };
    let Input::Read(raw) = read_hook_input(client.deadline) else {
        return fail_closed();
    };
    let Route::Respond { stdout, exit_code } = client.route(&raw);
    write_stdout(&stdout);
    exit_code
}

/// Stamp the time left as the daemon receives it. `None` once the deadline
/// has passed.
fn stamp_remaining(payload: &mut Vec<(String, PyVal)>, deadline: Instant) -> Option<()> {
    let left = seconds_left(deadline);
    if left <= 0.0 {
        return None;
    }
    payload.retain(|(key, _)| key != "guard_remaining_seconds");
    // `max(1, int(remaining * 1000))`; the cast truncates like `int`.
    let millis = ((left * 1000.0) as u64).max(1);
    set_member(
        payload,
        "guard_remaining_ms",
        PyVal::Int(millis.to_string()),
    );
    Some(())
}

#[cfg(all(test, unix))]
#[path = "bounded_hook_bridge_grok_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bounded_hook_bridge_grok_client_tests.rs"]
mod client_tests;
