//! Native Claude Code hook bridge, started by the installed hook command or
//! by the legacy launcher `adapters/claude_daemon_hook_bridge.py`. Claude Code runs this once per
//! hook. It forwards the hook to the authenticated loopback Guard daemon and
//! recovers a dead daemon once, waiting for it to come back up, all inside the harness's hook deadline. Every
//! failure ends in a hook response that denies or degrades the action, unless
//! the signed posture proves the harness is in Watch, where a live daemon would
//! only have recorded the call; nothing here decides a verdict itself, and no
//! Python hook command runs in its place.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_harness::{attributed_query, current_cursor_run};
use crate::claude_hook_bridge_http::{remaining, MINIMUM_OPERATION};
use crate::claude_hook_bridge_recovery::launcher_recovery;
use crate::claude_hook_bridge_render::{
    control_plane_failure, degraded, event_name, hook_decision, limit_denied, py_strip,
    should_suppress_output, DEFAULT_EVENT,
};
use crate::claude_hook_bridge_transport::{
    authenticated_claude_hook_response, daemon_proves_identity, json_failure, BridgeError,
};
use crate::claude_hook_bridge_url::{
    assert_loopback_http_url, endpoint_query, state_names_loopback_port, state_path_for_query,
};
use crate::codex_hook_bridge_direct::{direct_answer_reporting, CLAUDE_CODE};
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::hook_bridge_daemon_start::{await_daemon, Attempt, MINIMUM_REQUEST};
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};
use crate::hook_process_spawn::{isolated_hook_environment, run_isolated_hook_process};
use crate::hook_watch_posture::harness_in_watch;

/// argv marker that selects the bridge, mirroring the Python module path.
pub(crate) const BRIDGE_MARKER: &str = "HOL_GUARD_CLAUDE_DAEMON_HOOK";
pub(crate) const BRIDGE_FEATURE: &str = "claude-hook-bridge-v1";

const HOOK_DEADLINE: Duration = Duration::from_secs(8);
const DAEMON_IO_TIMEOUT: Duration = Duration::from_millis(5_500);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(3);
const MINIMUM_RECOVERY: Duration = Duration::from_millis(1_500);
const MAX_HOOK_INPUT_BYTES: usize = 1_000_000;
const CONTROL_PLANE_FAILURE: &str = "authenticated-control-plane-failure";
const INVALID_CONFIG: &str = "claude hook bridge configuration is invalid";

/// The launcher's JSON config. Python accepts any value and calls `str()`
/// on it; the launcher only ever writes strings, so anything else is
/// refused as an invalid configuration.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BridgeConfig {
    pub(crate) state_path: String,
    pub(crate) fallback_daemon_url: String,
    pub(crate) query: String,
    pub(crate) recovery_command: Vec<String>,
}

fn string_list(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

pub(crate) fn parse_config(text: &str) -> Option<BridgeConfig> {
    let payload: serde_json::Value = serde_json::from_str(text).ok()?;
    let payload = payload.as_object()?;
    let text_field = |key: &str| payload.get(key)?.as_str().map(str::to_owned);
    // Launchers still write a fallback command; the bridge no longer runs it,
    // but a config without one is not one a launcher wrote.
    if string_list(payload.get("fallback_command"))?.is_empty() {
        return None;
    }
    let state_path = text_field("state_path")?;
    let query = text_field("query")?;
    let recovery_command = match (
        payload.get("recovery_command"),
        payload.get("recovery_launcher"),
    ) {
        (None, None) => Vec::new(),
        (None, Some(launcher)) => launcher_recovery(&state_path, &query, launcher.as_object()?)?,
        (value, None) => string_list(value)?,
        (Some(_), Some(_)) => return None,
    };
    Some(BridgeConfig {
        state_path,
        fallback_daemon_url: text_field("fallback_daemon_url")?,
        query,
        recovery_command,
    })
}

/// `reason_code` of the daemon's fail-closed prompt envelope
/// (`hook-fail-closed-envelopes.v1.json`).
const PROMPT_OUTAGE_CODE: &str = "native_prompt_unavailable";
const PROMPT_OUTAGE_SETTLED: &str = "Guard daemon could not check the prompt in time";

/// Whether `body` is the daemon's "could not check this prompt" block for a
/// `UserPromptSubmit` hook, as opposed to a verdict on the prompt.
fn is_prompt_outage(body: &str, data: &str) -> bool {
    if event_name(data).name != "UserPromptSubmit" {
        return false;
    }
    let Ok(serde_json::Value::Object(reply)) = serde_json::from_str(body) else {
        return false;
    };
    reply.get("decision").and_then(serde_json::Value::as_str) == Some("block")
        && reply.get("reason_code").and_then(serde_json::Value::as_str) == Some(PROMPT_OUTAGE_CODE)
}

fn capped(deadline: Instant, cap: Duration) -> Duration {
    remaining(deadline).min(cap)
}

/// `Path.home()`: `$HOME` without trailing slashes, else the passwd entry.
#[cfg(unix)]
pub(crate) fn home_directory() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        let text = home.to_string_lossy();
        let trimmed = text.trim_end_matches('/');
        return Some(PathBuf::from(if trimmed.is_empty() {
            "/"
        } else {
            trimmed
        }));
    }
    Some(
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map_or_else(|| PathBuf::from("/"), |user| user.dir),
    )
}

/// `Path.home()` on Windows (`ntpath.expanduser`): `%USERPROFILE%`, else
/// `%HOMEDRIVE%` joined with `%HOMEPATH%`. `HOME` is ignored, as CPython
/// ignores it there. With neither set CPython raises; the bridge instead
/// declines to start the child process.
#[cfg(windows)]
pub(crate) fn home_directory() -> Option<PathBuf> {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Some(if profile.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(profile)
        });
    }
    let home_path = std::env::var_os("HOMEPATH")?;
    let drive = std::env::var_os("HOMEDRIVE").unwrap_or_default();
    Some(PathBuf::from(drive).join(home_path))
}

/// `isolated_hook_environment()` including the signed Desktop proxy
/// selectors (`desktop_hook_proxy_context`).
fn hook_environment() -> BTreeMap<String, String> {
    let source: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let mut environment = isolated_hook_environment(&source);
    if source.get("HOL_GUARD_DESKTOP").map(String::as_str) == Some("1") {
        if let Some(proxy) = source.get("HOL_GUARD_DESKTOP_HOOK_PROXY") {
            if !proxy.is_empty() && !proxy.contains('\0') && proxy.starts_with('/') {
                environment.insert("HOL_GUARD_DESKTOP".to_owned(), "1".to_owned());
                environment.insert("HOL_GUARD_DESKTOP_HOOK_PROXY".to_owned(), proxy.clone());
            }
        }
    }
    environment
}

struct Bridge<'a> {
    config: &'a BridgeConfig,
    /// The configured query, attributed to the harness running this hook.
    query: String,
    /// The runtime harness key of that harness.
    harness: &'static str,
    data: String,
    deadline: Instant,
}

impl Bridge<'_> {
    /// One authenticated daemon exchange and its hook-JSON validation,
    /// classified exactly as the Python `try` block classifies it. `miss`
    /// names why the resident did not answer. `Ok(None)` is a reply that is
    /// not a decision.
    fn exchange(
        &self,
        state_path: &Path,
        deadline: Instant,
        miss: DirectMiss,
    ) -> Result<Option<String>, BridgeError> {
        if !state_names_loopback_port(state_path) {
            let fallback = format!("{}/", self.config.fallback_daemon_url.trim_end_matches('/'));
            assert_loopback_http_url(&fallback).map_err(BridgeError::Value)?;
        }
        let timeout = capped(deadline, DAEMON_IO_TIMEOUT);
        if timeout < MINIMUM_OPERATION {
            return Err(BridgeError::Transport(
                "Guard daemon hook request exhausted its absolute deadline".to_owned(),
            ));
        }
        let response =
            authenticated_claude_hook_response(state_path, &self.query, &self.data, timeout, miss)?;
        hook_decision(&response, &self.data).map_err(json_failure)
    }

    /// The response a live resident answered for a passed-through `PreToolUse`,
    /// a reviewed `PostToolUse`, a `UserPromptSubmit` hook without Guard's
    /// notice or a `PermissionRequest`, checked as a daemon response is; the
    /// miss takes the daemon path. `Ok(None)` is a reply that is not a
    /// decision.
    fn direct_response(&self, state_path: &Path) -> Result<Option<String>, DirectMiss> {
        let guard_home = state_path.parent().ok_or(DirectMiss::NoState)?;
        let event = event_name(&self.data);
        let text = direct_answer_reporting(
            CLAUDE_CODE,
            guard_home,
            &self.query,
            &event.name,
            &self.data,
            self.deadline,
        )?;
        hook_decision(&text, &self.data).map_err(|_| DirectMiss::Unanswered)
    }

    fn respond(&self, state_path: &Path) -> Option<String> {
        let (answered, miss, malformed) = match self.direct_response(state_path) {
            Ok(reply) => (
                Ok(reply),
                DirectMiss::Unanswered,
                "resident returned malformed hook JSON",
            ),
            Err(miss) => (
                self.exchange(state_path, self.deadline, miss),
                miss,
                "daemon returned malformed hook JSON",
            ),
        };
        let error = match answered {
            Ok(reply) => {
                // A reply that is not a decision answers nothing, so it takes
                // the same Watch check as a daemon that never replied.
                let body = match reply {
                    Some(body) => self.settle_prompt_outage(body, state_path),
                    None => self.unanswered(degraded(malformed, &self.data), state_path),
                };
                if should_suppress_output(&self.data, &body) {
                    return None;
                }
                if py_strip(&body).is_empty() {
                    return Some("{}".to_owned());
                }
                return Some(body);
            }
            Err(error) => error,
        };
        let reason = error.reason();
        let kind = error.failure_kind();
        Some(if kind == CONTROL_PLANE_FAILURE {
            self.unanswered(control_plane_failure(&reason, &self.data), state_path)
        } else if error.is_recoverable() {
            self.recover_or_degrade(reason, state_path, kind, miss)
        } else {
            self.unanswered(degraded(&reason, &self.data), state_path)
        })
    }

    /// A daemon that ran out of time on a prompt answers with its outage
    /// block ("could not check this prompt"), most often on the first hook
    /// after an idle spell, when the daemon is slow to warm up and the bridge
    /// has already spent most of the hook deadline. That answer is not a
    /// verdict on the prompt, so the bridge asks again: the resident first,
    /// whose lane is usually back by now, then the daemon if time is left.
    /// When neither can answer, the prompt gets the same response as a
    /// daemon that never replied: it continues, with the local-secrets
    /// notice where the prompt asks for secrets. Every tool call the prompt
    /// leads to is still reviewed. Any other block is returned unchanged.
    fn settle_prompt_outage(&self, body: String, state_path: &Path) -> String {
        if !is_prompt_outage(&body, &self.data) {
            return body;
        }
        let miss = match self.direct_response(state_path) {
            Ok(Some(reply)) if !is_prompt_outage(&reply, &self.data) => return reply,
            Ok(_) => DirectMiss::Unanswered,
            Err(miss) => miss,
        };
        if remaining(self.deadline) >= MINIMUM_REQUEST {
            if let Ok(Some(reply)) = self.exchange(state_path, self.deadline, miss) {
                if !is_prompt_outage(&reply, &self.data) {
                    return reply;
                }
            }
        }
        degraded(PROMPT_OUTAGE_SETTLED, &self.data)
    }

    /// The answer for a hook no daemon answered: `failure`, which denies a
    /// tool call, unless the signed posture proves this harness is in Watch.
    /// A live daemon only records a Watch harness's calls, so a dead one
    /// leaves the call to the harness's own permission flow.
    fn unanswered(&self, failure: String, state_path: &Path) -> String {
        let event = event_name(&self.data);
        let denies = event.name == DEFAULT_EVENT || event.is_permission();
        match state_path.parent() {
            Some(guard_home) if denies && harness_in_watch(guard_home, self.harness) => {
                "{}".to_owned()
            }
            _ => failure,
        }
    }

    /// Restarts a dead daemon once and retries the hook; the action is
    /// degraded when that does not produce an answer in time.
    fn recover_or_degrade(
        &self,
        mut reason: String,
        state_path: &Path,
        kind: &str,
        miss: DirectMiss,
    ) -> String {
        let window = capped(self.deadline, RECOVERY_TIMEOUT);
        if !self.config.recovery_command.is_empty()
            && window >= MINIMUM_RECOVERY
            && self.run_recovery(self.deadline, kind)
        {
            // The recovery command only schedules the daemon start: wait for
            // a daemon that proves its identity before sending the hook again.
            // A probe never eats the time the hook itself needs.
            let probe_end = self
                .deadline
                .checked_sub(MINIMUM_REQUEST)
                .unwrap_or(self.deadline);
            let started = await_daemon(self.deadline, || {
                let timeout = capped(probe_end, DAEMON_IO_TIMEOUT);
                match daemon_proves_identity(state_path, &self.data, timeout) {
                    Err(error) if error.is_recoverable() => Attempt::NotUp,
                    _ => Attempt::Settled(()),
                }
            });
            if started.is_none() {
                return self.unanswered(
                    degraded(
                        &format!("{reason}; daemon recovery retry failed: the restarted daemon did not answer in time"),
                        &self.data,
                    ),
                    state_path,
                );
            }
            let malformed = format!("{reason}; recovered daemon returned malformed hook JSON");
            match self.exchange(state_path, self.deadline, miss) {
                Ok(Some(body)) => return self.settle_prompt_outage(body, state_path),
                Ok(None) => return self.unanswered(degraded(&malformed, &self.data), state_path),
                Err(error) => reason = format!("{reason}; daemon recovery retry failed: {error}"),
            }
        }
        self.unanswered(degraded(&reason, &self.data), state_path)
    }

    fn run_recovery(&self, recovery_deadline: Instant, kind: &str) -> bool {
        let timeout = capped(recovery_deadline, RECOVERY_TIMEOUT);
        if timeout < MINIMUM_OPERATION {
            return false;
        }
        let Some(home) = home_directory() else {
            return false;
        };
        let mut environment = hook_environment();
        environment.insert("HOL_GUARD_HOOK_FAILURE_KIND".to_owned(), kind.to_owned());
        let result = run_isolated_hook_process(
            &self.config.recovery_command,
            "",
            &home,
            &environment,
            Some(timeout.as_secs_f64()),
            None,
            None,
            None,
        );
        result.returncode == Some(0) && !result.timed_out && !result.output_limit_exceeded
    }
}

/// `read_stdin_text(limit)`: at most `limit + 1` bytes, UTF-8 with an
/// optional BOM, invalid sequences replaced.
fn read_hook_input(input: &mut impl Read) -> (String, bool) {
    let mut raw = Vec::new();
    let limit = MAX_HOOK_INPUT_BYTES as u64 + 1;
    // A read error ends the input, as a closed pipe would.
    let _ = input.take(limit).read_to_end(&mut raw);
    let oversized = raw.len() > MAX_HOOK_INPUT_BYTES;
    let body = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&raw);
    (String::from_utf8_lossy(body).into_owned(), oversized)
}

/// The hook response for one Claude hook invocation, or `None` when the
/// bridge stays silent.
pub(crate) fn hook_response(config_text: &str, input: &mut impl Read) -> Option<String> {
    let deadline = Instant::now() + HOOK_DEADLINE;
    let (body, oversized) = read_hook_input(input);
    if oversized {
        return Some(limit_denied("hook input", &event_name(&body)));
    }
    let stripped = match py_strip(&body) {
        "" => "{}",
        text => text,
    };
    let data = match stamp_hook_input_text(stripped, &current_environment()) {
        Stamp::Text(text) => text,
        // CPython would crash here; refuse the action instead.
        Stamp::Unrepresentable => {
            return Some(degraded("hook input could not be stamped", stripped));
        }
    };
    let Some(config) = parse_config(config_text) else {
        return Some(degraded(INVALID_CONFIG, &data));
    };
    let cursor = current_cursor_run();
    let bridge = Bridge {
        config: &config,
        query: attributed_query(&endpoint_query(&config.query), cursor.as_ref()),
        harness: if cursor.is_some() {
            "cursor"
        } else {
            "claude-code"
        },
        data,
        deadline,
    };
    match state_path_for_query(&config.state_path, &config.query) {
        Ok(state_path) => bridge.respond(&state_path),
        // A config whose state path does not match its Guard home is refused.
        Err(reason) => Some(degraded(&reason, &bridge.data)),
    }
}

/// `claude-hook-bridge HOL_GUARD_CLAUDE_DAEMON_HOOK <config>`: always exits
/// zero; the decision travels in the hook JSON.
pub(crate) fn run(config_text: &str) -> Result<(), String> {
    let response = hook_response(config_text, &mut io::stdin().lock());
    if let Some(response) = response {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(response.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_unmanaged_tests.rs"]
mod unmanaged_tests;

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_watch_tests.rs"]
mod watch_tests;

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_prompt_outage_tests.rs"]
mod prompt_outage_tests;
