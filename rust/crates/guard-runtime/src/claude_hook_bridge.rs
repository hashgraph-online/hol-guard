//! Native Claude Code hook bridge: a port of `main` in
//! `adapters/claude_daemon_hook_bridge.py`. Claude Code runs this once per
//! hook. It forwards the hook to the authenticated loopback Guard daemon and
//! recovers a dead daemon once, waiting for it to come back up, all inside the harness's hook deadline. Every
//! failure ends in a hook response that denies or degrades the action; nothing
//! here decides a verdict itself, and no Python hook command runs in its place.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http::{remaining, MINIMUM_OPERATION};
use crate::claude_hook_bridge_render::{
    control_plane_failure, degraded, event_name, limit_denied, py_strip, should_suppress_output,
    valid_hook_json_or_degraded,
};
use crate::claude_hook_bridge_transport::{
    authenticated_claude_hook_response, daemon_proves_identity, json_failure, BridgeError,
};
use crate::claude_hook_bridge_url::{
    assert_loopback_http_url, endpoint_query, state_names_loopback_port, state_path_for_query,
};
use crate::codex_hook_bridge_direct::{direct_answer, CLAUDE_CODE};
use crate::hook_bridge_daemon_start::{await_daemon, Attempt, MINIMUM_REQUEST};
use crate::hook_env_stamp::{current_environment, stamp_hook_input_text, Stamp};
use crate::hook_process_spawn::{isolated_hook_environment, run_isolated_hook_process};

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
    let recovery_command = match payload.get("recovery_command") {
        None => Vec::new(),
        value => string_list(value)?,
    };
    Some(BridgeConfig {
        state_path: text_field("state_path")?,
        fallback_daemon_url: text_field("fallback_daemon_url")?,
        query: text_field("query")?,
        recovery_command,
    })
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
    data: String,
    deadline: Instant,
}

impl Bridge<'_> {
    /// One authenticated daemon exchange and its hook-JSON validation,
    /// classified exactly as the Python `try` block classifies it.
    fn exchange(
        &self,
        state_path: &Path,
        deadline: Instant,
        malformed: &str,
    ) -> Result<String, BridgeError> {
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
        let query = endpoint_query(&self.config.query);
        let response = authenticated_claude_hook_response(state_path, &query, &self.data, timeout)?;
        valid_hook_json_or_degraded(&response, malformed, &self.data).map_err(json_failure)
    }

    /// The response a live resident answered for a passed-through `PreToolUse`,
    /// a reviewed `PostToolUse`, a `UserPromptSubmit` hook without Guard's
    /// notice or a `PermissionRequest`, checked as a daemon response is; `None`
    /// takes the daemon path.
    fn direct_response(&self, state_path: &Path) -> Option<String> {
        let guard_home = state_path.parent()?;
        let query = endpoint_query(&self.config.query);
        let event = event_name(&self.data);
        let text = direct_answer(
            CLAUDE_CODE,
            guard_home,
            &query,
            &event.name,
            &self.data,
            self.deadline,
        )?;
        valid_hook_json_or_degraded(&text, "resident returned malformed hook JSON", &self.data).ok()
    }

    fn respond(&self, state_path: &Path) -> Option<String> {
        let answered = match self.direct_response(state_path) {
            Some(body) => Ok(body),
            None => self.exchange(
                state_path,
                self.deadline,
                "daemon returned malformed hook JSON",
            ),
        };
        let error = match answered {
            Ok(body) if should_suppress_output(&self.data, &body) => return None,
            Ok(body) if py_strip(&body).is_empty() => return Some("{}".to_owned()),
            Ok(body) => return Some(body),
            Err(error) => error,
        };
        let reason = error.reason();
        let kind = error.failure_kind();
        Some(if kind == CONTROL_PLANE_FAILURE {
            control_plane_failure(&reason, &self.data)
        } else if error.is_recoverable() {
            self.recover_or_degrade(reason, state_path, kind)
        } else {
            degraded(&reason, &self.data)
        })
    }

    /// Restarts a dead daemon once and retries the hook; the action is
    /// degraded when that does not produce an answer in time.
    fn recover_or_degrade(&self, mut reason: String, state_path: &Path, kind: &str) -> String {
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
                return degraded(
                    &format!("{reason}; daemon recovery retry failed: the restarted daemon did not answer in time"),
                    &self.data,
                );
            }
            let malformed = format!("{reason}; recovered daemon returned malformed hook JSON");
            match self.exchange(state_path, self.deadline, &malformed) {
                Ok(body) => return body,
                Err(error) => reason = format!("{reason}; daemon recovery retry failed: {error}"),
            }
        }
        degraded(&reason, &self.data)
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
    let bridge = Bridge {
        config: &config,
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
