//! The signed bundle command that answers a Desktop transition probe.
//!
//! The bundle executable is both the signed proxy and the Core it would fall
//! back to, and the proxy is required, so a proxy that does not verify exits
//! before any Core runs. The command is the strict `/bin/sh` launch
//! `desktop_hook_proxy` builds, over the bounded-hook config the Python
//! launcher's `bounded_cli_hook_command` wrote for it.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use crate::claude_hook_bridge::home_directory;
use crate::claude_hook_bridge_url::resolve_absolute;
use crate::desktop_hook_proxy::signed_argv;
use crate::hook_env_stamp::json_string;
use crate::hook_process_spawn::{isolated_hook_environment, run_isolated_hook_process};

const DESKTOP_ENV: &str = "HOL_GUARD_DESKTOP";
const PROXY_ENV: &str = "HOL_GUARD_DESKTOP_HOOK_PROXY";
const OUTPUT_LIMIT: usize = 64 * 1024;
/// The argv positions of the proxy and Core in the strict launch.
const PROXY_INDEX: usize = 4;
const CORE_INDEX: usize = 8;

/// The probe body, the paths it names and the hook's remaining budget.
pub(super) struct Target<'a> {
    pub(super) data: &'a str,
    pub(super) guard_home: String,
    pub(super) home: String,
    pub(super) workspace: String,
    pub(super) timeout_seconds: i64,
    pub(super) deadline: Instant,
}

/// What the signed command wrote when it answered.
#[derive(Debug, PartialEq)]
pub(super) struct Answer {
    pub(super) stdout: String,
    pub(super) stderr: String,
}

/// This process's environment.
pub(super) fn environment() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

/// `desktop_hook_proxy_context`: the proxy the Desktop app named, when it
/// launched this process.
fn proxy(environment: &BTreeMap<String, String>) -> Option<&str> {
    if environment.get(DESKTOP_ENV).map(String::as_str) != Some("1") {
        return None;
    }
    let proxy = environment.get(PROXY_ENV)?;
    (!proxy.is_empty() && !proxy.contains('\0') && Path::new(proxy).is_absolute())
        .then_some(proxy.as_str())
}

/// The bounded-hook config `bounded_cli_hook_command` writes for the probe:
/// `json.dumps(config, ensure_ascii=True, separators=(",", ":"))`.
pub(super) fn config(proxy: &str, package_root: &str, target: &Target<'_>) -> String {
    let text = |value: &str| json_string(value, true, false);
    let guard_home = resolve_absolute(&target.guard_home);
    let home = resolve_absolute(&target.home);
    let workspace = resolve_absolute(&target.workspace);
    let cli_args = [
        "guard",
        "hook",
        "--guard-home",
        &guard_home,
        "--harness",
        "codex",
        "--home",
        &home,
        "--workspace",
        &workspace,
    ]
    .map(text)
    .join(",");
    format!(
        r#"{{"python_executable":{},"package_root":{},"guard_home":{},"cli_args":[{cli_args}],"harness":"codex","timeout_seconds":{:?},"frozen_launcher":true}}"#,
        text(proxy),
        text(package_root),
        text(&guard_home),
        target.timeout_seconds as f64,
    )
}

/// The signed command's answer to the probe, or `None` when it cannot be
/// built, cannot run, or did not answer cleanly in time.
pub(super) fn answer(
    package_root: &str,
    target: &Target<'_>,
    environment: &BTreeMap<String, String>,
) -> Option<Answer> {
    let proxy = proxy(environment)?;
    let config = config(proxy, package_root, target);
    let command = signed_argv(proxy, &config, true, Some("1"), Some(proxy))?;
    // The launch must name the proxy the app gave, as both proxy and Core,
    // and require it. It names the canonical path, as `signed_argv` verified.
    let named = std::fs::canonicalize(proxy).ok()?;
    let named = named.to_str()?;
    if command.len() != 10
        || command[PROXY_INDEX] != named
        || command[CORE_INDEX] != named
        || command[9] != "1"
    {
        return None;
    }
    let mut child_environment = isolated_hook_environment(environment);
    child_environment.insert(DESKTOP_ENV.to_owned(), "1".to_owned());
    child_environment.insert(PROXY_ENV.to_owned(), proxy.to_owned());
    let result = run_isolated_hook_process(
        &command,
        target.data,
        &home_directory()?,
        &child_environment,
        None,
        Some(OUTPUT_LIMIT),
        None,
        Some(target.deadline),
    );
    (result.returncode == Some(0)
        && !result.timed_out
        && !result.containment_failed
        && !result.output_limit_exceeded)
        .then_some(Answer {
            stdout: result.stdout,
            stderr: result.stderr,
        })
}

#[cfg(test)]
#[path = "codex_hook_bridge_desktop_probe_tests.rs"]
mod tests;
