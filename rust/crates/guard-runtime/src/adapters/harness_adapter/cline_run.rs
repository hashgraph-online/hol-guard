//! The two processes a Cline install runs to prove its transport: the hook
//! canary through Guard's own PreToolUse launcher, and `node --check` over the
//! generated plugin, which `_run_canary` and `_node_check` in
//! `guard/adapters/cline_runtime.py` ran before they moved here.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::{which, Ctx};
use crate::hook_bridge_daemon_start::start_environment;
use crate::hook_process_spawn::run_isolated_hook_process;

const CANARY_TIMEOUT_SECONDS: f64 = 10.0;
const NODE_CHECK_TIMEOUT_SECONDS: f64 = 5.0;
const OUTPUT_LIMIT: usize = 1024 * 1024;

/// Where a process runs: the caller's working directory, else Guard's home.
fn cwd(ctx: &Ctx) -> PathBuf {
    ctx.cwd
        .clone()
        .filter(|cwd| cwd.is_dir())
        .unwrap_or_else(|| ctx.guard_home.clone())
}

/// The class name Python's `subprocess` raised for a run that did not finish.
fn failure(timed_out: bool) -> &'static str {
    if timed_out {
        "TimeoutExpired"
    } else {
        "OSError"
    }
}

/// One canary run with the synthetic read on stdin: `{returncode, stdout,
/// error}`. It runs with the caller's hook environment and
/// `HOL_GUARD_CLINE_CANARY` set, so the worker records no live proof.
pub(super) fn canary(ctx: &Ctx, argv: &[String], input: &str) -> Value {
    let mut env = start_environment(&ctx.env);
    env.insert("HOL_GUARD_CLINE_CANARY".into(), "1".into());
    let result = run_isolated_hook_process(
        argv,
        input,
        &cwd(ctx),
        &env,
        Some(CANARY_TIMEOUT_SECONDS),
        Some(OUTPUT_LIMIT),
        None,
        None,
    );
    match result.returncode {
        Some(code) if !result.timed_out && !result.output_limit_exceeded => {
            json!({"returncode": code, "stdout": result.stdout, "error": null})
        }
        _ => json!({"returncode": null, "stdout": "", "error": failure(result.timed_out)}),
    }
}

/// The syntax verdict on the generated plugin, without executing it. With no
/// `node` on the caller's PATH the check is skipped, as it always was.
pub(super) fn node_check(ctx: &Ctx, index: &str) -> Value {
    let Some(node) = which::which(ctx, "node") else {
        return json!({"ok": true, "skipped": true, "reason": "node_not_available"});
    };
    let argv = [node, "--check".into(), "--".into(), index.into()];
    let result = run_isolated_hook_process(
        &argv,
        "",
        &cwd(ctx),
        &start_environment(&ctx.env),
        Some(NODE_CHECK_TIMEOUT_SECONDS),
        Some(OUTPUT_LIMIT),
        None,
        None,
    );
    match result.returncode {
        Some(code) if !result.timed_out => json!({"ok": code == 0, "return_code": code}),
        _ => json!({"ok": false, "reason": failure(result.timed_out)}),
    }
}

#[cfg(all(test, unix))]
#[path = "cline_run_tests.rs"]
mod tests;
