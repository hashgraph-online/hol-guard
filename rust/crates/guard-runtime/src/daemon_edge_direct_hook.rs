//! `POST /v1/hooks/<harness>`: the resident's direct answer to a hook the
//! daemon received (`pi_direct_answer` in `_handle_runtime_hook`).
//!
//! Oh My Pi has no bridge to ask the resident first, and a bridge that
//! reached the daemon may have found the resident busy, so the daemon asks
//! it. An `answer` is the resident's harness response, returned unchanged. A
//! defer, an error, a missing resident, or any request the daemon must
//! settle first keeps the daemon path, which reviews the hook itself.
//!
//! Codex and Claude Code hooks reach this only after their bridge redeemed
//! an identity proof on the same connection (`identity`).

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::super::http::{query_value, Request};
use super::{authorize_token, json_response, ReadConfig};
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct::{daemon_direct_answer, daemon_direct_harness};

/// The harnesses whose hooks need a redeemed identity proof first.
const PROOF_HARNESSES: [&str; 2] = ["codex", "claude-code"];
/// The bridges' `DIRECT_TIMEOUT`.
const DIRECT_TIMEOUT: Duration = Duration::from_secs(1);

/// The harness a hook path names, when the direct lane may answer it.
fn harness(path: &str) -> Option<&str> {
    path.strip_prefix("/v1/hooks/")
        .filter(|name| daemon_direct_harness(name))
}

/// Whether the daemon asks the resident about this hook route before any
/// identity proof.
pub(in crate::daemon_edge) fn owns(path: &str) -> bool {
    harness(path).is_some_and(|name| !PROOF_HARNESSES.contains(&name))
}

/// The query's value with Python's `strip`, or `None` when it is absent or
/// blank (`_optional_string`).
fn optional(query: &str, name: &str) -> Result<Option<String>, ()> {
    Ok(query_value(query, name)?
        .map(|value| py_strip(&value).to_owned())
        .filter(|value| !value.is_empty()))
}

/// The response the resident answered, or `None` for the daemon path.
pub(in crate::daemon_edge) fn respond(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
) -> Option<Vec<u8>> {
    let harness = harness(request.path)?;
    // The daemon refuses a caller without its credential and audits it.
    authorize_token(request, &config.token)?;
    let query = request.query;
    // A `runtime-harness` query names another harness's review.
    if optional(query, "runtime-harness").ok()?.is_some() {
        return None;
    }
    // `_hook_guard_home_query_is_this_home`: the lane answers out of the
    // home it bound, so only a claim naming exactly this home may skip the
    // daemon's settling of it.
    if let Some(claimed) = optional(query, "guard-home").ok()? {
        if Path::new(&claimed) != Path::new(&config.guard_home) {
            return None;
        }
    }
    let home = optional(query, "home").ok()?;
    let workspace = query_value(query, "workspace").ok()?;
    let Ok(Value::Object(mut payload)) = serde_json::from_slice::<Value>(body) else {
        return None;
    };
    payload.remove("hook_env");
    let answer = daemon_direct_answer(
        harness,
        Path::new(&config.guard_home),
        home.as_deref(),
        workspace,
        &Value::Object(payload),
        Instant::now() + DIRECT_TIMEOUT,
    )?;
    let response: Value = serde_json::from_str(&answer).ok()?;
    Some(json_response(
        200,
        &response,
        config.dashboard_build.as_deref(),
        None,
        false,
    ))
}
