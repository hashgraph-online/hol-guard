//! Native Oh My Pi hook bridge (`pi-hook-bridge-v1`).
//!
//! The generated Pi and `omp` extension runs
//! `guard-runtime pi-hook-bridge <config>` once per hook, with the hook
//! payload on stdin, in place of posting it to the daemon itself. The
//! config names the harness, the Guard home and the query the extension
//! would have sent, and the time the hook may take.
//!
//! A live resident of this runtime answers the hook first through
//! `hook_direct`, exactly as the daemon would have asked it. Everything the
//! resident defers, or a hook no resident can take, is posted to the
//! loopback daemon with the same path, query, token and body the extension
//! used. The bridge writes one JSON line, `{"status":200,"body":...}` for an
//! answer and the daemon's status and body for anything else, so the
//! extension reads the reply as it read the daemon's HTTP response.
//! `{"status":0}` means no answer arrived: the extension then recovers the
//! daemon or fails the hook closed. The bridge never decides a verdict and
//! never starts Python.
//!
//! A resident's workspace sandbox requirement whose shape the runtime's own
//! sink reproduces is marked `native_contained_sink`, as the edge marks the
//! routed calls of other harnesses. The extension then starts this runtime's
//! `contained-workspace-sink` in place of Guard's CLI. That sink asks the
//! resident about the call again before anything runs, so the mark only
//! picks the sink and never authorizes. A daemon's answer is never marked:
//! the resident it would ask again did not answer.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bounded_hook_bridge::{daemon_target, read_hook_input, Input};
use crate::claude_hook_bridge_http::remaining;
use crate::codex_hook_bridge_direct::{
    direct_answer_reporting, parse_hook_query, DirectHarness, OMP, PI,
};
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::hook_direct::contained::{native_sink, unprojected_sink_command, NativeSink};

pub(crate) const BRIDGE_COMMAND: &str = "pi-hook-bridge";
pub(crate) const BRIDGE_FEATURE: &str = "pi-hook-bridge-v1";
/// The extension's longest daemon request; a longer config is refused.
const MAX_TIMEOUT_MS: u64 = 60_000;
const INVALID_CONFIG: &str = "pi hook bridge configuration is invalid";
/// The mark on an answer the runtime's own sink runs.
pub(crate) const NATIVE_SINK_FIELD: &str = "native_contained_sink";

/// The extension's config for one hook.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PiBridgeConfig {
    pub(crate) harness: DirectHarness,
    pub(crate) guard_home: PathBuf,
    /// `URLSearchParams.toString()` of the extension's daemon query.
    pub(crate) query: String,
    pub(crate) timeout: Duration,
}

/// Bytes `URLSearchParams` writes unescaped, plus its separators and
/// escapes, so the query goes on the request line exactly as given.
fn query_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"*-._%+&=".contains(&byte)
}

pub(crate) fn parse_config(text: &str) -> Option<PiBridgeConfig> {
    let payload: Value = serde_json::from_str(text).ok()?;
    let harness = match payload.get("harness")?.as_str()? {
        "pi" => PI,
        "omp" => OMP,
        _ => return None,
    };
    let guard_home = PathBuf::from(payload.get("guard_home")?.as_str()?);
    if !guard_home.is_absolute() {
        return None;
    }
    let query = payload.get("query")?.as_str()?.to_owned();
    if !query.bytes().all(query_byte) {
        return None;
    }
    let timeout_ms = payload
        .get("timeout_ms")?
        .as_u64()
        .filter(|ms| (1..=MAX_TIMEOUT_MS).contains(ms))?;
    Some(PiBridgeConfig {
        harness,
        guard_home,
        query,
        timeout: Duration::from_millis(timeout_ms),
    })
}

/// The payload's `hook_event_name`, which the resident is asked about.
fn event_name(data: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(data).ok()?;
    Some(payload.get("hook_event_name")?.as_str()?.to_owned())
}

/// The status and body the extension reads, or `None` when neither the
/// resident nor the daemon answered in time.
pub(crate) fn reply(
    config: &PiBridgeConfig,
    data: &str,
    deadline: Instant,
) -> Option<(u16, String)> {
    let miss = match event_name(data) {
        Some(event_name) => {
            // The resident gets half the time left, so the daemon keeps the
            // rest.
            let rpc_deadline = deadline.min(Instant::now() + remaining(deadline) / 2);
            match direct_answer_reporting(
                config.harness,
                &config.guard_home,
                &config.query,
                &event_name,
                data,
                rpc_deadline,
            ) {
                Ok(answer) => {
                    return Some((200, marked(&config.query, data, answer, native_sink)));
                }
                Err(miss) => miss,
            }
        }
        None => DirectMiss::Request,
    };
    let target = daemon_target(&config.guard_home, config.harness.name)?;
    let path = format!("/v1/hooks/{}?{}", config.harness.name, config.query);
    let (status, body) = target.post_status(&path, data, deadline, miss)?;
    // `fetch` decodes the body as UTF-8, replacing malformed bytes, and
    // drops a leading BOM.
    let text = String::from_utf8_lossy(&body);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned();
    Some((status, text))
}

/// `answer` marked for the runtime's own sink when it is a sandbox
/// requirement for a `bash` call whose shape `native` reproduces, from the
/// workspace and home the extension named. The shape is read as the Codex
/// bridge reads it: a call with its own `cwd` argument as that directory's
/// `cd` form, and a projected call (a virtualenv activation, a trailing
/// group or a home-spelled launcher) as the text the verdict answered for.
/// Any other answer, or one the bridge cannot read, is relayed as sent.
fn marked(query: &str, data: &str, answer: String, native: NativeSink) -> String {
    let mark = || {
        let Value::Object(mut response) = serde_json::from_str(&answer).ok()? else {
            return None;
        };
        let text = |name: &str| response.get(name).and_then(Value::as_str);
        if text("decision") != Some("deny") || text("policy_action") != Some("sandbox-required") {
            return None;
        }
        let payload: Value = serde_json::from_str(data).ok()?;
        if payload.get("tool_name")?.as_str()? != "bash" {
            return None;
        }
        let input = payload.get("tool_input")?.as_object()?;
        let query = parse_hook_query(query)?;
        let workspace = query.workspace?;
        let home = match query.home {
            Some(home) => home,
            None => std::env::var("HOME").ok()?,
        };
        let reviewed = Value::Object(response.clone());
        unprojected_sink_command(&reviewed, input, &workspace, &home, native)?;
        response.insert(NATIVE_SINK_FIELD.to_owned(), Value::Bool(true));
        serde_json::to_string(&response).ok()
    };
    mark().unwrap_or(answer)
}

/// The line the extension reads for a reply.
pub(crate) fn envelope(reply: Option<(u16, String)>) -> String {
    let value = match reply {
        Some((status, body)) => json!({ "status": status, "body": body }),
        None => json!({ "status": 0 }),
    };
    format!("{value}\n")
}

/// Run the bridge for one hook; the exit status.
pub(crate) fn run(config_text: &str) -> i32 {
    let started = Instant::now();
    let Some(config) = parse_config(config_text) else {
        let _ = writeln!(io::stderr(), "{INVALID_CONFIG}");
        return 2;
    };
    let Some(deadline) = started.checked_add(config.timeout) else {
        return 2;
    };
    let reply = match read_hook_input(deadline) {
        Input::Read(raw) => String::from_utf8(raw)
            .ok()
            .and_then(|data| reply(&config, data.trim_end_matches('\n'), deadline)),
        Input::Failed => None,
    };
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(envelope(reply).as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[cfg(all(test, unix))]
#[path = "pi_hook_bridge_tests.rs"]
mod tests;
