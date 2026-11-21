//! `runner_authority` kind `cline_hook_files`: the Guard-managed native Cline
//! hook files and the health verdict over them.
//!
//! Python resolves every path from its harness context, reads and writes the
//! files and runs the synthetic canary. This kind is lexical over what it is
//! given:
//!
//! - `render` spells each event's worker configuration, launcher slot name and
//!   launcher (a POSIX `sh` script or a fail-closed PowerShell script) with
//!   their SHA-256 digests, byte for byte as the original Python renderers did.
//! - `state` compares what Python read back from each bound hook file with the
//!   digests recorded at install, and reads the live proof files. `ready`
//!   assumes the canary passes: when `canary` is true the caller runs it and
//!   only then may report the hooks ready.

use guard_contracts::write_json_string;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::local_cli_identify::shlex_quote;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const MARKER: &str = "HOL_GUARD_MANAGED_CLINE_HOOK_V1";
const WORKER_SCHEMA: &str = "cline-hook-worker.v1";
const PROOF_MAX_AGE_SECONDS: f64 = 7.0 * 24.0 * 60.0 * 60.0;
const EVENTS: [&str; 6] = [
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "TaskStart",
    "TaskError",
    "SessionShutdown",
];
const PROOF_EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];
const BLOCKING_EVENT: &str = "PreToolUse";
const RENDER_KEYS: [&str; 6] = [
    "op",
    "windows",
    "runtime",
    "guard_cli",
    "adapter_state",
    "events",
];
const STATE_KEYS: [&str; 6] = ["op", "now", "state_text", "launchers", "workers", "proofs"];

/// What Python read back from one bound hook file: its SHA-256 and whether it
/// is a regular, non-symlink file carrying the managed marker. `None` when
/// the recorded path is unbound or the file is unreadable.
type Observed<'a> = Option<(&'a str, bool)>;
type Fields = Map<String, Value>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("render") => render(fields),
        Some("state") => state(fields),
        _ => Err(ERR_INVALID),
    }
}

fn exact_keys(fields: &Fields, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(())
    } else {
        Err(ERR_INVALID)
    }
}

fn text<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn optional_text(value: Option<&Value>) -> Result<Option<&str>, &'static str> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        _ => Err(ERR_INVALID),
    }
}

/// An object keyed by exactly `events`.
fn per_event<'a>(value: Option<&'a Value>, events: &[&str]) -> Result<&'a Fields, &'static str> {
    let fields = value.and_then(Value::as_object).ok_or(ERR_INVALID)?;
    exact_keys(fields, events)?;
    Ok(fields)
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// A JSON string as Python's default (`ensure_ascii`) encoder spells it.
fn json_string(text: &str) -> String {
    let mut out = Vec::new();
    write_json_string(text, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// `json.dumps(config, indent=2, sort_keys=True) + "\n"` over the worker's
/// fixed key set, listed here in sorted order.
fn worker_config(event: &str, guard_cli: &[&str], proof: &str, adapter_state: &str) -> String {
    let guard = if guard_cli.is_empty() {
        "[]".to_owned()
    } else {
        let items: Vec<String> = guard_cli
            .iter()
            .map(|arg| format!("    {}", json_string(arg)))
            .collect();
        format!("[\n{}\n  ]", items.join(",\n"))
    };
    let entries = [
        ("adapter_state", json_string(adapter_state)),
        ("event", json_string(event)),
        ("guard", guard),
        ("marker", json_string(MARKER)),
        ("proof", json_string(proof)),
        ("schema", json_string(WORKER_SCHEMA)),
    ];
    let body: Vec<String> = entries
        .iter()
        .map(|(key, value)| format!("  \"{key}\": {value}"))
        .collect();
    format!("{{\n{}\n}}\n", body.join(",\n"))
}

fn posix_launcher(worker: &str, runtime: &str) -> String {
    format!(
        "#!/bin/sh\n# {MARKER}\nexec {} cline-hook-worker {}\n",
        shlex_quote(runtime),
        shlex_quote(worker)
    )
}

/// A PowerShell single-quoted string literal.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The Windows launcher. It never exits non-zero: an unavailable worker
/// answers with a cancel (blocking events) or a diagnostic payload.
fn powershell_launcher(worker: &str, runtime: &str, blocking: bool) -> String {
    let (message, cancel) = if blocking {
        (
            "HOL Guard evaluation was unavailable; this Cline action was not allowed to proceed.",
            "$true",
        )
    } else {
        (
            "HOL Guard hook diagnostic: evaluation was unavailable.",
            "$false",
        )
    };
    let message = ps_quote(message);
    let failure = format!(
        "@{{cancel={cancel};errorMessage={message};contextModification={message}}} | ConvertTo-Json -Compress"
    );
    [
        format!("# {MARKER}"),
        format!("$Runtime = {}", ps_quote(runtime)),
        format!("$Worker = {}", ps_quote(worker)),
        "$Args = @(\"cline-hook-worker\", $Worker)".to_owned(),
        "$Raw = [Console]::In.ReadToEnd()".to_owned(),
        "try {".to_owned(),
        "  $Lines = $Raw | & $Runtime @Args 2>$null".to_owned(),
        "  $Code = $LASTEXITCODE".to_owned(),
        "  $Text = ($Lines -join [Environment]::NewLine)".to_owned(),
        "  if ($Code -ne 0 -or [string]::IsNullOrWhiteSpace($Text)) {".to_owned(),
        format!("    {failure}"),
        "    exit 0".to_owned(),
        "  }".to_owned(),
        "  [Console]::Out.WriteLine($Text)".to_owned(),
        "} catch {".to_owned(),
        format!("    {failure}"),
        "}".to_owned(),
        "exit 0".to_owned(),
        String::new(),
    ]
    .join("\n")
}

/// Every event's files as `{"files": {event: {slot, worker, worker_sha256,
/// launcher, launcher_sha256}}}`.
fn render(fields: &Fields) -> KindResult {
    exact_keys(fields, &RENDER_KEYS)?;
    let windows = fields
        .get("windows")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let runtime = text(fields, "runtime")?;
    let adapter_state = text(fields, "adapter_state")?;
    let guard_cli = fields
        .get("guard_cli")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|arg| arg.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<&str>, &'static str>>()?;
    let events = per_event(fields.get("events"), &EVENTS)?;
    let mut files = Map::new();
    for event in EVENTS {
        let paths = events
            .get(event)
            .and_then(Value::as_object)
            .ok_or(ERR_INVALID)?;
        exact_keys(paths, &["worker", "proof"])?;
        let worker_path = text(paths, "worker")?;
        let worker = worker_config(event, &guard_cli, text(paths, "proof")?, adapter_state);
        let (slot, launcher) = if windows {
            (
                format!("{event}.ps1"),
                powershell_launcher(worker_path, runtime, event == BLOCKING_EVENT),
            )
        } else {
            (event.to_owned(), posix_launcher(worker_path, runtime))
        };
        files.insert(
            event.to_owned(),
            json!({
                "slot": slot,
                "worker_sha256": sha256_hex(&worker),
                "worker": worker,
                "launcher_sha256": sha256_hex(&launcher),
                "launcher": launcher,
            }),
        );
    }
    Ok(json!({ "files": files }))
}

fn observation(value: &Value) -> Result<Observed<'_>, &'static str> {
    if value.is_null() {
        return Ok(None);
    }
    let fields = value.as_object().ok_or(ERR_INVALID)?;
    exact_keys(fields, &["sha256", "managed"])?;
    let managed = fields
        .get("managed")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    Ok(Some((text(fields, "sha256")?, managed)))
}

fn observations(value: Option<&Value>) -> Result<Vec<Observed<'_>>, &'static str> {
    let fields = per_event(value, &EVENTS)?;
    EVENTS
        .iter()
        .map(|event| observation(fields.get(*event).ok_or(ERR_INVALID)?))
        .collect()
}

/// Missing unless both the recorded path and digest are strings and the bound
/// file is managed; modified when its digest differs from the recorded one.
fn file_verdict(
    recorded: &Fields,
    digests: &Fields,
    event: &str,
    observed: Observed<'_>,
) -> Option<bool> {
    recorded.get(event).and_then(Value::as_str)?;
    let digest = digests.get(event).and_then(Value::as_str)?;
    match observed {
        Some((actual, true)) => Some(actual == digest),
        _ => None,
    }
}

/// A proof timestamp read as Python's `isinstance(value, (int, float))`,
/// where a boolean is an integer.
fn timestamp(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn proof(text: Option<&str>, event: &str, now: f64) -> Value {
    let Some(document) = text.and_then(|text| serde_json::from_str::<Value>(text).ok()) else {
        return json!({ "present": false, "fresh": false, "live": false });
    };
    let fields = document.as_object();
    let fresh = fields
        .and_then(|fields| timestamp(fields.get("timestamp")))
        .is_some_and(|stamp| now - stamp <= PROOF_MAX_AGE_SECONDS);
    let live = fresh
        && fields
            .and_then(|fields| fields.get("source"))
            .and_then(Value::as_str)
            == Some("cline");
    let outcome = fields
        .and_then(|fields| fields.get("outcome"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "present": true,
        "fresh": fresh,
        "live": live,
        "event": event,
        "outcome": outcome,
    })
}

fn proven(proof: &Value, outcome: &str) -> bool {
    proof.get("live").and_then(Value::as_bool) == Some(true)
        && proof.get("outcome").and_then(Value::as_str) == Some(outcome)
}

/// The installed, integrity and live-proof verdict as
/// `{"state": {...}, "canary": bool}`.
fn state(fields: &Fields) -> KindResult {
    exact_keys(fields, &STATE_KEYS)?;
    let now = fields
        .get("now")
        .and_then(Value::as_f64)
        .ok_or(ERR_INVALID)?;
    let state_text = optional_text(fields.get("state_text"))?;
    let launchers = observations(fields.get("launchers"))?;
    let workers = observations(fields.get("workers"))?;
    let proofs = per_event(fields.get("proofs"), &PROOF_EVENTS)?;
    let pre_text = optional_text(proofs.get("PreToolUse"))?;
    let post_text = optional_text(proofs.get("PostToolUse"))?;

    let document = state_text.and_then(|text| serde_json::from_str::<Value>(text).ok());
    let group = |name: &str| {
        document
            .as_ref()
            .and_then(|document| document.get(name))
            .and_then(Value::as_object)
    };
    let (Some(paths), Some(digests)) = (group("paths"), group("sha256")) else {
        return Ok(json!({
            "state": {
                "installed": false,
                "integrity_ok": false,
                "ready": false,
                "missing_events": EVENTS,
            },
            "canary": false,
        }));
    };
    let mut missing: Vec<String> = Vec::new();
    let mut modified: Vec<String> = Vec::new();
    for (event, observed) in EVENTS.iter().zip(&launchers) {
        match file_verdict(paths, digests, event, *observed) {
            None => missing.push((*event).to_owned()),
            Some(false) => modified.push((*event).to_owned()),
            Some(true) => {}
        }
    }
    match (group("workers"), group("worker_sha256")) {
        (Some(recorded), Some(worker_digests)) => {
            for (event, observed) in EVENTS.iter().zip(&workers) {
                match file_verdict(recorded, worker_digests, event, *observed) {
                    None => missing.push(format!("{event}:worker")),
                    Some(false) => modified.push(format!("{event}:worker")),
                    Some(true) => {}
                }
            }
        }
        _ => missing.extend(EVENTS.iter().map(|event| format!("{event}:worker"))),
    }
    let intact = missing.is_empty() && modified.is_empty();
    let pre = proof(pre_text, "PreToolUse", now);
    let post = proof(post_text, "PostToolUse", now);
    let pretool_blocking_proven = proven(&pre, "blocked");
    let posttool_observation_proven = proven(&post, "observed");
    Ok(json!({
        "state": {
            "installed": missing.is_empty(),
            "integrity_ok": intact,
            "synthetic_canary_ok": false,
            "live_pretool_proof": pre,
            "live_posttool_proof": post,
            "pretool_blocking_proven": pretool_blocking_proven,
            "posttool_observation_proven": posttool_observation_proven,
            "post_tool_output_mediation": "observation-only",
            "missing_events": missing,
            "modified_events": modified,
            "ready": intact && pretool_blocking_proven,
        },
        "canary": intact,
    }))
}
