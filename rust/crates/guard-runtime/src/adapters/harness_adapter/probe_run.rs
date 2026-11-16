//! `runtime_probe` with its CLI probes run here: the `--help`, `--version`
//! and `debug` subprocesses each Python adapter ran through
//! `_run_command_probe` (`guard/adapters/base.py`) after the harness op named
//! the argv.
//!
//! A probe runs through the `command_probe` kind with the caller's working
//! directory and only the caller variables `_PROBE_ENV_KEYS` named. A caller
//! that turned probes off (`without_command_probes`, the passive global
//! doctor) gets the skipped record without any subprocess.
//!
//! The answer is always `{"probe": ...}`: the record the doctor renders, or
//! `null` when the harness has no CLI probe to run.

use serde_json::{json, Map, Value};

use super::{path_text, route, Ctx, Spec, Step};

/// `_PROBE_ENV_KEYS`: the caller environment a harness CLI probe runs with.
const PROBE_ENV: [&str; 16] = [
    "PATH",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "LANG",
    "LC_ALL",
];
/// `_run_command_probe`'s default deadline.
pub(super) const DEFAULT_TIMEOUT: u64 = 5;
/// `ClineHarnessAdapter._cli`'s `--version` deadline.
const CLINE_VERSION_TIMEOUT: u64 = 3;

fn unavailable(argv: &[String]) -> Value {
    json!({
        "command": argv,
        "ok": false,
        "return_code": null,
        "stdout": "",
        "stderr": "probe unavailable",
    })
}

/// `_run_command_probe(argv, timeout_seconds)`.
pub(super) fn command(ctx: &Ctx, argv: &[String], timeout: u64) -> Value {
    if !ctx.probes {
        return json!({
            "command": argv,
            "ok": null,
            "return_code": null,
            "stdout": "",
            "stderr": "",
            "skipped": true,
            "skip_reason": "global_doctor_passive_checks",
        });
    }
    let Some(cwd) = ctx.cwd.as_deref() else {
        return unavailable(argv);
    };
    let env: Map<String, Value> = PROBE_ENV
        .iter()
        .filter_map(|key| Some(((*key).to_owned(), json!(ctx.env(key)?))))
        .collect();
    let request = json!({
        "command": argv,
        "cwd": path_text(cwd),
        "env": env,
        "timeout_seconds": timeout,
    });
    crate::command_probe::dispatch(&request).unwrap_or_else(|_| unavailable(argv))
}

/// Whether a probe record says the CLI ran: `ok`, or a zero exit.
pub(super) fn succeeded(record: &Value) -> bool {
    record.get("ok") == Some(&Value::Bool(true)) || record.get("return_code") == Some(&json!(0))
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|part| part.as_str().map(str::to_owned))
        .collect()
}

fn text(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `ClineHarnessAdapter._cli`: the Cline CLI and its `--version` output.
pub(super) fn cline_cli(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let resolved = route(spec, "resolved_executable", ctx, fields)?;
    let Some(path) = resolved.get("path").and_then(Value::as_str) else {
        return Ok(json!({ "path": null, "output": "" }));
    };
    let record = command(
        ctx,
        &[path.to_owned(), "--version".into()],
        CLINE_VERSION_TIMEOUT,
    );
    let output = format!("{}\n{}", text(&record, "stdout"), text(&record, "stderr"));
    Ok(json!({ "path": path, "output": output }))
}

/// `fields` with `cli` filled in by the `--version` probe when the caller
/// did not name it.
pub(super) fn with_cline_cli(
    spec: &Spec,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Map<String, Value>> {
    let mut asked = fields.clone();
    if !asked.contains_key("cli") {
        asked.insert("cli".into(), cline_cli(spec, ctx, fields)?);
    }
    Ok(asked)
}

/// The harness's `runtime_probe`, with every CLI probe it names run here.
pub(super) fn runtime(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let probe = match spec.harness {
        "claude-code" => {
            let resolved = route(spec, "resolved_executable", ctx, fields)?;
            match resolved.get("path").and_then(Value::as_str) {
                Some(path) => command(ctx, &[path.to_owned(), "--help".into()], DEFAULT_TIMEOUT),
                None => Value::Null,
            }
        }
        "cline" => {
            let mut asked = fields.clone();
            asked.insert("cli".into(), cline_cli(spec, ctx, fields)?);
            let answer = route(spec, "runtime_probe", ctx, &asked)?;
            answer.get("probe").cloned().unwrap_or(Value::Null)
        }
        "copilot" => {
            let answer = route(spec, "runtime_probe", ctx, fields)?;
            match strings(answer.get("argv")) {
                Some(argv) => command(ctx, &argv, DEFAULT_TIMEOUT),
                None => Value::Null,
            }
        }
        "cursor" => {
            let answer = route(spec, "runtime_probe", ctx, fields)?;
            match strings(answer.get("argv")) {
                Some(argv) => {
                    let mut record = command(ctx, &argv, DEFAULT_TIMEOUT);
                    let mut asked = fields.clone();
                    asked.insert(
                        "stdout".into(),
                        record.get("stdout").cloned().unwrap_or(Value::Null),
                    );
                    let reported = route(spec, "runtime_probe", ctx, &asked)?;
                    record["reported_artifacts"] = reported
                        .get("reported_artifacts")
                        .cloned()
                        .unwrap_or(Value::Null);
                    record
                }
                None => Value::Null,
            }
        }
        "opencode" => {
            let answer = route(spec, "runtime_probe", ctx, fields)?;
            match answer.get("commands").and_then(Value::as_array) {
                Some(commands) => {
                    let mut probes = Map::new();
                    for entry in commands {
                        let Some([name, argv]) = entry.as_array().map(Vec::as_slice) else {
                            return Err(super::Failure::Invalid);
                        };
                        let name = name.as_str().ok_or(super::Failure::Invalid)?;
                        let argv = strings(Some(argv)).ok_or(super::Failure::Invalid)?;
                        probes.insert(name.to_owned(), command(ctx, &argv, DEFAULT_TIMEOUT));
                    }
                    Value::Object(probes)
                }
                None => Value::Null,
            }
        }
        _ if !spec.dynamic => Value::Null,
        _ => {
            let answer = route(spec, "runtime_probe", ctx, fields)?;
            match answer.get("probe") {
                Some(Value::Object(probe)) => {
                    let ran = strings(answer.get("command_argv"))
                        .map_or(Value::Null, |argv| command(ctx, &argv, DEFAULT_TIMEOUT));
                    let mut record = Map::new();
                    record.insert("command".into(), ran);
                    for (key, value) in probe {
                        record.insert(key.clone(), value.clone());
                    }
                    Value::Object(record)
                }
                _ => Value::Null,
            }
        }
    };
    Ok(json!({ "probe": probe }))
}
