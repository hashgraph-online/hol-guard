//! `POST /v1/protection/repair`: restores local protection one check at a
//! time and says which checks it confirmed, which failed and why.
//!
//! The daemon decides the checks, their order, the containment confirmation
//! retries, the per-check reasons and the reply. Each store step is one
//! `repair.*` Guard library call (`routes/repair_calls.py`) that reports its
//! outcome as data. An incomplete repair is written to the daemon log as
//! `protection_repair_incomplete` with stable `check:reason` pairs.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::super::super::library::{self, CallError};
use super::super::ReadConfig;
use super::DROPPED;

const INTEGRITY_CHECK_IDS: [&str; 3] = ["policy_engine", "rule_packs", "tamper_checks"];
const CONTAINMENT_CHECK_IDS: [&str; 3] = [
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
];
const CONTAINMENT_ATTEMPTS: usize = 3;

/// Why a step gave no answer: the library was unreachable (`None` from the
/// route, so the request is relayed) or raised (the connection drops).
enum Stop {
    Unavailable,
    Dropped,
}

type Step<T> = Result<T, Stop>;

/// Runs one library call by name.
type Call<'a> = dyn FnMut(&str, Value) -> Result<Value, CallError> + 'a;

/// Where the repair calls and logs.
struct Repair<'a, 'b> {
    call: &'a mut Call<'b>,
    guard_home: &'a Path,
}

fn step(repair: &mut Repair<'_, '_>, name: &str, args: Value) -> Step<Map<String, Value>> {
    match (repair.call)(name, args) {
        Ok(Value::Object(answer)) => Ok(answer),
        Ok(_) | Err(CallError::Raised(_)) => Err(Stop::Dropped),
        Err(CallError::Unavailable) => Err(Stop::Unavailable),
    }
}

/// The reply, `None` when the library could not be reached.
pub(super) fn protection_repair(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    port: u64,
) -> Option<(u16, Value)> {
    let mut call = |name: &str, args: Value| library::call(config, name, args);
    run(
        payload,
        &mut Repair {
            call: &mut call,
            guard_home: Path::new(&config.guard_home),
        },
        port,
    )
}

fn run(
    payload: &Map<String, Value>,
    repair: &mut Repair<'_, '_>,
    port: u64,
) -> Option<(u16, Value)> {
    let check_id = payload
        .get("check_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let answer = match check_id {
        Some(check @ ("all" | "policy_engine" | "rule_packs" | "tamper_checks")) => {
            integrity_repair(repair, port, check == "all")
        }
        Some("decision_stream") => decision_stream_repair(repair),
        _ => Ok((400, json!({"error": "unsupported_protection_check"}))),
    };
    match answer {
        Ok(reply) => Some(reply),
        Err(Stop::Unavailable) => None,
        Err(Stop::Dropped) => Some((DROPPED, Value::Null)),
    }
}

#[derive(Default)]
struct Outcome {
    repaired: Vec<String>,
    failed: Vec<String>,
    reasons: BTreeMap<String, String>,
}

impl Outcome {
    fn pass(&mut self, check: &str) {
        self.repaired.push(check.to_owned());
    }

    fn fail(&mut self, check: &str, reason: &str) {
        self.failed.push(check.to_owned());
        self.reasons.insert(check.to_owned(), reason.to_owned());
    }

    fn reasons_value(&self) -> Value {
        Value::Object(
            self.reasons
                .iter()
                .map(|(check, reason)| (check.clone(), Value::from(reason.as_str())))
                .collect(),
        )
    }
}

fn integrity_repair(repair: &mut Repair<'_, '_>, port: u64, all: bool) -> Step<(u16, Value)> {
    let mut outcome = Outcome::default();
    if all {
        let registration = step(
            repair,
            "repair.daemon_registration",
            json!({ "port": port }),
        )?;
        match registration.get("session_id").and_then(Value::as_str) {
            None => outcome.fail("daemon", "daemon_registration_unavailable"),
            Some(session)
                if Some(session) == registration.get("expected").and_then(Value::as_str) =>
            {
                outcome.pass("daemon");
            }
            Some(_) => outcome.fail("daemon", "daemon_registration_foreign"),
        }
    }
    let integrity = step(repair, "repair.policy_integrity", json!({}))?;
    if integrity.get("failed").and_then(Value::as_bool) != Some(false) {
        for check in INTEGRITY_CHECK_IDS {
            outcome
                .reasons
                .insert(check.to_owned(), "local_integrity_unproven".to_owned());
        }
        record_incomplete(repair.guard_home, &outcome.reasons);
        return Ok((
            409,
            json!({
                "error": "protection_repair_failed",
                "message": "Guard could not restore integrity protection automatically.",
                "check_reasons": outcome.reasons_value(),
            }),
        ));
    }
    let repaired = integrity.get("mode").and_then(Value::as_str) == Some("protected");
    let reason_count = integrity
        .get("reason_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    for check in INTEGRITY_CHECK_IDS {
        if repaired {
            outcome.pass(check);
        } else {
            outcome.fail(check, "local_integrity_unproven");
        }
    }
    if all {
        let hooks = step(repair, "repair.harness_hooks", json!({}))?;
        let failures: Vec<Value> = hooks
            .get("failures")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let unknown = hooks.get("unknown").and_then(Value::as_bool) == Some(true);
        let active = hooks.get("has_active_hooks").and_then(Value::as_bool) == Some(true);
        if !failures.is_empty() || unknown || !active {
            let reason = if unknown {
                "hook_repair_unknown"
            } else if !failures.is_empty() {
                "hook_repair_failed"
            } else {
                "no_managed_harness"
            };
            outcome.fail("harness_hooks", reason);
        } else {
            outcome.pass("harness_hooks");
        }
        if repaired {
            containment_repair(repair, &mut outcome)?;
            let stream = step(repair, "repair.decision_stream", json!({}))?;
            if stream.get("unavailable").and_then(Value::as_bool) != Some(false) {
                outcome.fail("decision_stream", "decision_stream_health_unavailable");
            } else if stream
                .get("active_error_count")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                > 0
            {
                outcome.fail("decision_stream", "decision_stream_degraded");
            } else {
                outcome.pass("decision_stream");
            }
            if !outcome.failed.is_empty() {
                record_incomplete(repair.guard_home, &outcome.reasons);
                let missing_app = outcome.failed.iter().any(|check| check == "harness_hooks")
                    && !active
                    && failures.is_empty()
                    && !unknown;
                return Ok((
                    409,
                    json!({
                        "error": "protection_repair_incomplete",
                        "repaired": false,
                        "check_ids": outcome.repaired,
                        "failed_check_ids": outcome.failed,
                        "failed_harnesses": failures,
                        "pending_check_ids": [],
                        "check_reasons": outcome.reasons_value(),
                        "message": if missing_app {
                            "Connect an AI app to start local protection. Repair cannot finish until at least one app is connected."
                        } else {
                            "Repair paused before every supported protection layer could be confirmed. Retry repair here."
                        },
                    }),
                ));
            }
        }
    }
    if !repaired || !outcome.failed.is_empty() {
        record_incomplete(repair.guard_home, &outcome.reasons);
    }
    let mut body = Map::new();
    if !repaired {
        body.insert("error".into(), "local_integrity_repair_incomplete".into());
    }
    body.insert("repaired".into(), repaired.into());
    body.insert("repair_scope".into(), "local_integrity".into());
    body.insert("check_ids".into(), json!(outcome.repaired));
    if !outcome.failed.is_empty() {
        body.insert("failed_check_ids".into(), json!(outcome.failed));
    }
    body.insert("pending_check_ids".into(), json!([]));
    body.insert("check_reasons".into(), outcome.reasons_value());
    let message = if repaired {
        "Integrity protection restored.".to_owned()
    } else {
        format!(
            "Guard could not establish a local integrity proof. Unverified local rules remain \
             disabled. Local repair did not change Guard Cloud policy availability. Retry local \
             repair from Protect; Guard will keep the remaining {} issue isolated.",
            reason_count.max(1)
        )
    };
    body.insert("message".into(), message.into());
    Ok((if repaired { 200 } else { 409 }, Value::Object(body)))
}

/// Confirms the containment checks, probing up to [`CONTAINMENT_ATTEMPTS`]
/// times until every repairable one passes. An unsupported platform is a
/// lasting limit, neither repaired nor failed.
fn containment_repair(repair: &mut Repair<'_, '_>, outcome: &mut Outcome) -> Step<()> {
    let mut latest: Option<Map<String, Value>> = None;
    for _ in 0..CONTAINMENT_ATTEMPTS {
        let answer = step(repair, "repair.containment_signals", json!({}))?;
        let Some(Value::Object(signals)) = answer.get("signals") else {
            continue;
        };
        let settled = CONTAINMENT_CHECK_IDS
            .iter()
            .all(|check| match signals.get(*check) {
                Some(signal) => {
                    reason(signal) == Some("unsupported_platform") || status(signal) == Some("pass")
                }
                None => false,
            });
        latest = Some(signals.clone());
        if settled {
            break;
        }
    }
    let Some(signals) = latest else {
        for check in CONTAINMENT_CHECK_IDS {
            outcome.fail(check, "containment_health_unavailable");
        }
        return Ok(());
    };
    for check in CONTAINMENT_CHECK_IDS {
        match signals.get(check) {
            Some(signal) if status(signal) == Some("pass") => outcome.pass(check),
            Some(signal) if reason(signal) == Some("unsupported_platform") => {}
            Some(signal) => outcome.fail(
                check,
                reason(signal).unwrap_or("containment_health_unavailable"),
            ),
            None => outcome.fail(check, "containment_health_unavailable"),
        }
    }
    Ok(())
}

fn status(signal: &Value) -> Option<&str> {
    signal.get("status").and_then(Value::as_str)
}

fn reason(signal: &Value) -> Option<&str> {
    signal.get("reason_code").and_then(Value::as_str)
}

fn decision_stream_repair(repair: &mut Repair<'_, '_>) -> Step<(u16, Value)> {
    let stream = step(repair, "repair.decision_stream", json!({}))?;
    let mut reasons = BTreeMap::new();
    if stream.get("unavailable").and_then(Value::as_bool) != Some(false) {
        reasons.insert(
            "decision_stream".to_owned(),
            "decision_stream_health_unavailable".to_owned(),
        );
        record_incomplete(repair.guard_home, &reasons);
        return Ok((
            409,
            json!({
                "error": "protection_repair_failed",
                "message": "Guard could not verify the command evidence store.",
                "check_reasons": reasons,
            }),
        ));
    }
    let repaired = stream
        .get("active_error_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count == 0);
    if !repaired {
        reasons.insert(
            "decision_stream".to_owned(),
            "decision_stream_degraded".to_owned(),
        );
        record_incomplete(repair.guard_home, &reasons);
    }
    let mut body = Map::new();
    body.insert("repaired".into(), repaired.into());
    body.insert("repair_scope".into(), "local_integrity".into());
    body.insert(
        "check_ids".into(),
        if repaired {
            json!(["decision_stream"])
        } else {
            json!([])
        },
    );
    if !repaired {
        body.insert("failed_check_ids".into(), json!(["decision_stream"]));
    }
    body.insert("check_reasons".into(), json!(reasons));
    body.insert(
        "message".into(),
        Value::from(if repaired {
            "Command evidence is healthy."
        } else {
            "Guard could not restore command evidence persistence."
        }),
    );
    Ok((if repaired { 200 } else { 409 }, Value::Object(body)))
}

/// One `protection_repair_incomplete` line in the daemon log, its detail the
/// sorted `check:reason` pairs. A log that cannot be written is skipped.
fn record_incomplete(guard_home: &Path, reasons: &BTreeMap<String, String>) {
    let detail = reasons
        .iter()
        .map(|(check, reason)| format!("{check}:{reason}"))
        .collect::<Vec<_>>()
        .join(" ");
    let _ = record_diagnostic(
        guard_home,
        "protection_repair_incomplete",
        (!detail.is_empty()).then_some(detail.as_str()),
    );
}

/// Appends one record to `logs/daemon.log` in the daemon's log format.
pub(in crate::daemon_edge) fn record_diagnostic(
    guard_home: &Path,
    event: &str,
    detail: Option<&str>,
) -> std::io::Result<()> {
    let directory = guard_home.join("logs");
    if directory.is_symlink() {
        return Err(std::io::Error::other("daemon log directory is a link"));
    }
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("daemon.log");
    if path.is_symlink() {
        return Err(std::io::Error::other("daemon log is a link"));
    }
    let mut record = Map::new();
    let timestamp = super::now_isoformat().ok_or_else(|| std::io::Error::other("no clock"))?;
    record.insert("timestamp".into(), timestamp.into());
    record.insert("level".into(), "info".into());
    record.insert("event".into(), event.into());
    if let Some(detail) = detail {
        record.insert("detail".into(), detail.into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
    }
    let mut file = options.open(&path)?;
    // Every field is an ASCII identifier or timestamp, so this matches
    // `json.dumps(..., ensure_ascii=True, separators=(",", ":"))`.
    let mut line = serde_json::to_string(&Value::Object(record)).map_err(std::io::Error::other)?;
    line.push('\n');
    file.write_all(line.as_bytes())
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_protection_repair_tests.rs"]
mod tests;
