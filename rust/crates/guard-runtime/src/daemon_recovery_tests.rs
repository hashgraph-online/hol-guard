use std::io::{BufReader, Read, Write};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use serde_json::{json, Value};

use super::run_session;

struct ChannelReader {
    lines: Receiver<String>,
    pending: Vec<u8>,
}

impl Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.pending.is_empty() {
            match self.lines.recv() {
                Ok(line) => self.pending = line.into_bytes(),
                Err(_) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len());
        buffer[..count].copy_from_slice(&self.pending[..count]);
        self.pending.drain(..count);
        Ok(count)
    }
}

struct ChannelWriter {
    lines: Sender<String>,
    buffer: Vec<u8>,
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(data);
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let _ = self.lines.send(String::from_utf8_lossy(&line).into_owned());
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const HOME: &str = "/private/tmp/hg-recovery-home";

fn identity(pid: i64) -> Value {
    json!({
        "pid": pid,
        "generation": "gen-1",
        "runtime": "rt-1",
        "guard_home": HOME,
        "user": "uid:501",
        "start_marker": "mark-1",
        "handle": pid,
    })
}

fn ready_service() -> Value {
    json!({
        "service": "ready",
        "reason_code": "healthy",
        "identity": identity(41),
        "process_running": true,
        "authenticated": true,
        "dashboard_ready": true,
        "protection": "verified",
        "checks": [],
    })
}

fn inspection(service: Value, posture: &str) -> Value {
    json!({"service": service, "posture": posture, "update_busy": false})
}

/// Run one session; `answer` maps each need to the caller's reply.
fn session(
    request: Value,
    mut answer: impl FnMut(&str, &Value) -> Value + Send + 'static,
) -> (Value, Vec<String>) {
    let (to_runtime, runtime_input) = channel::<String>();
    let (runtime_output, from_runtime) = channel::<String>();
    let worker = thread::spawn(move || {
        let reader = BufReader::new(ChannelReader {
            lines: runtime_input,
            pending: Vec::new(),
        });
        let writer = ChannelWriter {
            lines: runtime_output,
            buffer: Vec::new(),
        };
        run_session(reader, writer)
    });
    to_runtime.send(format!("{request}\n")).expect("request");
    let mut needs = Vec::new();
    let reply = loop {
        let line = from_runtime.recv().expect("runtime line");
        let message: Value = serde_json::from_str(line.trim()).expect("json");
        let Some(need) = message.get("need").and_then(Value::as_str) else {
            break message;
        };
        needs.push(need.to_owned());
        let response = answer(need, &message["args"]);
        to_runtime.send(format!("{response}\n")).expect("answer");
    };
    worker.join().expect("join").expect("session");
    (reply, needs)
}

fn run_request() -> Value {
    json!({
        "schema": "daemon-recovery.v1",
        "mode": "run",
        "guard_home": HOME,
        "active_budget_seconds": 60.0,
        "lock_timeout_seconds": 1.0,
        "can_persist": true,
        "operation": {
            "operation_id": "6f1c1f1e-8a7b-4c2d-9e0f-1a2b3c4d5e6f",
            "request_id": "6f1c1f1e-8a7b-4c2d-9e0f-1a2b3c4d5e6f",
            "started_at": "2026-11-10T00:00:00+00:00",
            "started_monotonic": 10.0,
            "deadline_monotonic": 10.0,
            "sequence": -1,
        },
    })
}

fn common(need: &str) -> Option<Value> {
    Some(match need {
        "clock" => json!({"ok": 11.0}),
        "wall" => json!({"ok": "2026-11-10T00:00:01+00:00"}),
        "user_marker" => json!({"ok": "uid:501"}),
        "authorize" => {
            json!({"ok": {"allowed": true, "requires_human_action": false, "reason_code": "healthy"}})
        }
        "lock" | "release" | "emit" | "record" => json!({"ok": null}),
        "load_receipt" => json!({"ok": null}),
        "load_snapshot" => json!({"ok": {"kind": "none"}}),
        "posture" => json!({"ok": "on"}),
        "update_busy" => json!({"ok": false}),
        _ => return None,
    })
}

#[test]
fn inspect_mode_reports_a_ready_service() {
    let request = json!({"schema": "daemon-recovery.v1", "mode": "inspect", "guard_home": HOME});
    let (reply, needs) = session(request, |need, _| {
        if need == "inspect" {
            return json!({"ok": inspection(ready_service(), "on")});
        }
        common(need).expect("need")
    });
    let snapshot = &reply["done"];
    assert_eq!(snapshot["phase"], "checking");
    assert_eq!(snapshot["retryAllowed"], true);
    assert_eq!(snapshot["protection"], "verified");
    assert_eq!(snapshot["operationId"], Value::Null);
    assert_eq!(needs, ["inspect", "wall", "wall"]);
}

#[test]
fn run_reconnects_a_ready_service_and_completes() {
    let (reply, needs) = session(run_request(), |need, _| match need {
        "inspect" => json!({"ok": inspection(ready_service(), "on")}),
        "verify_ready" => {
            json!({"ok": {"ready": true, "identity": identity(41), "reason_code": "healthy"}})
        }
        "protection_health" => json!({"ok": {"state": "verified", "reason_code": "healthy"}}),
        other => common(other).expect("need"),
    });
    let snapshot = &reply["done"];
    assert_eq!(snapshot["phase"], "complete");
    assert_eq!(snapshot["outcome"], "reconnected");
    assert_eq!(snapshot["workerActive"], false);
    assert_eq!(reply["state"]["unresolved_owner"], false);
    let releases: Vec<_> = needs.iter().filter(|need| *need == "release").collect();
    assert_eq!(releases.len(), 1);
}

#[test]
fn run_reports_a_busy_owner_when_the_lock_times_out() {
    let (reply, _) = session(run_request(), |need, _| match need {
        "inspect" => json!({"ok": inspection(ready_service(), "on")}),
        "lock" => json!({"raise": "lock_timeout"}),
        other => common(other).expect("need"),
    });
    let snapshot = &reply["done"];
    assert_eq!(snapshot["phase"], "waiting_for_owner");
    assert_eq!(snapshot["reasonCode"], "operation_busy");
}

#[test]
fn run_stops_before_mutation_when_protection_is_off() {
    let (reply, needs) = session(run_request(), |need, _| match need {
        "inspect" => json!({"ok": inspection(ready_service(), "off")}),
        other => common(other).expect("need"),
    });
    assert_eq!(reply["done"]["phase"], "needs_action");
    assert_eq!(reply["done"]["reasonCode"], "protection_off");
    assert!(!needs
        .iter()
        .any(|need| need == "authorize" || need == "lock"));
}

#[test]
fn an_initial_inspection_error_is_reraised() {
    let (reply, _) = session(run_request(), |need, _| match need {
        "inspect" => json!({"raise": "value"}),
        other => common(other).expect("need"),
    });
    assert_eq!(reply["reraise"], true);
}

#[test]
fn replace_times_out_when_the_old_worker_exit_is_unconfirmed() {
    let unresponsive = json!({
        "service": "unavailable",
        "reason_code": "service_unresponsive",
        "identity": identity(41),
        "process_running": true,
    });
    let (reply, needs) = session(run_request(), move |need, _| match need {
        "inspect" => json!({"ok": inspection(unresponsive.clone(), "on")}),
        "stop" => {
            json!({"ok": {"exit_confirmed": false, "reason_code": "worker_exit_unconfirmed"}})
        }
        "process_dead" => json!({"ok": false}),
        other => common(other).expect("need"),
    });
    assert_eq!(reply["done"]["phase"], "timed_out_waiting");
    assert_eq!(reply["state"]["unresolved_owner"], true);
    assert_eq!(reply["state"]["unresolved_identity"]["handle"], 41);
    let releases: Vec<_> = needs
        .iter()
        .enumerate()
        .filter(|(_, need)| *need == "release")
        .collect();
    assert_eq!(releases.len(), 2);
}

#[test]
fn an_invalid_terminal_snapshot_falls_back_to_unknown() {
    let request = json!({
        "schema": "daemon-recovery.v1",
        "mode": "snapshot",
        "guard_home": HOME,
        "fields": {
            "operation_id": "6f1c1f1e-8a7b-4c2d-9e0f-1a2b3c4d5e6f",
            "phase": "complete",
            "outcome": "pending",
            "service": "ready",
            "started_at": "2026-11-10T00:00:00+00:00",
        },
    });
    let (reply, _) = session(request, |need, _| common(need).expect("need"));
    assert_eq!(reply["done"]["phase"], "needs_action");
    assert_eq!(reply["done"]["requiresHumanAction"], true);
}
