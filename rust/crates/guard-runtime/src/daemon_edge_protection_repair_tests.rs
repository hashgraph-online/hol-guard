use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

fn answers(
    home: &Path,
    steps: &[(&str, Value)],
    body: Value,
) -> (Option<(u16, Value)>, Vec<String>) {
    let mut by_name: HashMap<String, Vec<Value>> = HashMap::new();
    for (name, answer) in steps {
        by_name
            .entry((*name).to_owned())
            .or_default()
            .push(answer.clone());
    }
    let mut seen = Vec::new();
    let mut call = |name: &str, _args: Value| {
        seen.push(name.to_owned());
        let queue = by_name.get_mut(name).filter(|queue| !queue.is_empty());
        match queue {
            Some(queue) if queue.len() == 1 => Ok(queue[0].clone()),
            Some(queue) => Ok(queue.remove(0)),
            None => Err(CallError::Unavailable),
        }
    };
    let Value::Object(payload) = body else {
        unreachable!()
    };
    let reply = run(
        &payload,
        &mut Repair {
            call: &mut call,
            guard_home: home,
        },
        4100,
    );
    (reply, seen)
}

fn pass_signals() -> Value {
    json!({"signals": {
        "decision_plane_compatibility": {"status": "pass", "reason_code": "ok"},
        "containment_compatibility": {"status": "pass", "reason_code": "ok"},
        "sandbox": {"status": "pass", "reason_code": "ok"},
    }})
}

fn healthy_all() -> Vec<(&'static str, Value)> {
    vec![
        (
            "repair.daemon_registration",
            json!({"session_id": "s1", "expected": "s1"}),
        ),
        (
            "repair.policy_integrity",
            json!({"failed": false, "mode": "protected", "reason_count": 0}),
        ),
        (
            "repair.harness_hooks",
            json!({"failures": [], "unknown": false, "has_active_hooks": true}),
        ),
        ("repair.containment_signals", pass_signals()),
        (
            "repair.decision_stream",
            json!({"unavailable": false, "active_error_count": 0}),
        ),
    ]
}

fn log(home: &Path) -> String {
    std::fs::read_to_string(home.join("logs/daemon.log")).unwrap_or_default()
}

#[test]
fn a_full_repair_confirms_every_check() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let (reply, _) = answers(home.path(), &healthy_all(), json!({"check_id": " all "}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 200);
    assert_eq!(body["repaired"], true);
    assert_eq!(
        body["check_ids"],
        json!([
            "daemon",
            "policy_engine",
            "rule_packs",
            "tamper_checks",
            "harness_hooks",
            "decision_plane_compatibility",
            "containment_compatibility",
            "sandbox",
            "decision_stream"
        ])
    );
    assert_eq!(body["message"], "Integrity protection restored.");
    assert!(body.get("failed_check_ids").is_none());
    assert_eq!(log(home.path()), "");
}

#[test]
fn a_full_repair_with_no_connected_app_asks_for_one_and_logs_why() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let mut steps = healthy_all();
    steps[2] = (
        "repair.harness_hooks",
        json!({"failures": [], "unknown": false, "has_active_hooks": false}),
    );
    let (reply, _) = answers(home.path(), &steps, json!({"check_id": "all"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(body["error"], "protection_repair_incomplete");
    assert_eq!(body["failed_check_ids"], json!(["harness_hooks"]));
    assert_eq!(
        body["check_reasons"],
        json!({"harness_hooks": "no_managed_harness"})
    );
    assert!(body["message"]
        .as_str()
        .unwrap_or_default()
        .starts_with("Connect an AI app"));
    let line: Value = serde_json::from_str(log(home.path()).trim()).unwrap_or_default();
    assert_eq!(line["event"], "protection_repair_incomplete");
    assert_eq!(line["detail"], "harness_hooks:no_managed_harness");
}

#[test]
fn containment_retries_until_it_passes_and_skips_unsupported_platforms() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let mut steps = healthy_all();
    steps.remove(3);
    steps.push((
        "repair.containment_signals",
        json!({"signals": {
            "decision_plane_compatibility": {"status": "fail", "reason_code": "stale"},
            "containment_compatibility": {"status": "pass", "reason_code": "ok"},
            "sandbox": {"status": "fail", "reason_code": "unsupported_platform"},
        }}),
    ));
    steps.push((
        "repair.containment_signals",
        json!({"signals": {
            "decision_plane_compatibility": {"status": "pass", "reason_code": "ok"},
            "containment_compatibility": {"status": "pass", "reason_code": "ok"},
            "sandbox": {"status": "fail", "reason_code": "unsupported_platform"},
        }}),
    ));
    let (reply, seen) = answers(home.path(), &steps, json!({"check_id": "all"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        seen.iter()
            .filter(|name| *name == "repair.containment_signals")
            .count(),
        2
    );
    let checks = body["check_ids"].as_array().cloned().unwrap_or_default();
    assert!(!checks.contains(&json!("sandbox")));
    assert!(checks.contains(&json!("decision_plane_compatibility")));
}

#[test]
fn unavailable_containment_fails_each_check() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let mut steps = healthy_all();
    steps[3] = ("repair.containment_signals", json!({"signals": null}));
    let (reply, seen) = answers(home.path(), &steps, json!({"check_id": "all"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(
        seen.iter()
            .filter(|name| *name == "repair.containment_signals")
            .count(),
        3
    );
    assert_eq!(
        body["check_reasons"]["sandbox"],
        "containment_health_unavailable"
    );
}

#[test]
fn an_integrity_failure_stops_before_any_other_check() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let steps = [("repair.policy_integrity", json!({"failed": true}))];
    let (reply, seen) = answers(home.path(), &steps, json!({"check_id": "rule_packs"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(body["error"], "protection_repair_failed");
    assert_eq!(
        body["check_reasons"]["tamper_checks"],
        "local_integrity_unproven"
    );
    assert_eq!(seen, vec!["repair.policy_integrity"]);
}

#[test]
fn an_unproven_integrity_counts_the_isolated_issues() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let steps = [(
        "repair.policy_integrity",
        json!({"failed": false, "mode": "degraded", "reason_count": 2}),
    )];
    let (reply, _) = answers(home.path(), &steps, json!({"check_id": "policy_engine"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(body["error"], "local_integrity_repair_incomplete");
    assert!(body["message"]
        .as_str()
        .unwrap_or_default()
        .contains("remaining 2 issue"));
    assert_eq!(
        body["failed_check_ids"],
        json!(["policy_engine", "rule_packs", "tamper_checks"])
    );
}

#[test]
fn a_foreign_runtime_row_is_reported_not_overwritten() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let mut steps = healthy_all();
    steps[0] = (
        "repair.daemon_registration",
        json!({"session_id": "other", "expected": "s1"}),
    );
    let (reply, _) = answers(home.path(), &steps, json!({"check_id": "all"}));
    let (_, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(
        body["check_reasons"]["daemon"],
        "daemon_registration_foreign"
    );
}

#[test]
fn the_decision_stream_check_runs_alone() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let steps = [(
        "repair.decision_stream",
        json!({"unavailable": false, "active_error_count": 3}),
    )];
    let (reply, seen) = answers(home.path(), &steps, json!({"check_id": "decision_stream"}));
    let (status, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(body["failed_check_ids"], json!(["decision_stream"]));
    assert_eq!(seen, vec!["repair.decision_stream"]);
    let steps = [("repair.decision_stream", json!({"unavailable": true}))];
    let (reply, _) = answers(home.path(), &steps, json!({"check_id": "decision_stream"}));
    let (_, body) = reply.unwrap_or_else(|| unreachable!());
    assert_eq!(body["error"], "protection_repair_failed");
}

#[test]
fn unknown_checks_and_unreachable_libraries() {
    let home = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
    let (reply, seen) = answers(home.path(), &[], json!({"check_id": "sandbox"}));
    assert_eq!(
        reply,
        Some((400, json!({"error": "unsupported_protection_check"})))
    );
    assert!(seen.is_empty());
    let (reply, _) = answers(home.path(), &[], json!({"check_id": "all"}));
    assert_eq!(reply, None);
}
