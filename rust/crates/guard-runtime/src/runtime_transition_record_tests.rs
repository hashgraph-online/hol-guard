use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Value};

use super::run_command;

const OPERATION: &str = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9";

struct Home {
    _root: tempfile::TempDir,
    path: PathBuf,
}

fn home() -> Home {
    let root = tempfile::tempdir().expect("root");
    let path = fs::canonicalize(root.path())
        .expect("canonical")
        .join("guard");
    fs::create_dir_all(&path).expect("home");
    Home { _root: root, path }
}

fn ask(home: &Home, op: &str, extra: Value) -> Value {
    let mut request = json!({
        "schema": "runtime-transition-record.v1",
        "op": op,
        "guard_home": home.path.to_str(),
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&[9_u8; 32]),
        "integrity_key_id": "k1",
    });
    for (key, value) in extra.as_object().expect("extra") {
        request[key] = value.clone();
    }
    let bytes = serde_json::to_vec(&request).expect("request");
    serde_json::from_slice(&run_command(bytes.as_slice()).expect("answer")).expect("json")
}

fn identity(path: &str) -> Value {
    json!({
        "version": "1.0.0",
        "source_commit": "abc",
        "target": "aarch64-apple-darwin",
        "format": "macho",
        "sha256": "a".repeat(64),
        "path": path,
        "generation": "g1",
    })
}

fn record(home: &Home) -> Value {
    json!({
        "schema": "hol-guard.runtime-transition.v1",
        "guard_home": home.path.to_str(),
        "operation_id": OPERATION,
        "files": [{
            "path": home.path.join("bin").join("hol-guard").to_str(),
            "before": null,
            "after": "b".repeat(64),
            "before_mode": 0o755,
            "after_mode": 0o755,
            "kind": "binding",
        }],
        "managed_installs": [],
        "candidate": identity("/opt/guard/new"),
        "predecessor": identity("/opt/guard/old"),
        "deadline_epoch": 1.5,
        "deadline_monotonic": 2.0,
        "forward_expires_epoch": 3,
        "forward_expires_monotonic": 4.25,
    })
}

fn journal(home: &Home) -> PathBuf {
    home.path.join("managed").join("runtime-transition.json")
}

#[test]
fn a_written_record_reads_back_without_its_signature() {
    let home = home();
    let payload = record(&home);
    assert_eq!(
        ask(&home, "write", json!({"payload": payload})),
        json!({"ok": true})
    );
    let mode = fs::metadata(journal(&home))
        .expect("journal")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let text = fs::read_to_string(journal(&home)).expect("text");
    assert!(text.ends_with("}\n") && text.contains("\"authentication\""));
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["payload"], payload);
}

#[test]
fn a_changed_record_or_another_key_is_unauthenticated() {
    let home = home();
    ask(&home, "write", json!({"payload": record(&home)}));
    let other_key = json!({
        "operation_id": OPERATION,
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&[8_u8; 32]),
    });
    assert_eq!(
        ask(&home, "read", other_key)["error"],
        "record_unauthenticated"
    );
    let text = fs::read_to_string(journal(&home)).expect("text");
    fs::write(journal(&home), text.replace("1.5", "9.5")).expect("tamper");
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "record_unauthenticated");
    fs::write(journal(&home), "{not json").expect("garbage");
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "record_invalid");
}

#[test]
fn a_record_for_another_operation_or_home_is_refused() {
    let home = home();
    ask(&home, "write", json!({"payload": record(&home)}));
    let other = json!({"operation_id": "ffffffff-4f50-4617-8293-a4b5c6d7e8f9"});
    assert_eq!(ask(&home, "read", other)["error"], "operation_superseded");
    let mut payload = record(&home);
    payload["guard_home"] = json!("/elsewhere");
    ask(&home, "write", json!({"payload": payload}));
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "record_context_mismatch");
}

#[test]
fn a_signed_record_with_a_bad_shape_is_still_refused() {
    let home = home();
    let mut payload = record(&home);
    payload["files"][0]["after_mode"] = json!(0o777);
    ask(&home, "write", json!({"payload": payload}));
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "file_mode_invalid");
    assert!(answer["detail"]
        .as_str()
        .is_some_and(|path| path.ends_with("hol-guard")));
    let mut payload = record(&home);
    payload["files"] = json!([]);
    ask(&home, "write", json!({"payload": payload}));
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "plan_invalid");
}

#[test]
fn a_missing_record_or_key_is_reported_plainly() {
    let home = home();
    let answer = ask(&home, "read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "record_unavailable");
    let answer = ask(
        &home,
        "write",
        json!({"payload": record(&home), "integrity_key_b64": null}),
    );
    assert_eq!(answer["error"], "signing_authority_unavailable");
    assert!(!journal(&home).exists());
}

#[test]
fn retire_keeps_one_readable_previous_record() {
    let home = home();
    ask(&home, "write", json!({"payload": record(&home)}));
    assert_eq!(ask(&home, "retire", json!({})), json!({"ok": true}));
    assert!(!journal(&home).exists());
    let answer = ask(
        &home,
        "read",
        json!({"operation_id": OPERATION, "previous": true}),
    );
    assert_eq!(answer["payload"]["operation_id"], OPERATION);
    let previous = journal(&home).with_file_name("runtime-transition.previous.json");
    fs::set_permissions(&previous, fs::Permissions::from_mode(0o666)).expect("mode");
    ask(&home, "write", json!({"payload": record(&home)}));
    assert_eq!(
        ask(&home, "retire", json!({}))["error"],
        "previous_record_unsafe"
    );
    assert!(journal(&home).exists());
}

fn refusal(home: &Home, operation: &str) -> Value {
    ask(
        home,
        "refusal_write",
        json!({
            "operation_id": operation,
            "artifact_generation": "c".repeat(64),
            "reason_code": "approval_denied",
            "deadline_seconds": 5.0,
        }),
    )
}

#[test]
fn a_refusal_receipt_is_written_once_and_reads_back() {
    let home = home();
    assert_eq!(refusal(&home, OPERATION), json!({"ok": true}));
    let directory = home.path.join("managed").join("runtime-refusals");
    let mode = fs::metadata(&directory).expect("dir").permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    let answer = ask(&home, "refusal_read", json!({"operation_id": OPERATION}));
    assert_eq!(
        answer,
        json!({"artifact_generation": "c".repeat(64), "reason_code": "approval_denied"})
    );
    assert_eq!(refusal(&home, OPERATION)["error"], "refusal_exists");
    let upper = OPERATION.to_uppercase();
    assert_eq!(refusal(&home, &upper)["error"], "operation_id_invalid");
}

#[test]
fn a_pending_transition_blocks_refusal_receipts() {
    let home = home();
    ask(&home, "write", json!({"payload": record(&home)}));
    assert_eq!(refusal(&home, OPERATION)["error"], "pending_transition");
    let answer = ask(&home, "refusal_read", json!({"operation_id": OPERATION}));
    assert_eq!(answer["error"], "pending_transition");
}

#[test]
fn a_shared_refusal_directory_is_refused() {
    let home = home();
    let directory = home.path.join("managed").join("runtime-refusals");
    fs::create_dir_all(&directory).expect("dir");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("mode");
    assert_eq!(
        refusal(&home, OPERATION)["error"],
        "refusal_directory_unsafe"
    );
}

#[test]
fn an_unknown_request_is_refused() {
    let answer: Value =
        serde_json::from_slice(&run_command(&b"{\"schema\":\"x\"}"[..]).expect("answer"))
            .expect("json");
    assert_eq!(answer["error"], "invalid");
}

fn phased(home: &Home, phase: &str) -> Value {
    let mut payload = record(home);
    payload["phase"] = json!(phase);
    payload["owner"] = json!({"pid": 7, "start": "s"});
    payload["first_cause"] = Value::Null;
    payload["recovery_causes"] = json!([]);
    payload["deadline_monotonic"] = json!(100.0);
    payload["forward_expires_monotonic"] = json!(50.0);
    ask(home, "write", json!({"payload": payload.clone()}));
    payload
}

fn step(home: &Home, op: &str, step: &str, extra: Value) -> Value {
    let mut fields = json!({
        "operation_id": OPERATION,
        "step": step,
        "owner": {"pid": 7, "start": "s"},
        "now": 10.0,
    });
    for (key, value) in extra.as_object().expect("extra") {
        fields[key] = value.clone();
    }
    ask(home, op, fields)
}

#[test]
fn advance_names_its_comparisons_and_moves_one_phase() {
    let home = home();
    phased(&home, "AuthorizedForExactTransition");
    let expected = json!({"expected_phase": "AuthorizedForExactTransition"});
    let plan = step(&home, "step_check", "advance", expected.clone());
    assert_eq!(plan["grant"], true);
    assert_eq!(plan["installs"], "after");
    assert_eq!(plan["compare"][0]["generation"], "after");
    assert_eq!(
        plan["compare"][0]["files"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(plan["compare"][1]["files"], json!([]));
    let answer = step(&home, "step_commit", "advance", expected.clone());
    assert_eq!(answer, json!({"phase": "HooksPrepared"}));
    let again = step(&home, "step_commit", "advance", expected);
    assert_eq!(again["error"], "phase_changed");
}

#[test]
fn advance_refuses_another_owner_and_a_passed_deadline() {
    let home = home();
    phased(&home, "HooksPrepared");
    let expected = json!({"expected_phase": "HooksPrepared", "owner": {"pid": 8}});
    let answer = step(&home, "step_check", "advance", expected);
    assert_eq!(answer["error"], "forward_owner_changed");
    let late = json!({"expected_phase": "HooksPrepared", "now": 60.0});
    let answer = step(&home, "step_check", "advance", late);
    assert_eq!(answer["error"], "forward_authorization_expired");
    let later = json!({"expected_phase": "HooksPrepared", "now": 200.0});
    assert_eq!(
        step(&home, "step_check", "advance", later)["error"],
        "deadline_exceeded"
    );
}

#[test]
fn a_switch_needs_a_matching_functional_observation() {
    let home = home();
    phased(&home, "Switching");
    let expected = json!({"expected_phase": "Switching"});
    let answer = step(&home, "step_check", "advance", expected);
    assert_eq!(answer["error"], "functional_proof_missing");
}

#[test]
fn recovery_keeps_the_first_cause_and_the_last_eight_causes() {
    let home = home();
    phased(&home, "Switching");
    let first = json!({"first_cause": "x".repeat(600)});
    let answer = step(&home, "step_commit", "prepare_recovery", first);
    assert_eq!(answer["phase"], "RestoringPrevious");
    for index in 0..10 {
        let cause = json!({"cause": {"code": format!("c{index}"), "errno": null}});
        step(&home, "step_commit", "restore_failed", cause);
    }
    let payload = ask(&home, "read", json!({"operation_id": OPERATION}))["payload"].clone();
    assert_eq!(payload["phase"], "RecoveryRequired");
    assert_eq!(payload["first_cause"].as_str().map(str::len), Some(512));
    assert_eq!(payload["recovery_owner"], json!({"pid": 7, "start": "s"}));
    let causes = payload["recovery_causes"].as_array().expect("causes");
    assert_eq!(causes.len(), 8);
    assert_eq!(causes[7]["code"], "c9");
    let stranger = json!({"owner": {"pid": 9}, "cause": {"code": "e", "errno": 5}});
    let answer = step(&home, "step_commit", "recovery_failure", stranger);
    assert_eq!(answer["error"], "recovery_owner_changed");
}

#[test]
fn a_daemon_step_outside_the_plan_is_refused() {
    let home = home();
    let mut payload = phased(&home, "HooksPrepared");
    payload["authorized_subject"] = json!("subject");
    ask(&home, "write", json!({"payload": payload}));
    let other = json!({"subject": "other", "side": "predecessor", "action": "stop"});
    assert_eq!(
        step(&home, "step_check", "daemon_step", other)["error"],
        "plan_context_mismatch"
    );
    let planned = json!({"subject": "subject", "side": "predecessor", "action": "stop"});
    assert_eq!(
        step(&home, "step_check", "daemon_step", planned)["grant"],
        true
    );
    let unplanned = json!({"subject": "subject", "side": "candidate", "action": "stop"});
    assert_eq!(
        step(&home, "step_check", "daemon_step", unplanned)["error"],
        "daemon_step_not_authorized"
    );
}

fn begin(home: &Home, op: &str, extra: Value) -> Value {
    let mut plan = record(home);
    plan["deadline_epoch"] = json!(1030.0);
    let mut fields = json!({
        "payload": plan,
        "now": 10.0,
        "now_epoch": 1000.0,
        "owner": {"pid": 7, "start": "s"},
        "installer_operation_id": "install-1",
        "subject": "runtime:g1",
        "approval_required": true,
        "grant_expires_epoch": 1020.0,
    });
    for (key, value) in extra.as_object().expect("extra") {
        fields[key] = value.clone();
    }
    ask(home, op, fields)
}

#[test]
fn begin_writes_the_first_journal_until_the_earlier_expiry() {
    let home = home();
    assert_eq!(begin(&home, "begin_check", json!({}))["deadline"], 40.0);
    let capped = json!({"deadline_monotonic": 25.0});
    assert_eq!(begin(&home, "begin_check", capped)["deadline"], 25.0);
    assert_eq!(begin(&home, "begin_commit", json!({}))["ok"], true);
    let written = ask(&home, "read", json!({"operation_id": OPERATION}));
    let payload = &written["payload"];
    assert_eq!(payload["phase"], "AuthorizedForExactTransition");
    assert_eq!(payload["forward_expires_epoch"], 1020.0);
    assert_eq!(payload["forward_expires_monotonic"], 30.0);
    assert_eq!(payload["deadline_monotonic"], 40.0);
    assert_eq!(payload["installer_operation_id"], "install-1");
    assert_eq!(payload["recovery_causes"], json!([]));
    let again = begin(&home, "begin_check", json!({}));
    assert_eq!(again["error"], "pending_transition");
}

#[test]
fn begin_refuses_bad_deadlines_owners_and_reserved_targets() {
    let home = home();
    let late = json!({"now_epoch": 960.0});
    assert_eq!(
        begin(&home, "begin_check", late)["error"],
        "deadline_invalid"
    );
    let passed = json!({"deadline_monotonic": 10.0});
    assert_eq!(
        begin(&home, "begin_check", passed)["error"],
        "deadline_exceeded"
    );
    let nobody = json!({"owner": null});
    assert_eq!(
        begin(&home, "begin_commit", nobody)["error"],
        "owner_identity_unavailable"
    );
    let mut plan = record(&home);
    plan["deadline_epoch"] = json!(1030.0);
    plan["files"][0]["path"] = json!(journal(&home).to_str());
    let reserved = begin(&home, "begin_check", json!({"payload": plan}));
    assert_eq!(reserved["error"], "authority_target_forbidden");
    let mut elsewhere = record(&home);
    elsewhere["deadline_epoch"] = json!(1030.0);
    elsewhere["guard_home"] = json!("/elsewhere");
    let other = begin(&home, "begin_check", json!({"payload": elsewhere}));
    assert_eq!(other["error"], "plan_context_mismatch");
    assert!(!journal(&home).exists());
}
