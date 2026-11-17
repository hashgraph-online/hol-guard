use super::super::super::{NativeReads, HANDSHAKE_SCHEMA};
use super::super::{plugin_update_dismiss, plugin_version_valid, requests_clear};
use super::*;
use crate::guard_store_approval_reads::tests::seed;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_page_read_vectors.json");
const REQUEST_ID: &str = "daemon-edge-ag-7";
const DIGEST: &str = "sha256:abc";

fn config(home: &Path, session_signals: Option<Value>) -> ReadConfig {
    let mut handshake = json!({
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": "gate-test-value",
        "guard_home": home.to_str().unwrap(),
        "store_path": home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    if let Some(signals) = session_signals {
        handshake["session_signals"] = signals;
    }
    ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap()
}

fn result(status: &str, extra: Value) -> Value {
    let mut envelope = json!({
        "schema": APPROVAL_GATE_RESULT_SCHEMA,
        "request_id": REQUEST_ID,
        "request_sha256": DIGEST,
        "status": status,
        "code": "ok",
    });
    envelope
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    envelope
}

fn refusal(status: u16, error: &str, message: &str) -> Gate {
    let Value::Object(body) = json!({"error": error, "message": message}) else {
        unreachable!()
    };
    Gate::Refused(status, body)
}

#[test]
fn reads_the_resident_answer_as_the_daemon_client_does() {
    let read = |envelope: Value| answer(&envelope, REQUEST_ID, DIGEST, true, true);
    assert_eq!(
        read(result("ok", json!({"payload": {"grant": null}}))),
        Some(Gate::Passed(None))
    );
    let grant = json!({
        "grant_id": "g", "purpose": "settings_write", "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:05:00Z", "action": "", "scope": "", "subject": "",
        "session_nonce": "", "factor_set": ["password"], "strict": false,
        "used_cooldown": false, "password_verified": true, "totp_verified": false,
    });
    assert_eq!(
        read(result("ok", json!({"payload": {"grant": grant.clone()}}))),
        Some(Gate::Passed(Some(Box::new(
            serde_json::from_value(grant).unwrap()
        ))))
    );
    // A consumer check passes on any answer the resident accepted.
    assert_eq!(
        answer(
            &result("ok", json!({"payload": {"ok": true}})),
            REQUEST_ID,
            DIGEST,
            true,
            false
        ),
        Some(Gate::Passed(None))
    );
    assert_eq!(
        read(result(
            "error",
            json!({"code": "approval_password_invalid", "message": "Wrong password.", "error_status": 401})
        )),
        Some(refusal(401, "approval_password_invalid", "Wrong password."))
    );
    assert_eq!(
        read(result("error", json!({"code": "", "message": null}))),
        Some(refusal(
            403,
            "approval_gate_required",
            "Approval gate check failed."
        ))
    );
    let unavailable = Some(unavailable());
    for envelope in [
        result("ok", json!({"payload": {}})),
        result("ok", json!({"payload": {"grant": "g"}})),
        result("ok", json!({"payload": {"grant": {"grant_id": "g"}}})),
        result("ok", json!({})),
        result("denied", json!({"payload": {"grant": null}})),
        result("error", json!({"code": 1})),
        result("error", json!({"error_status": 70_000})),
        result(
            "ok",
            json!({"request_id": "other", "payload": {"grant": null}}),
        ),
        result(
            "ok",
            json!({"request_sha256": "sha256:def", "payload": {"grant": null}}),
        ),
        result("ok", json!({"schema": "other", "payload": {"grant": null}})),
        json!({"error": "native_overloaded", "retryable": true}),
        json!([]),
    ] {
        assert_eq!(read(envelope.clone()), unavailable, "{envelope}");
    }
}

#[test]
fn an_unprovisioned_resident_passes_only_an_unset_gate() {
    let envelope = json!({"error": "native_policy_verifier_key_missing", "retryable": false});
    assert_eq!(
        answer(&envelope, REQUEST_ID, DIGEST, false, true),
        Some(Gate::Passed(None))
    );
    assert_eq!(
        answer(&envelope, REQUEST_ID, DIGEST, true, true),
        Some(unavailable())
    );
}

#[test]
fn without_the_daemon_session_the_daemon_checks_the_gate() {
    let home = temp_home("edge-gate-no-session");
    std::fs::write(home.join(STATE_FILE), "{}").unwrap();
    for signals in [None, Some(json!([])), Some(json!([""]))] {
        assert_eq!(
            require_high_risk("queue_clear", &Map::new(), &config(&home, signals)),
            None
        );
    }
}

#[test]
fn a_missing_resident_fails_closed_only_once_the_gate_is_set_up() {
    let home = temp_home("edge-gate-no-resident");
    let config = config(&home, Some(json!(["sid=1"])));
    assert_eq!(
        require_high_risk("queue_clear", &Map::new(), &config),
        Some(Gate::Passed(None))
    );
    std::fs::write(home.join(STATE_FILE), "{}").unwrap();
    assert_eq!(
        require_high_risk("queue_clear", &Map::new(), &config),
        Some(unavailable())
    );
}

#[test]
fn clears_the_queue_only_through_the_gate() {
    let home = temp_home("edge-gate-requests-clear");
    let config = config(&home, Some(json!(["sid=1"])));
    let reads = NativeReads::new(None);
    let clear = |body: Value| requests_clear(body.as_object().unwrap(), &config, &reads);
    assert_eq!(
        clear(json!({"status": "open"})),
        Some((
            400,
            json!({"error": "invalid_status", "cleared": 0, "status": "open"})
        ))
    );
    // An unset gate with no resident passes, as the daemon's client does.
    assert!(clear(json!({})).is_some());
    std::fs::write(home.join(STATE_FILE), "{}").unwrap();
    assert_eq!(
        clear(json!({"status": "resolved", "harness": "codex"})),
        Some((
            503,
            json!({
                "error": "native_approval_gate_unavailable",
                "message": "The native approval authority did not answer. Retry the approval.",
                "cleared": 0,
                "status": "resolved",
            })
        ))
    );
}

#[test]
fn the_clear_op_drops_matching_requests_and_their_resumes() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "page_mixed")
        .unwrap()
        .clone();
    let home = temp_home("edge-gate-clear-op");
    let store = home.join("guard.db");
    seed(&store, &vectors, &scenario);
    let config = config(&home, None);
    let reads = NativeReads::new(None);
    let connection = rusqlite::Connection::open(&store).unwrap();
    let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
    let pending = count("select count(*) from approval_requests where status = 'pending'");
    let total = count("select count(*) from approval_requests");
    assert!(pending > 0 && total > pending);
    connection
        .execute(
            "insert into guard_request_resumes (request_id, harness, strategy, status,
                 created_at, updated_at)
             select request_id, harness, 'manual-only', 'skipped', 't1', 't2'
             from approval_requests",
            [],
        )
        .unwrap();
    let cleared = reads.store_call(
        &config,
        "clear_approval_requests",
        json!({"harness": null, "status": "pending"}),
    );
    assert_eq!(cleared, Some(json!(pending)));
    assert_eq!(
        count("select count(*) from approval_requests"),
        total - pending
    );
    assert_eq!(
        count("select count(*) from guard_request_resumes"),
        total - pending
    );
    assert_eq!(
        reads.store_call(&config, "clear_approval_requests", json!({})),
        Some(json!(total - pending))
    );
    assert_eq!(count("select count(*) from guard_request_resumes"), 0);
}

#[test]
fn dismisses_a_plugin_update_as_the_daemon_does() {
    let home = temp_home("edge-plugin-dismiss");
    let config = config(&home, None);
    let dismiss = |body: Value| plugin_update_dismiss(body.as_object().unwrap(), &config);
    let invalid = (
        400,
        json!({
            "error": "invalid_plugin_update",
            "message": "Name the listing slug and the version to dismiss.",
        }),
    );
    for body in [
        json!({}),
        json!({"slug": " ", "version": "1.0.0"}),
        json!({"slug": "a".repeat(257), "version": "1.0.0"}),
        json!({"slug": "demo", "version": "-1"}),
        json!({"slug": "demo", "version": "1 0"}),
        json!({"slug": "demo", "version": 1}),
    ] {
        assert_eq!(dismiss(body.clone()), invalid, "{body}");
    }
    assert_eq!(
        dismiss(json!({"slug": " demo ", "version": " 1.2.0+b_1 "})),
        (
            200,
            json!({"slug": "demo", "version": "1.2.0+b_1", "dismissed": true})
        )
    );
}

#[test]
fn checks_plugin_versions_as_the_daemon_pattern_does() {
    assert!(plugin_version_valid("a"));
    assert!(plugin_version_valid(&"1".repeat(64)));
    assert!(!plugin_version_valid(&"1".repeat(65)));
    assert!(!plugin_version_valid(""));
    assert!(!plugin_version_valid(".1"));
    assert!(!plugin_version_valid("1/2"));
    assert!(!plugin_version_valid("1é"));
}
