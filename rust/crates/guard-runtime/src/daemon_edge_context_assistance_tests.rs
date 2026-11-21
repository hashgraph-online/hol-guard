use std::cell::RefCell;
use std::time::{Duration, Instant};

use super::super::super::HANDSHAKE_SCHEMA;
use super::*;

fn config(session_signals: Option<Value>) -> ReadConfig {
    let home = std::env::temp_dir().join("guard-edge-cigar-routes");
    let mut handshake = json!({
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": "cigar-route-test-value",
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

fn state() -> Value {
    json!({
        "schema": STATUS_SCHEMA,
        "availability": "ready",
        "requested_enabled": true,
        "effective_enabled": true,
        "preferences": {},
        "effective_preferences": {},
        "restriction": null,
        "verification_permitted": true,
        "generation": "g-1",
        "diagnostic": null,
        "runtime": {"persistence_compile_verified": true},
        "last_check": null,
        "qualification": null,
        "capabilities": {"shared_agents": true, "private_persistence": false},
        "installation_options": null,
        "job": null,
    })
}

fn payload(kind: &str, extra: Value) -> Map<String, Value> {
    let mut payload = json!({"kind": kind, "state": state()});
    for (key, value) in extra.as_object().unwrap() {
        payload[key] = value.clone();
    }
    payload.as_object().unwrap().clone()
}

fn body(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// A resident that records each query and answers `answer`.
struct Resident {
    seen: RefCell<Vec<(Value, bool)>>,
}

impl Resident {
    fn new() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
        }
    }

    fn answer(
        &self,
        answer: Result<Map<String, Value>, String>,
    ) -> impl FnOnce(Value, bool) -> Result<Map<String, Value>, String> + '_ {
        move |query, slow| {
            self.seen.borrow_mut().push((query, slow));
            answer
        }
    }
}

#[test]
fn status_answers_the_engine_state_without_caching() {
    let resident = Resident::new();
    let config = config(None);
    let reply = get_with(
        "/v1/context-assistance",
        &config,
        resident.answer(Ok(payload("status", json!({})))),
    )
    .unwrap();
    assert_eq!(reply, (200, state(), true));
    assert_eq!(
        resident.seen.borrow().as_slice(),
        [(json!({"kind": "status", "input": {}}), false)]
    );
}

#[test]
fn control_writes_send_the_whole_body_as_input() {
    let resident = Resident::new();
    let config = config(None);
    let reply = post_with(
        "/v1/context-assistance/activate",
        &body(json!({"confirm": true})),
        &config,
        resident.answer(Ok(payload("activate", json!({})))),
    )
    .unwrap();
    assert_eq!(reply.0, 200);
    assert_eq!(
        resident.seen.borrow()[0].0,
        json!({"kind": "activate", "input": {"confirm": true}})
    );
}

#[test]
fn engine_refusals_keep_their_http_status() {
    for (code, status) in [
        ("native_context_assistance_control_input_invalid", 400),
        ("native_context_assistance_request_invalid", 400),
        ("native_context_assistance_context_scope_denied", 403),
        ("native_context_assistance_disabled", 409),
        ("native_context_assistance_busy", 409),
        ("native_context_assistance_context_resource_limit", 429),
        ("native_context_assistance_unavailable", 503),
        ("native_context_assistance_runtime_retired", 503),
    ] {
        let resident = Resident::new();
        let reply = get_with(
            "/v1/context-assistance/installations",
            &config(None),
            resident.answer(Err(code.to_owned())),
        )
        .unwrap();
        assert_eq!(
            reply,
            (
                status,
                json!({"error": "context_assistance_unavailable", "code": code}),
                true
            ),
            "{code}"
        );
    }
}

#[test]
fn a_malformed_state_is_the_engine_being_unavailable() {
    let mut extra_field = payload("status", json!({}));
    extra_field["state"]["surprise"] = json!(1);
    let mut wrong_schema = payload("status", json!({}));
    wrong_schema["state"]["schema"] = json!("guard-context-assistance-status.v1");
    let mut bad_flag = payload("status", json!({}));
    bad_flag["state"]["runtime"]["execution_handoff_verified"] = json!("yes");
    let mut bad_capability = payload("status", json!({}));
    bad_capability["state"]["capabilities"]["execution_context"] = json!(1);
    let mut extra_payload = payload("status", json!({}));
    extra_payload.insert("data".to_owned(), json!({}));
    for answer in [
        extra_field,
        wrong_schema,
        bad_flag,
        bad_capability,
        extra_payload,
    ] {
        let resident = Resident::new();
        let reply = get_with(
            "/v1/context-assistance",
            &config(None),
            resident.answer(Ok(answer)),
        )
        .unwrap();
        assert_eq!(reply.0, 503);
        assert_eq!(reply.1["code"], INVALID);
    }
}

#[test]
fn newer_engine_state_fields_are_accepted() {
    let mut answer = payload("status", json!({}));
    answer["state"]["execution_ready"] = json!(true);
    answer["state"]["execution_observations"] = json!([]);
    answer["state"]["upgrade"] = json!(null);
    answer["state"]["capabilities"]["execution_context"] = json!(true);
    let resident = Resident::new();
    let reply = get_with(
        "/v1/context-assistance",
        &config(None),
        resident.answer(Ok(answer)),
    )
    .unwrap();
    assert_eq!(reply.0, 200);
    assert_eq!(reply.1["execution_ready"], true);
}

#[test]
fn workspace_routes_need_an_input_object() {
    for path in [
        "/v1/context-assistance/workspace",
        "/v1/context-assistance/workspace-access",
        "/v1/context-assistance/workspace-grant",
    ] {
        let resident = Resident::new();
        let reply = post_with(
            path,
            &body(json!({"input": "x"})),
            &config(None),
            resident.answer(Err(UNAVAILABLE.to_owned())),
        )
        .unwrap();
        assert_eq!(
            reply,
            (400, json!({"error": "invalid_context_input"}), false)
        );
        assert!(resident.seen.borrow().is_empty(), "{path}");
    }
}

#[test]
fn workspace_answers_the_engine_data() {
    let data = json!({"schema": WORKSPACE_SCHEMA, "data_role": true, "result": {"items": []}});
    let resident = Resident::new();
    let reply = post_with(
        "/v1/context-assistance/workspace",
        &body(json!({"input": {"action": "list"}, "approval_gate": {"x": 1}})),
        &config(None),
        resident.answer(Ok(payload("workspace", json!({"data": data.clone()})))),
    )
    .unwrap();
    assert_eq!(reply, (200, data, true));
    // Only `input` reaches the engine; approval proofs never do.
    assert_eq!(
        resident.seen.borrow().as_slice(),
        [(
            json!({"kind": "workspace", "input": {"action": "list"}}),
            true
        )]
    );
    for data in [
        json!({"schema": WORKSPACE_SCHEMA, "data_role": false, "result": {}}),
        json!({"schema": "other", "data_role": true, "result": {}}),
        json!({"schema": WORKSPACE_SCHEMA, "data_role": true, "result": {}, "x": 1}),
    ] {
        let resident = Resident::new();
        let reply = post_with(
            "/v1/context-assistance/workspace-access",
            &body(json!({"input": {}})),
            &config(None),
            resident.answer(Ok(payload("workspace_access", json!({"data": data})))),
        )
        .unwrap();
        assert_eq!(reply.0, 503);
    }
}

#[test]
fn a_workspace_grant_without_an_approval_check_never_reaches_the_engine() {
    // With no session facts the edge cannot ask the approval gate, so the
    // grant fails closed instead of widening access unchecked.
    let resident = Resident::new();
    let reply = post_with(
        "/v1/context-assistance/workspace-grant",
        &body(json!({"input": {"path": "/tmp/project"}})),
        &config(None),
        resident.answer(Ok(payload("workspace_grant", json!({})))),
    )
    .unwrap();
    assert_eq!(reply.0, 503);
    assert_eq!(reply.1["error"], "native_approval_gate_unavailable");
    assert!(resident.seen.borrow().is_empty());
}

#[test]
fn folders_answer_names_and_their_own_refusals() {
    let data = json!({"schema": WORKSPACE_SCHEMA, "data_role": true, "result": {"folders": ["a"]}});
    let resident = Resident::new();
    let reply = post_with(
        "/v1/context-assistance/folders",
        &body(json!({"path": "/tmp"})),
        &config(None),
        resident.answer(Ok(payload("folders", json!({"data": data})))),
    )
    .unwrap();
    assert_eq!(reply, (200, json!({"folders": ["a"]}), true));
    assert_eq!(
        resident.seen.borrow()[0].0,
        json!({"kind": "folders", "input": {"path": "/tmp"}})
    );
    for (code, status) in [
        ("folder_not_found", 404),
        ("folder_denied", 403),
        ("folder_not_absolute", 400),
    ] {
        let resident = Resident::new();
        let reply = post_with(
            "/v1/context-assistance/folders",
            &body(json!({})),
            &config(None),
            resident.answer(Err(format!("{CODE_PREFIX}{code}"))),
        )
        .unwrap();
        assert_eq!(
            reply,
            (
                status,
                json!({"error": "folder_unavailable", "code": code}),
                true
            )
        );
    }
    let resident = Resident::new();
    let reply = post_with(
        "/v1/context-assistance/folders",
        &body(json!({})),
        &config(None),
        resident.answer(Err(format!("{CODE_PREFIX}busy"))),
    )
    .unwrap();
    assert_eq!(reply.0, 409);
    assert_eq!(reply.1["error"], "context_assistance_unavailable");
}

#[test]
fn jobs_list_without_an_approval_check() {
    let data = json!({"schema": VERSIONS_SCHEMA, "result": {"jobs": []}});
    let resident = Resident::new();
    let reply = get_with(
        "/v1/context-assistance/jobs",
        &config(None),
        resident.answer(Ok(payload("versions", json!({"data": data})))),
    )
    .unwrap();
    assert_eq!(
        reply,
        (
            200,
            json!({"schema": VERSIONS_SCHEMA, "result": {"jobs": []}, "state": state()}),
            true
        )
    );
    assert_eq!(
        resident.seen.borrow().as_slice(),
        [(
            json!({"kind": "versions", "input": {"action": "jobs"}}),
            true
        )]
    );
}

#[test]
fn version_changes_pass_the_approval_gate_first() {
    let resident = Resident::new();
    let reply = post_with(
        "/v1/context-assistance/versions",
        &body(json!({"input": {"action": "select", "version": "1.2.3"}})),
        &config(None),
        resident.answer(Err(UNAVAILABLE.to_owned())),
    )
    .unwrap();
    assert_eq!(reply.0, 503);
    assert_eq!(reply.1["error"], "native_approval_gate_unavailable");
    assert!(resident.seen.borrow().is_empty());
    for input in [json!(null), json!({}), json!({"action": 3})] {
        let resident = Resident::new();
        let reply = post_with(
            "/v1/context-assistance/versions",
            &body(json!({"input": input})),
            &config(None),
            resident.answer(Err(UNAVAILABLE.to_owned())),
        )
        .unwrap();
        assert_eq!(
            reply,
            (400, json!({"error": "invalid_context_input"}), false)
        );
    }
}

#[test]
fn version_refusals_keep_their_http_status() {
    for (code, status) in [
        ("native_context_assistance_request_invalid", 400),
        ("native_context_assistance_idempotency_conflict", 400),
        ("native_context_assistance_switch_busy", 409),
        ("native_context_assistance_acknowledgement_required", 409),
        ("native_context_assistance_unavailable", 503),
    ] {
        let resident = Resident::new();
        let reply = post_with(
            "/v1/context-assistance/versions",
            &body(json!({"input": {"action": "cancel"}})),
            &config(None),
            resident.answer(Err(code.to_owned())),
        )
        .unwrap();
        assert_eq!(reply.0, status, "{code}");
        assert_eq!(reply.1["code"], code);
    }
}

#[test]
fn the_edge_owns_only_the_engine_routes() {
    for path in [
        "/v1/context-assistance/versions",
        "/v1/context-assistance/recheck",
        "/v1/context-assistance/activate",
        "/v1/context-assistance/stop",
        "/v1/context-assistance/workspace",
        "/v1/context-assistance/workspace-access",
        "/v1/context-assistance/workspace-grant",
        "/v1/context-assistance/folders",
    ] {
        assert!(writes(path), "{path}");
    }
    for path in [
        "/v1/context-assistance/codex-lean",
        "/v1/context-assistance/codex-short-replies",
        "/v1/context-assistance/usage",
        "/v1/context-assistance",
    ] {
        assert!(!writes(path), "{path}");
    }
    assert!(!reads("/v1/context-assistance/usage"));
    assert!(!reads("/v1/context-assistance/codex-lean"));
}

#[test]
fn replies_bind_to_their_request() {
    let request = json!({"schema": REQUEST_SCHEMA, "request_id": "r-1",
        "query": {"kind": "status", "guard_home": "/h", "input": {}}});
    let reply = |extra: Value| {
        let mut envelope = json!({"schema": RESULT_SCHEMA, "request_id": "r-1",
            "request_sha256": "sha256:d", "status": "ok", "code": "ok",
            "payload": {"kind": "status"}});
        for (key, value) in extra.as_object().unwrap() {
            envelope[key] = value.clone();
        }
        envelope
    };
    assert!(bound(reply(json!({})), &request, "sha256:d").is_ok());
    for (extra, code) in [
        (json!({"request_id": "r-2"}), UNAVAILABLE),
        (json!({"request_sha256": "sha256:e"}), UNAVAILABLE),
        (json!({"schema": "other"}), UNAVAILABLE),
        (json!({"payload": {"kind": "stop"}}), UNAVAILABLE),
        (json!({"code": "nope"}), UNAVAILABLE),
        (
            json!({"status": "error", "code": "native_context_assistance_disabled", "payload": null}),
            "native_context_assistance_disabled",
        ),
        (
            json!({"status": "error", "code": "native_other_failure", "payload": null}),
            UNAVAILABLE,
        ),
        (
            json!({"status": "error", "code": "native_context_assistance_Bad", "payload": null}),
            UNAVAILABLE,
        ),
    ] {
        assert_eq!(
            bound(reply(extra.clone()), &request, "sha256:d").unwrap_err(),
            code,
            "{extra}"
        );
    }
}

#[test]
fn slow_requests_share_two_places() {
    let deadline = Instant::now() + Duration::from_millis(50);
    let first = SlowSlot::acquire(deadline).unwrap();
    let second = SlowSlot::acquire(deadline).unwrap();
    assert!(SlowSlot::acquire(deadline).is_none());
    drop(first);
    let third = SlowSlot::acquire(Instant::now() + Duration::from_millis(50)).unwrap();
    drop((second, third));
}
