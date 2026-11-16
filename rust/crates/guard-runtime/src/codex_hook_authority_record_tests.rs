use super::*;

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const HOME: &str = "/guard-home";
const CONFIG: &str = "/codex/config.toml";
// `Path::is_absolute` needs a drive or UNC prefix on Windows.
const ROOT: &str = if cfg!(windows) { "C:\\" } else { "/" };

fn call(request: Value) -> Value {
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    serde_json::from_slice(&bytes).expect("json")
}

fn base(op: &str, kind: &str) -> Map<String, Value> {
    let Value::Object(map) = json!({
        "schema": SCHEMA,
        "op": op,
        "kind": kind,
        "key_hex": KEY_HEX,
        "key_id": "key-1",
        "installation_id": "install-1",
    }) else {
        unreachable!()
    };
    map
}

fn seal_request(kind: &str, payload: Value, signed_at: Option<&str>) -> Value {
    let mut request = base("seal", kind);
    request.insert("payload".to_owned(), payload);
    if let Some(signed_at) = signed_at {
        request.insert("signed_at".to_owned(), json!(signed_at));
    }
    call(Value::Object(request))
}

fn sealed_text(answer: &Value) -> String {
    answer["text"].as_str().expect("sealed text").to_owned()
}

fn open_request(kind: &str, text: &str, extra: Value) -> Value {
    let mut request = base("open", kind);
    request.insert("text".to_owned(), json!(text));
    request.insert("guard_home".to_owned(), json!(HOME));
    if let Value::Object(extra) = extra {
        request.extend(extra);
    }
    call(Value::Object(request))
}

fn request_payload(kind: Kind, created: f64, expires: f64) -> Value {
    json!({
        "schema": kind.schema(),
        "guard_home": HOME,
        "config_path": CONFIG,
        "installation_id": "install-1",
        "created_monotonic": created,
        "expires_monotonic": expires,
        "plan": {"operation_id": "op-1"},
        "subject": "codex",
    })
}

fn receipt_payload(manifest: &[u8]) -> Value {
    json!({
        "schema": Kind::Receipt.schema(),
        "guard_home": HOME,
        "config_path": CONFIG,
        "installation_id": "install-1",
        "config_sha256": sha256_hex(b"config"),
        "manifest": STANDARD.encode(manifest),
    })
}

#[test]
fn python_canonical_json_matches_json_dumps() {
    let value = json!({
        "b": [1, -2, 1.5, 100.0, 1e16, 1.25e-5, 0.0001, 123456789.125],
        "a": "caf\u{e9} \u{1f600} \"q\" \\ \n\t\u{1}",
    });
    assert_eq!(
        python_canonical_json(&value).unwrap(),
        "{\"a\":\"caf\\u00e9 \\ud83d\\ude00 \\\"q\\\" \\\\ \\n\\t\\u0001\",\
         \"b\":[1,-2,1.5,100.0,1e+16,1.25e-05,0.0001,123456789.125]}"
    );
}

#[test]
fn nonfinite_literals_parse_like_json_loads() {
    assert_eq!(
        parse_python_json(r#"{"a":NaN,"b":[-Infinity,Infinity],"c":"NaN \" Infinity"}"#).unwrap(),
        (
            json!({"a": null, "b": [null, null], "c": "NaN \" Infinity"}),
            true
        )
    );
    assert_eq!(
        parse_python_json(r#"{"c":"NaN"}"#).unwrap(),
        (json!({"c": "NaN"}), false)
    );
    assert!(parse_python_json("{\"a\":nan}").is_err());
}

#[test]
fn request_round_trips_within_its_window() {
    for kind in ["repair_request", "inverse_request"] {
        let parsed = Kind::parse(kind).unwrap();
        let answer = seal_request(kind, request_payload(parsed, 10.0, 310.0), Some("op-1"));
        let text = sealed_text(&answer);
        assert!(text.ends_with('\n') && text.is_ascii());
        let opened = open_request(
            kind,
            &text,
            json!({"config_path": CONFIG, "now_monotonic": 20.0}),
        );
        assert_eq!(opened["signed_at"], "op-1");
        assert_eq!(opened["payload"]["subject"], "codex");
        assert!(opened["payload"].get("authentication").is_none());
    }
}

#[test]
fn request_refuses_expiry_context_and_other_purpose() {
    let kind = Kind::RepairRequest;
    let text = sealed_text(&seal_request(
        "repair_request",
        request_payload(kind, 10.0, 310.0),
        Some("op-1"),
    ));
    let open_at = |now: f64, config: &str, kind: &str| {
        open_request(
            kind,
            &text,
            json!({"config_path": config, "now_monotonic": now}),
        )["error"]
            .clone()
    };
    assert_eq!(open_at(310.0, CONFIG, "repair_request"), "expired");
    assert_eq!(open_at(5.0, CONFIG, "repair_request"), "expired");
    assert_eq!(
        open_at(20.0, "/other.toml", "repair_request"),
        "context_invalid"
    );
    assert_eq!(open_at(20.0, CONFIG, "inverse_request"), "context_invalid");

    let long = sealed_text(&seal_request(
        "repair_request",
        request_payload(kind, 10.0, 400.0),
        Some("op-1"),
    ));
    let answer = open_request(
        "repair_request",
        &long,
        json!({"config_path": CONFIG, "now_monotonic": 20.0}),
    );
    assert_eq!(answer["error"], "expired");
}

#[test]
fn request_refuses_tampering_and_other_installations() {
    let text = sealed_text(&seal_request(
        "repair_request",
        request_payload(Kind::RepairRequest, 10.0, 310.0),
        Some("op-1"),
    ));
    let tampered = text.replace("\"subject\":\"codex\"", "\"subject\":\"other\"");
    let extra = json!({"config_path": CONFIG, "now_monotonic": 20.0});
    assert_eq!(
        open_request("repair_request", &tampered, extra.clone())["error"],
        "authentication_invalid"
    );
    let mut request = base("open", "repair_request");
    request.insert("installation_id".to_owned(), json!("install-2"));
    request.insert("text".to_owned(), json!(text));
    request.insert("guard_home".to_owned(), json!(HOME));
    request.insert("config_path".to_owned(), json!(CONFIG));
    request.insert("now_monotonic".to_owned(), json!(20.0));
    assert_eq!(
        call(Value::Object(request))["error"],
        "authentication_invalid"
    );
    let extra_key = text.replacen('{', "{\"extra\":1,", 1);
    assert_eq!(
        open_request("repair_request", &extra_key, extra)["error"],
        "invalid"
    );
}

#[test]
fn receipt_is_bound_to_its_manifest() {
    let manifest = br#"{"harness":"codex"}"#;
    let answer = seal_request("receipt", receipt_payload(manifest), None);
    let text = sealed_text(&answer);
    let opened = open_request("receipt", &text, json!({"config_path": CONFIG}));
    assert_eq!(opened["signed_at"], sha256_hex(manifest));
    assert_eq!(
        open_request("receipt", &text, json!({"config_path": "/other.toml"}))["error"],
        "receipt_authentication_invalid"
    );
    let mut chosen = base("seal", "receipt");
    chosen.insert("payload".to_owned(), receipt_payload(manifest));
    chosen.insert("signed_at".to_owned(), json!("chosen"));
    assert!(run_command(Value::Object(chosen).to_string().as_bytes()).is_err());
}

#[test]
fn receipt_manifest_checks_context() {
    let mut request = base("receipt_manifest", "receipt");
    request.insert("guard_home".to_owned(), json!(HOME));
    request.insert("config_path".to_owned(), json!(CONFIG));
    let manifest = json!({
        "harness": "codex",
        "installation_id": "install-1",
        "config": {"scope": "global", "target": CONFIG},
        "context": {"guard_home": HOME},
    });
    request.insert("manifest".to_owned(), manifest.clone());
    assert_eq!(call(Value::Object(request.clone()))["ok"], true);
    let mut other = manifest;
    other["config"]["scope"] = json!("workspace");
    request.insert("manifest".to_owned(), other);
    assert_eq!(
        call(Value::Object(request))["error"],
        "receipt_context_invalid"
    );
}

fn recovery_payload(phase: &str) -> Value {
    json!({
        "schema": Kind::Recovery.schema(),
        "guard_home": HOME,
        "config_path": ROOT,
        "installation_id": "install-1",
        "phase": phase,
    })
}

#[test]
fn recovery_round_trips_and_checks_phase() {
    let text = sealed_text(&seal_request(
        "recovery",
        recovery_payload("prepared"),
        Some("t"),
    ));
    let opened = open_request("recovery", &text, json!({}));
    assert_eq!(opened["payload"]["phase"], "prepared");

    let text = sealed_text(&seal_request(
        "recovery",
        recovery_payload("other"),
        Some("t"),
    ));
    assert_eq!(
        open_request("recovery", &text, json!({}))["error"],
        "phase_invalid"
    );

    let mut relative = recovery_payload("prepared");
    relative["config_path"] = json!("relative.toml");
    let text = sealed_text(&seal_request("recovery", relative, Some("t")));
    assert_eq!(
        open_request("recovery", &text, json!({}))["error"],
        "target_invalid"
    );

    let mut receipts = recovery_payload("prepared");
    receipts["after_receipt"] = json!("x");
    let text = sealed_text(&seal_request("recovery", receipts, Some("t")));
    assert_eq!(
        open_request("recovery", &text, json!({}))["error"],
        "record_invalid"
    );

    let mut other_home = base("open", "recovery");
    other_home.insert("text".to_owned(), json!(text));
    other_home.insert("guard_home".to_owned(), json!("/elsewhere"));
    assert_eq!(
        call(Value::Object(other_home))["error"],
        "authentication_invalid"
    );
}

#[test]
fn a_null_edited_to_nan_does_not_authenticate() {
    let mut payload = recovery_payload("prepared");
    payload["before_manifest"] = Value::Null;
    let text = sealed_text(&seal_request("recovery", payload, Some("t")));
    assert!(open_request("recovery", &text, json!({}))
        .get("error")
        .is_none());
    let edited = text.replace("\"before_manifest\":null", "\"before_manifest\":NaN");
    assert_ne!(edited, text);
    assert_eq!(
        open_request("recovery", &edited, json!({}))["error"],
        "authentication_invalid"
    );
}

#[test]
fn recovery_refuses_publication_time_without_plan() {
    let mut payload = recovery_payload("prepared");
    payload["repair_publication_monotonic"] = json!(5.0);
    assert_eq!(
        seal_request("recovery", payload, Some("t"))["error"],
        "repair_record_invalid"
    );
}

fn repair_payload(phase: &str) -> (Value, Value) {
    let config = b"config".as_slice();
    let manifest = b"manifest".as_slice();
    let plan = json!({
        "schema": REPAIR_PLAN_SCHEMA,
        "action": REPAIR_ACTION,
        "guard_home": HOME,
        "config_path": ROOT,
        "operation_id": "op-1",
        "native_runtime": {"version": "1"},
    });
    let generation = format!(
        "codex-authority-repair-{}",
        sha256_hex(python_canonical_json(&plan).unwrap().as_bytes())
    );
    let mut payload = recovery_payload(phase);
    let object = payload.as_object_mut().unwrap();
    object.insert("repair_plan".to_owned(), plan);
    object.insert("key_created".to_owned(), json!(false));
    object.insert("before_manifest".to_owned(), Value::Null);
    object.insert(
        "after_manifest".to_owned(),
        json!(STANDARD.encode(manifest)),
    );
    object.insert("before_config".to_owned(), json!(STANDARD.encode(config)));
    object.insert("after_config".to_owned(), json!(STANDARD.encode(config)));
    object.insert("before_receipt".to_owned(), json!("r"));
    object.insert("after_receipt".to_owned(), json!("r"));
    object.insert("repair_publication_monotonic".to_owned(), json!(10.0));
    let proof = json!({
        "schema": "hol-guard.native-protection-admission.v1",
        "operation_id": "op-1",
        "generation": generation,
        "guard_home": HOME,
        "runtime_identity": {"version": "1"},
        "observed_monotonic": 11.0,
        "installed_hook_evidence": {
            "harness": "codex",
            "config_sha256": sha256_hex(config),
            "manifest_sha256": sha256_hex(manifest),
        },
    });
    (payload, proof)
}

#[test]
fn repair_record_needs_a_matching_proof_once_committed() {
    let (prepared, proof) = repair_payload("prepared");
    let text = sealed_text(&seal_request("recovery", prepared.clone(), Some("t")));
    assert_eq!(
        open_request("recovery", &text, json!({}))["payload"]["phase"],
        "prepared"
    );

    let mut request = base("repair_proof", "recovery");
    request.insert("payload".to_owned(), prepared);
    request.insert("proof".to_owned(), proof.clone());
    assert_eq!(call(Value::Object(request.clone()))["matches"], true);
    let mut early = proof.clone();
    early["observed_monotonic"] = json!(9.0);
    request.insert("proof".to_owned(), early);
    assert_eq!(call(Value::Object(request))["matches"], false);

    let (mut committed, _) = repair_payload("committed");
    assert_eq!(
        seal_request("recovery", committed.clone(), Some("t"))["error"],
        "repair_record_invalid"
    );
    committed["native_verification"] = proof;
    let text = sealed_text(&seal_request("recovery", committed, Some("t")));
    assert_eq!(
        open_request("recovery", &text, json!({}))["payload"]["phase"],
        "committed"
    );
}

#[test]
fn seal_refuses_wrong_schema_and_installation() {
    let mut payload = recovery_payload("prepared");
    payload["installation_id"] = json!("install-2");
    let request = {
        let mut request = base("seal", "recovery");
        request.insert("payload".to_owned(), payload);
        request.insert("signed_at".to_owned(), json!("t"));
        Value::Object(request)
    };
    assert!(run_command(request.to_string().as_bytes()).is_err());
    let mut wrong = base("seal", "nonsense");
    wrong.insert("payload".to_owned(), recovery_payload("prepared"));
    assert!(run_command(Value::Object(wrong).to_string().as_bytes()).is_err());
}
