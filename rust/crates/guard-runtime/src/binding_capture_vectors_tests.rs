//! Parity with the retired Python `codex_binding_capture*.py` modules. The
//! vectors were recorded from that code with time pinned to `now`.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use crate::binding_capture_capture::{record_bridge_ingress, record_native_worker};
use crate::binding_capture_crypto::{open_receipt, parse_marker, CaptureSession};
use crate::binding_capture_join::{join_binding_records, valid_existing_records};
use crate::binding_capture_json::{self as json, Json};
use crate::binding_capture_receipt::receipt_projection;

const VECTORS: &str = include_str!("../testdata/binding_capture/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn now(v: &Value) -> f64 {
    v["now"].as_f64().expect("now")
}

fn text(value: &Value) -> String {
    serde_json::to_string(value).expect("serialize")
}

fn to_json(value: &Value) -> Json {
    json::parse(&text(value)).expect("vector json")
}

fn to_value(value: &Json) -> Value {
    serde_json::from_slice(&json::encode(value)).expect("encoded json")
}

fn session_value(session: Option<&CaptureSession>) -> Value {
    session.map_or(Value::Null, |s| {
        serde_json::json!({
            "run_id": s.run_id, "expires_at": s.expires_at, "max_records": s.max_records,
            "max_bytes": s.max_bytes, "key_id": s.key_id, "key_hex": hex::encode(&s.key),
        })
    })
}

fn default_marker(v: &Value) -> Value {
    v["markers"][0]["marker"].clone()
}

fn session_with(v: &Value, overrides: &Value) -> CaptureSession {
    let mut marker = default_marker(v);
    if let Some(extra) = overrides.as_object() {
        for (key, value) in extra {
            marker[key] = value.clone();
        }
    }
    parse_marker(&to_json(&marker), now(v)).expect("session")
}

#[test]
fn json_layer_matches_python() {
    for case in vectors()["json"].as_array().unwrap() {
        let source = case["text"].as_str().unwrap();
        let parsed = json::parse_object(source.as_bytes());
        assert_eq!(
            parsed.is_some(),
            case["validated"].as_bool().unwrap(),
            "{source:.80}"
        );
        let canonical = parsed
            .and_then(|value| json::canonical(&value))
            .map(|bytes| String::from_utf8(bytes).unwrap());
        assert_eq!(
            canonical.as_deref(),
            case["object"].as_str(),
            "{source:.80}"
        );
    }
}

#[test]
fn markers_match_python() {
    let v = vectors();
    for case in v["markers"].as_array().unwrap() {
        let parsed = json::parse(&text(&case["marker"])).and_then(|m| parse_marker(&m, now(&v)));
        assert_eq!(
            session_value(parsed.as_ref()),
            case["session"],
            "{}",
            case["marker"]
        );
    }
}

#[test]
fn hmacs_match_python() {
    let v = vectors();
    let session = session_with(&v, &Value::Null);
    for case in v["hmac"].as_array().unwrap() {
        let actual = if case["kind"] == "row" {
            session.row_hmac(&to_json(&case["row"]), now(&v))
        } else {
            let source = case["payload_text"]
                .as_str()
                .map_or_else(|| text(&case["payload"]), str::to_owned);
            json::parse(&source).and_then(|payload| {
                session.payload_hmac(case["role"].as_str().unwrap(), &payload, now(&v))
            })
        };
        assert_eq!(actual.as_deref(), case["expected"].as_str(), "{case}");
    }
}

#[test]
fn receipts_match_python() {
    for case in vectors()["receipts"].as_array().unwrap() {
        let parsed = json::parse(&text(&case["receipt"]));
        let projected = parsed.as_ref().and_then(receipt_projection);
        if let Some(first) = &projected {
            let again = receipt_projection(first);
            assert_eq!(
                again.as_ref().map(json::encode),
                Some(json::encode(first)),
                "projection must remain a valid receipt: {}",
                case["receipt"]
            );
        }
        let projection = projected.map_or(Value::Null, |p| to_value(&p));
        assert_eq!(projection, case["projection"], "{}", case["receipt"]);
    }
}

#[test]
fn join_and_existing_match_python() {
    let v = vectors();
    for case in v["join"]["joins"].as_array().unwrap() {
        let session = case["session"]
            .as_bool()
            .unwrap()
            .then(|| session_with(&v, &case["session_overrides"]));
        let records: Vec<Json> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(to_json)
            .collect();
        let joined = to_value(&join_binding_records(&records, session.as_ref(), now(&v)));
        assert_eq!(joined, case["result"], "{}", case["name"]);
    }
    for case in v["join"]["existing"].as_array().unwrap() {
        let session = session_with(&v, &case["session_overrides"]);
        let count = valid_existing_records(
            case["raw"].as_str().unwrap().as_bytes(),
            case["run_id"].as_str().unwrap(),
            Some(&session),
            now(&v),
        );
        assert_eq!(
            count.map(|c| c as u64),
            case["count"].as_u64(),
            "{}",
            case["name"]
        );
    }
}

fn scratch() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "bc-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&path).unwrap();
    let path = fs::canonicalize(path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn mode(value: &Value) -> u32 {
    u32::try_from(value.as_u64().unwrap()).unwrap()
}

fn apply_setup(home: &Path, setup: &[Value]) {
    for step in setup {
        let kind = step[0].as_str().unwrap();
        let path = home.join(step[1].as_str().unwrap());
        match kind {
            "mkdir" => {
                fs::create_dir_all(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode(&step[2]))).unwrap();
            }
            "write" => {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, step[2].as_str().unwrap()).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode(&step[3]))).unwrap();
            }
            "symlink" => symlink(step[2].as_str().unwrap(), &path).unwrap(),
            "hardlink" => fs::hard_link(home.join(step[2].as_str().unwrap()), &path).unwrap(),
            "chmod" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode(&step[2]))).unwrap()
            }
            other => panic!("unknown setup {other}"),
        }
    }
}

/// Sealed receipts are random, so compare their opened body and verify the MAC.
fn normalize(raw: &str, session: &CaptureSession, at: f64) -> Value {
    let mut rows = Vec::new();
    for line in raw.lines() {
        let Some(row) = json::parse(line) else {
            rows.push(serde_json::json!({"unparsed": line}));
            continue;
        };
        let mut value = to_value(&row);
        if let Some(sealed) = row.get("sealed_receipt") {
            assert!(session.verify_row_hmac(&row, at), "row mac {line}");
            let opened =
                open_receipt(session, &row, sealed, at).map_or(Value::Null, |r| to_value(&r));
            value["sealed_receipt"] = serde_json::json!({"opened": opened});
            value.as_object_mut().unwrap().remove("row_mac");
        }
        rows.push(value);
    }
    serde_json::json!({"line_count": rows.len(), "rows": rows, "trailing_newline": raw.ends_with('\n') || raw.is_empty()})
}

#[test]
fn scenarios_match_python() {
    let v = vectors();
    let at = now(&v);
    let session = session_with(&v, &Value::Null);
    for scenario in v["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = scratch().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        apply_setup(&home, scenario["setup"].as_array().unwrap());
        let mut results = Vec::new();
        for op in scenario["ops"].as_array().unwrap() {
            let harness = op["harness"].as_str().unwrap_or("codex");
            let event = op["event"].as_str().unwrap();
            results.push(if op["op"] == "bridge" {
                record_bridge_ingress(
                    &home,
                    op["raw"].as_str().unwrap(),
                    op["forwarded"].as_str(),
                    event,
                    harness,
                    at,
                )
            } else {
                record_native_worker(
                    &home,
                    &text(&op["payload"]),
                    harness,
                    event,
                    &text(&op["receipt"]),
                    at,
                )
            });
        }
        assert_eq!(Value::from(results), scenario["results"], "{name}");
        let output = home.join("diagnostics/codex-binding-capture.run-1.jsonl");
        let raw = fs::read_to_string(&output).ok();
        assert_eq!(raw.is_some(), !scenario["raw_output"].is_null(), "{name}");
        if let Some(raw) = raw {
            let has_native = scenario["ops"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["op"] == "native");
            if !has_native {
                assert_eq!(
                    Some(raw.as_str()),
                    scenario["raw_output"].as_str(),
                    "{name}"
                );
            }
            assert_eq!(
                normalize(&raw, &session, at),
                normalize_expected(&scenario["output"]),
                "{name}"
            );
        }
        let _ = fs::remove_dir_all(home.parent().unwrap());
    }
}

/// Recorded native rows keep their random `row_mac`; the replay drops it.
fn normalize_expected(expected: &Value) -> Value {
    let mut expected = expected.clone();
    if let Some(rows) = expected["rows"].as_array_mut() {
        for row in rows {
            if row.get("sealed_receipt").is_some() {
                row.as_object_mut().unwrap().remove("row_mac");
            }
        }
    }
    expected
}

#[test]
fn op_round_trip_initializes_records_and_joins() {
    use crate::binding_capture_op::{evaluate_at, CaptureCommandV1, CodexBindingCaptureRequestV1};
    let home = scratch();
    let at = crate::binding_capture_op::now_seconds();
    let call = |command: CaptureCommandV1| -> Value {
        let request = CodexBindingCaptureRequestV1 {
            schema: "guard-codex-binding-capture-request.v1".to_owned(),
            request_id: "r".to_owned(),
            guard_home: home.to_string_lossy().into_owned(),
            command,
        };
        let response: Value = serde_json::from_slice(&evaluate_at(&request, at).unwrap()).unwrap();
        assert_eq!(response["status"], "ok");
        assert!(response["request_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        response["payload"].clone()
    };
    let session = call(CaptureCommandV1::InitMarker {
        run_id: "run-op".to_owned(),
        expires_at: at as i64 + 300,
        max_records: None,
        max_bytes: None,
    });
    assert_eq!(session["session"]["run_id"], "run-op");
    assert!(session["session"].get("key").is_none());
    let raw = r#"{"hook_event_name":"PreToolUse","tool_use_id":"c1"}"#.to_owned();
    let bridge = call(CaptureCommandV1::Bridge {
        raw_payload: raw,
        forwarded_payload: None,
        event_name: "PreToolUse".to_owned(),
        harness: "codex".to_owned(),
    });
    assert_eq!(bridge["recorded"], true);
    let output =
        fs::read_to_string(home.join("diagnostics/codex-binding-capture.run-op.jsonl")).unwrap();
    let joined = call(CaptureCommandV1::Join {
        records: output.lines().map(str::to_owned).collect(),
    });
    assert_eq!(joined["result"]["status"], "unbound");
    let _ = fs::remove_dir_all(&home);
}
