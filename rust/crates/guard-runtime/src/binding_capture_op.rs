//! `CodexBindingCapture` resident operation: opt-in private evidence that
//! binds Codex hook ingress to a native-edge receipt. The per-run key never
//! leaves the runtime; callers send JSON text and receive typed outcomes.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::binding_capture_capture::{record_bridge_ingress, record_native_worker};
use crate::binding_capture_fs::{initialize_marker, load_capture_config};
use crate::binding_capture_join::join_binding_records;
use crate::binding_capture_json::{self as bjson, Json};

pub(crate) const BINDING_CAPTURE_FEATURE: &str = "codex-binding-capture-v1";
const REQUEST_SCHEMA: &str = "guard-codex-binding-capture-request.v1";
const RESULT_SCHEMA: &str = "guard-codex-binding-capture-result.v1";
const MAX_RECORDS_IN: usize = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodexBindingCaptureRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub command: CaptureCommandV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CaptureCommandV1 {
    Bridge {
        raw_payload: String,
        forwarded_payload: Option<String>,
        event_name: String,
        harness: String,
    },
    Native {
        payload: String,
        receipt: String,
        event_name: String,
        harness: String,
    },
    InitMarker {
        run_id: String,
        expires_at: i64,
        max_records: Option<i64>,
        max_bytes: Option<i64>,
    },
    Join {
        records: Vec<String>,
    },
}

#[derive(Serialize)]
struct ResultV1 {
    schema: &'static str,
    request_id: String,
    request_sha256: String,
    status: &'static str,
    code: &'static str,
    payload: Value,
}

pub(crate) fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

pub(crate) fn evaluate_codex_binding_capture_request(
    request: &CodexBindingCaptureRequestV1,
) -> Result<Vec<u8>, String> {
    evaluate_at(request, now_seconds())
}

fn request_digest(request: &CodexBindingCaptureRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_codex_binding_capture_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_codex_binding_capture_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn evaluate_at(
    request: &CodexBindingCaptureRequestV1,
    now: f64,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != REQUEST_SCHEMA {
        return Err("native_codex_binding_capture_schema_mismatch".to_owned());
    }
    let guard_home = Path::new(&request.guard_home);
    let payload = if guard_home.is_absolute() {
        Some(run(guard_home, &request.command, now))
    } else {
        None
    };
    let (status, code) = if payload.is_some() {
        ("ok", "ok")
    } else {
        ("error", "native_codex_binding_capture_path_invalid")
    };
    crate::resident_protocol::encode_response(&ResultV1 {
        schema: RESULT_SCHEMA,
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload: payload.unwrap_or(Value::Null),
    })
}

fn run(guard_home: &Path, command: &CaptureCommandV1, now: f64) -> Value {
    match command {
        CaptureCommandV1::Bridge {
            raw_payload,
            forwarded_payload,
            event_name,
            harness,
        } => json!({"recorded": record_bridge_ingress(
            guard_home, raw_payload, forwarded_payload.as_deref(), event_name, harness, now)}),
        CaptureCommandV1::Native {
            payload,
            receipt,
            event_name,
            harness,
        } => json!({"recorded": record_native_worker(
            guard_home, payload, harness, event_name, receipt, now)}),
        CaptureCommandV1::InitMarker {
            run_id,
            expires_at,
            max_records,
            max_bytes,
        } => match initialize_marker(
            guard_home,
            run_id,
            *expires_at,
            *max_records,
            *max_bytes,
            now,
        ) {
            Some(session) => json!({"session": {
                "run_id": session.run_id,
                "key_id": session.key_id,
                "expires_at": session.expires_at,
                "max_records": session.max_records,
                "max_bytes": session.max_bytes,
            }}),
            None => json!({"session": null}),
        },
        CaptureCommandV1::Join { records } => {
            let session = load_capture_config(guard_home, now);
            let parsed = parse_records(records);
            let joined = join_binding_records(&parsed, session.as_ref(), now);
            json!({"result": serde_json::from_slice::<Value>(&bjson::encode(&joined)).unwrap_or(Value::Null)})
        }
    }
}

/// Unparseable evaluator input is carried as a non-object so the join reports
/// `record_not_object` for it, as the Python join did for non-mappings.
fn parse_records(records: &[String]) -> Vec<Json> {
    records
        .iter()
        .take(MAX_RECORDS_IN)
        .map(|text| bjson::parse(text).unwrap_or(Json::Null))
        .collect()
}
