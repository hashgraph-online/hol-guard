//! Replay of the shared cloud-connected supply-chain evaluation vectors.
//!
//! `tests/fixtures/supply-chain-eval/cloud-cases.v1.json` was recorded from the
//! Python evaluator (see `record_cloud_vectors.py` and the file's
//! `recorded_from_commit`). Each case seeds a store from recorded rows, serves
//! the recorded cloud response from a loopback server, and requires the
//! resident evaluation to equal the recorded Python result and to send the
//! recorded cloud request.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use guard_contracts::{
    EgressNeedV1, EgressOutcomeV1, EgressRequiredV1, EgressSuppliedV1, SupplyChainEvalRequestV1,
    SupplyChainEvalResultV1, EGRESS_REQUIRED_CODE, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Value};

use crate::package_authority_op::evaluate_supply_chain_eval_with_seams;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/supply-chain-eval/cloud-cases.v1.json"
));
static CASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

struct CloudServer {
    port: u16,
    seen: Seen,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CloudServer {
    fn start(spec: &Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let seen: Seen = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_seen, thread_stop, spec) = (seen.clone(), stop.clone(), spec.clone());
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    serve(stream, &spec, &thread_seen);
                }
            }
        });
        Self {
            port,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<(String, Value)> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            handle.join().expect("server thread");
        }
        self.seen.lock().expect("seen").clone()
    }
}

fn serve(mut stream: TcpStream, spec: &Value, seen: &Seen) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let path = head
        .split_whitespace()
        .nth(1)
        .and_then(|target| target.split('?').next())
        .unwrap_or("")
        .to_owned();
    let body: Value = serde_json::from_slice(&buffer[header_end..]).unwrap_or(Value::Null);
    let index = {
        let mut seen = seen.lock().expect("seen");
        seen.push((path, body));
        seen.len() - 1
    };
    // `responses` scripts one reply per request; the last one repeats.
    let spec = spec["responses"]
        .as_array()
        .and_then(|replies| replies.get(index).or_else(|| replies.last()))
        .unwrap_or(spec);
    if spec["mode"] == "dropped" {
        return;
    }
    let payload = spec["payload"].to_string();
    let status = spec["status"].as_u64().unwrap_or(200);
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Bool(flag) => SqlValue::Integer(i64::from(*flag)),
        Value::Number(number) => number
            .as_i64()
            .map(SqlValue::Integer)
            .unwrap_or_else(|| SqlValue::Real(number.as_f64().unwrap_or(0.0))),
        Value::String(text) => SqlValue::Text(text.clone()),
        other => SqlValue::Text(other.to_string()),
    }
}

fn seed_store(db_path: &Path, vectors: &Value, case: &Value) {
    let connection = rusqlite::Connection::open(db_path).expect("open store");
    for ddl in vectors["schema_sql"].as_object().expect("schema").values() {
        connection
            .execute(ddl.as_str().expect("ddl"), [])
            .expect("create table");
    }
    for (table, rows) in case["rows"].as_object().expect("rows") {
        for row in rows.as_array().expect("row list") {
            let columns: Vec<&String> = row.as_object().expect("row").keys().collect();
            let placeholders = vec!["?"; columns.len()].join(", ");
            let names = columns
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let values: Vec<SqlValue> = columns
                .iter()
                .map(|c| sql_value(&row[c.as_str()]))
                .collect();
            connection
                .execute(
                    &format!("INSERT INTO {table} ({names}) VALUES ({placeholders})"),
                    rusqlite::params_from_iter(values),
                )
                .expect("seed row");
        }
    }
}

fn case_dir(name: &str) -> PathBuf {
    let unique = CASE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!(
        "guard-cloud-vectors-{}-{unique}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("home")).expect("home");
    std::fs::create_dir_all(root.join("ws")).expect("ws");
    root
}

fn run_case(vectors: &Value, case: &Value) -> Result<(), String> {
    let name = case["name"].as_str().expect("name");
    let (payload, sent) = evaluate_case(vectors, case)?;
    if payload != case["expect"] {
        return Err(format!(
            "{name}: evaluation differs\n{}",
            diff(&case["expect"], &payload)
        ));
    }
    check_cloud_requests(name, case, &sent)
}

fn evaluate_case(vectors: &Value, case: &Value) -> Result<(Value, Vec<(String, Value)>), String> {
    let name = case["name"].as_str().expect("name");
    let root = case_dir(name);
    let db_path = root.join("home").join("guard.db");
    seed_store(&db_path, vectors, case);
    for (file, spec) in case["files"].as_object().expect("files") {
        std::fs::write(
            root.join("ws").join(file),
            spec["text"].as_str().expect("text"),
        )
        .expect("write file");
    }
    let server = (!case["network"].is_null()).then(|| CloudServer::start(&case["network"]));
    let mut request = SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: format!("vector-{name}"),
        store_path: db_path.to_string_lossy().into_owned(),
        guard_home: root.join("home").to_string_lossy().into_owned(),
        artifact: case["artifact"].clone(),
        workspace_dir: Some(root.join("ws").to_string_lossy().into_owned()),
        now: vectors["now"].as_str().map(str::to_owned),
        external_archive_network_authorized: false,
        retain_external_archive_blob: false,
        runtime_private_metadata: None,
        sync_auth_context_override: None,
        package_entitlement_override: None,
        registry_metadata_override: None,
        saved_policy_probe: None,
        egress_supplied: None,
        egress_spool_dir: None,
    };
    if let Some(server) = &server {
        request.sync_auth_context_override = Some(json!({
            "sync_url": format!("http://127.0.0.1:{}/api/guard/receipts/sync", server.port),
            "access_token": vectors["sync_token"],
            "dpop_key_material": null,
        }));
    }
    if !case["entitlement"].is_null() {
        request.package_entitlement_override = Some(case["entitlement"].clone());
    }
    let mut result = drive(&mut request)?;
    // A cached Cloud validation error needs the saved-policy lookup only the
    // caller can hydrate. The vector records what the Python lookup returned.
    let asked = result.code == "saved_policy_probe_required";
    let recorded_probe = !case["saved_policy_probe"].is_null();
    if asked != recorded_probe {
        return Err(format!(
            "{name}: saved-policy probe asked={asked} but vector probe is {}",
            case["saved_policy_probe"]
        ));
    }
    if asked {
        if result.status != "ok" || result.payload.is_none() {
            return Err(format!(
                "{name}: probe request malformed: {}",
                result.status
            ));
        }
        request.saved_policy_probe = Some(
            serde_json::from_value(case["saved_policy_probe"].clone())
                .map_err(|e| format!("{name}: probe vector: {e}"))?,
        );
        result = drive(&mut request)?;
    }
    let sent = server.map(CloudServer::finish).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    if result.status != "ok" {
        return Err(format!(
            "{name}: status {} code {}",
            result.status, result.code
        ));
    }
    Ok((result.payload.unwrap_or(Value::Null), sent))
}

/// What the Python caller does: perform each need the resident asks for and
/// repeat the request with the outcomes, until the resident answers. The
/// exchanges go to a loopback server through a hand-written client so the
/// transport under test is never the thing that fulfils it.
fn drive(request: &mut SupplyChainEvalRequestV1) -> Result<SupplyChainEvalResultV1, String> {
    for _ in 0..24 {
        let result = decode(&evaluate_supply_chain_eval_with_seams(request, true)?)?;
        if result.code != EGRESS_REQUIRED_CODE {
            return Ok(result);
        }
        let required: EgressRequiredV1 =
            serde_json::from_value(result.payload.ok_or("egress answer without needs")?)
                .map_err(|e| e.to_string())?;
        if required.needs.is_empty() {
            return Err("egress answer with no needs".to_owned());
        }
        let supplied = request.egress_supplied.get_or_insert_with(Vec::new);
        for need in required.needs {
            supplied.push(EgressSuppliedV1 {
                outcome: perform_on_loopback(&need)?,
                class: need.class,
                method: need.method,
                url: need.url,
                body_sha256: need.body_sha256,
                occurrence: need.occurrence,
            });
        }
    }
    Err("evaluation did not settle in 24 rounds".to_owned())
}

fn perform_on_loopback(need: &EgressNeedV1) -> Result<EgressOutcomeV1, String> {
    let rest = need
        .url
        .strip_prefix("http://127.0.0.1:")
        .ok_or_else(|| format!("not a loopback url: {}", need.url))?;
    let (port, path) = rest.split_once('/').ok_or("url without a path")?;
    let mut stream =
        TcpStream::connect(("127.0.0.1", port.parse::<u16>().map_err(|e| e.to_string())?))
            .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let body = need.body.clone().unwrap_or_default();
    let mut head = format!(
        "{} /{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n",
        need.method,
        body.len()
    );
    for (name, value) in &need.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(EgressOutcomeV1::Error {
            message: "connection closed without a response".to_owned(),
        });
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("no status line")?;
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Ok(EgressOutcomeV1::Response {
        status,
        headers,
        body: Some(String::from_utf8_lossy(&raw[split + 4..]).into_owned()),
        body_file: None,
    })
}

fn check_cloud_requests(name: &str, case: &Value, sent: &[(String, Value)]) -> Result<(), String> {
    let bodies: Vec<&Value> = sent.iter().map(|(_, body)| body).collect();
    let recorded: Vec<&Value> = case["cloud_requests"]
        .as_array()
        .expect("requests")
        .iter()
        .collect();
    if bodies != recorded {
        return Err(format!(
            "{name}: cloud requests differ\nexpected {recorded:?}\nactual {bodies:?}"
        ));
    }
    let paths: Vec<&str> = sent.iter().map(|(path, _)| path.as_str()).collect();
    let recorded_paths: Vec<&str> = case["cloud_request_paths"]
        .as_array()
        .expect("paths")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if paths != recorded_paths {
        return Err(format!(
            "{name}: cloud paths differ {recorded_paths:?} vs {paths:?}"
        ));
    }
    Ok(())
}

fn decode(reply: &[u8]) -> Result<SupplyChainEvalResultV1, String> {
    serde_json::from_slice(reply).map_err(|e| e.to_string())
}

fn diff(expected: &Value, actual: &Value) -> String {
    let empty = serde_json::Map::new();
    let (left, right) = (
        expected.as_object().unwrap_or(&empty),
        actual.as_object().unwrap_or(&empty),
    );
    let mut lines = Vec::new();
    for key in left
        .keys()
        .chain(right.keys().filter(|k| !left.contains_key(*k)))
    {
        if left.get(key) != right.get(key) {
            lines.push(format!(
                "  {key}: expected {}\n  {key}: actual   {}",
                left.get(key)
                    .map_or("<absent>".to_owned(), Value::to_string),
                right
                    .get(key)
                    .map_or("<absent>".to_owned(), Value::to_string)
            ));
        }
    }
    lines.join("\n")
}

#[test]
fn resident_cloud_evaluation_matches_recorded_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let failures: Vec<String> = vectors["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter_map(|case| run_case(&vectors, case).err())
        .collect();
    let report = failures.join("\n\n");
    if let Some(path) = std::env::var_os("GUARD_VECTOR_REPORT") {
        std::fs::write(path, &report).expect("write report");
    }
    assert!(failures.is_empty(), "{} case(s) differ", failures.len());
}

#[test]
fn refreshed_retry_with_invalid_payload_needs_review_not_a_stale_401() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let mut case = vectors["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "cloud_http_401_paid")
        .expect("401 case")
        .clone();
    // The first POST is rejected with 401; the forced-refresh retry answers
    // with a body that is not a JSON object.
    case["network"] = json!({"responses": [
        {"mode": "http", "status": 401, "payload": {}},
        {"mode": "http", "status": 200, "payload": []},
    ]});
    let (payload, sent) = evaluate_case(&vectors, &case).expect("evaluates");
    assert_eq!(sent.len(), 2, "401 then one refreshed retry");
    let reason = &payload["packages"][0]["reasons"][0];
    assert_eq!(reason["code"], "cloud_validation_error");
    assert_eq!(payload["decision"], "block");
}
