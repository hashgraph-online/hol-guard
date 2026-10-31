use serde_json::{json, Value};

use super::*;

const MANAGED_FILE: &str = r"C:\ProgramData\HOL\Guard\ca-bundle.pem";

fn managed_file_payload_for(file: &str) -> Result<Vec<Value>, String> {
    let response = run(json!({
        "schema": SCHEMA,
        "op": "windows-file-payload",
        "managed_file": file,
    }))?;
    Ok(response["payload"].as_array().unwrap().clone())
}

fn verify_managed_file(rows: Value) -> Value {
    run(json!({
        "schema": SCHEMA,
        "op": "windows-file-verify",
        "managed_file": MANAGED_FILE,
        "rows": rows,
    }))
    .unwrap()
}

#[test]
fn a_managed_file_payload_walks_every_ancestor_to_the_file() {
    let payload = managed_file_payload_for(MANAGED_FILE).unwrap();
    let rows: Vec<(String, String, bool, bool)> = payload
        .iter()
        .map(|item| {
            assert_eq!(item["kind"], "filesystem");
            (
                item["name"].as_str().unwrap().to_owned(),
                item["path"].as_str().unwrap().to_owned(),
                item["expectedContainer"].as_bool().unwrap(),
                item["leaf"].as_bool().unwrap(),
            )
        })
        .collect();
    let expected = [
        ("managed-file-000", r"C:\", true, false),
        ("managed-file-001", r"C:\ProgramData", true, false),
        ("managed-file-002", r"C:\ProgramData\HOL", true, false),
        ("managed-file-003", r"C:\ProgramData\HOL\Guard", true, false),
        ("managed-file-004", MANAGED_FILE, false, true),
    ]
    .map(|(name, path, container, leaf)| (name.to_owned(), path.to_owned(), container, leaf));
    assert_eq!(rows, expected);
    assert_eq!(
        managed_file_payload_for(r"relative\ca.pem"),
        Err("ownership_acl_request_invalid".to_owned())
    );
}

#[test]
fn a_managed_file_is_trusted_only_when_every_row_is_healthy() {
    let rows = healthy_rows_for(managed_file_payload_for(MANAGED_FILE).unwrap());
    assert_eq!(
        verify_managed_file(Value::Array(rows.clone()))["status"],
        "healthy"
    );

    let mut writable = rows.clone();
    writable[2]["Rules"][0]["Rights"] = json!(FILE_MUTATION_MASK);
    let verdict = verify_managed_file(Value::Array(writable));
    assert_eq!(verdict["status"], "tampered");
    assert_eq!(verdict["reason_code"], USER_WRITABLE);

    let mut missing = rows.clone();
    missing.pop();
    assert_eq!(
        verify_managed_file(Value::Array(missing))["reason_code"],
        PROBE_FAILED
    );

    let mut renamed = rows;
    renamed[4]["Name"] = json!("filesystem-004");
    assert_eq!(
        verify_managed_file(Value::Array(renamed))["reason_code"],
        PROBE_FAILED
    );
}

#[test]
fn a_managed_file_on_a_network_share_walks_from_the_share_root() {
    let payload = managed_file_payload_for(r"\\Server\Certs/HOL/../Guard\ca.pem").unwrap();
    let paths: Vec<&str> = payload
        .iter()
        .map(|item| item["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            r"\\Server\Certs\",
            r"\\Server\Certs\Guard",
            r"\\Server\Certs\Guard\ca.pem",
        ]
    );
    assert_eq!(payload[2]["leaf"], true);
    assert_eq!(payload[0]["expectedContainer"], true);
}
