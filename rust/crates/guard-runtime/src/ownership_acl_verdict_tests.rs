use serde_json::{json, Value};

use super::*;

fn default_paths() -> Value {
    json!({
        "runtime_root": r"C:\Program Files\HOL Guard",
        "manifest_path": r"C:\Program Files\HOL Guard\release-manifest.json",
        "state_root": r"C:\ProgramData\HOL\Guard",
        "log_root": r"C:\ProgramData\HOL\Guard\logs",
    })
}

fn run(request: Value) -> Result<Value, String> {
    let bytes = run_command(serde_json::to_vec(&request).unwrap().as_slice())?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

fn payload_for(paths: Value) -> Vec<Value> {
    let response = run(json!({
        "schema": SCHEMA,
        "op": "windows-payload",
        "windows_paths": paths,
    }))
    .unwrap();
    response["payload"].as_array().unwrap().clone()
}

/// One healthy probe row per payload item: SYSTEM owns it and users may read.
fn healthy_rows() -> Vec<Value> {
    healthy_rows_for(payload_for(default_paths()))
}

fn healthy_rows_for(payload: Vec<Value>) -> Vec<Value> {
    payload
        .iter()
        .map(|item| {
            let container = item["expectedContainer"].as_bool().unwrap();
            json!({
                "Name": item["name"],
                "Kind": item["kind"],
                "ExpectedContainer": container,
                "Leaf": item["leaf"],
                "Exists": true,
                "Owner": "S-1-5-18",
                "Attributes": if container { 16 } else { 0 },
                "Container": container,
                "NullDacl": false,
                "Truncated": false,
                "Rules": [{
                    "Sid": "S-1-5-32-545",
                    "Type": "Allow",
                    "Rights": 1_179_817,
                    "Propagation": "None",
                }],
            })
        })
        .collect()
}

fn verify(rows: Value) -> Value {
    run(json!({
        "schema": SCHEMA,
        "op": "windows-verify",
        "windows_paths": default_paths(),
        "rows": rows,
    }))
    .unwrap()
}

fn row_named<'a>(rows: &'a mut [Value], kind: &str, path: &str) -> &'a mut Value {
    let name = payload_for(default_paths())
        .into_iter()
        .find(|item| item["kind"] == kind && item["path"] == path)
        .unwrap()["name"]
        .clone();
    rows.iter_mut().find(|row| row["Name"] == name).unwrap()
}

fn first_rule(row: &mut Value) -> &mut Value {
    &mut row["Rules"][0]
}

#[test]
fn the_payload_lists_every_ancestor_once() {
    let payload = payload_for(default_paths());
    let spelled: Vec<(&str, &str, bool, bool)> = payload
        .iter()
        .map(|item| {
            (
                item["kind"].as_str().unwrap(),
                item["path"].as_str().unwrap(),
                item["expectedContainer"].as_bool().unwrap(),
                item["leaf"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        spelled,
        vec![
            ("filesystem", r"C:\", true, false),
            ("filesystem", r"C:\Program Files", true, false),
            ("filesystem", r"C:\Program Files\HOL Guard", true, true),
            (
                "filesystem",
                r"C:\Program Files\HOL Guard\release-manifest.json",
                false,
                true
            ),
            ("filesystem", r"C:\ProgramData", true, false),
            ("filesystem", r"C:\ProgramData\HOL", true, false),
            ("filesystem", r"C:\ProgramData\HOL\Guard", true, true),
            (
                "filesystem",
                r"C:\ProgramData\HOL\Guard\device-key.json",
                false,
                true
            ),
            (
                "filesystem",
                r"C:\ProgramData\HOL\Guard\installation-continuity.json",
                false,
                true
            ),
            (
                "filesystem",
                r"C:\ProgramData\HOL\Guard\.installation-continuity.lock",
                false,
                true
            ),
            ("filesystem", r"C:\ProgramData\HOL\Guard\logs", true, true),
            ("registry", r"HKLM:\", true, false),
            ("registry", r"HKLM:\Software", true, false),
            ("registry", r"HKLM:\Software\Policies", true, false),
            ("registry", r"HKLM:\Software\Policies\HOL", true, false),
            ("registry", r"HKLM:\Software\Policies\HOL\Guard", true, true),
            ("registry", r"HKLM:\Software\Microsoft", true, false),
            (
                "registry",
                r"HKLM:\Software\Microsoft\Active Setup",
                true,
                false
            ),
            (
                "registry",
                r"HKLM:\Software\Microsoft\Active Setup\Installed Components",
                true,
                false
            ),
            ("registry", WINDOWS_ACTIVE_SETUP, true, true),
        ]
    );
    let names: Vec<&str> = payload
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names[0], "filesystem-000");
    assert_eq!(names[11], "registry-011");
}

#[test]
fn the_payload_ignores_case_and_normalizes_separators() {
    let mut paths = default_paths();
    paths["manifest_path"] = json!(r"C:\PROGRAM FILES\HOL GUARD/./release-manifest.json");
    paths["log_root"] = json!(r"C:\ProgramData\HOL\Guard\state\..\logs\");
    let payload = payload_for(paths);
    let mut keys: Vec<(String, String)> = payload
        .iter()
        .map(|item| {
            (
                item["kind"].as_str().unwrap().to_owned(),
                item["path"].as_str().unwrap().to_lowercase(),
            )
        })
        .collect();
    let count = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), count);
    assert!(payload.iter().any(|item| item["path"]
        == r"C:\PROGRAM FILES\HOL GUARD\release-manifest.json"
        && item["leaf"] == true));
    assert!(payload
        .iter()
        .any(|item| item["path"] == r"C:\ProgramData\HOL\Guard\logs"));
}

#[test]
fn an_ancestor_that_is_also_a_requested_leaf_is_marked_leaf() {
    let mut paths = default_paths();
    paths["state_root"] = json!(r"C:\ProgramData\HOL\Guard\logs\state");
    paths["log_root"] = json!(r"C:\ProgramData\HOL\Guard\logs");
    let payload = payload_for(paths);
    let logs = payload
        .iter()
        .find(|item| item["path"] == r"C:\ProgramData\HOL\Guard\logs")
        .unwrap();
    assert_eq!(logs["leaf"], true);
    assert_eq!(logs["expectedContainer"], true);
}

#[test]
fn paths_that_are_not_drive_or_share_absolute_are_refused() {
    for spelling in [
        r"Program Files\HOL Guard",
        r"\HOL Guard",
        "C:relative",
        r"\\server\share",
        r"\\server\\Guard",
        r"\\?\C:\HOL Guard",
        r"\\?\UNC\server\share\Guard",
        r"\\.\C:\HOL Guard",
    ] {
        let mut paths = default_paths();
        paths["runtime_root"] = json!(spelling);
        let error = run(json!({"schema": SCHEMA, "op": "windows-payload", "windows_paths": paths}));
        assert_eq!(error, Err("ownership_acl_request_invalid".to_owned()));
        let verdict = run(json!({
            "schema": SCHEMA,
            "op": "windows-verify",
            "windows_paths": paths,
            "rows": healthy_rows(),
        }))
        .unwrap();
        assert_eq!(verdict["reason_code"], PROBE_FAILED);
    }
}

#[test]
fn read_only_users_are_healthy() {
    let verdict = verify(Value::Array(healthy_rows()));
    assert_eq!(verdict["status"], "healthy");
    assert_eq!(verdict["reason_code"], VALID);
}

#[test]
fn row_failures_are_reported_honestly() {
    let cases = [
        ("Owner", json!("S-1-5-21-1-2-3-1001"), WRONG_OWNER),
        ("Owner", json!("S-1-3-0"), WRONG_OWNER),
        ("Attributes", json!(0x400), PATH_ESCAPE),
        ("Attributes", json!("Directory"), PATH_ESCAPE),
        ("Container", json!(false), PATH_ESCAPE),
        ("Exists", json!(false), ABSENT),
        ("Truncated", json!(true), PROBE_FAILED),
        ("NullDacl", json!(true), USER_WRITABLE),
    ];
    for (field, value, reason) in cases {
        let mut rows = healthy_rows();
        rows[0][field] = value;
        assert_eq!(verify(Value::Array(rows))["reason_code"], reason, "{field}");
    }
}

#[test]
fn a_single_row_object_is_read_as_one_row() {
    let rows = healthy_rows();
    let verdict = verify(rows[0].clone());
    assert_eq!(verdict["reason_code"], PROBE_FAILED);
    assert_eq!(verdict["surfaces"][0]["name"], "platform");
}

#[test]
fn standard_user_mutation_is_tampering() {
    let mut rows = healthy_rows();
    let runtime = row_named(&mut rows, "filesystem", r"C:\Program Files\HOL Guard");
    first_rule(runtime)["Rights"] = json!(2);
    assert_eq!(verify(Value::Array(rows))["reason_code"], USER_WRITABLE);
}

#[test]
fn generic_mutation_bits_are_tampering_on_leaves_and_ancestors() {
    for rights in [0x4000_0000_i64, 0x1000_0000] {
        for path in [r"C:\Program Files", r"C:\Program Files\HOL Guard"] {
            let mut rows = healthy_rows();
            first_rule(row_named(&mut rows, "filesystem", path))["Rights"] = json!(rights);
            assert_eq!(verify(Value::Array(rows))["reason_code"], USER_WRITABLE);
        }
    }
}

#[test]
fn a_mutable_ancestor_is_tampering() {
    for (kind, path, rights) in [
        ("filesystem", r"C:\ProgramData", 64),
        ("registry", r"HKLM:\Software", 65_536),
    ] {
        let mut rows = healthy_rows();
        first_rule(row_named(&mut rows, kind, path))["Rights"] = json!(rights);
        assert_eq!(verify(Value::Array(rows))["reason_code"], USER_WRITABLE);
    }
}

#[test]
fn creating_children_under_an_ancestor_is_allowed() {
    for (kind, path) in [("filesystem", r"C:\"), ("registry", r"HKLM:\Software")] {
        let mut rows = healthy_rows();
        first_rule(row_named(&mut rows, kind, path))["Rights"] = json!(4);
        assert_eq!(verify(Value::Array(rows))["status"], "healthy");
    }
}

#[test]
fn privileged_and_inherit_only_rules_are_not_tampering() {
    for sid in ["S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"] {
        let mut rows = healthy_rows();
        first_rule(&mut rows[0])["Sid"] = json!(sid);
        first_rule(&mut rows[0])["Rights"] = json!(983_551);
        assert_eq!(verify(Value::Array(rows))["status"], "healthy", "{sid}");
    }
    let mut rows = healthy_rows();
    first_rule(&mut rows[0])["Rights"] = json!(983_551);
    first_rule(&mut rows[0])["Propagation"] = json!("InheritOnly");
    assert_eq!(verify(Value::Array(rows.clone()))["status"], "healthy");
    first_rule(&mut rows[0])["Propagation"] = json!("NoPropagateInherit, InheritOnly");
    assert_eq!(verify(Value::Array(rows.clone()))["status"], "healthy");
    first_rule(&mut rows[0])["Type"] = json!("Deny");
    first_rule(&mut rows[0])["Propagation"] = json!("None");
    assert_eq!(verify(Value::Array(rows))["status"], "healthy");
}

#[test]
fn malformed_duplicate_or_missing_rows_fail_the_probe() {
    let mut malformed = healthy_rows();
    first_rule(&mut malformed[0])["Rights"] = json!("Write");
    let mut bad_type = healthy_rows();
    first_rule(&mut bad_type[0])["Type"] = json!("Audit");
    let mut bad_propagation = healthy_rows();
    first_rule(&mut bad_propagation[0])["Propagation"] = json!("");
    let mut bad_kind = healthy_rows();
    bad_kind[0]["Kind"] = json!("share");
    let mut no_rules = healthy_rows();
    no_rules[0]["Rules"] = json!({});
    let mut duplicate = healthy_rows();
    duplicate.push(duplicate[0].clone());
    let mut missing = healthy_rows();
    missing.pop();
    let mut renamed = healthy_rows();
    renamed[0]["Name"] = json!("filesystem-999");
    for rows in [
        malformed,
        bad_type,
        bad_propagation,
        bad_kind,
        no_rules,
        duplicate,
        missing,
        renamed,
    ] {
        let verdict = verify(Value::Array(rows));
        assert_eq!(verdict["status"], "unknown");
        assert_eq!(verdict["reason_code"], PROBE_FAILED);
        assert_eq!(
            verdict["surfaces"],
            json!([{"name": "platform", "state": "unknown", "reason_code": PROBE_FAILED}])
        );
    }
    assert_eq!(verify(json!("rows"))["reason_code"], PROBE_FAILED);
}

#[test]
fn aggregate_ranks_tampering_before_absence_and_unknowns() {
    let surface =
        |state: &str, reason: &str| json!({"name": "x", "state": state, "reason_code": reason});
    let cases = [
        (
            vec![
                surface("healthy", VALID),
                surface("tampered", WRONG_OWNER),
                surface("tampered", PATH_ESCAPE),
            ],
            "tampered",
            PATH_ESCAPE,
        ),
        (
            vec![
                surface("tampered", WRONG_OWNER),
                surface("tampered", USER_WRITABLE),
            ],
            "tampered",
            USER_WRITABLE,
        ),
        (
            vec![
                surface("absent", ABSENT),
                surface("tampered", "ownership_acl_other"),
            ],
            "tampered",
            PROBE_FAILED,
        ),
        (
            vec![surface("unknown", PROBE_FAILED), surface("absent", ABSENT)],
            "absent",
            ABSENT,
        ),
        (
            vec![
                surface("unsupported", UNSUPPORTED),
                surface("unknown", PROBE_FAILED),
            ],
            "unknown",
            PROBE_FAILED,
        ),
        (
            vec![surface("unsupported", UNSUPPORTED)],
            "unsupported",
            UNSUPPORTED,
        ),
        (vec![surface("healthy", VALID)], "healthy", VALID),
        (vec![], "healthy", VALID),
    ];
    for (surfaces, status, reason) in cases {
        let verdict =
            run(json!({"schema": SCHEMA, "op": "aggregate", "surfaces": surfaces.clone()}))
                .unwrap();
        assert_eq!(verdict["status"], status);
        assert_eq!(verdict["reason_code"], reason);
        assert_eq!(verdict["surfaces"], Value::Array(surfaces));
    }
}

#[test]
fn malformed_requests_are_refused() {
    let invalid = Err("ownership_acl_request_invalid".to_owned());
    assert_eq!(
        run(json!({"schema": "other", "op": "aggregate", "surfaces": []})),
        invalid
    );
    assert_eq!(run(json!({"schema": SCHEMA, "op": "probe"})), invalid);
    assert_eq!(run(json!({"schema": SCHEMA, "op": "aggregate"})), invalid);
    assert_eq!(
        run(json!({"schema": SCHEMA, "op": "windows-verify", "windows_paths": default_paths()})),
        invalid
    );
    assert_eq!(
        run(json!({"schema": SCHEMA, "op": "windows-payload"})),
        invalid
    );
    assert_eq!(
        run(json!({"schema": SCHEMA, "op": "aggregate", "surfaces": [], "extra": 1})),
        invalid
    );
    assert_eq!(
        run(
            json!({"schema": SCHEMA, "op": "aggregate", "surfaces": [{"name": "x", "state": "fine", "reason_code": VALID}]})
        ),
        invalid
    );
    assert_eq!(
        run_command(&b"not json"[..]),
        Err("ownership_acl_request_invalid".to_owned())
    );
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(oversized.as_slice()),
        Err("ownership_acl_request_too_large".to_owned())
    );
}

#[path = "ownership_acl_verdict_managed_file_tests.rs"]
mod managed_file;
