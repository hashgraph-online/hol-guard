//! Store, schema-marker and request-validation cases for `LocalCliGrantDecide`.

use super::*;

#[test]
fn ungrantable_material_matches_nothing() {
    let fixture = Fixture::new();
    let source = LocalCliIdentitySourceV1::Script {
        entrypoint: serde_json::json!({"kind": "python-c", "status": "verified"}),
    };
    let request = fixture.request(&source, "review", None);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["payload"]["state"], "none");
    assert_eq!(reply["payload"]["cli_id"], Value::Null);
}

#[test]
fn missing_store_and_missing_tables_match_nothing() {
    let fixture = Fixture::new();
    let identity = script();
    fs::remove_file(fixture.home.join("guard.db")).unwrap();
    assert_eq!(state(&fixture, &identity, "review", None), "none");
    Connection::open(fixture.home.join("guard.db"))
        .unwrap()
        .execute_batch("create table unrelated (x integer)")
        .unwrap();
    assert_eq!(state(&fixture, &identity, "review", None), "none");
}

#[test]
fn newer_schema_fails_instead_of_guessing() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    fixture
        .connection
        .execute("update local_cli_schema_migration set version = 12", [])
        .unwrap();
    let request = fixture.request(&identity.source, "review", None);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_local_cli_grant_schema_unsupported");
    assert_eq!(reply["payload"], Value::Null);
}

#[test]
fn damaged_schema_marker_fails_instead_of_authorizing() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    assert_eq!(state(&fixture, &identity, "review", None), "allowed");
    for (version, checksum) in [
        (11, "checksum".to_owned()),
        (11, crate::local_store_read::schema_checksum(10)),
        (0, crate::local_store_read::schema_checksum(0)),
    ] {
        fixture
            .connection
            .execute(
                "update local_cli_schema_migration set version = ?1, checksum = ?2",
                rusqlite::params![version, checksum],
            )
            .unwrap();
        let request = fixture.request(&identity.source, "review", None);
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "error", "{version} {checksum}");
        assert_eq!(reply["code"], "native_local_cli_grant_schema_invalid");
        assert_eq!(reply["payload"], Value::Null);
    }
}

#[test]
fn store_path_must_be_guard_db_directly_under_home() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    let other = Fixture::new();
    let mut cases = Vec::new();
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = other.home.join("guard.db").to_string_lossy().into_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = fixture.home.join("other.db").to_string_lossy().into_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = "guard.db".to_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.guard_home = "relative".to_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = fixture
        .home
        .join("..")
        .join(fixture.home.file_name().unwrap())
        .join("sub")
        .join("guard.db")
        .to_string_lossy()
        .into_owned();
    cases.push(request);
    for request in cases {
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "error", "{request:?}");
        assert_eq!(reply["code"], "native_local_cli_grant_path_invalid");
    }
}

#[test]
fn invalid_command_id_and_schema_are_rejected() {
    let fixture = Fixture::new();
    let identity = script();
    for bad in ["", "caf\u{e9}"] {
        let request = fixture.request(&identity.source, "review", Some(bad));
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["code"], "native_local_cli_grant_command_invalid");
    }
    let mut request = fixture.request(&identity.source, "review", None);
    request.schema = "wrong".to_owned();
    assert_eq!(
        evaluate_local_cli_grant_request(&request).unwrap_err(),
        "native_local_cli_grant_schema_mismatch"
    );
}

#[test]
fn reply_binds_to_the_request_digest() {
    let fixture = Fixture::new();
    let identity = script();
    let request = fixture.request(&identity.source, "review", None);
    let first: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    let other = fixture.request(&identity.source, "warn", None);
    let second: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&other).unwrap()).unwrap();
    assert!(first["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_ne!(first["request_sha256"], second["request_sha256"]);
}
