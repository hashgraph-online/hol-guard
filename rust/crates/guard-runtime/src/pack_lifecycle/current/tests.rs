use super::*;

fn fixture() -> (Floor, Value) {
    let engine = guard_command::source_cli::compiler_info()["implementation_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let installed = Identity {
        profile: "installed".into(),
        source: "a".repeat(40),
        engine: engine.clone(),
        root: "0".repeat(64),
        version: "3.49.0".into(),
        authority: 1,
        revocation: 0,
    };
    let floor = Floor {
        schema: "guard.command-pack-floor.v1".into(),
        source: installed.source.clone(),
        authority: 1,
        revocation: 0,
        installed: Some(installed),
        remote: None,
    };
    let root = json!({"schema":"guard.extension-distribution.v2","source_sha":"a".repeat(40),
        "engine":engine,"authority_epoch":1,"publication_id":"10.1","issued_at":1000,"expires_at":2000,
        "policy":{"revocations":{"epoch":0,"count":0,"index":null}}});
    (floor, root)
}
fn request(root: &Value) -> Value {
    json!({"publication":root.to_string(),"now":1500})
}
#[test]
fn current_cursor_is_monotonic_and_separate_from_activation() {
    let (active, mut root) = fixture();
    let key = [7; 32];
    let before = encode(&active, &key).unwrap();
    let first = evaluate(&request(&root), &active, &key).unwrap();
    assert_eq!(encode(&active, &key).unwrap(), before);
    let cursor = first["record"].clone();
    root["publication_id"] = json!("10.2");
    let mut input = request(&root);
    input["cursor"] = cursor;
    let next = evaluate(&input, &active, &key).unwrap();
    input["cursor"] = next["record"].clone();
    root["publication_id"] = json!("10.1");
    input["publication"] = json!(root.to_string());
    assert_eq!(
        evaluate(&input, &active, &key).unwrap_err(),
        "pack_lifecycle_version_rollback"
    );
    let retained = evaluate(&json!({"cursor":next["record"]}), &active, &key).unwrap();
    assert_eq!(retained["retained"]["version"], "10.2");
}
#[test]
fn current_rejects_expiry_engine_sentinel_epoch_and_substitution() {
    let (active, root) = fixture();
    let key = [7; 32];
    let first = evaluate(&request(&root), &active, &key).unwrap();
    for (field, value, code) in [
        ("expires_at", json!(1500), "authority_expired"),
        ("engine", json!("e".repeat(64)), "engine_incompatible"),
        ("publication_id", json!("0.0"), "remote_authority_required"),
        ("authority_epoch", json!(0), "identity_invalid"),
    ] {
        let mut bad = root.clone();
        bad[field] = value;
        assert!(evaluate(&request(&bad), &active, &key)
            .unwrap_err()
            .contains(code));
    }
    let mut bad = root.clone();
    bad["issued_at"] = json!(1001);
    let mut input = request(&bad);
    input["cursor"] = first["record"].clone();
    assert_eq!(
        evaluate(&input, &active, &key).unwrap_err(),
        "pack_lifecycle_version_reused"
    );
    input["cursor"] = json!("corrupt");
    assert!(evaluate(&input, &active, &key)
        .unwrap_err()
        .contains("floor_invalid"));
}
#[test]
fn ancestry_is_requested_and_checked_for_each_protected_floor() {
    let (active, mut root) = fixture();
    let key = [7; 32];
    root["source_sha"] = json!("b".repeat(40));
    let mut input = request(&root);
    let missing = evaluate(&input, &active, &key).unwrap();
    assert_eq!(missing["lineage_kind"], "active");
    input["active_ancestry"] = json!({"status":"ahead","base_commit":{"sha":active.source},
        "merge_base_commit":{"sha":active.source},"head_commit":{"sha":"b".repeat(40)},
        "behind_by":0,"ahead_by":1});
    assert!(evaluate(&input, &active, &key).is_ok());
    input["active_ancestry"]["head_commit"]["sha"] = json!("c".repeat(40));
    assert_eq!(
        evaluate(&input, &active, &key).unwrap_err(),
        "pack_lifecycle_source_ancestry_required"
    );
}

#[test]
fn restore_uses_only_exact_completed_identity_without_lowering_cursor() {
    let (active, mut root) = fixture();
    let key = [7; 32];
    let complete = evaluate(&request(&root), &active, &key).unwrap()["record"].clone();
    root["publication_id"] = json!("10.2");
    let mut input = request(&root);
    input["cursor"] = complete.clone();
    let cursor = evaluate(&input, &active, &key).unwrap()["record"].clone();
    root["publication_id"] = json!("10.1");
    input = request(&root);
    input["cursor"] = cursor.clone();
    input["restore"] = json!(true);
    input["complete"] = complete;
    assert_eq!(evaluate(&input, &active, &key).unwrap()["view"], true);
    assert_eq!(input["cursor"], cursor);
    root["issued_at"] = json!(1001);
    input["publication"] = json!(root.to_string());
    assert_eq!(
        evaluate(&input, &active, &key).unwrap_err(),
        "discovery_current_complete_mismatch"
    );
    input["complete"] = json!("corrupt");
    assert!(evaluate(&input, &active, &key).is_err());
}

#[test]
fn cache_plan_pins_observed_and_complete_roots_and_ignores_other_files() {
    let (active, mut root) = fixture();
    let key = [7; 32];
    let complete = evaluate(&request(&root), &active, &key).unwrap()["record"].clone();
    let old = decode(complete.as_str().unwrap(), &key)
        .unwrap()
        .remote
        .unwrap()
        .root;
    root["publication_id"] = json!("10.2");
    let mut input = request(&root);
    input["cursor"] = complete.clone();
    let current = evaluate(&input, &active, &key).unwrap()["record"].clone();
    let new = decode(current.as_str().unwrap(), &key)
        .unwrap()
        .remote
        .unwrap()
        .root;
    let stale = format!("{}.root", "f".repeat(64));
    let plan = evaluate(&json!({"cursor":current,"complete":complete,
        "files":[format!("{old}.root"),format!("{new}.provenance"),stale,"../secret","notes.root"]}),&active,&key).unwrap();
    assert_eq!(plan["remove"], json!([stale]));
}
