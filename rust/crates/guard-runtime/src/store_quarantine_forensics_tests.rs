use super::*;

fn request(guard_home: &Path, body: Value) -> Value {
    let mut request = json!({
        "schema": SCHEMA,
        "guard_home": guard_home.to_str().expect("utf-8 home"),
        "quarantine_id": "20260101T000000000000Z-test",
    });
    for (name, value) in body.as_object().expect("object") {
        request[name] = value.clone();
    }
    request
}

fn facts(guard_home: &Path, store_path: Option<&Path>) -> Value {
    json!({
        "store_path": store_path.map(|path| path.to_str().expect("utf-8 path")),
        "quarantined_at": "2026-01-01T00:00:00+00:00",
        "error_class": "DatabaseError",
        "error_message": format!("{}/guard.db: database disk image is malformed", guard_home.display()),
        "sqlite_errorcode": 11,
        "sqlite_errorname": "SQLITE_CORRUPT",
        "probe": {"first_state": "fatal", "second_state": "fatal", "guard_home_accepts_write": true, "identity_stable": true},
        "files": {"db": {"size": 12, "dev": 1, "ino": 2, "mtime_ns": 3}},
        "pid": 42,
        "guard_version": "9.9.9",
        "sqlite_version": "3.45.0",
        "process": "hol-guard",
    })
}

fn ask(request: &Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn record_file(guard_home: &Path) -> PathBuf {
    guard_home.join("guard.db.corrupt-20260101T000000000000Z-test.forensics.json")
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("record")).expect("record JSON")
}

#[test]
fn a_record_redacts_the_guard_home_and_is_owner_only() {
    let home = tempfile::tempdir().expect("home");
    let store = home.path().join("guard.db");
    let mut page = vec![0_u8; 4096];
    page[..8].copy_from_slice(&[0x0D, 0, 0, 0, 1, 0x0F, 0x85, 0]);
    fs::write(&store, page.repeat(3)).expect("store");

    let answer = ask(&request(
        home.path(),
        json!({"op": "record", "record": facts(home.path(), Some(&store))}),
    ))
    .expect("recorded");
    assert_eq!(answer, json!({"written": true}));

    let path = record_file(home.path());
    let text = fs::read_to_string(&path).expect("record text");
    assert!(text.ends_with('\n'));
    assert!(!text.contains(home.path().to_str().expect("utf-8 home")));
    let record = read(&path);
    assert_eq!(record["schema"], RECORD_SCHEMA);
    assert_eq!(
        record["error_message"],
        "<guard_home>/guard.db: database disk image is malformed"
    );
    assert_eq!(record["sqlite_wal_reset_bug_possible"], true);
    assert_eq!(record["sqlite_errorname"], "SQLITE_CORRUPT");
    assert_eq!(record["process"], "hol-guard");
    assert_eq!(record["pid"], 42);
    assert_eq!(record["files"]["db"]["ino"], 2);
    assert_eq!(record["header"]["header_magic_ok"], false);
    assert_eq!(
        record["header"]["page1_looks_like_btree_page"],
        "leaf-table"
    );
    assert_eq!(record["header"]["file_size"], 3 * 4096);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("mode").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let leftovers: Vec<_> = fs::read_dir(home.path())
        .expect("home listing")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
}

/// The record is canonical JSON: sorted keys, no spaces, ASCII escapes.
#[test]
fn a_record_is_canonical_ascii_json() {
    let home = tempfile::tempdir().expect("home");
    let mut facts = facts(home.path(), None);
    facts["error_message"] = json!("caf\u{e9} broke");
    facts["probe"] = Value::Null;
    ask(&request(
        home.path(),
        json!({"op": "record", "record": facts}),
    ))
    .expect("recorded");
    let text = fs::read_to_string(record_file(home.path())).expect("record text");
    assert!(text.contains(r#""error_message":"caf\u00e9 broke""#));
    assert!(text.contains(r#""probe":null"#));
    assert!(!text.contains("header"));
    assert!(text.starts_with(r#"{"error_class":"DatabaseError","error_message":"#));
}

#[test]
fn a_long_message_is_cut_to_five_hundred_characters() {
    let home = tempfile::tempdir().expect("home");
    let mut facts = facts(home.path(), None);
    facts["error_message"] = json!("\u{e9}".repeat(800));
    ask(&request(
        home.path(),
        json!({"op": "record", "record": facts}),
    ))
    .expect("recorded");
    let record = read(&record_file(home.path()));
    assert_eq!(
        record["error_message"]
            .as_str()
            .expect("text")
            .chars()
            .count(),
        MESSAGE_LIMIT
    );
}

#[test]
fn an_outcome_keeps_the_record_and_adds_the_salvage() {
    let home = tempfile::tempdir().expect("home");
    ask(&request(
        home.path(),
        json!({"op": "record", "record": facts(home.path(), None)}),
    ))
    .expect("recorded");
    ask(&request(
        home.path(),
        json!({"op": "outcome", "outcome": "reinitialized_salvaged", "salvage": {"cloud_review": true, "local_cli": false}}),
    ))
    .expect("updated");
    let record = read(&record_file(home.path()));
    assert_eq!(record["outcome"], "reinitialized_salvaged");
    assert_eq!(
        record["salvage"],
        json!({"cloud_review": true, "local_cli": false})
    );
    assert_eq!(record["pid"], 42);
}

#[test]
fn an_outcome_without_a_readable_record_starts_one() {
    let home = tempfile::tempdir().expect("home");
    fs::write(record_file(home.path()), b"[not an object]").expect("garbage");
    ask(&request(
        home.path(),
        json!({"op": "outcome", "outcome": "restored", "salvage": {}}),
    ))
    .expect("updated");
    assert_eq!(
        read(&record_file(home.path())),
        json!({
            "schema": RECORD_SCHEMA,
            "quarantine_id": "20260101T000000000000Z-test",
            "outcome": "restored",
        })
    );
}

#[test]
fn the_header_diagnosis_reads_real_and_damaged_stores() {
    let home = tempfile::tempdir().expect("home");
    let good = home.path().join("good.db");
    let mut header = vec![0_u8; 4096 * 2];
    header[..16].copy_from_slice(SQLITE_MAGIC);
    header[16..18].copy_from_slice(&4096_u16.to_be_bytes());
    header[18] = 2;
    header[19] = 2;
    fs::write(&good, &header).expect("good");
    let diagnosis = header_diagnosis(&good);
    assert_eq!(diagnosis["header_magic_ok"], true);
    assert_eq!(diagnosis["page_size_field"], 4096);
    assert_eq!(diagnosis["size_multiple_of_page"], true);
    assert_eq!(diagnosis["wal_mode_header"], true);
    assert!(!diagnosis.contains_key("page1_looks_like_btree_page"));
    assert!(!diagnosis.contains_key("header_zeroed"));

    header[16..18].copy_from_slice(&1_u16.to_be_bytes());
    header.resize(4096 * 2 + 100, 0);
    fs::write(&good, &header).expect("odd size");
    let diagnosis = header_diagnosis(&good);
    assert_eq!(diagnosis["page_size_field"], 65536);
    assert_eq!(diagnosis["size_multiple_of_page"], false);

    let zeroed = home.path().join("zero.db");
    fs::write(&zeroed, vec![0_u8; 4096]).expect("zeroed");
    let diagnosis = header_diagnosis(&zeroed);
    assert_eq!(diagnosis["header_zeroed"], true);
    assert_eq!(diagnosis["header_magic_ok"], false);

    let empty = home.path().join("empty.db");
    fs::write(&empty, b"").expect("empty");
    let diagnosis = header_diagnosis(&empty);
    assert_eq!(diagnosis["file_size"], 0);
    assert!(!diagnosis.contains_key("header_zeroed"));

    assert!(header_diagnosis(&home.path().join("missing.db")).is_empty());
    assert!(header_diagnosis(home.path()).is_empty());
    #[cfg(unix)]
    {
        let link = home.path().join("link.db");
        std::os::unix::fs::symlink(&zeroed, &link).expect("symlink");
        assert!(header_diagnosis(&link).is_empty());
    }
}

#[test]
fn the_wal_reset_bug_window_ends_at_3_51_3() {
    assert!(wal_reset_bug_possible("3.45.0"));
    assert!(wal_reset_bug_possible("3.51.2"));
    assert!(!wal_reset_bug_possible("3.51.3"));
    assert!(!wal_reset_bug_possible("3.52.0"));
    assert!(!wal_reset_bug_possible("4.0"));
    assert!(wal_reset_bug_possible("3.51"));
    assert!(wal_reset_bug_possible("not-a-version"));
}

#[test]
fn branch_backports_of_the_wal_reset_fix_count_as_fixed() {
    assert!(wal_reset_bug_possible("3.50.6"));
    assert!(!wal_reset_bug_possible("3.50.7"));
    assert!(!wal_reset_bug_possible("3.50.7.1"));
    assert!(wal_reset_bug_possible("3.44.5"));
    assert!(!wal_reset_bug_possible("3.44.6"));
    assert!(wal_reset_bug_possible("3.49.9"));
}

#[test]
fn a_record_at_the_size_limit_survives_an_outcome_read() {
    let home = tempfile::tempdir().expect("home");
    let path = record_file(home.path());
    let pad = "a".repeat(MAX_RECORD_BYTES as usize - r#"{"pad":""}"#.len());
    write_owner_only(&path, &json!({ "pad": pad })).expect("written at the limit");
    assert_eq!(
        fs::metadata(&path).expect("record").len(),
        MAX_RECORD_FILE_BYTES
    );
    assert_eq!(
        read_record(&path).expect("readable")["pad"].as_str(),
        Some(pad.as_str())
    );
}

#[test]
fn a_failed_write_answers_its_reason() {
    let home = tempfile::tempdir().expect("home");
    let missing = home.path().join("missing");
    let answer = ask(&request(
        &missing,
        json!({"op": "outcome", "outcome": "restored"}),
    ))
    .expect("answered");
    assert_eq!(answer, json!({"written": false, "error": "NotFound"}));
}

#[test]
fn requests_are_validated() {
    let home = tempfile::tempdir().expect("home");
    let record = json!({"op": "record", "record": facts(home.path(), None)});
    let mut cases = Vec::new();
    for (name, value) in [
        ("schema", json!("store-quarantine-forensics.v0")),
        ("op", json!("delete")),
        ("guard_home", json!("")),
        ("quarantine_id", json!("../escape")),
        ("quarantine_id", json!("a/b")),
        ("quarantine_id", json!("")),
        ("quarantine_id", json!("x".repeat(MAX_ID_BYTES + 1))),
        ("outcome", json!("restored")),
        ("salvage", json!({"local_cli": true})),
        ("extra", json!(true)),
    ] {
        let mut request = request(home.path(), record.clone());
        request[name] = value;
        cases.push(request);
    }
    let mut unknown_fact = request(home.path(), record);
    unknown_fact["record"]["path"] = json!("/etc/passwd");
    cases.push(unknown_fact);
    cases.push(request(home.path(), json!({"op": "outcome"})));
    for request in cases {
        assert_eq!(
            ask(&request).expect_err("refused"),
            "store_quarantine_forensics_request_invalid",
            "{request}"
        );
    }
    assert_eq!(fs::read_dir(home.path()).expect("listing").count(), 0);
}
