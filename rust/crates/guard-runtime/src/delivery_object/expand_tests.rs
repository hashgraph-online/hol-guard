use super::*;

const PACK: &str = "guard.pack-concat.v1";
const LOCATED: &str = "guard.delivery-concat.v2";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn put(dir: &Path, bytes: &[u8]) -> String {
    let sha = digest(bytes);
    fs::write(dir.join(format!("{sha}.json")), bytes).unwrap();
    sha
}

fn data_ref(bytes: &[u8]) -> Value {
    json!({
        "sha256": digest(bytes),
        "length": bytes.len(),
        "expanded_length": bytes.len(),
        "kind": "data",
    })
}

fn located(mut reference: Value) -> Value {
    let sha = reference["sha256"].as_str().unwrap().to_owned();
    let tag = format!("extension-data-{}-1.1-000001", "c".repeat(40));
    reference["location"] = json!({"tag": tag, "asset": format!("object-{sha}.json")});
    reference
}

fn concat_ref(bytes: &[u8], expanded: u64) -> Value {
    json!({
        "sha256": digest(bytes),
        "length": bytes.len(),
        "expanded_length": expanded,
        "kind": "concat",
    })
}

/// Write the concatenation object for `parts` and return its reference.
fn concat(dir: &Path, schema: &str, parts: &[Value]) -> Value {
    let total: u64 = parts
        .iter()
        .map(|part| part["expanded_length"].as_u64().unwrap())
        .sum();
    let value = json!({"schema": schema, "parts": parts});
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value).unwrap();
    put(dir, &bytes);
    concat_ref(&bytes, total)
}

fn expand(dir: &Path, mode: &str, reference: &Value) -> Outcome {
    run(&json!({
        "mode": mode,
        "directory": dir.to_str().unwrap(),
        "reference": reference,
    }))
}

fn bytes_of(outcome: &Value) -> Vec<u8> {
    STANDARD.decode(outcome["data"].as_str().unwrap()).unwrap()
}

#[test]
fn a_data_object_is_its_own_blob() {
    let dir = tempfile::tempdir().unwrap();
    let sha = put(dir.path(), b"hello");
    let out = expand(dir.path(), "pack", &data_ref(b"hello")).unwrap();
    assert_eq!(bytes_of(&out), b"hello");
    assert_eq!(out["reads"], json!([sha]));
}

#[test]
fn a_concat_object_joins_its_parts_in_order() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"alpha");
    put(dir.path(), b"beta");
    let inner = concat(dir.path(), PACK, &[data_ref(b"alpha"), data_ref(b"beta")]);
    put(dir.path(), b"!");
    let outer = concat(dir.path(), PACK, &[inner, data_ref(b"!")]);
    let out = expand(dir.path(), "pack", &outer).unwrap();
    assert_eq!(bytes_of(&out), b"alphabeta!");
    assert_eq!(out["reads"].as_array().unwrap().len(), 5);
}

#[test]
fn a_concat_object_may_end_with_a_newline() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"one");
    let value = json!({"schema": PACK, "parts": [data_ref(b"one")]});
    let mut bytes = guard_policy_snapshot::canonical_json_bytes(&value).unwrap();
    bytes.push(b'\n');
    put(dir.path(), &bytes);
    let out = expand(dir.path(), "pack", &concat_ref(&bytes, 3)).unwrap();
    assert_eq!(bytes_of(&out), b"one");
}

#[test]
fn a_concat_object_written_in_declaration_order_is_refused() {
    // These are the bytes the pack writer would emit if serde_json kept
    // insertion order: `schema` before `parts`, and the reference's fields in
    // the order `ObjectRef` declares them. The reader joins parts only from a
    // canonical object, so it has to refuse this one, and the writer sorts the
    // keys for exactly that reason.
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"one");
    let sha = digest(b"one");
    let part = format!(r#"{{"sha256":"{sha}","length":3,"expanded_length":3,"kind":"data"}}"#);
    let bytes = format!(r#"{{"schema":"{PACK}","parts":[{part}]}}"#).into_bytes();
    put(dir.path(), &bytes);
    assert_eq!(
        expand(dir.path(), "pack", &concat_ref(&bytes, 3)).unwrap_err(),
        "pack concat invalid"
    );
    let sorted = guard_policy_snapshot::canonical_json_bytes(
        &serde_json::from_slice::<Value>(&bytes).unwrap(),
    )
    .unwrap();
    put(dir.path(), &sorted);
    let out = expand(dir.path(), "pack", &concat_ref(&sorted, 3)).unwrap();
    assert_eq!(bytes_of(&out), b"one");
}

#[test]
fn a_located_walk_joins_its_parts_and_checks_each_location() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"left");
    put(dir.path(), b"right");
    let parts = [located(data_ref(b"left")), located(data_ref(b"right"))];
    let top = located(concat(dir.path(), LOCATED, &parts));
    let out = expand(dir.path(), "located", &top).unwrap();
    assert_eq!(bytes_of(&out), b"leftright");
    assert_eq!(out["reads"].as_array().unwrap().len(), 3);
    let mut wrong = located(data_ref(b"right"));
    wrong["location"]["asset"] = json!(format!("object-{}.json", digest(b"left")));
    let parts = [located(data_ref(b"left")), wrong];
    let top = located(concat(dir.path(), LOCATED, &parts));
    assert_eq!(
        expand(dir.path(), "located", &top).unwrap_err(),
        "delivery asset identity invalid"
    );
}

#[test]
fn a_missing_object_is_requested_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    let single = expand(dir.path(), "pack", &data_ref(b"later")).unwrap();
    assert_eq!(single["need"][0]["sha256"], digest(b"later"));
    assert_eq!(single["need"][0]["location"], Value::Null);
    let wanted = located(data_ref(b"later"));
    let out = expand(dir.path(), "located", &wanted).unwrap();
    assert_eq!(
        out["need"],
        json!([{"sha256": wanted["sha256"], "length": 5, "location": wanted["location"]}])
    );
}

#[test]
fn every_missing_sibling_is_requested_once_in_one_round() {
    let dir = tempfile::tempdir().unwrap();
    let parts = [
        located(data_ref(b"one")),
        located(data_ref(b"two")),
        located(data_ref(b"one")),
    ];
    let top = located(concat(dir.path(), LOCATED, &parts));
    let first = expand(dir.path(), "located", &top).unwrap();
    let need = first["need"].as_array().unwrap();
    assert_eq!(need.len(), 2);
    assert_eq!(need[0]["sha256"], digest(b"one"));
    assert_eq!(need[1]["sha256"], digest(b"two"));
    put(dir.path(), b"one");
    put(dir.path(), b"two");
    let done = expand(dir.path(), "located", &top).unwrap();
    assert_eq!(bytes_of(&done), b"onetwoone");
}

#[test]
fn a_walk_asks_for_a_bounded_number_of_objects() {
    let dir = tempfile::tempdir().unwrap();
    let mut branches = Vec::new();
    for branch in 0..5 {
        let parts: Vec<Value> = (0..64)
            .map(|part| data_ref(format!("part-{branch}-{part}").as_bytes()))
            .collect();
        branches.push(concat(dir.path(), PACK, &parts));
    }
    let top = concat(dir.path(), PACK, &branches);
    let out = expand(dir.path(), "pack", &top).unwrap();
    assert_eq!(out["need"].as_array().unwrap().len(), NEED_LIMIT);
}

#[test]
fn a_cached_object_must_match_what_was_asked() {
    let dir = tempfile::tempdir().unwrap();
    let wanted = data_ref(b"original");
    let name = format!("{}.json", digest(b"original"));
    fs::write(dir.path().join(&name), b"tampered").unwrap();
    assert_eq!(
        expand(dir.path(), "pack", &wanted).unwrap_err(),
        "pack object integrity invalid"
    );
    fs::write(dir.path().join(&name), b"OriginaL").unwrap();
    assert_eq!(
        expand(dir.path(), "pack", &wanted).unwrap_err(),
        "pack object integrity invalid"
    );
    fs::write(dir.path().join(&name), b"").unwrap();
    assert_eq!(
        expand(dir.path(), "pack", &wanted).unwrap_err(),
        "pack cache object type or length invalid"
    );
}

#[cfg(unix)]
#[test]
fn a_cached_object_must_not_be_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let real = elsewhere.path().join("real.json");
    fs::write(&real, b"linked").unwrap();
    let link = dir.path().join(format!("{}.json", digest(b"linked")));
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        expand(dir.path(), "pack", &data_ref(b"linked")).unwrap_err(),
        "pack object must not be a symlink"
    );
}

#[test]
fn a_reference_has_exactly_its_known_fields() {
    let dir = tempfile::tempdir().unwrap();
    let mut extra = data_ref(b"x");
    extra["note"] = json!(1);
    let mut short = data_ref(b"x");
    short.as_object_mut().unwrap().remove("kind");
    for case in [extra, short, json!([]), json!(null)] {
        assert_eq!(
            expand(dir.path(), "pack", &case).unwrap_err(),
            "invalid pack object reference"
        );
    }
    for case in [data_ref(b"x"), json!("x")] {
        assert_eq!(
            expand(dir.path(), "located", &case).unwrap_err(),
            "located delivery reference invalid"
        );
    }
}

#[test]
fn reference_bounds_are_enforced_before_any_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut upper = data_ref(b"x");
    upper["sha256"] = json!("AB".repeat(32));
    let mut empty = data_ref(b"x");
    empty["length"] = json!(0);
    let mut large = data_ref(b"x");
    large["length"] = json!(OBJECT_BYTES + 1);
    let mut huge = data_ref(b"x");
    huge["expanded_length"] = json!(BLOB_BYTES + 1);
    let mut text = data_ref(b"x");
    text["length"] = json!("1");
    for case in [upper, empty, large, huge, text] {
        assert_eq!(
            expand(dir.path(), "pack", &case).unwrap_err(),
            "pack object reference bounds invalid",
            "{case}"
        );
    }
    let deep = run(&json!({
        "mode": "pack",
        "directory": dir.path().to_str().unwrap(),
        "reference": data_ref(b"x"),
        "depth": MAX_DEPTH + 1,
    }));
    assert_eq!(deep.unwrap_err(), "pack object reference bounds invalid");
}

#[test]
fn a_located_reference_needs_a_known_kind_and_location() {
    let dir = tempfile::tempdir().unwrap();
    let mut kind = located(data_ref(b"x"));
    kind["kind"] = json!("pack");
    assert_eq!(
        expand(dir.path(), "located", &kind).unwrap_err(),
        "located delivery reference bounds invalid"
    );
    let mut empty = located(data_ref(b"x"));
    empty["expanded_length"] = json!(0);
    assert_eq!(
        expand(dir.path(), "located", &empty).unwrap_err(),
        "located delivery expansion invalid"
    );
    let mut moved = located(data_ref(b"x"));
    moved["location"]["asset"] = json!(format!("object-{}.json", digest(b"y")));
    assert_eq!(
        expand(dir.path(), "located", &moved).unwrap_err(),
        "delivery asset identity invalid"
    );
    let deep = run(&json!({
        "mode": "located",
        "directory": dir.path().to_str().unwrap(),
        "reference": located(data_ref(b"x")),
        "depth": MAX_DEPTH + 1,
    }));
    assert_eq!(deep.unwrap_err(), "located delivery expansion invalid");
}

#[test]
fn a_data_object_must_expand_to_its_declared_length() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"four");
    let mut wrong = data_ref(b"four");
    wrong["expanded_length"] = json!(5);
    assert_eq!(
        expand(dir.path(), "pack", &wrong).unwrap_err(),
        "pack expansion length invalid"
    );
    let wrong = located(wrong);
    assert_eq!(
        expand(dir.path(), "located", &wrong).unwrap_err(),
        "located delivery length invalid"
    );
    let mut unknown = data_ref(b"four");
    unknown["kind"] = json!("blob");
    assert_eq!(
        expand(dir.path(), "pack", &unknown).unwrap_err(),
        "pack object kind invalid"
    );
}

#[test]
fn declared_expansion_is_checked_before_children_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let parts = [data_ref(b"12345"), data_ref(b"6789")];
    let mut top = concat(dir.path(), PACK, &parts);
    top["expanded_length"] = json!(6);
    assert_eq!(
        expand(dir.path(), "pack", &top).unwrap_err(),
        "pack expansion length invalid"
    );
    put(dir.path(), b"12345");
    put(dir.path(), b"6789");
    let mut short = concat(dir.path(), PACK, &parts);
    short["expanded_length"] = json!(10);
    assert_eq!(
        expand(dir.path(), "pack", &short).unwrap_err(),
        "pack expansion length invalid"
    );
    let parts = [located(data_ref(b"12345")), located(data_ref(b"6789"))];
    let mut top = located(concat(dir.path(), LOCATED, &parts));
    top["expanded_length"] = json!(8);
    assert_eq!(
        expand(dir.path(), "located", &top).unwrap_err(),
        "located delivery expansion invalid"
    );
}

#[test]
fn a_concat_object_must_be_canonical_and_well_formed() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), b"a");
    let part = data_ref(b"a");
    let pretty = serde_json::to_vec_pretty(&json!({"schema": PACK, "parts": [part]})).unwrap();
    put(dir.path(), &pretty);
    let wrong_schema = concat(dir.path(), LOCATED, &[part.clone()]);
    let mut none = concat(dir.path(), PACK, &[]);
    none["expanded_length"] = json!(1);
    let many = concat(dir.path(), PACK, &vec![part.clone(); MAX_PARTS + 1]);
    let mut extra = concat(dir.path(), PACK, &[part.clone()]);
    let value = json!({"schema": PACK, "parts": [part], "note": 1});
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value).unwrap();
    put(dir.path(), &bytes);
    extra["sha256"] = json!(digest(&bytes));
    extra["length"] = json!(bytes.len());
    for case in [concat_ref(&pretty, 1), wrong_schema, none, many, extra] {
        assert_eq!(
            expand(dir.path(), "pack", &case).unwrap_err(),
            "pack concat invalid",
            "{case}"
        );
    }
}

#[test]
fn a_concat_part_must_state_its_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let part = json!({"sha256": digest(b"a")});
    let value = json!({"schema": PACK, "parts": [part, 7]});
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value).unwrap();
    put(dir.path(), &bytes);
    assert_eq!(
        expand(dir.path(), "pack", &concat_ref(&bytes, 1)).unwrap_err(),
        "pack expansion length invalid"
    );
    let value = json!({"schema": LOCATED, "parts": [json!({"sha256": digest(b"a")})]});
    let bytes = guard_policy_snapshot::canonical_json_bytes(&value).unwrap();
    put(dir.path(), &bytes);
    let reference = located(concat_ref(&bytes, 1));
    assert_eq!(
        expand(dir.path(), "located", &reference).unwrap_err(),
        "located delivery part invalid"
    );
}

#[test]
fn a_malformed_request_is_refused() {
    let reference = data_ref(b"x");
    for case in [
        json!({"mode": "other", "directory": "/", "reference": reference}),
        json!({"mode": "pack", "reference": reference}),
        json!({"mode": "pack", "directory": "/", "reference": reference, "depth": -1}),
        json!({"mode": "pack", "directory": "/", "reference": reference, "depth": "0"}),
    ] {
        assert_eq!(run(&case).unwrap_err(), "delivery object request invalid");
    }
}
