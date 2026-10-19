use super::*;
use std::fs;

fn home() -> TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn raw(i: usize) -> Value {
    json!({"extension_id":format!("command.scale-{i:06}"),"version":"1.0.0","name":format!("Scale {i}"),
        "source":"built-in","executables":[format!("scale-{i}")],"ecosystem_ids":[],"risk_classes":[],
        "delegated_protection":null,"permissions":[],"description":"PRIVATE-SENTINEL","rules":["SECRET"]})
}
fn observation(home: &Path) -> Observation {
    Observation {
        guard_home: home.into(),
        discovery_root: "b".repeat(64),
        discovery_authority: "c".repeat(64),
        enforcement_catalog_digest: "a".repeat(64),
        guard_version: "3.49.0".into(),
        generated_at: "2026-10-18T00:00:00Z".into(),
    }
}
fn prepare(home: &Path, count: usize) -> Value {
    let builder = Builder::new(observation(home)).unwrap();
    for i in 0..count {
        builder
            .insert(projection::project(&raw(i)).unwrap(), false)
            .unwrap();
    }
    builder.publish().unwrap()
}
fn call(home: &Path, token: &Value, op: &str, ordinal: usize) -> Value {
    let result = evaluate(
        &json!({"action":"request","guard_home":home,"token":token,"operation":op,"ordinal":ordinal}),
    );
    assert!(result.get("error").is_none(), "{result}");
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut bytes = STANDARD
        .decode(result["payload"]["body_chunk"].as_str().unwrap())
        .unwrap();
    let total = result["payload"]["total_bytes"].as_u64().unwrap() as usize;
    while bytes.len() < total {
        let more = evaluate(
            &json!({"action":"request","guard_home":home,"token":token,"operation":op,
            "ordinal":ordinal,"offset":bytes.len()}),
        );
        bytes.extend(
            STANDARD
                .decode(more["payload"]["body_chunk"].as_str().unwrap())
                .unwrap(),
        );
    }
    serde_json::from_slice(&bytes).unwrap()
}

#[path = "cloud_catalog_completion_tests.rs"]
mod completion_tests;

#[test]
fn actual_scale_bytes_and_legacy_identity() {
    let mut vectors = Vec::new();
    for count in [166, 1660, 16600] {
        let home = home();
        let view = prepare(home.path(), count);
        let manifest = &view["manifest"];
        let token = &view["token"];
        assert_eq!(manifest["extensionCount"], count);
        assert_eq!(manifest["pageCount"], count.div_ceil(64));
        assert_ne!(
            manifest["catalogDigest"],
            manifest["enforcementCatalogDigest"]
        );
        let begin = call(home.path(), token, "begin", 0);
        assert_eq!(begin["manifest"], *manifest);
        vectors.push(encode(&json!({"manifest":manifest})).unwrap());
        let mut seen = 0;
        let mut bytes = 0;
        for i in 0..count.div_ceil(64) {
            let page = call(home.path(), token, "page", i)["page"].clone();
            let encoded = encode(&page).unwrap();
            assert!(!String::from_utf8_lossy(&encoded).contains("PRIVATE-SENTINEL"));
            assert!(encoded.len() <= MAX_PAGE);
            bytes += encoded.len();
            seen += page["entries"].as_array().unwrap().len();
            vectors.push(encode(&json!({"page":page})).unwrap());
        }
        assert_eq!(seen, count);
        let complete = call(home.path(), token, "complete", 0);
        assert_eq!(complete["idempotencyKey"], begin["idempotencyKey"]);
        vectors.push(encode(&json!({"finish":count})).unwrap());
        let legacy = evaluate(&json!({"action":"legacy","guard_home":home.path(),"token":token}));
        if count <= 512 {
            let catalog = &legacy["payload"]["catalog"];
            assert_eq!(
                catalog["catalogDigest"],
                digest(&catalog["extensions"]).unwrap()
            );
            assert_ne!(catalog["catalogDigest"], manifest["catalogDigest"]);
        } else {
            assert_eq!(legacy["error"], "catalog_limit");
        }
        eprintln!(
            "native scale {count}: {} pages, {bytes} bytes",
            count.div_ceil(64)
        );
    }
    if let Ok(path) = std::env::var("NATIVE_CLOUD_VECTORS") {
        let mut joined = Vec::new();
        for line in vectors {
            joined.extend(line);
            joined.push(b'\n');
        }
        fs::write(path, joined).unwrap();
    }
}

#[test]
fn retries_pin_time_and_durable_observation() {
    let home = home();
    let first = prepare(home.path(), 166);
    let mut o = observation(home.path());
    o.generated_at = "2026-10-19T00:00:00Z".into();
    let b = Builder::new(o).unwrap();
    for i in 0..166 {
        b.insert(projection::project(&raw(i)).unwrap(), false)
            .unwrap();
    }
    let second = b.publish().unwrap();
    assert_eq!(first, second);
    let m = &first["manifest"];
    let result = evaluate(
        &json!({"action":"observe","guard_home":home.path(),"view_digest":m["catalogDigest"],
        "enforcement_digest":m["enforcementCatalogDigest"],"generated_at":m["generatedAt"]}),
    );
    assert_eq!(result["payload"], first);
    assert_eq!(
        call(home.path(), &first["token"], "page", 0),
        call(home.path(), &second["token"], "page", 0)
    );
}

#[test]
fn corrupted_missing_page_never_completes() {
    for missing in [true, false] {
        let home = home();
        let view = prepare(home.path(), 166);
        let path = home
            .path()
            .join("native-runtime/cloud-catalog")
            .join(view["token"].as_str().unwrap())
            .join("1.json");
        if missing {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, b"{}").unwrap();
        }
        for op in ["page", "complete"] {
            let result = evaluate(
                &json!({"action":"request","guard_home":home.path(),"token":view["token"],"operation":op,"ordinal":1}),
            );
            assert!(result.get("error").is_some());
        }
    }
}

#[test]
fn global_permission_collision_and_missing_replacement() {
    let home = home();
    let b = Builder::new(observation(home.path())).unwrap();
    for id in ["command.x", "command.x.permission.nested"] {
        let mut e = projection::project(&raw(0)).unwrap();
        e["id"] = json!(id);
        e["permissions"] = json!([{"id":"command.x.permission.nested.permission.shared","name":"Shared",
            "configurable":true,"required":false,"riskClasses":[],"typedCapabilities":[]}]);
        b.insert(projection::validate(&e).unwrap(), false).unwrap();
    }
    assert!(b.publish().is_err());
    let b = Builder::new(observation(home.path())).unwrap();
    let mut e = projection::project(&raw(0)).unwrap();
    e["deprecated"] = json!(true);
    e["replacementId"] = json!("command.absent");
    b.insert(e, false).unwrap();
    assert!(b.publish().is_err());
}

#[test]
fn privacy_validation_and_exact_entry_boundary() {
    let clean = projection::project(&raw(0)).unwrap();
    assert!(clean.get("description").is_none());
    let mut private = clean.clone();
    private["environment"] = json!({"secret":"x"});
    assert!(projection::validate(&private).is_err());
    let mut signed = raw(0);
    signed["source"] = json!("signed-cloud");
    assert!(projection::project(&signed).is_err());
    let mut entry = clean.clone();
    // Bounded strings can collectively hit the exact one-million-byte limit.
    entry["executables"] = json!((0..121)
        .map(|i| format!("{i:03}{}", "x".repeat(8189)))
        .collect::<Vec<_>>());
    entry["riskClasses"] = json!(["r"]);
    let size = encode(&entry).unwrap().len();
    entry["name"] = json!("n".repeat(1_000_000 - size + "Scale 0".len()));
    assert_eq!(encode(&entry).unwrap().len(), MAX_ENTRY);
    assert!(projection::validate(&entry).is_ok());
    entry["name"] = json!(format!("{}x", entry["name"].as_str().unwrap()));
    assert!(matches!(projection::validate(&entry), Err(Error::Limit)));
}

#[test]
fn raw_projection_preserves_legacy_set_normalization() {
    let mut value = raw(0);
    value["executables"] = json!(["z", "a", "a"]);
    value["ecosystem_ids"] = json!(["x", "x"]);
    value["risk_classes"] = json!(["write", "write", "read"]);
    let output = projection::project(&value).unwrap();
    assert_eq!(output["executables"], json!(["a", "z"]));
    assert_eq!(output["ecosystemIds"], json!(["x"]));
    assert_eq!(output["riskClasses"], json!(["read", "write"]));
    let mut invalid_wire = output;
    invalid_wire["executables"] = json!(["a", "a"]);
    assert!(projection::validate(&invalid_wire).is_err());
}

fn put(directory: &Path, value: &Value) -> Value {
    let bytes = encode(value).unwrap();
    let sha = hash(&bytes);
    fs::write(directory.join(format!("{sha}.json")), &bytes).unwrap();
    json!({"sha256":sha,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"})
}
fn discovery(home: &Path, values: &[Value], bad_count: bool) -> Observation {
    let directory = home.join("native-runtime/catalog-discovery/objects");
    fs::create_dir_all(&directory).unwrap();
    let mut next = Value::Null;
    for chunk in values.chunks(64).rev() {
        let entries: Vec<Value> = chunk
            .iter()
            .map(|v| json!([v["extension_id"], put(&directory, v)]))
            .collect();
        next = put(
            &directory,
            &json!({"schema":"guard.catalog-discovery-page.v1","entries":entries,"next":next}),
        );
    }
    let root = put(
        &directory,
        &json!({"schema":"guard.catalog-discovery.v1","authority":"c".repeat(64),
        "count":values.len()+usize::from(bad_count),"first":next}),
    );
    let mut o = observation(home);
    o.discovery_root = root["sha256"].as_str().unwrap().into();
    o
}

#[test]
fn fixed_cas_complete_active_overlay_and_incomplete_rejection() {
    for bad in [false, true] {
        let home = home();
        // Initialize private native-runtime before fixture CAS directories.
        cache::directory(home.path()).unwrap();
        let values: Vec<_> = (0..166).map(raw).collect();
        let o = discovery(home.path(), &values, bad);
        let mut b = Builder::new(o).unwrap();
        let mut active = raw(1);
        active["name"] = json!("Active authoritative");
        b.append(&active).unwrap();
        b.append(&raw(999)).unwrap();
        let result = b.finish();
        if bad {
            assert!(result.is_err());
            continue;
        }
        let v = result.unwrap();
        assert_eq!(v["manifest"]["extensionCount"], 167);
        assert_eq!(
            call(home.path(), &v["token"], "page", 0)["page"]["entries"][1]["name"],
            "Active authoritative"
        );
    }
}

#[test]
fn policy_last_page_complete_native_producer_and_substitution() {
    use std::collections::BTreeSet;
    for count in [166, 1660, 16600] {
        let home = home();
        cache::directory(home.path()).unwrap();
        let values: Vec<_> = (0..count).map(raw).collect();
        let observation = discovery(home.path(), &values, false);
        let view = Builder::new(observation.clone()).unwrap().finish().unwrap();
        let id = format!("command.scale-{:06}", count - 1);
        let ids = BTreeSet::from([id.clone()]);
        let select = |o: &Observation, token: &str, digest: &str| {
            select_policy_metadata(home.path(), token, o, digest, &ids, &BTreeSet::new())
        };
        let token = view["token"].as_str().unwrap();
        let digest = view["manifest"]["catalogDigest"].as_str().unwrap();
        let selected = select(&observation, token, digest).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0]["id"], id);
        for field in [
            "enforcement_catalog_digest",
            "discovery_root",
            "discovery_authority",
            "generated_at",
        ] {
            let mut changed = serde_json::to_value(&observation).unwrap();
            changed[field] = json!(if field == "generated_at" {
                "2026-10-18T00:01:00Z".to_owned()
            } else {
                "d".repeat(64)
            });
            let o: Observation = serde_json::from_value(changed).unwrap();
            assert!(select(&o, token, digest).is_err(), "{field}");
        }
        assert!(select(&observation, token, &"d".repeat(64)).is_err());
        let last = cache::directory(home.path())
            .unwrap()
            .join(token)
            .join(format!("{}.json", count.div_ceil(64) - 1));
        fs::write(last, b"{}").unwrap();
        assert!(select(&observation, token, digest).is_err());
    }
}

#[test]
fn byte_driven_pages_empty_duplicate_and_page_limit() {
    let home = home();
    let b = Builder::new(observation(home.path())).unwrap();
    assert!(b.publish().is_err());
    let mut b = Builder::new(observation(home.path())).unwrap();
    b.append(&raw(0)).unwrap();
    assert!(b.append(&raw(0)).is_err());
    let mut hashes = vec!["0".repeat(64); MAX_PAGES];
    let mut prev = Value::Null;
    let mut pending = vec![projection::project(&raw(0)).unwrap()];
    assert!(matches!(
        flush(home.path(), &mut pending, &mut hashes, &mut prev, &mut 0),
        Err(Error::Limit)
    ));
    let mut hashes = Vec::new();
    let mut total = MAX_TOTAL;
    assert!(matches!(
        flush(
            home.path(),
            &mut pending,
            &mut hashes,
            &mut prev,
            &mut total
        ),
        Err(Error::Limit)
    ));
    let b = Builder::new(observation(home.path())).unwrap();
    for i in 0..4 {
        let mut e = projection::project(&raw(i)).unwrap();
        e["executables"] = json!((0..100)
            .map(|j| format!("{j}{}", "x".repeat(8000)))
            .collect::<Vec<_>>());
        b.insert(projection::validate(&e).unwrap(), false).unwrap();
    }
    assert_eq!(b.publish().unwrap()["manifest"]["pageCount"], 2);
}

#[test]
fn cache_eviction_preserves_leases_and_bounds_durable_views() {
    let home = home();
    let first = prepare(home.path(), 1);
    let acquire =
        evaluate(&json!({"action":"acquire","guard_home":home.path(),"token":first["token"]}));
    assert!(acquire.get("error").is_none());
    for count in 2..8 {
        prepare(home.path(), count);
    }
    call(home.path(), &first["token"], "complete", 0);
    let directory = home.path().join("native-runtime/cloud-catalog");
    assert_eq!(
        fs::read_dir(&directory)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_str().is_some_and(sha))
            .count(),
        4
    );
    let release = evaluate(
        &json!({"action":"release","guard_home":home.path(),"lease":acquire["payload"]["lease"]}),
    );
    assert!(release.get("error").is_none());
    prepare(home.path(), 8);
    assert!(evaluate(&json!({"action":"request","guard_home":home.path(),"token":first["token"],"operation":"complete"})).get("error").is_some());
}

#[test]
fn discovery_corruption_order_authority_and_owner_fail_closed() {
    for fault in ["object", "root", "authority", "duplicate", "order", "owner"] {
        let home = home();
        cache::directory(home.path()).unwrap();
        let mut values: Vec<_> = (0..2).map(raw).collect();
        if fault == "duplicate" {
            values[1] = values[0].clone();
        }
        if fault == "order" {
            values.reverse();
        }
        if fault == "owner" {
            values[0]["permissions"] = json!([{"extension_id":"command.other"}]);
        }
        let mut o = discovery(home.path(), &values, false);
        if fault == "authority" {
            o.discovery_authority = "d".repeat(64);
        }
        if fault == "root" {
            o.discovery_root = "d".repeat(64);
        }
        if fault == "object" {
            let directory = home.path().join("native-runtime/catalog-discovery/objects");
            let target = directory.join(format!("{}.json", hash(&encode(&values[0]).unwrap())));
            fs::write(target, b"{}").unwrap();
        }
        assert!(Builder::new(o).unwrap().finish().is_err(), "{fault}");
    }
}

#[cfg(unix)]
#[test]
fn discovery_and_cache_symlink_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;
    let home = home();
    cache::directory(home.path()).unwrap();
    let observation = discovery(home.path(), &[raw(0)], false);
    let directory = home.path().join("native-runtime/catalog-discovery/objects");
    let moved = home.path().join("objects");
    fs::rename(&directory, &moved).unwrap();
    symlink(&moved, &directory).unwrap();
    assert!(Builder::new(observation).unwrap().finish().is_err());
    let view = prepare(home.path(), 1);
    let path = home
        .path()
        .join("native-runtime/cloud-catalog")
        .join(view["token"].as_str().unwrap());
    let moved = home.path().join("cached-view");
    fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    assert!(evaluate(&json!({"action":"request","guard_home":home.path(),"token":view["token"],"operation":"complete"})).get("error").is_some());
}
