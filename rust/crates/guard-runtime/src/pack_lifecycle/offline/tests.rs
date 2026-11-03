use super::*;

#[test]
fn offline_native_complete_unique_index_over_512_and_corruption() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    let directory = canonical.as_path();
    std::fs::create_dir(directory.join("objects")).unwrap();
    let put = |value: Value| {
        let bytes = serde_json::to_vec(&value).unwrap();
        let sha = hash(&bytes);
        std::fs::write(
            directory.join("objects").join(format!("{sha}.json")),
            &bytes,
        )
        .unwrap();
        json!({"sha256":sha,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"})
    };
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for n in 0..600 {
        let id = format!("command.unique{n:04}");
        let prefix = hash(id.as_bytes())[..1].to_owned();
        groups
            .entry(prefix)
            .or_default()
            .push(json!([id, put(json!({"number":n}))]));
    }
    let children = groups
        .into_iter()
        .map(|(prefix, rows)| {
            json!([
                prefix,
                rows.len(),
                put(json!({
        "schema":"guard.pack-index.v1","kind":"leaf","prefix":prefix,"entries":rows}))
            ])
        })
        .collect::<Vec<_>>();
    let reference = put(
        json!({"schema":"guard.pack-index.v1","kind":"branch","prefix":"","children":children}),
    );
    let mut graph = graph::Graph::new(directory);
    graph.walk(&reference, 0).unwrap();
    assert!(graph.needs.is_empty());
    assert!(!graph.unavailable);
    let mut ids = BTreeMap::new();
    graph.index(&reference, 600, "", &mut ids).unwrap();
    assert_eq!(ids.len(), 600);
    assert!(graph.retain_expansion(LIMIT).is_err());
    assert!(graph
        .index(&reference, 599, "", &mut BTreeMap::new())
        .is_err());
    std::fs::write(
        directory
            .join("objects")
            .join(format!("{}.json", reference["sha256"].as_str().unwrap())),
        b"corrupt",
    )
    .unwrap();
    assert!(graph::Graph::new(directory).walk(&reference, 0).is_err());
}

#[test]
fn offline_cleanup_fences_live_leases_and_collects_orphans_after_crash() {
    use fs2::FileExt;
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    let directory = canonical.as_path();
    std::fs::write(directory.join(".cache-lease"), b"0").unwrap();
    std::fs::create_dir(directory.join("objects")).unwrap();
    let orphan = directory
        .join("objects")
        .join(format!("{}.json", "a".repeat(64)));
    std::fs::write(&orphan, b"orphan").unwrap();
    let interrupted = directory.join("objects/.obj-abcdefgh");
    std::fs::write(&interrupted, b"interrupted").unwrap();
    // An abandoned pack preparation write counts toward the budget too.
    let preparing = directory.join("objects/.prepare-4242-7");
    std::fs::write(&preparing, b"preparing").unwrap();
    let unrelated = directory.join("objects/.prepare-x-7");
    std::fs::write(&unrelated, b"unrelated").unwrap();
    let request =
        json!({"directory":directory,"key":"01".repeat(32),"activations":[],"maximum_bytes":0});
    // Preparers hold the lease open for writing, as the Python cache lease does.
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.join(".cache-lease"))
        .unwrap();
    FileExt::lock_shared(&lease).unwrap();
    assert_eq!(cleanup::run(&request).unwrap()["busy"], true);
    assert!(orphan.exists());
    drop(lease); // kernel lease recovery, including process termination
    let result = cleanup::run(&request).unwrap();
    assert_eq!(result["evicted"], 3);
    assert!(!orphan.exists());
    assert!(!interrupted.exists());
    assert!(!preparing.exists());
    assert!(unrelated.exists());
    assert_eq!(cleanup::run(&request).unwrap()["evicted"], 0);
}

#[test]
fn offline_archive_rejects_unbounded_and_non_zip_inputs() {
    for bytes in [vec![], vec![0; 22], vec![0; 32 * 1024 * 1024 + 1]] {
        assert!(archive::members(&bytes).is_err());
    }
}

#[test]
fn offline_expiry_selection_retains_live_and_non_pack_proofs() {
    assert_eq!(
        evaluate(&json!({"operation":"expired-leases","now":100.0,
        "expires":[0.0,null,100.0,101.0]}))
        .unwrap()["expired"],
        json!([0, 2])
    );
    assert!(
        evaluate(&json!({"operation":"expired-leases","now":100.0,"expires":["bad"]})).is_err()
    );
}

#[test]
fn offline_copy_rechecks_bytes_before_any_partial_export_write() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("substituted");
    let target = base.join("exported.json");
    std::fs::write(&source, b"private credential sentinel").unwrap();
    assert!(copy::object(&source, &target, &hash(b"public bytes"), 65536).is_err());
    assert!(!target.exists());
    std::fs::write(&source, b"public bytes").unwrap();
    copy::object(&source, &target, &hash(b"public bytes"), 65536).unwrap();
    assert_eq!(std::fs::read(target).unwrap(), b"public bytes");
}
