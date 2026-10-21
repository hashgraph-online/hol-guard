use super::*;

#[cfg(unix)]
#[test]
fn pinned_reader_rejects_replaced_directories_symlinks_and_public_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = fixture(1, "");
    let (handle, _) = prepare(&fixture).unwrap();
    let directory = fixture
        .home
        .path()
        .join("native-runtime/catalog-discovery/objects");
    let reader = CacheReader::new(&directory).unwrap();
    let added = reader.put_json(&json!({"atomic":"metadata"})).unwrap();
    assert_eq!(reader.read(&added.sha256).unwrap().len(), added.length);
    let input_reader = CacheReader::new(&directory.with_file_name("transport")).unwrap();
    assert_eq!(
        input_reader.put_json(&json!({"not":"output"})).unwrap_err(),
        "catalog_prepare_write_scope_invalid"
    );
    let leaf = directory.join(format!("{}.json", handle.root));
    assert!(reader.read(&handle.root).is_ok());
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(reader.read(&handle.root).is_err());
    assert!(reader.read_pinned(&handle.root).is_err());
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = directory.join("hardlink-root");
    fs::hard_link(&leaf, &hardlink).unwrap();
    assert!(reader.read(&handle.root).is_err());
    fs::remove_file(hardlink).unwrap();
    let saved = directory.join("saved-root");
    fs::rename(&leaf, &saved).unwrap();
    symlink(&saved, &leaf).unwrap();
    assert!(reader.read(&handle.root).is_err());
    assert!(reader.read_pinned(&handle.root).is_err());
    fs::remove_file(&leaf).unwrap();
    fs::rename(saved, &leaf).unwrap();
    let moved = directory.with_file_name("moved-objects");
    fs::rename(&directory, &moved).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(reader.read(&handle.root).is_err());
    // A batched scan stays on the authenticated inode; its final namespace
    // check rejects publication after replacement, even with valid leaf bytes.
    assert!(reader.read_pinned(&handle.root).is_ok());
    assert!(reader.finish().is_err());
    let pinned = reader.put_json(&json!({"pinned":"write"})).unwrap();
    assert!(!directory.join(format!("{}.json", pinned.sha256)).exists());
    assert!(moved.join(format!("{}.json", pinned.sha256)).is_file());
    assert!(reader.finish().is_err()); // No result may be published for the changed namespace.
    fs::remove_dir(&directory).unwrap();
    fs::rename(moved, &directory).unwrap();
    assert!(reader.read(&handle.root).is_ok());
    reader.finish().unwrap();
}

fn batched(fixture: &Fixture, corrupt: bool) -> Value {
    run_batched(fixture, corrupt).0
}

pub(super) fn prepare_batched(fixture: &Fixture) -> std::result::Result<(Handle, usize), String> {
    let (result, fetches) = run_batched(fixture, false);
    if result["outcome"] != "complete" {
        return Err(result.to_string());
    }
    Ok((
        serde_json::from_value(result["handle"].clone()).unwrap(),
        fetches,
    ))
}

fn run_batched(fixture: &Fixture, corrupt: bool) -> (Value, usize) {
    let home = fixture.home.path();
    let mut result = evaluate(Request {
        guard_home: home.into(),
        action: Action::BeginBatched {
            authority: authority(&fixture.root, Profile::Remote),
        },
    });
    let mut largest = 0;
    let mut fetches = 0;
    loop {
        let session = result["session"].as_str().unwrap_or("").to_owned();
        let action = match result["outcome"].as_str().unwrap() {
            "fetch_batch" => {
                let targets = result["fetches"].as_array().unwrap();
                assert!(!targets.is_empty() && targets.len() <= 64);
                largest = largest.max(targets.len());
                fetches += targets.len();
                let mut data: Vec<_> = targets
                    .iter()
                    .map(|target| {
                        fs::read(
                            fixture
                                .origin
                                .path()
                                .join(format!("{}.json", target["sha256"].as_str().unwrap())),
                        )
                        .unwrap()
                    })
                    .collect();
                if corrupt {
                    data[0] = b"corrupt".to_vec();
                }
                Action::AdvanceBatch { session, data }
            }
            "continue" => Action::Resume { session },
            "complete" => {
                assert!(
                    fetches == 0
                        || largest > 1
                        || fixture.root["policy"]["root"]["extensions"] == 1
                );
                return (result, fetches);
            }
            _ => return (result, fetches),
        };
        result = evaluate(Request {
            guard_home: home.into(),
            action,
        });
    }
}

#[test]
fn bounded_input_spill_completes_large_concatenations() {
    let fixture = fixture(1, "spill");
    let (handle, fetches) = prepare_batched(&fixture).unwrap();
    assert!(fetches > 64);
    assert_eq!(
        body(&read_request(fixture.home.path(), handle))["total_count"],
        1
    );
    let directory = fixture
        .home
        .path()
        .join("native-runtime/catalog-discovery/transport");
    assert!(fs::read_dir(directory).unwrap().count() > 0);
}

#[test]
fn bounded_batch_preserves_complete_proofs_and_repairs_corrupt_cache() {
    let fixture = fixture(166, "");
    let (result, fetches) = run_batched(&fixture, false);
    assert_eq!(result["outcome"], "complete", "{result}");
    let handle: Handle = serde_json::from_value(result["handle"].clone()).unwrap();
    let request = read_request(fixture.home.path(), handle.clone());
    assert_eq!(body(&request)["total_count"], 166);
    assert!(
        fs::read_dir(
            fixture
                .home
                .path()
                .join("native-runtime/catalog-discovery/transport")
        )
        .unwrap()
        .count()
            < fetches
    );
    // A corrupted discovery root fails before repair, never produces content.
    let path = fixture.home.path().join(format!(
        "native-runtime/catalog-discovery/objects/{}.json",
        handle.root
    ));
    fs::write(&path, b"{}").unwrap();
    assert_eq!(read(&request).http_status, 503);
    let (rebuilt, fetched) = prepare(&fixture).unwrap();
    assert!(fetched > 0); // Transient input is rebuilt from the verified source.
    assert_eq!(prepare(&fixture).unwrap().1, 0); // Legacy CAS remains compatible.
    assert_eq!(rebuilt.root, handle.root);
    assert_eq!(
        body(&read_request(fixture.home.path(), rebuilt))["total_count"],
        166
    );
    // Corrupt transport bytes are re-requested and proof-checked on repair.
    let directory = fixture
        .home
        .path()
        .join("native-runtime/catalog-discovery/transport");
    let path = fs::read_dir(directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for corrupt in [b"{}".as_slice(), b"".as_slice()] {
        fs::write(&path, corrupt).unwrap();
        assert!(prepare(&fixture).unwrap().1 >= 1);
    }
    assert!(
        !fs::read_dir(fixture.home.path().join("native-runtime/catalog-discovery"))
            .unwrap()
            .any(|p| p
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("preparation-"))
    );
}

#[test]
fn batch_corruption_duplicates_and_wire_budgets_fail_closed() {
    for fault in ["", "duplicate-permission", "ownership", "count"] {
        let fixture = fixture(2, fault);
        let result = batched(&fixture, fault.is_empty());
        assert_eq!(result["outcome"], "error", "{fault}: {result}");
        assert!(!state()
            .lock()
            .unwrap()
            .handles
            .iter()
            .any(|(home, _)| home == fixture.home.path()));
    }
    for data in [json!([]), json!(vec!["eA=="; 65]), json!(["eA==", "!"])] {
        assert!(serde_json::from_value::<Request>(json!({"guard_home":"/synthetic", "action":{"kind":"advance_batch","session":"none","data":data}})).is_err());
    }
}
