use super::*;
use crate::catalog_read_model::{CatalogReadRequestV1, CATALOG_READ_REQUEST_SCHEMA};
use std::{fs, time::Instant};

struct Fixture {
    _serial: std::sync::MutexGuard<'static, ()>,
    origin: tempfile::TempDir,
    home: tempfile::TempDir,
    root: Value,
}
// Fixture publication is intentionally cheap; production CAS publication is
// exercised by the preparation itself, including its atomic-link path.
fn put(directory: &Path, bytes: &[u8], kind: &str, expanded_length: usize) -> PackObjectRef {
    assert!(!bytes.is_empty() && bytes.len() <= OBJECT_BYTES);
    let sha256 = io::hash(bytes);
    fs::write(directory.join(format!("{sha256}.json")), bytes).unwrap();
    PackObjectRef {
        sha256,
        length: bytes.len(),
        expanded_length,
        kind: kind.into(),
    }
}
fn put_json(directory: &Path, value: &Value) -> PackObjectRef {
    let bytes = serde_json::to_vec(value).unwrap();
    put(directory, &bytes, "data", bytes.len())
}
fn located(reference: &PackObjectRef) -> Value {
    let mut value = serde_json::to_value(reference).unwrap();
    value["location"] = json!({"tag":format!("extension-data-{}-0.0-000001", "a".repeat(40)),"asset":format!("object-{}.json",reference.sha256)});
    value
}
fn metadata(directory: &Path, value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut parts: Vec<_> = bytes
        .chunks(OBJECT_BYTES)
        .map(|part| located(&put(directory, part, "data", part.len())))
        .collect();
    while parts.len() > 1 {
        parts = parts
            .chunks(64)
            .map(|group| {
                let bytes =
                    serde_json::to_vec(&json!({"schema":"guard.delivery-concat.v2","parts":group}))
                        .unwrap();
                let expanded = group
                    .iter()
                    .map(|v| v["expanded_length"].as_u64().unwrap() as usize)
                    .sum();
                located(&put(directory, &bytes, "concat", expanded))
            })
            .collect();
    }
    parts.remove(0)
}
fn index(
    directory: &Path,
    entries: &[(String, PackObjectRef, PackObjectRef)],
    prefix: &str,
) -> (PackObjectRef, Value) {
    let mut wrapper = json!({"schema":"guard.policy-transport.v2"});
    let native = if entries.len() <= 64 {
        wrapper["kind"] = json!("leaf");
        wrapper["records"] = json!(entries
            .iter()
            .map(|(id, _, record)| json!([id, located(record)]))
            .collect::<Vec<_>>());
        json!({"schema":"guard.pack-index.v1","kind":"leaf","prefix":prefix,"entries":entries.iter().map(|(id,m,_)|json!([id,m])).collect::<Vec<_>>()})
    } else {
        let mut groups = BTreeMap::<String, Vec<_>>::new();
        for entry in entries {
            groups
                .entry(io::hash(entry.0.as_bytes())[..prefix.len() + 1].into())
                .or_default()
                .push(entry.clone());
        }
        let mut children = Vec::new();
        let mut transports = Vec::new();
        for (key, group) in groups {
            let (native, transport) = index(directory, &group, &key);
            children.push(json!([key, group.len(), native]));
            transports.push(json!([key, group.len(), transport]));
        }
        wrapper["kind"] = json!("branch");
        wrapper["children"] = json!(transports);
        json!({"schema":"guard.pack-index.v1","kind":"branch","prefix":prefix,"children":children})
    };
    let native = put_json(directory, &native);
    wrapper["native"] = located(&native);
    (native, located(&put_json(directory, &wrapper)))
}

fn fixture(count: usize, fault: &str) -> Fixture {
    static SERIAL: Mutex<()> = Mutex::new(());
    let serial = SERIAL.lock().unwrap();
    let temporary = std::env::temp_dir().canonicalize().unwrap();
    let origin = tempfile::tempdir_in(&temporary).unwrap();
    let home = tempfile::tempdir_in(&temporary).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [origin.path(), home.path()] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let embedded: Value =
        serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes()).unwrap();
    let mut template = embedded["catalog"][0].clone();
    let permission = embedded["catalog"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|e| e["permissions"].as_array().unwrap())
        .next()
        .unwrap()
        .clone();
    let mut entries = Vec::new();
    for n in 0..count {
        let id = format!("synthetic-{n:06}");
        template["extension_id"] = json!(id);
        template["description"] = json!(if n + 1 == count {
            "unloadedneedle"
        } else {
            "metadata"
        });
        template["rules"] = json!([]);
        template["mcp_tools"] = json!([]);
        template["rule_count"] = json!(0);
        let mut permission = permission.clone();
        permission["permission_id"] = json!(if fault == "duplicate-permission" {
            "duplicate".into()
        } else {
            format!("permission-{n:06}")
        });
        permission["extension_id"] = json!(if fault == "ownership" { "another" } else { &id });
        permission["description"] = json!(if n + 1 == count {
            "permissionneedle"
        } else {
            "permission"
        });
        template["permissions"] = json!([permission]);
        template["permission_count"] = json!(1);
        if fault == "metadata-id" {
            template["extension_id"] = json!("another");
        }
        if matches!(fault, "large" | "spill") {
            let urls = if fault == "spill" { 18_000 } else { 300 };
            template["reference_urls"] = json!((0..urls)
                .map(|i| format!("https://example.com/{i}/{}", "x".repeat(250)))
                .collect::<Vec<_>>());
        }
        let metadata = metadata(origin.path(), &json!([template]));
        let manifest = put_json(origin.path(), &json!({"test":n}));
        let record = put_json(
            origin.path(),
            &json!({
                "schema":"guard.policy-delivery.v2","extension_id":id,"manifest":manifest,
                "catalog_metadata":metadata, "archives":[{"sha256":"f".repeat(64),"length":1,"location":{
                    "tag":format!("extension-data-{}-0.0-000001","a".repeat(40)),"asset":format!("pack-{}.zip","f".repeat(64))}}],
                "dependencies":[],"related_interfaces":[],"required":false,"activation":"opt-in","trust_class":"external"
            }),
        );
        entries.push((id, manifest, record));
    }
    if fault == "duplicate-extension" {
        entries[1].0 = entries[0].0.clone();
    }
    let (native, transport) = index(origin.path(), &entries, "");
    let root = json!({"schema":"guard.extension-distribution.v2","source_sha":"a".repeat(40),"engine":"e".repeat(64),"expires_at":9_999_999_999u64,
        "policy":{"root":{"schema":"guard.command-pack-release.v1","engine":"e".repeat(64),"extensions":if fault == "count" {count+1} else {count},"index":native},"transport":transport}});
    Fixture {
        _serial: serial,
        origin,
        home,
        root,
    }
}
fn authority(root: &Value, profile: Profile) -> VerifiedAuthority {
    let data = serde_json::to_vec(root).unwrap();
    VerifiedAuthority {
        digest: io::hash(&data),
        data,
        source_sha: "a".repeat(40),
        expires_at: if profile == Profile::Remote {
            root["expires_at"].as_u64()
        } else {
            None
        },
        profile,
    }
}
fn prepare(fixture: &Fixture) -> std::result::Result<(Handle, usize), String> {
    let home = fixture.home.path();
    let profile = if fixture.root["schema"] == "guard.command-pack-bundle.v1" {
        Profile::Installed
    } else {
        Profile::Remote
    };
    let mut result = evaluate(Request {
        guard_home: home.into(),
        action: Action::Begin {
            authority: authority(&fixture.root, profile),
        },
    });
    let mut fetches = 0;
    loop {
        match result["outcome"].as_str().unwrap() {
            "continue" => {
                result = evaluate(Request {
                    guard_home: home.into(),
                    action: Action::Resume {
                        session: result["session"].as_str().unwrap().into(),
                    },
                });
            }
            "complete" => {
                return Ok((
                    serde_json::from_value(result["handle"].clone()).unwrap(),
                    fetches,
                ))
            }
            "fetch" => {
                let target = &result["fetch"];
                assert!(target["location"]["asset"]
                    .as_str()
                    .unwrap()
                    .starts_with("object-"));
                let bytes = fs::read(
                    fixture
                        .origin
                        .path()
                        .join(format!("{}.json", target["sha256"].as_str().unwrap())),
                )
                .unwrap();
                assert!(bytes.len() <= OBJECT_BYTES);
                fetches += 1;
                result = evaluate(Request {
                    guard_home: home.into(),
                    action: Action::Advance {
                        session: result["session"].as_str().unwrap().into(),
                        data: bytes,
                    },
                });
            }
            _ => return Err(result.to_string()),
        }
    }
}
fn read_request(home: &Path, handle: Handle) -> ReadRequest {
    ReadRequest {
        guard_home: home.into(),
        handle,
        read: CatalogReadRequestV1 {
            schema: CATALOG_READ_REQUEST_SCHEMA.into(),
            route: "index".into(),
            query: "limit=1".into(),
            if_none_match: None,
            expected_catalog_digest: "b".repeat(64),
        },
    }
}
fn body(request: &ReadRequest) -> Value {
    let result = read(request);
    assert_eq!(result.http_status, 200, "{result:?}");
    let bytes = result.body.unwrap();
    assert!(bytes.len() <= 262_144);
    serde_json::from_str(&bytes).unwrap()
}

#[test]
fn native_preparation_and_reads_scale_166_1660_16600() {
    let counts = std::env::var("HOL_GUARD_CATALOG_SCALE")
        .map(|v| vec![v.parse::<usize>().unwrap()])
        .unwrap_or(vec![166, 1660, 16600]);
    for count in counts {
        assert!([166, 1660, 16600].contains(&count));
        let fixture = fixture(count, "");
        if let Ok(export) = std::env::var("HOL_GUARD_CATALOG_EXPORT") {
            let directory = PathBuf::from(export).join(count.to_string());
            fs::create_dir_all(directory.join("origin")).unwrap();
            fs::write(
                directory.join("root.json"),
                serde_json::to_vec(&fixture.root).unwrap(),
            )
            .unwrap();
            for file in fs::read_dir(fixture.origin.path()).unwrap() {
                let file = file.unwrap();
                fs::copy(file.path(), directory.join("origin").join(file.file_name())).unwrap();
            }
        }
        let started = Instant::now();
        let (handle, fetches) = fast::prepare_batched(&fixture).unwrap();
        let prepare_ms = started.elapsed().as_millis();
        let mut request = read_request(fixture.home.path(), handle);
        assert_eq!(body(&request)["total_count"], count);
        request.read.query = "q=unloadedneedle&limit=1".into();
        assert_eq!(
            body(&request)["items"][0]["extension_id"],
            format!("synthetic-{:06}", count - 1)
        );
        request.read.route = "permissions".into();
        request.read.query = "q=permissionneedle&limit=1".into();
        assert_eq!(body(&request)["total_count"], 1);
        request.read.route = format!("extensions/synthetic-{:06}", count - 1);
        request.read.query.clear();
        let result = read(&request);
        assert_eq!(result.http_status, 200);
        request.read.if_none_match = result.etag;
        assert_eq!(read(&request).http_status, 304);
        let read_ms = started.elapsed().as_millis() - prepare_ms;
        if count == 166 {
            let (renewed, fetched) = fast::prepare_batched(&fixture).unwrap();
            assert!(fetched > 0 && fetched <= fetches);
            assert_eq!(renewed.root, request.handle.root);
            assert_ne!(renewed.token, request.handle.token);
            assert_eq!(read(&request).http_status, 304);
        }
        eprintln!("native-discovery-fast-scale count={count} fetched_objects={fetches} prepare_ms={prepare_ms} read_ms={read_ms} row_bound={count} ownership_scratch_files=1 retained_metadata_entries=1 object_bytes=65536 blob_bytes=8388608");
    }
}

#[path = "catalog_prepare_fast_tests.rs"]
mod fast;

#[test]
fn invalid_complete_proofs_never_publish_a_handle() {
    for fault in [
        "duplicate-permission",
        "duplicate-extension",
        "ownership",
        "metadata-id",
        "count",
    ] {
        let fixture = fixture(2, fault);
        assert!(prepare(&fixture).is_err(), "{fault}");
        assert!(!state()
            .lock()
            .unwrap()
            .handles
            .iter()
            .any(|(h, _)| h == fixture.home.path()));
    }
}

#[test]
fn corrupt_missing_unverified_roots_and_session_bindings_fail_closed() {
    let fixture = fixture(2, "");
    let home = fixture.home.path();
    let begin = || Request {
        guard_home: home.into(),
        action: Action::Begin {
            authority: authority(&fixture.root, Profile::Remote),
        },
    };
    let mut wrong = authority(&fixture.root, Profile::Remote);
    wrong.digest = "0".repeat(64);
    assert_eq!(
        evaluate(Request {
            guard_home: home.into(),
            action: Action::Begin { authority: wrong }
        })["outcome"],
        "error"
    );
    let result = evaluate(begin());
    let session = result["session"].as_str().unwrap().to_owned();
    assert_eq!(
        evaluate(Request {
            guard_home: fixture.origin.path().into(),
            action: Action::Advance {
                session: session.clone(),
                data: vec![]
            }
        })["outcome"],
        "error"
    );
    assert_eq!(
        evaluate(Request {
            guard_home: home.into(),
            action: Action::Advance {
                session: session.clone(),
                data: b"corrupt".to_vec()
            }
        })["error_code"],
        "catalog_prepare_fetch_integrity"
    );
    assert!(!state()
        .lock()
        .unwrap()
        .handles
        .iter()
        .any(|(h, _)| h == home));
    let missing = evaluate(begin());
    assert_eq!(missing["outcome"], "fetch");
    assert_eq!(
        evaluate(Request {
            guard_home: home.into(),
            action: Action::Abort {
                session: missing["session"].as_str().unwrap().into()
            }
        })["outcome"],
        "aborted"
    );
    let (handle, _) = prepare(&fixture).unwrap();
    let mut request = read_request(home, handle.clone());
    request.handle.root = "f".repeat(64);
    assert_eq!(read(&request).http_status, 503);
    request.handle = handle.clone();
    request.guard_home = fixture.origin.path().into();
    assert_eq!(read(&request).http_status, 503);
    request.guard_home = home.into();
    request.handle.token = "0".repeat(64);
    assert_eq!(read(&request).http_status, 503);
    request.handle = handle;
    fs::write(
        home.join(format!(
            "native-runtime/catalog-discovery/objects/{}.json",
            request.handle.root
        )),
        b"{}",
    )
    .unwrap();
    assert_eq!(read(&request).http_status, 503);
}

#[test]
fn installed_no_expiry_is_distinct_from_remote_and_expiry_is_checked_at_completion() {
    let mut fixture = fixture(1, "");
    fixture.root["expires_at"] = json!(0);
    assert!(Session::begin(
        fixture.home.path(),
        authority(&fixture.root, Profile::Remote)
    )
    .is_err());
    fixture.root["schema"] = json!("guard.command-pack-bundle.v1");
    fixture.root.as_object_mut().unwrap().remove("expires_at");
    let mut session = Session::begin(
        fixture.home.path(),
        authority(&fixture.root, Profile::Installed),
    )
    .unwrap();
    assert!(session.drive().unwrap().is_none());
    session.profile = Profile::Remote;
    session.expires_at = Some(0);
    assert_eq!(
        session.drive().unwrap_err(),
        "catalog_prepare_authority_expired"
    );
    drop(session);
    let (handle, _) = prepare(&fixture).unwrap();
    assert_eq!(handle.profile, Profile::Installed);
    assert_eq!(handle.expires_at, None);
    assert_eq!(
        body(&read_request(fixture.home.path(), handle))["total_count"],
        1
    );
    assert!(serde_json::from_value::<Request>(
        json!({"guard_home":fixture.home.path(),"action":{"kind":"unknown"}})
    )
    .is_err());
}

#[test]
fn bounded_concatenated_metadata_is_prepared_not_policy_archives() {
    let fixture = fixture(1, "large");
    let (handle, _) = prepare(&fixture).unwrap();
    assert_eq!(
        body(&read_request(fixture.home.path(), handle))["total_count"],
        1
    );
}

#[cfg(unix)]
#[test]
fn symlink_and_permissive_native_runtime_roots_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = fixture(1, "");
    symlink(
        fixture.origin.path(),
        fixture.home.path().join("native-runtime"),
    )
    .unwrap();
    assert!(Session::begin(
        fixture.home.path(),
        authority(&fixture.root, Profile::Remote)
    )
    .is_err());
    fs::remove_file(fixture.home.path().join("native-runtime")).unwrap();
    fs::create_dir(fixture.home.path().join("native-runtime")).unwrap();
    fs::set_permissions(
        fixture.home.path().join("native-runtime"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Session::begin(
        fixture.home.path(),
        authority(&fixture.root, Profile::Remote)
    )
    .is_err());
}
