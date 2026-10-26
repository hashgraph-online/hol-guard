//! Source-pinned Python outcomes; no kernel filters are installed by replay.
use super::*;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn expand(value: &Value, root: &str) -> Value {
    match value {
        Value::String(v) => json!(v.replace("$ROOT", root)),
        Value::Array(v) => json!(v.iter().map(|v| expand(v, root)).collect::<Vec<_>>()),
        Value::Object(v) => Value::Object(
            v.iter()
                .map(|(k, v)| (k.replace("$ROOT", root), expand(v, root)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn projection(plan: plan::Plan) -> Value {
    json!({"schema":"guard-linux-readonly-plan.v2","command":plan.command,"mapping_records":plan.mapping_records,
        "read_roots":plan.read_roots,"read_files":plan.read_files,"list_roots":plan.list_roots,"write_roots":plan.write_roots,
        "executables":plan.executables,"device_files":plan.device_files,"read_identities":plan.read_identities,
        "write_identities":plan.write_identities})
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(prefix: &str) -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = std::env::temp_dir().join(format!("{prefix}-{}", hex::encode(random)));
    std::fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

#[test]
fn expired_snapshot_deadline_cannot_create_or_append_a_plan() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    let fixture = fixture("hol-guard-linux-index");
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot = fixture.0.join("linux-index.json");
    let expired = Instant::now();
    assert!(index_snapshot::write(&snapshot, &json!([]), expired).is_err());
    assert!(!snapshot.exists());
    let envelope = index_snapshot::write(
        &snapshot,
        &json!([]),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(envelope["decoded_bytes"], json!(2));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&snapshot)
        .unwrap();
    assert!(index_snapshot::write_bytes(&mut file, b"late", expired).is_err());
    assert_eq!(std::fs::read(snapshot).unwrap(), b"[]");
}

#[test]
fn discovery_records_library_aliases_without_granting_link_or_secret_reads() {
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};
    let fixture = fixture("guard-library-index");
    std::fs::write(fixture.0.join("libfixture.so.1.2"), b"fixture").unwrap();
    std::fs::write(fixture.0.join("id_rsa"), b"ordinary fixture outside .ssh").unwrap();
    std::fs::write(fixture.0.join(".env"), b"synthetic secret fixture").unwrap();
    symlink("libfixture.so.1.2", fixture.0.join("libfixture.so.1")).unwrap();
    let (grants, candidates) =
        paths::collect_with_candidates(&fixture.0, 100, Instant::now() + Duration::from_secs(5))
            .unwrap();
    let grants: BTreeSet<_> = grants.into_iter().map(|(path, _, _)| path).collect();
    assert_eq!(grants.len(), 2);
    assert!(grants.contains(&fixture.0.join("id_rsa")));
    assert_eq!(
        candidates["libfixture.so.1"],
        BTreeSet::from([fixture.0.clone()])
    );
    assert!(!candidates.contains_key(".env"));
}

#[test]
fn non_utf8_names_stay_ungranted_without_aborting_discovery() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    let fixture = fixture("guard-non-utf8-index");
    let opaque = fixture.0.join(OsStr::from_bytes(b"opaque-\xff"));
    std::fs::create_dir(&opaque).unwrap();
    std::fs::write(opaque.join("nested.txt"), b"fixture").unwrap();
    std::fs::write(fixture.0.join(OsStr::from_bytes(b"file-\xfe")), b"fixture").unwrap();
    std::fs::write(fixture.0.join("plain.txt"), b"fixture").unwrap();
    let (grants, candidates) =
        paths::collect_with_candidates(&fixture.0, 100, Instant::now() + Duration::from_secs(5))
            .unwrap();
    let grants: Vec<_> = grants.into_iter().map(|(path, _, _)| path).collect();
    assert_eq!(grants, vec![fixture.0.join("plain.txt")]);
    assert_eq!(candidates.keys().collect::<Vec<_>>(), vec!["plain.txt"]);
}

#[test]
fn original_python_kernel_plan_and_mount_contracts() {
    let fixture = fixture("guard-linux-launch-parity");
    std::fs::write(fixture.0.join("runner"), b"\x7fELFfixture-not-executed").unwrap();
    let document: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/linux_launch_parity.json"
    ))
    .unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert!(cases.len() >= 40);
    for original in cases {
        let case = expand(original, fixture.0.to_str().unwrap());
        let input = &case["input"];
        let mut expected = case["expected"].clone();
        let result: plan::Result<Value> = match case["operation"].as_str().unwrap() {
            "landlock_admission" => {
                let evidence = &input["evidence"];
                let evidence = admission::Evidence {
                    mode: evidence["mode"].as_u64().unwrap() as u32,
                    device: evidence["device"].as_u64().unwrap(),
                    inode: evidence["inode"].as_u64().unwrap(),
                    links: evidence["links"].as_u64().unwrap(),
                    major: evidence["major"].as_u64().unwrap() as u32,
                    minor: evidence["minor"].as_u64().unwrap() as u32,
                };
                let identity = input["identity"]
                    .as_array()
                    .map(|v| (v[0].as_u64().unwrap(), v[1].as_u64().unwrap()));
                admission::rights(
                    Path::new(input["path"].as_str().unwrap()),
                    input["access"].as_u64().unwrap(),
                    input["directory"].as_bool(),
                    identity,
                    input["device"].as_bool().unwrap(),
                    &evidence,
                )
                .map(|v| json!([v]))
            }
            "socket_filter" => {
                socket::instructions(input["machine"].as_str().unwrap()).map(|v| json!(v))
            }
            "mount_targets" => {
                mounts::targets(input["raw"].as_str().unwrap().as_bytes()).map(|v| json!(v))
            }
            "validate_records" => {
                let approved: BTreeSet<PathBuf> =
                    serde_json::from_value(input["approved_paths"].clone()).unwrap();
                mapping_records::validate(&input["records"], &approved).map(|v| {
                    json!(v
                        .into_iter()
                        .map(|v| (v.path, v.identity, v.digest, v.aliases))
                        .collect::<Vec<_>>())
                })
            }
            "load_plan" => plan::parse(input["payload"].clone()).map(projection),
            "plan_locator" => plan::locator(input["digest"].as_str().unwrap()).map(|_| Value::Null),
            "elf_loader" => {
                let path = Path::new(input["executable"].as_str().unwrap());
                std::fs::write(
                    path,
                    hex::decode(input["image_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                elf::resolve(path).map(|v| json!(v))
            }
            "seal_copy" => {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let mutation = input["mutation"].as_str().unwrap();
                let source = fixture.0.join(format!("copy-{mutation}"));
                let destination = fixture.0.join(format!("sealed-{mutation}"));
                let data = hex::decode(input["data_hex"].as_str().unwrap()).unwrap();
                std::fs::write(&source, &data).unwrap();
                std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
                let metadata = std::fs::metadata(&source).unwrap();
                let mut record = mapping_records::Record {
                    path: source.clone(),
                    identity: mapping_copy::identity(&metadata).unwrap(),
                    digest: format!("{:x}", sha2::Sha256::digest(&data)),
                    aliases: vec![source.clone()],
                };
                match mutation {
                    "hash" => record.digest = "0".repeat(64),
                    "inode" => record.identity[1] += 1,
                    "size" => record.identity[2] += 1,
                    "mode" => record.identity[4] ^= 0o100,
                    "symlink" => {
                        record.path = fixture.0.join("copy-alias");
                        std::os::unix::fs::symlink(&source, &record.path).unwrap();
                    }
                    _ => {}
                }
                match mapping_copy::seal(&record, &destination) {
                    Ok(file) => Ok(
                        json!({"bytes_hex":hex::encode(std::fs::read(destination).unwrap()),
                        "mode":file.metadata().unwrap().mode()&0o7777}),
                    ),
                    Err(_) => {
                        assert_eq!(expected, json!({"refused":true}));
                        continue;
                    }
                }
            }
            "read_grants" => {
                let mutation = input["fixture_tree"].as_str().unwrap();
                let workspace = fixture.0.join(format!("tree-{mutation}"));
                std::fs::create_dir(&workspace).unwrap();
                std::fs::write(workspace.join("source.py"), "fixture source").unwrap();
                std::fs::create_dir(workspace.join("subdir")).unwrap();
                std::fs::write(workspace.join("subdir/module.py"), "fixture module").unwrap();
                match mutation {
                    "credentials" => {
                        std::fs::write(workspace.join(".env"), "fixture").unwrap();
                        std::fs::create_dir(workspace.join(".ssh")).unwrap();
                        std::fs::write(workspace.join(".ssh/id_rsa"), "fixture").unwrap();
                    }
                    "symlink" => std::os::unix::fs::symlink(
                        workspace.join("source.py"),
                        workspace.join("alias.py"),
                    )
                    .unwrap(),
                    "hardlink" => std::fs::hard_link(
                        workspace.join("source.py"),
                        workspace.join("hardlink.py"),
                    )
                    .unwrap(),
                    "root-alias" => {
                        std::os::unix::fs::symlink(&workspace, fixture.0.join("root-alias"))
                            .unwrap()
                    }
                    "parent-alias" => {
                        std::os::unix::fs::symlink(&workspace, fixture.0.join("parent-alias"))
                            .unwrap()
                    }
                    "protected-root" => std::fs::create_dir(workspace.join(".ssh")).unwrap(),
                    _ => {}
                }
                if let Some(grants) = expected.get_mut("value").and_then(Value::as_array_mut) {
                    use std::os::unix::fs::MetadataExt;
                    for grant in grants {
                        let metadata = std::fs::metadata(grant["path"].as_str().unwrap()).unwrap();
                        grant["device"] = json!(metadata.dev());
                        grant["inode"] = json!(metadata.ino());
                    }
                }
                paths::collect(
                    Path::new(input["root"].as_str().unwrap()),
                    input["max_entries"].as_u64().unwrap() as usize,
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
            }
            _ => panic!("Unknown original contract operation"),
        };
        let actual = match result {
            Ok(v) => json!({"value":v}),
            Err(e) => json!({"error":e}),
        };
        assert_eq!(actual, expected, "{}", case["operation"]);
    }
}

#[test]
fn duplicate_json_fields_cannot_gain_authority_with_a_matching_digest() {
    assert!(json::parse(br#"{"schema":"one","schema":"two"}"#).is_err());
    assert!(json::parse(br#"{"nested":{"identity":1,"identity":2}}"#).is_err());
    assert!(json::parse(br#"{"nested":{"identity":1}}"#).is_ok());
}

#[test]
fn invalid_cli_locator_has_no_path_or_execution_authority() {
    for digest in ["", "../plan.json", "/etc/passwd", "A", "ffffffff"] {
        assert_eq!(launch(digest), 126);
    }
}

#[test]
fn replaced_directory_cannot_redirect_descriptor_discovery() {
    use std::os::unix::fs::MetadataExt;
    let fixture = fixture("guard-linux-directory-race");
    let child = fixture.0.join("child");
    std::fs::create_dir(&child).unwrap();
    let original = std::fs::metadata(&child).unwrap();
    let parent = std::fs::File::open(&fixture.0).unwrap();
    std::fs::rename(&child, fixture.0.join("original")).unwrap();
    std::fs::create_dir(&child).unwrap();
    let name = std::ffi::CString::new("child").unwrap();
    assert!(paths::child(&parent, &name, original.dev(), original.ino()).is_err());
    std::fs::remove_dir(&child).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("original"), &child).unwrap();
    assert!(paths::child(&parent, &name, original.dev(), original.ino()).is_err());
}

#[test]
fn private_plan_snapshot_requires_bound_owner_permissions_bytes_and_unique_fields() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture("guard-linux-plan-snapshot");
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = fixture.0.join("runner");
    std::fs::write(&image, "fixture").unwrap();
    let payload = json!({"schema":"guard-linux-readonly-plan.v2","mapping_records":[],"command":[image],
        "read_roots":[],"read_files":[],"list_roots":[],"write_roots":[],"executables":[image],
        "device_files":[],"read_identities":[],"write_identities":[]});
    let raw = serde_json::to_vec(&payload).unwrap();
    let digest = format!("{:x}", sha2::Sha256::digest(&raw));
    let path = fixture.0.join(plan::FILENAME);
    std::fs::write(&path, &raw).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read::read_at(&fixture.0, &digest).is_ok());
    assert!(read::read_at(&fixture.0, &"0".repeat(64)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read::read_at(&fixture.0, &digest).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = fixture.0.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(read::read_at(&fixture.0, &digest).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::rename(&path, &alias).unwrap();
    std::os::unix::fs::symlink(&alias, &path).unwrap();
    assert!(read::read_at(&fixture.0, &digest).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&alias, &path).unwrap();
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read::read_at(&fixture.0, &digest).is_err());
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let raw = br#"{"schema":"one","schema":"two"}"#;
    std::fs::write(&path, raw).unwrap();
    assert!(read::read_at(&fixture.0, &format!("{:x}", sha2::Sha256::digest(raw))).is_err());
}

#[test]
fn namespace_argv_keeps_only_a_fixed_snapshot_and_native_helper() {
    let fixture = fixture("guard-linux-argv-parity");
    let image = fixture.0.join("runner");
    std::fs::write(&image, "fixture").unwrap();
    let helper = fixture.0.join("native-runtime");
    std::fs::write(&helper, "fixture").unwrap();
    let snapshot = fixture.0.join(plan::FILENAME);
    let value = argv::compose(
        Path::new("/usr/bin/bwrap"),
        &fixture.0,
        &fixture.0,
        &helper,
        vec![fixture.0.clone(), image.clone(), helper.clone()],
        vec![fixture.0.clone()],
        BTreeSet::from([image.clone()]),
        &snapshot,
        &"f".repeat(64),
        plan::DIRECTORY,
    )
    .unwrap();
    let argv: Vec<String> = serde_json::from_value(value).unwrap();
    assert_eq!(
        &argv[argv.len() - 3..],
        &[
            helper.to_string_lossy().into_owned(),
            "restricted-linux-launch".into(),
            "f".repeat(64)
        ]
    );
    assert!(argv.windows(3).any(|v| v
        == [
            "--ro-bind",
            snapshot.to_str().unwrap(),
            "/guard-linux-plan/linux-plan.json"
        ]));
    assert!(argv.windows(3).any(|v| v
        == [
            "--ro-bind",
            image.to_str().unwrap(),
            image.to_str().unwrap()
        ]));
    assert!(!argv
        .iter()
        .any(|v| v.ends_with("restricted_linux_entry.py")));
}

#[test]
fn linked_metadata_is_listed_without_parent_checkout_or_secret_read_grants() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    for with_library in [false, true] {
        let fixture = fixture("guard-linux-linked-metadata");
        let workspace = fixture.0.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("ordinary.txt"), "ordinary").unwrap();
        let image = workspace.join("runner");
        std::fs::write(&image, "#!/bin/sh\n").unwrap();
        let parent = fixture.0.join("other-checkout");
        let metadata = parent.join(".git");
        std::fs::create_dir_all(&metadata).unwrap();
        std::fs::write(metadata.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(metadata.join(".env"), "synthetic fixture").unwrap();
        let private = fixture.0.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let approved = private.join("esbuild");
        std::fs::write(&approved, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&approved, std::fs::Permissions::from_mode(0o500)).unwrap();
        let library = fixture.0.join("library");
        std::fs::create_dir(&library).unwrap();
        std::fs::write(library.join("ordinary.dat"), "ordinary runtime data").unwrap();
        std::fs::write(library.join(".env"), "synthetic fixture").unwrap();
        let mut read_only_roots = vec![metadata.clone()];
        if with_library {
            read_only_roots.push(library.clone());
        }
        let input = json!({"profile_version":"git-readonly-v1","workspace":workspace,"cwd":workspace,
            "private_root":private,"allowed_executables":[image,approved],"read_only_roots":read_only_roots,
            "output_roots":[],"command":[image,"diff","--stat"],"backend_executable":"/usr/bin/bwrap",
            "backend":"linux-bubblewrap","platform":"linux","search_path":""});
        let value =
            prepare::argv_with_system(&input, &[], &[], Instant::now() + Duration::from_secs(5))
                .unwrap();
        let argv: Vec<String> = serde_json::from_value(value).unwrap();
        let raw = std::fs::read(private.join(plan::FILENAME)).unwrap();
        let digest = format!("{:x}", sha2::Sha256::digest(&raw));
        let snapshot: Value = serde_json::from_slice(&raw).unwrap();
        let has = |key: &str, path: &Path| {
            snapshot[key]
                .as_array()
                .unwrap()
                .contains(&json!(path.to_str().unwrap()))
        };
        assert_eq!(snapshot["schema"], "guard-linux-readonly-plan.v2");
        assert!(has("list_roots", &workspace) && has("list_roots", &metadata));
        assert_eq!(has("list_roots", &library), with_library);
        assert_eq!(snapshot["read_roots"], json!([]));
        assert!(has("read_files", &metadata.join("HEAD")));
        assert!(!has("read_files", &metadata.join(".env")));
        assert!(!has("read_files", &library.join(".env")));
        assert_eq!(
            has("read_files", &library.join("ordinary.dat")),
            with_library
        );
        assert_eq!(snapshot["write_roots"], json!([private]));
        assert!(!argv.contains(&parent.to_str().unwrap().to_owned()));
        assert!(argv.contains(&"--unshare-all".to_owned()));
        let position = |value: &str| argv.iter().position(|v| v == value).unwrap();
        assert_eq!(argv[position("--cap-drop") + 1], "ALL");
        assert_eq!(argv.last().unwrap(), &digest);
        assert_eq!(argv[argv.len() - 2], "restricted-linux-launch");
    }
}
