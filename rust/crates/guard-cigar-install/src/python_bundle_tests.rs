use super::*;
use guard_cigar_release::{CatalogTrust, InterpreterBuild, TrustedCatalog, TrustedKey};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::io::Write;

#[derive(Clone)]
struct Member {
    name: String,
    kind: u8,
    bytes: Vec<u8>,
    link: String,
}
fn member(name: &str, kind: u8, bytes: &[u8], link: &str) -> Member {
    Member {
        name: name.into(),
        kind,
        bytes: bytes.into(),
        link: link.into(),
    }
}
fn members() -> Vec<Member> {
    vec![
        member(
            "python/bin/python3.14",
            b'0',
            b"synthetic interpreter bytes, never executed",
            "",
        ),
        member(
            "python/lib/python3.14/os.py",
            b'0',
            b"# synthetic standard library\n",
            "",
        ),
        member("python/bin/python3", b'2', b"", "python3.14"),
    ]
}
fn tar(members: &[Member]) -> Vec<u8> {
    let mut raw = Vec::new();
    for entry in members {
        let mut header = ::tar::Header::new_gnu();
        header.set_mode(if entry.name.contains("/bin/") {
            0o755
        } else {
            0o644
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(entry.bytes.len() as u64);
        header.set_entry_type(::tar::EntryType::new(entry.kind));
        assert!(entry.name.len() <= 100 && entry.link.len() <= 100);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
        header.as_mut_bytes()[157..257].fill(0);
        header.as_mut_bytes()[157..157 + entry.link.len()].copy_from_slice(entry.link.as_bytes());
        header.set_cksum();
        raw.extend_from_slice(header.as_bytes());
        raw.extend_from_slice(&entry.bytes);
        raw.resize((raw.len() + 511) & !511, 0);
    }
    raw.resize(raw.len() + 1024, 0);
    raw
}
fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}
fn contents() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("bin/python3.14".into(), members()[0].bytes.clone()),
        ("bin/python3".into(), members()[0].bytes.clone()),
        ("lib/python3.14/os.py".into(), members()[1].bytes.clone()),
    ])
}
fn tree() -> String {
    let mut hash = Sha256::new();
    hash.update(b"guard-cigar-python-tree.v1\0");
    for (name, bytes) in contents() {
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(format!("{:x}", Sha256::digest(bytes)).as_bytes());
    }
    format!("{:x}", hash.finalize())
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    archive: PathBuf,
    build: guard_cigar_release::ResolvedInterpreterBuild,
}
impl Fixture {
    fn new(bytes: Vec<u8>, change: impl FnOnce(&mut InterpreterBuild)) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let archive = root.join("python.tar.gz");
        fs::write(&archive, &bytes).unwrap();
        let mut doc = TrustedCatalog::bundled().unwrap().document().clone();
        doc.issued_at = 900;
        doc.expires_at = 2000;
        let build = &mut doc.interpreters[0];
        build.archive_bytes = bytes.len() as u64;
        build.archive_sha256 = format!("{:x}", Sha256::digest(bytes));
        build.tree_sha256 = tree();
        build.files = 3;
        build.expanded_bytes = contents().values().map(|v| v.len() as u64).sum();
        build.executable_sha256 = format!("{:x}", Sha256::digest(&members()[0].bytes));
        change(build);
        let id = build.build_id.clone();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[111; 32]).unwrap();
        let key = TrustedKey {
            key_id: "python-preparation-test-only".into(),
            public_key: pair.public_key().as_ref().try_into().unwrap(),
            not_before: 1,
            not_after: 3000,
            revoked: false,
        };
        let payload = serde_json::to_string(&doc).unwrap();
        let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
        message.extend_from_slice(payload.as_bytes());
        let signature: String = pair
            .sign(&message)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let envelope=serde_json::to_vec(&serde_json::json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,"payload":payload,"signature_hex":signature})).unwrap();
        let catalog = TrustedCatalog::verify(
            &envelope,
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: 1000,
            },
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            archive,
            build: catalog.prepare_interpreter(&id, "darwin-arm64").unwrap(),
        }
    }
    fn plan(&self) -> Result<BundlePlan, InstallError> {
        prepare_python(&self.build, &self.archive, &crate::tests::control())
    }
    fn output(&self) -> PathBuf {
        let path = self.root.join("python");
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        }
        path
    }
}
#[test]
#[cfg(unix)]
fn private_python_materializes_internal_aliases_and_rechecks_complete_tree() {
    let fixture = Fixture::new(gzip(&tar(&members())), |_| {});
    let plan = fixture.plan().unwrap();
    let output = fixture.output();
    plan.write_into(&output, &crate::tests::control()).unwrap();
    for (name, expected) in contents() {
        let path = output.join(name);
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(fs::read(path).unwrap(), expected);
    }
    let verified =
        crate::verify_python_tree(&fixture.build, &output, &crate::tests::control()).unwrap();
    assert_eq!(verified.files(), 3);
    assert_eq!(verified.tree_sha256(), tree());
    assert_eq!(
        plan.write_into(&output, &crate::tests::control()),
        Err(InstallError::DestinationNotEmpty)
    );
    assert!(!fixture.build.setup_qualified());
}
#[test]
fn unsafe_paths_aliases_special_records_and_ambiguous_extensions_are_refused() {
    for extra in [
        member("python/../escape", b'0', b"x", ""),
        member("/outside", b'0', b"x", ""),
        member("python/BIN/alias", b'0', b"x", ""),
        member("python/hooks.pth", b'0', b"x", ""),
        member("python/bin/outside", b'2', b"", "../../outside"),
        member("python/bin/outside", b'2', b"", "/outside"),
        member("python/bin/missing", b'2', b"", "missing"),
        member("python/bin/cycle", b'2', b"", "cycle"),
        member("python/hard", b'1', b"", "outside"),
        member("python/device", b'3', b"", ""),
        member("python/pax", b'x', b"", ""),
    ] {
        // A case-only alias is a distinct path where the file system keeps case.
        if extra.name == "python/BIN/alias" && !cfg!(any(target_os = "macos", windows)) {
            continue;
        }
        let mut entries = members();
        let name = extra.name.clone();
        entries.push(extra);
        let fixture = Fixture::new(gzip(&tar(&entries)), |_| {});
        assert!(
            matches!(
                fixture.plan(),
                Err(InstallError::EntryUnsafe | InstallError::PythonArchiveUnsupported)
            ),
            "{name}"
        );
        assert!(!fixture.root.join("python").exists());
    }
}
#[test]
fn exact_archive_tree_executable_and_framing_are_checked_before_writes() {
    let valid = gzip(&tar(&members()));
    let fixture = Fixture::new(valid.clone(), |_| {});
    fs::write(&fixture.archive, b"changed archive").unwrap();
    assert!(matches!(
        fixture.plan(),
        Err(InstallError::ArtifactMismatch)
    ));
    let fixture = Fixture::new(valid.clone(), |b| b.tree_sha256 = "0".repeat(64));
    assert!(matches!(fixture.plan(), Err(InstallError::TreeMismatch)));
    let fixture = Fixture::new(valid.clone(), |b| b.executable_sha256 = "0".repeat(64));
    assert!(matches!(
        fixture.plan(),
        Err(InstallError::ArtifactMismatch)
    ));
    let mut raw = tar(&members());
    raw[0] ^= 1;
    let mut trailing = tar(&members());
    trailing.extend_from_slice(&tar(&members()));
    let mut gzip_trailing = valid.clone();
    gzip_trailing.extend_from_slice(&valid);
    for bytes in [
        gzip(&raw),
        gzip(&trailing),
        gzip_trailing,
        valid[..valid.len() - 2].to_vec(),
    ] {
        let fixture = Fixture::new(bytes, |_| {});
        assert!(matches!(fixture.plan(), Err(InstallError::ArchiveInvalid)));
    }
}
#[test]
fn cancellation_and_advertised_member_limits_refuse_before_output() {
    let fixture = Fixture::new(gzip(&tar(&members())), |_| {});
    let cancelled =
        PreparationControl::new(Arc::new(AtomicBool::new(true)), Duration::from_secs(1)).unwrap();
    assert!(matches!(
        prepare_python(&fixture.build, &fixture.root.join("missing"), &cancelled),
        Err(InstallError::Cancelled)
    ));
    let mut raw = tar(&members());
    let mut header = ::tar::Header::new_gnu();
    header.as_mut_bytes().copy_from_slice(&raw[..512]);
    header.set_size(MAX_FILE_BYTES + 1);
    header.set_cksum();
    raw[..512].copy_from_slice(header.as_bytes());
    let fixture = Fixture::new(gzip(&raw), |_| {});
    assert!(matches!(fixture.plan(), Err(InstallError::LimitExceeded)));
}
#[test]
#[cfg(unix)]
fn tree_verification_refuses_modified_files_extra_paths_links_and_writable_code() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for change in [
        "bytes",
        "extra",
        "symlink",
        "hardlink",
        "writable",
        "empty-directory",
        "executable-mode",
    ] {
        let fixture = Fixture::new(gzip(&tar(&members())), |_| {});
        let output = fixture.output();
        fixture
            .plan()
            .unwrap()
            .write_into(&output, &crate::tests::control())
            .unwrap();
        let file = output.join("lib/python3.14/os.py");
        match change {
            "bytes" => {
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&file, b"changed").unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
            }
            "extra" => {
                fs::write(output.join("extra.py"), b"extra").unwrap();
            }
            "symlink" => {
                fs::remove_file(&file).unwrap();
                symlink(&fixture.archive, &file).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&file, fixture.root.join("alias")).unwrap();
            }
            "writable" => {
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "empty-directory" => {
                let path = output.join("extra");
                fs::create_dir(&path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            _ => {
                fs::set_permissions(
                    output.join("bin/python3.14"),
                    fs::Permissions::from_mode(0o400),
                )
                .unwrap();
            }
        }
        assert!(
            crate::verify_python_tree(&fixture.build, &output, &crate::tests::control()).is_err(),
            "{change}"
        );
    }
}
