use super::*;
use guard_cigar_release::{CatalogTrust, TrustedCatalog, TrustedKey, WheelLock, WheelSource};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use std::io::Cursor;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

type Entry = (String, Vec<u8>, bool);
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    inputs: BTreeMap<String, PathBuf>,
    release: ResolvedRelease,
    entries: Vec<Entry>,
}
pub(super) fn control() -> PreparationControl {
    PreparationControl::new(Arc::new(AtomicBool::new(false)), Duration::from_secs(20)).unwrap()
}
fn zip(entries: &[Entry]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes, executable) in entries {
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(if *executable { 0o755 } else { 0o644 });
        zip.start_file(name.clone(), options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn entries(name: &str, version: &str, import_path: &str) -> Vec<Entry> {
    let info = format!("{}-{version}.dist-info", name.replace('-', "_"));
    vec![
        (
            import_path.into(),
            b"# synthetic package, never executed\n".to_vec(),
            false,
        ),
        (
            format!("{info}/METADATA"),
            format!("Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n").into_bytes(),
            false,
        ),
        (
            format!("{info}/WHEEL"),
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
            false,
        ),
    ]
}
fn tree(entries: &[Entry]) -> String {
    let sorted: BTreeMap<_, _> = entries
        .iter()
        .map(|(name, bytes, _)| (name, bytes))
        .collect();
    let mut digest = Sha256::new();
    digest.update(b"guard-cigar-package-tree.v1\0");
    for (name, bytes) in sorted {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(format!("{:x}", Sha256::digest(bytes)).as_bytes());
    }
    format!("{:x}", digest.finalize())
}
impl Fixture {
    fn new(extra: Option<Entry>, wrong_tree: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let mut sdk = entries("hol-cigar", "0.15.2", "cigar_sdk/__init__.py");
        sdk.push((
            "cigar_sdk/_native/darwin-arm64/cigar-context-worker".into(),
            b"synthetic executable bytes".to_vec(),
            true,
        ));
        if let Some(extra) = extra {
            sdk.push(extra);
        }
        let dependency = entries("protobuf", "7.36.2", "google/protobuf/__init__.py");
        let all: Vec<_> = sdk.iter().chain(&dependency).cloned().collect();
        let mut locks = Vec::new();
        let mut inputs = BTreeMap::new();
        for (name, version, contents) in [
            ("hol-cigar", "0.15.2", &sdk),
            ("protobuf", "7.36.2", &dependency),
        ] {
            let filename = format!("{}-{version}-py3-none-any.whl", name.replace('-', "_"));
            let bytes = zip(contents);
            let path = root.join(&filename);
            fs::write(&path, &bytes).unwrap();
            inputs.insert(filename.clone(), path);
            locks.push(WheelLock {
                distribution: name.into(),
                version: version.into(),
                filename,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                bytes: bytes.len() as u64,
                requires_python: None,
                source: WheelSource::OfflineBundle,
            });
        }
        let mut doc = TrustedCatalog::bundled().unwrap().document().clone();
        doc.issued_at = 900;
        doc.expires_at = 2000;
        let build = &mut doc.builds[0];
        build.identity.build_id = "test-only-future-build".into();
        build.identity.sdk_version = "0.15.2".into();
        build.identity.core_version = "0.15.1".into();
        // Only the first platform gets the fixture locks; drop the real ones.
        build.platforms.truncate(1);
        let artifact = &mut build.platforms[0];
        artifact.wheel = Some(locks.remove(0));
        artifact.dependencies = locks;
        artifact.package_tree_sha256 = Some(if wrong_tree {
            "0".repeat(64)
        } else {
            tree(&all)
        });
        let pair = Ed25519KeyPair::from_seed_unchecked(&[51; 32]).unwrap();
        let key = TrustedKey {
            key_id: "extractor-test-only".into(),
            public_key: pair.public_key().as_ref().try_into().unwrap(),
            not_before: 500,
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
        let envelope = serde_json::to_vec(
            &json!({"schema":"guard-cigar-signed-catalog.v1", "key_id":key.key_id,
            "payload":payload,"signature_hex":signature}),
        )
        .unwrap();
        let catalog = TrustedCatalog::verify(
            &envelope,
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: 1000,
            },
        )
        .unwrap();
        let release = catalog
            .prepare("test-only-future-build", "darwin-arm64", false)
            .unwrap();
        Self {
            _dir: dir,
            root,
            inputs,
            release,
            entries: all,
        }
    }
    fn plan(&self) -> Result<BundlePlan, InstallError> {
        prepare_locked(&self.release, &self.inputs, &control())
    }
    fn output(&self) -> PathBuf {
        let output = self.root.join("output");
        fs::create_dir(&output).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        }
        output
    }
}
#[test]
#[cfg(unix)]
fn extracts_exact_pinned_sdk_and_dependency_without_python_or_pip() {
    let fixture = Fixture::new(None, false);
    let plan = fixture.plan().unwrap();
    assert_eq!(plan.files(), fixture.entries.len());
    assert_eq!(
        plan.bytes(),
        fixture
            .entries
            .iter()
            .map(|(_, bytes, _)| bytes.len() as u64)
            .sum::<u64>()
    );
    let output = fixture.output();
    plan.write_into(&output, &control()).unwrap();
    for (name, expected, executable) in &fixture.entries {
        let path = output.join(name);
        assert_eq!(&fs::read(&path).unwrap(), expected);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            if *executable { 0o500 } else { 0o400 }
        );
    }
    assert!(
        !fixture.release.activation_qualified(),
        "preparation confers no activation qualification"
    );
    assert_eq!(
        plan.write_into(&output, &control()),
        Err(InstallError::DestinationNotEmpty)
    );
}
#[test]
fn changed_wheel_bytes_and_missing_or_additional_dependencies_refuse() {
    let mut fixture = Fixture::new(None, false);
    let original = fixture.inputs.clone();
    fixture
        .inputs
        .remove(fixture.inputs.keys().next().unwrap().clone().as_str());
    assert!(matches!(fixture.plan(), Err(InstallError::InputsInvalid)));
    fixture.inputs = original.clone();
    fixture
        .inputs
        .insert("unexpected.whl".into(), fixture.root.join("missing"));
    assert!(matches!(fixture.plan(), Err(InstallError::InputsInvalid)));
    fixture.inputs = original;
    fs::write(fixture.inputs.values().next().unwrap(), b"changed bytes").unwrap();
    assert!(matches!(
        fixture.plan(),
        Err(InstallError::ArtifactMismatch)
    ));
}
#[test]
fn installed_tree_digest_is_required_before_output() {
    let fixture = Fixture::new(None, true);
    assert!(matches!(fixture.plan(), Err(InstallError::TreeMismatch)));
    assert!(!fixture.root.join("output").exists());
}
#[test]
fn path_traversal_import_hooks_and_portable_aliases_refuse() {
    for name in [
        "../outside",
        "/absolute",
        "safe/../../outside",
        "C:/drive",
        "safe\\escape",
        "hooks.PTH",
        "x.egg-link",
        "hol_cigar-0.15.2.data/scripts/evil",
        "CON.py",
        "safe./x",
        "pkg/../x",
    ] {
        let fixture = Fixture::new(Some((name.into(), b"unsafe".to_vec(), false)), false);
        assert!(
            matches!(fixture.plan(), Err(InstallError::EntryUnsafe)),
            "{name}"
        );
        assert!(!fixture.root.join("output").exists());
    }
}
#[test]
fn duplicate_paths_case_aliases_and_file_directory_collisions_refuse() {
    for name in [
        "CIGAR_SDK/alias.py",
        "cigar_sdk",
        "cigar_sdk/__init__.py/child",
    ] {
        let fixture = Fixture::new(Some((name.into(), b"unsafe".to_vec(), false)), false);
        assert!(
            matches!(fixture.plan(), Err(InstallError::EntryUnsafe)),
            "{name}"
        );
    }
    let mut namespace = BTreeMap::new();
    paths::admit_name(b"package/file", false, &mut namespace).unwrap();
    assert_eq!(
        paths::admit_name(b"package/file", false, &mut namespace),
        Err(InstallError::EntryUnsafe)
    );
}
#[test]
fn cancellation_and_deadlines_refuse_before_reading_inputs() {
    let fixture = Fixture::new(None, false);
    let cancelled =
        PreparationControl::new(Arc::new(AtomicBool::new(true)), Duration::from_secs(1)).unwrap();
    assert!(matches!(
        prepare_locked(&fixture.release, &BTreeMap::new(), &cancelled),
        Err(InstallError::Cancelled)
    ));
    let expired =
        PreparationControl::new(Arc::new(AtomicBool::new(false)), Duration::from_nanos(1)).unwrap();
    std::thread::sleep(Duration::from_millis(1));
    assert!(matches!(
        prepare_locked(&fixture.release, &BTreeMap::new(), &expired),
        Err(InstallError::DeadlineExceeded)
    ));
    assert!(
        PreparationControl::new(Arc::new(AtomicBool::new(false)), Duration::from_secs(121))
            .is_err()
    );
}
#[test]
#[cfg(unix)]
fn output_symlink_or_public_directory_and_input_hardlinks_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = Fixture::new(None, false);
    let plan = fixture.plan().unwrap();
    let output = fixture.output();
    symlink(&output, fixture.root.join("alias")).unwrap();
    assert_eq!(
        plan.write_into(&fixture.root.join("alias"), &control()),
        Err(InstallError::DestinationUnsafe)
    );
    fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        plan.write_into(&output, &control()),
        Err(InstallError::DestinationUnsafe)
    );
    fs::hard_link(
        fixture.inputs.values().next().unwrap(),
        fixture.root.join("hardlink"),
    )
    .unwrap();
    assert!(matches!(
        fixture.plan(),
        Err(InstallError::ArtifactUnreadable)
    ));
}
#[test]
fn managed_slot_binds_interpreter_and_exact_build_without_catalog_checkpoint() {
    let fixture = Fixture::new(None, false);
    let a = slot_id(&fixture.release, &"a".repeat(64)).unwrap();
    assert_eq!(a.len(), 64);
    assert_eq!(a, slot_id(&fixture.release, &"a".repeat(64)).unwrap());
    assert_ne!(a, slot_id(&fixture.release, &"b".repeat(64)).unwrap());
    let different = Fixture::new(
        Some((
            "cigar_sdk/new_module.py".into(),
            b"same SDK label, different bytes".to_vec(),
            false,
        )),
        false,
    );
    assert_ne!(a, slot_id(&different.release, &"a".repeat(64)).unwrap());
    assert_eq!(
        slot_id(&fixture.release, "unverified"),
        Err(InstallError::InputsInvalid)
    );
}
