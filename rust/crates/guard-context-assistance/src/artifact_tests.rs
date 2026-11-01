use super::*;
#[path = "release_artifact_tests.rs"]
mod releases;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    selection: RuntimeSelection,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-cigar-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let site = root.join("site");
        let package = site.join("cigar_sdk");
        let native = package.join("_native/darwin-arm64");
        fs::create_dir_all(&native).unwrap();
        fs::write(
            root.join("python"),
            b"fixture executable bytes, never launched",
        )
        .unwrap();
        fs::write(package.join("release.json"), serde_json::to_vec(&json!({"schema_version": "cigar.sdk-release.v1", "name": "hol-cigar", "version": CIGAR_VERSION, "local_context_core_version": CIGAR_VERSION, "local_context_protocol": CIGAR_PROTOCOL})).unwrap()).unwrap();
        fs::write(package.join("native-platforms.v1.json"), serde_json::to_vec(&json!({"schema": "cigar.native-platforms.v1", "platforms": [{"id": "darwin-arm64", "target": "aarch64-apple-darwin", "executable": "cigar-context-worker"}]})).unwrap()).unwrap();
        fs::write(
            native.join("cigar-context-worker"),
            b"fixture worker bytes, never launched",
        )
        .unwrap();
        let sha = format!(
            "{:x}",
            Sha256::digest(b"fixture worker bytes, never launched")
        );
        fs::write(native.join("manifest.json"), serde_json::to_vec(&json!({"core_version": CIGAR_VERSION, "sdk_release": CIGAR_VERSION, "protocol": CIGAR_PROTOCOL, "target": "aarch64-apple-darwin", "sha256": sha})).unwrap()).unwrap();
        Self {
            selection: RuntimeSelection {
                verified_python: None,
                python_bundle: None,
                python: root.join("python"),
                site_packages: site,
                work_dir: root.clone(),
            },
            root,
        }
    }
    fn inspect(&self) -> Result<BundleApproval, RuntimeError> {
        inspect_bundle(&self.selection, "darwin-arm64")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn code_bytecode_and_extra_files_are_bound_to_the_approved_inventory() {
    let fixture = Fixture::new();
    let original = fixture.inspect().unwrap();
    fs::create_dir(fixture.selection.site_packages.join("__pycache__")).unwrap();
    fs::write(
        fixture
            .selection
            .site_packages
            .join("__pycache__/injected.cpython-314.pyc"),
        b"injected bytecode",
    )
    .unwrap();
    let changed = fixture.inspect().unwrap();
    assert_ne!(original.package_tree_sha256, changed.package_tree_sha256);
    assert_eq!(changed.files, original.files + 1);
    fs::write(fixture.selection.python.clone(), b"different executable").unwrap();
    assert_ne!(
        changed.python_sha256,
        fixture.inspect().unwrap().python_sha256
    );
}

#[test]
fn startup_hooks_worker_tampering_and_shared_writable_trees_are_refused() {
    let fixture = Fixture::new();
    fs::write(
        fixture.selection.site_packages.join("unexpected.pth"),
        b"import side_effect",
    )
    .unwrap();
    assert_eq!(fixture.inspect(), Err(RuntimeError::PackageUnsafe));
    fs::remove_file(fixture.selection.site_packages.join("unexpected.pth")).unwrap();
    fs::write(
        fixture
            .selection
            .site_packages
            .join("cigar_sdk/_native/darwin-arm64/cigar-context-worker"),
        b"tampered",
    )
    .unwrap();
    assert_eq!(fixture.inspect(), Err(RuntimeError::PackageMismatch));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &fixture.selection.site_packages,
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(fixture.inspect(), Err(RuntimeError::PackageUnsafe));
    }
}

#[cfg(unix)]
#[test]
fn symlinks_cannot_add_importable_code_outside_the_verified_tree() {
    let fixture = Fixture::new();
    std::os::unix::fs::symlink(
        &fixture.selection.python,
        fixture.selection.site_packages.join("outside.py"),
    )
    .unwrap();
    assert_eq!(fixture.inspect(), Err(RuntimeError::PackageUnsafe));
}
