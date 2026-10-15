use super::*;
use std::fs;
use std::time::Duration;

// Framing fixture only: this is not a trusted or valid X.509 certificate.
const CERT: &[u8] = b"# public certificate fixture\n-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n";

fn capture_tree(root: &Path) -> io::Result<Resources> {
    let excluded = root.join("control");
    let cancel = AtomicBool::new(false);
    let mut capture = Capture {
        files: BTreeMap::new(),
        directories: BTreeSet::new(),
        bindings: Vec::new(),
        total: 0,
        entries: 0,
        deadline: Instant::now() + Duration::from_secs(10),
        cancel: &cancel,
        approved: vec![root.to_path_buf()],
        active: BTreeSet::new(),
        link_directories: BTreeMap::new(),
        excluded: &excluded,
    };
    capture.tree(root, Path::new("site-packages"), false)?;
    let resources = Resources {
        files: capture.files.into_values().collect(),
        directories: capture.directories.into_iter().collect(),
        bindings: capture.bindings,
        python_version: None,
        total_bytes: capture.total,
    };
    resources.verify()?;
    Ok(resources)
}

#[test]
fn approved_public_ca_bundles_are_captured_but_private_keys_are_not() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("site-packages");
    for name in [
        "certifi/cacert.pem",
        "pip/_vendor/certifi/cacert.pem",
        "botocore/cacert.pem",
    ] {
        fs::create_dir_all(root.join(name).parent().unwrap()).unwrap();
        fs::write(root.join(name), CERT).unwrap();
    }
    for name in [
        "certifi/private.pem",
        "certifi/client.key",
        ".ssh/cacert.pem",
        "other/cacert.pem",
    ] {
        fs::create_dir_all(root.join(name).parent().unwrap()).unwrap();
        fs::write(root.join(name), b"private material").unwrap();
    }
    let resources = capture_tree(&root).unwrap();
    assert_eq!(resources.files.len(), 3);
    assert!(resources.files.iter().all(|file| file.bytes == CERT));
}

#[test]
fn mixed_or_private_pem_under_a_public_filename_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("site-packages");
    fs::create_dir_all(root.join("certifi")).unwrap();
    for bytes in [
        b"-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----".as_slice(),
        b"-----BEGIN CERTIFICATE-----\nYWJjZA==",
        b"",
        b"unframed private data",
    ] {
        fs::write(root.join("certifi/cacert.pem"), bytes).unwrap();
        assert!(capture_tree(&root).is_err());
    }
    let mut mixed = CERT.to_vec();
    mixed.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----");
    fs::write(root.join("certifi/cacert.pem"), mixed).unwrap();
    assert!(capture_tree(&root).is_err());
}

#[test]
fn certificate_exception_does_not_broaden_secret_paths() {
    for path in [
        ".ssh/site-packages/certifi/cacert.pem",
        "site-packages/certifi/private.pem",
        "certifi/cacert.pem",
        "site-packages/other/cacert.pem",
        "site-packages/.aws/cacert.pem",
    ] {
        assert!(resource_protected(Path::new(path)), "{path}");
    }
    assert!(secret(Path::new("site-packages/certifi/cacert.pem")));
}

#[cfg(unix)]
#[test]
fn public_ca_symlink_cannot_capture_a_private_source() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("site-packages");
    fs::create_dir_all(root.join("certifi")).unwrap();
    fs::write(root.join("private.pem"), CERT).unwrap();
    symlink(root.join("private.pem"), root.join("certifi/cacert.pem")).unwrap();
    assert!(capture_tree(&root).is_err());
}
