//! Metadata capture tests, separate from real-interpreter execution evidence.
use super::*;
use std::fs;
use std::time::Duration;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    image: PathBuf,
    guard: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let image = root.join("installation/bin/python3.12");
        fs::create_dir_all(image.parent().unwrap()).unwrap();
        fs::write(&image, b"metadata-only interpreter fixture").unwrap();
        let stdlib = root.join("installation/lib/python3.12");
        fs::create_dir_all(stdlib.join("site-packages")).unwrap();
        fs::write(stdlib.join("os.py"), b"standard source").unwrap();
        fs::write(stdlib.join("site-packages/unrelated.py"), b"package source").unwrap();
        let guard = root.join("control");
        fs::create_dir(&guard).unwrap();
        Self {
            _temp: temp,
            root,
            image,
            guard,
        }
    }

    fn capture(&self) -> io::Result<Resources> {
        python_identity(
            &self.image,
            &self.image,
            &self.guard,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
        )
    }
}

#[test]
fn identity_omits_unrelated_packages_but_default_capture_retains_them() {
    let fixture = Fixture::new();
    let identity = fixture.capture().unwrap();
    assert!(identity
        .files
        .iter()
        .any(|file| file.source.ends_with("os.py")));
    assert!(!identity
        .files
        .iter()
        .any(|file| file.source.ends_with("unrelated.py")));
    assert_eq!(
        identity.standard_library.as_deref(),
        Some(fixture.root.join("installation/lib/python3.12").as_path())
    );
    let contained = python(
        &fixture.image,
        &fixture.image,
        &fixture.guard,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(contained
        .files
        .iter()
        .any(|file| file.source.ends_with("unrelated.py")));
}

#[test]
fn identity_refuses_unbound_path_selectors_and_detects_mid_capture_creation() {
    for relative in [
        "lib/python312.zip",
        "lib/python3.12.zip",
        "bin/python3.12._pth",
        "bin/pyvenv.cfg",
    ] {
        let fixture = Fixture::new();
        let captured = fixture.capture().unwrap();
        let path = fixture.root.join("installation").join(relative);
        fs::write(&path, b"unbound selector").unwrap();
        assert!(captured.verify().is_err(), "missed creation of {relative}");
        assert!(fixture.capture().is_err(), "accepted {relative}");
    }
}

#[test]
fn identity_preserves_venv_configuration_content_evidence() {
    let fixture = Fixture::new();
    let config = fixture.root.join("installation/pyvenv.cfg");
    let text = format!(
        "home = {}\nversion = 3.12.1\ninclude-system-site-packages = false\n",
        fixture.image.parent().unwrap().display()
    );
    fs::write(&config, &text).unwrap();
    let before = fixture.capture().unwrap();
    assert_eq!(before.configuration.len(), 1);
    let changed = text.replace("false", "true");
    let before_configuration = before.configuration.clone();
    if cfg!(windows) {
        // The held binding excludes writers, so the configuration cannot change
        // while it is held. Release it before changing the file.
        let error = fs::write(&config, &changed).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32));
        before.verify().unwrap();
        drop(before);
        fs::write(&config, &changed).unwrap();
    } else {
        fs::write(&config, &changed).unwrap();
        assert!(before.verify().is_err());
    }
    let after = fixture.capture().unwrap();
    assert_ne!(before_configuration, after.configuration);
}
