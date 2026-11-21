use super::*;
use std::fs;
use std::time::Duration;

struct Layout {
    _temp: tempfile::TempDir,
    root: PathBuf,
    base: PathBuf,
    venv: PathBuf,
    image: PathBuf,
    config: String,
}
impl Layout {
    fn new(include_system: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let base = root.join("installation");
        let venv = root.join("environment");
        let bindir = if cfg!(windows) { "Scripts" } else { "bin" };
        let name = if cfg!(windows) {
            "python3.12.exe"
        } else {
            "python3.12"
        };
        fs::create_dir_all(base.join(bindir)).unwrap();
        fs::create_dir_all(venv.join(bindir)).unwrap();
        let base_image = base.join(bindir).join(name);
        let image = venv.join(bindir).join(name);
        // Metadata-only fixture. No interpreter is executed to discover roots.
        fs::write(&base_image, b"copied interpreter image fixture").unwrap();
        fs::copy(&base_image, &image).unwrap();
        let stdlib = if cfg!(windows) {
            "Lib"
        } else {
            "lib/python3.12"
        };
        for prefix in [&base, &venv] {
            fs::create_dir_all(prefix.join(stdlib).join("site-packages")).unwrap();
        }
        fs::write(base.join(stdlib).join("os.py"), b"standard library").unwrap();
        fs::write(
            base.join(stdlib).join("site-packages/shared.py"),
            b"base copy",
        )
        .unwrap();
        fs::write(
            base.join(stdlib).join("site-packages/base_only.py"),
            b"base package",
        )
        .unwrap();
        fs::write(
            venv.join(stdlib).join("site-packages/shared.py"),
            b"venv copy",
        )
        .unwrap();
        fs::create_dir(root.join("control")).unwrap();
        let config = format!("home = {}\nexecutable = {}\nversion = 3.12.1\ninclude-system-site-packages = {include_system}\n",
            base.join(bindir).display(), base_image.display());
        fs::write(venv.join("pyvenv.cfg"), &config).unwrap();
        Self {
            _temp: temp,
            root,
            base,
            venv,
            image,
            config,
        }
    }
    fn capture(&self) -> io::Result<Resources> {
        python(
            &self.image,
            &self.image,
            &self.root.join("control"),
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
        )
    }
}

#[test]
fn copied_venv_uses_base_stdlib_but_keeps_venv_site_precedence() {
    for include_system in [false, true] {
        let layout = Layout::new(include_system);
        let captured = layout.capture().unwrap();
        assert_eq!(captured.python_version.as_deref(), Some("3.12"));
        assert!(captured
            .files
            .iter()
            .any(|file| file.bytes == b"standard library"));
        assert!(captured.files.iter().any(|file| file.bytes == b"venv copy"));
        assert!(!captured.files.iter().any(|file| file.bytes == b"base copy"));
        assert_eq!(
            captured
                .files
                .iter()
                .any(|file| file.bytes == b"base package"),
            include_system
        );
    }
}

#[test]
fn copied_venv_rejects_mismatched_version_and_control_home() {
    let layout = Layout::new(false);
    fs::write(
        layout.venv.join("pyvenv.cfg"),
        layout.config.replace("3.12.1", "3.11.9"),
    )
    .unwrap();
    assert!(layout.capture().is_err());
    fs::write(
        layout.venv.join("pyvenv.cfg"),
        format!("home = {}\n", layout.root.join("control").display()),
    )
    .unwrap();
    assert!(layout.capture().is_err());
}

#[cfg(unix)]
#[test]
fn retained_config_binding_detects_retargeting_after_capture() {
    let layout = Layout::new(false);
    let captured = layout.capture().unwrap();
    fs::rename(layout.venv.join("pyvenv.cfg"), layout.venv.join("old.cfg")).unwrap();
    fs::write(layout.venv.join("pyvenv.cfg"), layout.config).unwrap();
    assert!(captured.verify().is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_venv_preserves_selector_custody() {
    use std::os::unix::fs::symlink;
    let layout = Layout::new(false);
    fs::remove_file(&layout.image).unwrap();
    symlink(layout.base.join("bin/python3.12"), &layout.image).unwrap();
    let captured = layout.capture().unwrap();
    assert!(captured
        .files
        .iter()
        .any(|file| file.bytes == b"standard library"));
    fs::remove_file(&layout.image).unwrap();
    symlink(layout.base.join("bin/missing"), &layout.image).unwrap();
    assert!(captured.verify().is_err());
}

#[cfg(windows)]
#[test]
fn windows_redirector_layout_does_not_require_image_byte_equality() {
    let layout = Layout::new(false);
    fs::write(&layout.image, b"venv launcher image fixture").unwrap();
    let captured = layout.capture().unwrap();
    assert!(captured
        .files
        .iter()
        .any(|file| file.bytes == b"standard library"));
    assert!(layout.base.join("Scripts/python3.12.exe").is_file());
}
