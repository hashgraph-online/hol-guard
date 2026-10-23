//! Real macOS kernel delivery of the nontrivial fixture. No approval-store or
//! managed-harness qualification is implied by these lower-level tests.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

use guard_contained_process::{
    bound_fs::Directory, bound_output::Output, Isolation, PinnedCommand, SourceLaunchGate,
};

use super::*;

struct HostResolver {
    helper: Code,
    source: Code,
    cwd: PathBuf,
}

impl Resolver for HostResolver {
    fn resolve_source(&self, path: &str) -> std::result::Result<Code, &'static str> {
        if path == self.source.original_path {
            Ok(self.source.clone())
        } else {
            Err("test_unknown_source")
        }
    }
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str> {
        if argv[0] == "fixture-registry" {
            return Ok(Executable::Bash(self.helper.clone()));
        }
        let path = match argv[0].as_str() {
            "sort" => "/usr/bin/sort",
            "head" => "/usr/bin/head",
            _ => return Err("test_unknown_native_operation"),
        };
        let image = PinnedCommand::new(Path::new(path), &[], &self.cwd, &[])
            .map_err(|_| "test_native_image_unavailable")?;
        if !image
            .has_readonly_system_image()
            .map_err(|_| "test_native_image_unavailable")?
        {
            return Err("test_native_image_not_system_root");
        }
        Ok(Executable::Native {
            resolved_path: path.into(),
            content_sha256: image.executable_digest.clone(),
            openssl_config: None,
            delivery: NativeDelivery::ReadonlySystem,
        })
    }
}

struct Gate<'a> {
    output: &'a Output,
    commits: usize,
    releases: usize,
}

impl SourceLaunchGate for Gate<'_> {
    fn commit(&mut self) -> std::io::Result<()> {
        self.output.verify()?;
        self.commits += 1;
        Ok(())
    }
    fn released(&mut self) -> std::io::Result<()> {
        self.releases += 1;
        Ok(())
    }
}

fn capture(path: &Path) -> Code {
    let read = guard_secure_fs::read_stable(path, MAX_SOURCE_BYTES, false).unwrap();
    Code {
        original_path: path.to_str().unwrap().into(),
        resolved_path: path.to_str().unwrap().into(),
        source: String::from_utf8(read.bytes).unwrap().into(),
    }
}

#[test]
fn native_frozen_graph_with_bound_report_survives_code_mutation() {
    run_native_fixture(None);
}

#[test]
fn native_frame_gate_rejects_retargeted_report_before_source_release() {
    run_native_fixture(Some(false));
    run_native_fixture(Some(true));
}

fn run_native_fixture(output_hardlink: Option<bool>) {
    let temporary = tempfile_root();
    let root = temporary.0.clone();
    let script = root.join("maintenance.sh");
    let helper = root.join("fixture-registry");
    let settings = root.join("settings.sh");
    let report = root.join("maintenance-report.tsv");
    let protected = root.join("protected");
    std::fs::write(
        &script,
        format!(
            ". \"$HOME/settings.sh\"\n{}",
            SCRIPT.replace("$HOME", "$fixture_home")
        ),
    )
    .unwrap();
    std::fs::write(&settings, "fixture_home=$HOME\n").unwrap();
    std::fs::write(&helper, HELPER).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&protected, b"protected sentinel").unwrap();
    let resolver = HostResolver {
        helper: capture(&helper),
        source: capture(&settings),
        cwd: root.clone(),
    };
    let argv = [script.to_str().unwrap().to_owned(), "dry".into()];
    let environment = BTreeMap::from([("HOME".into(), root.to_str().unwrap().into())]);
    let graph = build_with_outputs(
        capture(&script),
        &argv,
        &environment,
        &resolver,
        Instant::now() + Duration::from_secs(5),
        &BTreeMap::from([(report.to_str().unwrap().into(), 6)]),
    )
    .unwrap();
    let source = graph.source_for_launch().unwrap();
    let directory = Arc::new(Directory::open(&root).unwrap());
    // The fixture controller authorizes this disposable output setup. A real
    // runtime must hold the authenticated reservation before opening outputs.
    let output = Output::open(directory, OsStr::new("maintenance-report.tsv"), true).unwrap();
    let bootstrap = super::super::super::delivery::bootstrap(source.len(), 0).unwrap();
    let command = PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new(&bootstrap),
            OsStr::new(&argv[0]),
            OsStr::new("dry"),
        ],
        &root,
        &[
            ("HOME".into(), root.clone().into_os_string()),
            ("LC_ALL".into(), "C".into()),
        ],
    )
    .unwrap();
    assert!(command.has_readonly_system_image().unwrap());
    // Same-inode edits happen after the exact code snapshot/render, before
    // the native child starts. They must never reach the interpreter.
    std::fs::write(&script, "printf attacked > \"$HOME/protected\"\n").unwrap();
    std::fs::write(&helper, "printf attacked > \"$HOME/protected\"\n").unwrap();
    std::fs::write(&settings, "printf attacked > \"$HOME/protected\"\n").unwrap();
    if let Some(hardlink) = output_hardlink {
        std::fs::remove_file(&report).unwrap();
        if hardlink {
            std::fs::hard_link(&protected, &report).unwrap();
        } else {
            std::os::unix::fs::symlink(&protected, &report).unwrap();
        }
    }
    let literal = |path: &Path| serde_json::to_string(path.to_str().unwrap()).unwrap();
    let profile = format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec (literal "/bin/bash") (literal "/usr/bin/sort") (literal "/usr/bin/head"))
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/dev") (literal "/bin/bash") (literal "/usr/bin/sort") (literal "/usr/bin/head"))
(allow file-read-metadata)
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") (literal "/bin/bash") (literal "/usr/bin/sort") (literal "/usr/bin/head"))
(allow file-write* (literal {}) (literal "/dev/null"))
(deny file-read* file-write* (literal {}))
(allow sysctl-read)
(allow mach-lookup)"#,
        literal(&report),
        literal(&protected)
    );
    let mut gate = Gate {
        output: &output,
        commits: 0,
        releases: 0,
    };
    let result = command.capture_frozen_source(
        source.as_bytes(),
        1024 * 1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation {
            seatbelt: Some(profile),
            inherited_files: vec![output.try_clone_file().unwrap()],
            ..Isolation::default()
        },
        &mut gate,
    );
    if output_hardlink.is_some() {
        assert!(result.is_err());
        assert_eq!((gate.commits, gate.releases), (0, 0));
        assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
        return;
    }
    let result = result.unwrap();
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!((gate.commits, gate.releases), (1, 1));
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
    assert_eq!(std::fs::read_to_string(&report).unwrap(), "alpha/current\nalpha/obsolete\nalpha\tlocal metadata\nbeta/current\nbeta/obsolete\nbeta\tlocal metadata\n");
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempfile_root() -> Temporary {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "guard-native-bash-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    Temporary(path.canonicalize().unwrap())
}
