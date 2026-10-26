use super::*;
use crate::{CapturedOutput, Isolation, PinnedCommand, SourceLaunchGate};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

struct Gate<'a> {
    report: &'a Path,
    allow: bool,
    append: bool,
    prepared: usize,
    committed: usize,
    released: usize,
    swap: Option<&'a Path>,
}

impl SourceLaunchGate for Gate<'_> {
    fn prepare_effects(&mut self) -> io::Result<()> {
        self.prepared += 1;
        if self.report.exists() {
            assert_eq!(std::fs::read(self.report)?, b"existing");
        }
        if let Some(protected) = self.swap {
            std::os::unix::fs::symlink(protected, self.report)?;
        }
        if self.allow {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    fn commit(&mut self) -> io::Result<()> {
        self.committed += 1;
        assert_eq!(self.prepared, 1);
        let expected: &[u8] = if self.append { b"existing" } else { b"" };
        assert_eq!(std::fs::read(self.report)?, expected);
        Ok(())
    }
    fn released(&mut self) -> io::Result<()> {
        self.released += 1;
        Ok(())
    }
}

fn execute(
    root: &Path,
    output: DeferredOutput,
    mask: u32,
    gate: &mut dyn SourceLaunchGate,
) -> io::Result<CapturedOutput> {
    execute_script(root, output, mask, b"printf reviewed >&7", gate)
}

fn execute_script(
    root: &Path,
    output: DeferredOutput,
    mask: u32,
    source: &[u8],
    gate: &mut dyn SourceLaunchGate,
) -> io::Result<CapturedOutput> {
    let bootstrap = format!(
        "[ -f /dev/fd/7 ] || exit 125; IFS= read -r -d '' code || exit 125; \
         [ \"${{#code}}\" -eq {} ] || exit 125; printf R >&6 || exit 125; \
         IFS= read -r -d '' auth || exit 125; [ -z \"$auth\" ] || exit 125; \
         printf S >&6 || exit 125; exec 6>&-; eval \"$code\"",
        source.len()
    );
    PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new(&bootstrap),
        ],
        root,
        &[("LC_ALL".into(), "C".into())],
    )?
    .capture_acknowledged_source(
        source,
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation {
            deferred_outputs: vec![output],
            creation_mask: Some(mask),
            ..Isolation::default()
        },
        gate,
    )
}

fn gate(report: &Path, allow: bool, append: bool) -> Gate<'_> {
    Gate {
        report,
        allow,
        append,
        prepared: 0,
        committed: 0,
        released: 0,
        swap: None,
    }
}

#[test]
fn deferred_report_waits_for_authorization_and_preserves_child_mask() {
    for mask in [0o022, 0o077, 0o002] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let report = root.join("report");
        let before = root.join("parent-before");
        std::fs::write(&before, b"control").unwrap();
        let parent_mode = std::fs::metadata(&before).unwrap().permissions().mode() & 0o777;
        let directory = Arc::new(Directory::open(&root).unwrap());
        let prepared = DeferredOutput::new(directory.clone(), OsStr::new("report"), true).unwrap();
        assert!(!report.exists());
        let mut denied = gate(&report, false, false);
        assert_eq!(
            execute(&root, prepared.clone(), mask, &mut denied)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            (denied.prepared, denied.committed, denied.released),
            (1, 0, 0)
        );
        assert!(!report.exists());
        let mut allowed = gate(&report, true, false);
        let result = execute(&root, prepared, mask, &mut allowed).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            (allowed.prepared, allowed.committed, allowed.released),
            (1, 1, 1)
        );
        assert_eq!(std::fs::read(&report).unwrap(), b"reviewed");
        assert_eq!(
            std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o666 & !mask
        );
        let after = root.join("parent-after");
        std::fs::write(&after, b"control").unwrap();
        assert_eq!(
            std::fs::metadata(after).unwrap().permissions().mode() & 0o777,
            parent_mode
        );
    }
}

#[test]
fn report_write_failure_stops_the_script_before_the_next_effect() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let report = root.join("report");
    let prepared = DeferredOutput::new(
        Arc::new(Directory::open(&root).unwrap()),
        OsStr::new("report"),
        true,
    )
    .unwrap();
    let mut authority = gate(&report, true, false);
    let result = execute_script(
        &root,
        prepared,
        0o022,
        // Limit only this shell's file writes; unrelated address-space or
        // process limits must not prevent interpreter startup in this check.
        b"set -e; ulimit -f 0; printf reviewed >&7; printf after",
        &mut authority,
    )
    .unwrap();
    assert_ne!(result.exit_code, Some(0));
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::metadata(report).unwrap().len(), 0);
}

#[test]
fn old_gate_without_output_authority_cannot_create_a_report() {
    struct OldGate;
    impl SourceLaunchGate for OldGate {
        fn commit(&mut self) -> io::Result<()> {
            panic!("output authorization must fail first")
        }
        fn released(&mut self) -> io::Result<()> {
            panic!("no dispatch may occur")
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let prepared = DeferredOutput::new(
        Arc::new(Directory::open(&root).unwrap()),
        OsStr::new("report"),
        true,
    )
    .unwrap();
    assert_eq!(
        execute(&root, prepared, 0o022, &mut OldGate)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!root.join("report").exists());
}

#[test]
fn deferred_existing_report_preserves_mode_and_append_semantics() {
    for append in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let report = root.join("report");
        std::fs::write(&report, b"existing").unwrap();
        std::fs::set_permissions(&report, std::fs::Permissions::from_mode(0o664)).unwrap();
        let prepared = DeferredOutput::new(
            Arc::new(Directory::open(&root).unwrap()),
            OsStr::new("report"),
            !append,
        )
        .unwrap();
        let mut authority = gate(&report, true, append);
        assert_eq!(
            execute(&root, prepared, 0o077, &mut authority)
                .unwrap()
                .exit_code,
            Some(0)
        );
        assert_eq!(
            std::fs::read(&report).unwrap(),
            if append {
                b"existingreviewed".as_slice()
            } else {
                b"reviewed".as_slice()
            }
        );
        assert_eq!(
            std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o664
        );
    }
}

#[test]
fn retarget_after_authorization_preserves_protected_sentinel() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let report = root.join("report");
    let protected = root.join("protected");
    std::fs::write(&protected, b"protected sentinel").unwrap();
    let prepared = DeferredOutput::new(
        Arc::new(Directory::open(&root).unwrap()),
        OsStr::new("report"),
        true,
    )
    .unwrap();
    let mut authority = gate(&report, true, false);
    authority.swap = Some(&protected);
    assert!(execute(&root, prepared, 0o022, &mut authority).is_err());
    assert_eq!(
        (authority.prepared, authority.committed, authority.released),
        (1, 0, 0)
    );
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
}
