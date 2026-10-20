use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;

use super::*;

#[derive(Default)]
struct Gate {
    allow: bool,
    fail_release: bool,
    commits: usize,
    releases: usize,
}

impl SourceLaunchGate for Gate {
    fn commit(&mut self) -> io::Result<()> {
        self.commits += 1;
        if self.allow {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    fn released(&mut self) -> io::Result<()> {
        self.releases += 1;
        if self.fail_release {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

fn command(root: &Path) -> PinnedCommand {
    let root = std::fs::canonicalize(root).unwrap();
    PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new("IFS= read -r -d '' frozen || exit 125; eval \"$frozen\""),
            OsStr::new("frozen-fixture"),
            OsStr::new("result"),
        ],
        &root,
        &[(OsString::from("LC_ALL"), OsString::from("C"))],
    )
    .unwrap()
}

#[test]
fn acknowledged_frame_is_ready_before_claim_and_denial_cannot_run() {
    for allow in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = format!("#{}\nprintf executed > result", "x".repeat(300_000));
        let bootstrap = format!(
            "IFS= read -r -d '' code || exit 125; [ \"${{#code}}\" -eq {} ] || exit 125; \
             printf R >&6 || exit 125; IFS= read -r -d '' auth || exit 125; \
             [ -z \"$auth\" ] || exit 125; printf S >&6 || exit 125; exec 6>&-; eval \"$code\"",
            source.len()
        );
        let command = PinnedCommand::new(
            Path::new("/bin/bash"),
            &[
                OsStr::new("--noprofile"),
                OsStr::new("--norc"),
                OsStr::new("-c"),
                OsStr::new(&bootstrap),
            ],
            &std::fs::canonicalize(root.path()).unwrap(),
            &[("LC_ALL".into(), "C".into())],
        )
        .unwrap();
        let mut gate = Gate {
            allow,
            ..Gate::default()
        };
        let result = command.capture_acknowledged_source(
            source.as_bytes(),
            1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
            &mut gate,
        );
        assert_eq!(gate.commits, 1);
        assert_eq!(gate.releases, usize::from(allow));
        assert_eq!(root.path().join("result").exists(), allow);
        if allow {
            assert_eq!(result.unwrap().exit_code, Some(0));
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

#[test]
fn missing_or_invalid_ack_never_claims_and_missing_start_is_not_retried() {
    for (ready, started, expected_claims) in [("", "S", 0), ("X", "S", 0), ("R", "X", 1)] {
        let root = tempfile::tempdir().unwrap();
        let bootstrap = format!(
            "IFS= read -r -d '' code || exit 125; printf '{ready}' >&6; \
             IFS= read -r -d '' auth || exit 125; printf '{started}' >&6; \
             IFS= read -r -d '' never || exit 125"
        );
        let command = PinnedCommand::new(
            Path::new("/bin/bash"),
            &[
                OsStr::new("--noprofile"),
                OsStr::new("--norc"),
                OsStr::new("-c"),
                OsStr::new(&bootstrap),
            ],
            &std::fs::canonicalize(root.path()).unwrap(),
            &[],
        )
        .unwrap();
        let mut gate = Gate {
            allow: true,
            ..Gate::default()
        };
        let result = command.capture_acknowledged_source(
            b"printf forbidden > result",
            1024,
            Instant::now() + Duration::from_millis(300),
            &AtomicBool::new(false),
            Isolation::default(),
            &mut gate,
        );
        assert!(result.is_err());
        assert_eq!(gate.commits, expected_claims);
        assert_eq!(gate.releases, 0);
        assert!(!root.path().join("result").exists());
    }
}

#[test]
fn rejected_commit_releases_no_marker_and_has_no_effect() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate::default();
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!((gate.commits, gate.releases), (1, 0));
    assert!(!root.path().join("result").exists());
}

#[test]
fn child_exit_before_readiness_closes_ack_channel_without_claim() {
    let root = tempfile::tempdir().unwrap();
    let command = PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new("IFS= read -r -d '' code || exit 125; exit 125"),
        ],
        &std::fs::canonicalize(root.path()).unwrap(),
        &[],
    )
    .unwrap();
    let mut gate = Gate {
        allow: true,
        ..Gate::default()
    };
    let result = command.capture_acknowledged_source(
        b"printf forbidden",
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    // The child may exit before or after the owner reaches the acknowledgement
    // read; both orders leave the frame unacknowledged, so the owner either
    // reports the closed channel or returns the child's own exit without a
    // claim. Neither order may claim the launch.
    match result {
        Ok(output) => assert_eq!(output.exit_code, Some(125)),
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
    }
    assert_eq!((gate.commits, gate.releases), (0, 0));
}

#[test]
fn successful_commit_runs_once_and_acknowledges_one_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        ..Gate::default()
    };
    let source = format!("#{}\nprintf executed > \"$1\"", "x".repeat(300_000));
    let result = command(root.path())
        .capture_frozen_source(
            source.as_bytes(),
            1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
            &mut gate,
        )
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!((gate.commits, gate.releases), (1, 1));
    assert_eq!(
        std::fs::read(root.path().join("result")).unwrap(),
        b"executed"
    );
}

#[test]
fn a_lost_acknowledgement_retains_the_released_state() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        fail_release: true,
        ..Gate::default()
    };
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    // The caller must regard this as uncertain execution, not an unused grant.
    assert_eq!((gate.commits, gate.releases), (1, 1));
}

#[test]
fn an_expired_window_cannot_claim_a_grant() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        ..Gate::default()
    };
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now(),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    assert_eq!((gate.commits, gate.releases), (0, 0));
    assert!(!root.path().join("result").exists());
}

#[test]
fn cancellation_during_commit_cannot_release_the_frame() {
    struct Cancels<'a>(&'a AtomicBool, usize);
    impl SourceLaunchGate for Cancels<'_> {
        fn commit(&mut self) -> io::Result<()> {
            self.0.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }
        fn released(&mut self) -> io::Result<()> {
            self.1 += 1;
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let cancelled = AtomicBool::new(false);
    let mut gate = Cancels(&cancelled, 0);
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &cancelled,
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    assert_eq!(gate.1, 0);
    assert!(!root.path().join("result").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn system_root_proof_does_not_trust_private_readonly_images() {
    let root = tempfile::tempdir().unwrap();
    assert!(command(root.path()).has_readonly_system_image().unwrap());
    let private = PinnedCommand::new(
        &std::env::current_exe().unwrap(),
        &[],
        &root.path().canonicalize().unwrap(),
        &[],
    )
    .unwrap();
    assert!(!private.has_readonly_system_image().unwrap());
}
