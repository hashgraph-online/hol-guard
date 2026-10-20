//! Cache regressions observe fresh source resolution and actual frozen output.

use super::*;
use guard_contained_process::SourceLaunchGate;
use std::sync::atomic::AtomicBool;

struct Gate;
impl SourceLaunchGate for Gate {
    fn prepare_effects(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn commit(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn released(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn local_fixture() -> (tempfile::TempDir, NativeBashCaptureV1) {
    let (root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "source ./settings.sh; printf '%s' \"$from_source\"",
    )
    .unwrap();
    std::fs::write(
        Path::new(&request.cwd).join("settings.sh"),
        "from_source=reviewed\n",
    )
    .unwrap();
    (root, request)
}

fn captured(request: &NativeBashCaptureV1) -> CapturedBash {
    capture_for_launch(request, &tests::admitted("allow")).unwrap()
}

#[test]
fn launch_analysis_cache_revalidates_same_size_same_mtime_source_bytes() {
    let (_root, request) = local_fixture();
    let settings = Path::new(&request.cwd).join("settings.sh");
    let original_times = std::fs::metadata(&settings).unwrap();
    let original = captured(&request);
    let repeated = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(1));
    assert_eq!(
        original.subject.identity_sha256().unwrap(),
        repeated.subject.identity_sha256().unwrap()
    );
    let result = super::super::super::bash_launch::execute(
        repeated,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
        &mut Gate,
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"reviewed");

    std::fs::write(&settings, "from_source=mutatedx\n").unwrap();
    let times = std::fs::FileTimes::new()
        .set_accessed(original_times.accessed().unwrap())
        .set_modified(original_times.modified().unwrap());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&settings)
        .unwrap()
        .set_times(times)
        .unwrap();
    let current = std::fs::metadata(&settings).unwrap();
    assert_eq!(current.len(), original_times.len());
    assert_eq!(
        current.modified().unwrap(),
        original_times.modified().unwrap()
    );

    let changed = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(0));
    assert_ne!(
        original.subject.identity_sha256().unwrap(),
        changed.subject.identity_sha256().unwrap()
    );
    let result = super::super::super::bash_launch::execute(
        changed,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
        &mut Gate,
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"mutatedx");
}

#[test]
fn launch_analysis_cache_rechecks_source_path_precedence() {
    let (_root, mut request) = local_fixture();
    let cwd = Path::new(&request.cwd);
    let first = cwd.join("first");
    let second = cwd.join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    request.execution_environment.path =
        format!("{}:{}:/usr/bin:/bin", first.display(), second.display());
    std::fs::write(
        cwd.join("maintenance.sh"),
        "source settings.sh; printf '%s' \"$from_source\"",
    )
    .unwrap();
    std::fs::write(second.join("settings.sh"), "from_source=reviewed\n").unwrap();
    let original = captured(&request);
    let _warm = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(1));
    std::fs::write(first.join("settings.sh"), "from_source=mutatedx\n").unwrap();
    let changed = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(0));
    assert_ne!(
        original.subject.identity_sha256().unwrap(),
        changed.subject.identity_sha256().unwrap()
    );
    assert!(changed
        .subject
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "%s", "mutatedx"]));
}

#[test]
fn launch_analysis_cache_rechecks_policy_and_report_symlinks() {
    let (_root, request) = local_fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        ": > \"$HOME/report.tsv\"; printf '%s' reviewed >> \"$HOME/report.tsv\"",
    )
    .unwrap();
    let _first = captured(&request);
    let _warm = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(1));
    assert!(
        matches!(capture_for_launch(&request, &tests::admitted("block")), Err(reason) if reason == "bash_current_policy_denied")
    );
    let protected = Path::new(&request.home_dir).join("protected");
    let report = Path::new(&request.home_dir).join("report.tsv");
    std::fs::write(&protected, "protected sentinel").unwrap();
    std::os::unix::fs::symlink(&protected, &report).unwrap();
    assert!(capture_for_launch(&request, &tests::admitted("allow")).is_err());
    assert_eq!(
        std::fs::read_to_string(protected).unwrap(),
        "protected sentinel"
    );
}

#[test]
fn launch_analysis_cache_keeps_entry_and_frozen_source_bounds() {
    let (_root, mut request) = local_fixture();
    let mut first = request.clone();
    for budget in 900..(900 + analysis_cache::MAX_ENTRIES as u64 + 2) {
        request.budget_ms = budget;
        if budget == 900 {
            first = request.clone();
        }
        let _ = captured(&request);
    }
    let (entries, frozen_bytes) = analysis_cache::bounds().unwrap();
    assert!(entries <= analysis_cache::MAX_ENTRIES);
    assert!(frozen_bytes <= analysis_cache::MAX_FROZEN_BYTES);
    assert_eq!(analysis_cache::lookup_hits(&first), None);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(0));
}

#[test]
fn launch_analysis_cache_evicts_before_retaining_more_than_eight_mib_of_source() {
    let (_root, mut request) = local_fixture();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    let padding = "x".repeat(900_000);
    std::fs::write(&entry, format!("# {padding}\nprintf '%s' reviewed\n")).unwrap();
    let mut first = request.clone();
    for budget in 900..910 {
        request.budget_ms = budget;
        if budget == 900 {
            first = request.clone();
        }
        let _ = captured(&request);
    }
    let (entries, frozen_bytes) = analysis_cache::bounds().unwrap();
    assert!(entries <= analysis_cache::MAX_ENTRIES);
    assert!(frozen_bytes <= analysis_cache::MAX_FROZEN_BYTES);
    assert_eq!(analysis_cache::lookup_hits(&first), None);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(0));
}

#[test]
fn launch_analysis_cache_keeps_metadata_edits_quiet_but_binds_exact_argv() {
    let (_root, mut request) = local_fixture();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    std::fs::write(
        &entry,
        "case \"$1\" in dry) printf reviewed;; delete) printf mutatedx;; *) exit 2;; esac\n",
    )
    .unwrap();
    let original = captured(&request);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&entry)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
        .unwrap();
    std::fs::write(
        Path::new(&request.cwd).join("unrelated.txt"),
        "ordinary data",
    )
    .unwrap();
    let warm = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), Some(1));
    assert_eq!(
        original.subject.identity_sha256().unwrap(),
        warm.subject.identity_sha256().unwrap()
    );
    request.command = request.command.strip_suffix(" dry").unwrap().to_owned() + " delete";
    let changed = captured(&request);
    assert_ne!(
        original.subject.identity_sha256().unwrap(),
        changed.subject.identity_sha256().unwrap()
    );
    assert!(changed
        .subject
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "mutatedx"]));
}

#[test]
fn launch_analysis_cache_excludes_helper_and_native_graphs() {
    let (_root, request) = tests::fixture();
    let _first = captured(&request);
    let _again = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), None);
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf '%s' safe | /usr/bin/head -n 1\n",
    )
    .unwrap();
    let _first = captured(&request);
    let _again = captured(&request);
    assert_eq!(analysis_cache::lookup_hits(&request), None);
}
