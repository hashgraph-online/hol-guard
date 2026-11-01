use std::time::SystemTime;

use super::*;

const THREE_HOURS: f64 = 3.0 * 3600.0;
const HTML: &[u8] = b"<html></html>";

/// Stands in for the operating system. Every directory a test creates has a
/// real mtime of about now, so a test picks each directory's age through the
/// sweep's `now` instead of rewriting mtimes.
struct FakeHost {
    live: BTreeSet<i64>,
    in_use: Option<BTreeSet<String>>,
    scans: usize,
    elapsed: Vec<Duration>,
    remove_error: Option<io::ErrorKind>,
    owned: bool,
    on_scan: Option<Box<dyn FnMut()>>,
    on_pid_check: Option<Box<dyn FnMut()>>,
}

impl FakeHost {
    fn new() -> Self {
        Self {
            live: BTreeSet::new(),
            in_use: Some(BTreeSet::new()),
            scans: 0,
            elapsed: Vec::new(),
            remove_error: None,
            owned: true,
            on_scan: None,
            on_pid_check: None,
        }
    }

    fn in_use(names: &[&str]) -> Self {
        Self {
            in_use: Some(names.iter().map(|name| (*name).to_owned()).collect()),
            ..Self::new()
        }
    }
}

impl Host for FakeHost {
    fn pid_alive(&mut self, pid: i64) -> bool {
        if let Some(on_pid_check) = self.on_pid_check.as_mut() {
            on_pid_check();
        }
        self.live.contains(&pid)
    }

    fn open_paths(&mut self, _temp_root: &Path) -> Option<BTreeSet<String>> {
        self.scans += 1;
        if let Some(on_scan) = self.on_scan.as_mut() {
            on_scan();
        }
        self.in_use.clone()
    }

    /// Each reading in turn, then the last one forever.
    fn elapsed(&mut self) -> Duration {
        if self.elapsed.len() > 1 {
            self.elapsed.remove(0)
        } else {
            self.elapsed.first().copied().unwrap_or_default()
        }
    }

    fn remove_dir_all(&mut self, path: &Path) -> io::Result<()> {
        match self.remove_error {
            Some(kind) => Err(io::Error::from(kind)),
            None => fs::remove_dir_all(path),
        }
    }

    fn owned_by_current_user(&mut self, _metadata: &Metadata) -> bool {
        self.owned
    }
}

fn seconds_from_now(offset: f64) -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs_f64()
        + offset
}

/// A sweep where every directory created so far is `age` seconds old.
fn aged(age: f64) -> Settings {
    Settings {
        current_meipass: None,
        now: seconds_from_now(age),
        min_age_seconds: 600.0,
        unmarked_min_age_seconds: 7200.0,
        max_unmarked_reclaims: 250,
        unmarked_time_budget: Some(Duration::from_secs(120)),
        scan_open_paths: true,
        dry_run: false,
    }
}

fn extraction_dir(root: &Path, name: &str) -> PathBuf {
    let directory = root.join(name);
    fs::create_dir_all(&directory).expect("extraction dir");
    directory
}

fn bundle(root: &Path, name: &str) -> PathBuf {
    let directory = extraction_dir(root, name);
    let sentinel = BUNDLE_SENTINEL
        .iter()
        .fold(directory.clone(), |path, part| path.join(part));
    fs::create_dir_all(sentinel.parent().expect("sentinel parent")).expect("sentinel dirs");
    fs::write(sentinel, HTML).expect("sentinel");
    directory
}

fn partial(root: &Path, name: &str) -> PathBuf {
    let directory = extraction_dir(root, name);
    fs::create_dir_all(directory.join(PACKAGE_DIR_NAME)).expect("package dir");
    fs::write(directory.join(PACKAGE_DIR_NAME).join("x.so"), b"x").expect("module");
    directory
}

fn marker(pid: i64, parent_pid: i64) -> String {
    serde_json::json!({
        "schema": OWNER_MARKER_SCHEMA,
        "pid": pid,
        "parent_pid": parent_pid,
        "started_at": "2026-02-01T00:00:00+00:00",
        "guard_version": "0.0.0-test",
    })
    .to_string()
}

fn marked(root: &Path, name: &str, pid: i64, parent_pid: i64) -> PathBuf {
    let directory = extraction_dir(root, name);
    fs::write(directory.join(OWNER_MARKER_NAME), marker(pid, parent_pid)).expect("marker");
    directory
}

#[test]
fn a_dead_owner_dir_is_reclaimed_and_its_bytes_counted() {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = marked(root.path(), "_MEIabc123", 4242, 4241);
    fs::write(directory.join("blob.bin"), [b'x'; 100]).expect("blob");

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut FakeHost::new());

    assert_eq!(result.reclaimed_count, 1);
    assert_eq!(result.killed_launches, 1);
    assert!(result.reclaimed_bytes >= 100);
    assert!(!directory.exists());
    assert!(result.errors.is_empty());
}

#[test]
fn a_dir_whose_owner_or_parent_is_alive_is_kept() {
    let root = tempfile::tempdir().expect("tempdir");
    let owner_alive = marked(root.path(), "_MEIalive00", 1, 2);
    let parent_alive = marked(root.path(), "_MEIparent0", 3, 4);
    let mut host = FakeHost::new();
    host.live = BTreeSet::from([1, 4]);

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert_eq!(result.reclaimed_count, 0);
    assert!(owner_alive.exists() && parent_alive.exists());
}

#[test]
fn young_and_current_extraction_dirs_are_skipped() {
    let root = tempfile::tempdir().expect("tempdir");
    let young = marked(root.path(), "_MEIyoung00", 5, 6);
    let result = reclaim(root.path(), &aged(0.0), &mut FakeHost::new());
    assert_eq!(result.reclaimed_count, 0);
    assert!(young.exists());

    let mut settings = aged(THREE_HOURS);
    settings.current_meipass = Some(fs::canonicalize(&young).expect("current"));
    let result = reclaim(root.path(), &settings, &mut FakeHost::new());
    assert_eq!(result.reclaimed_count, 0);
    assert!(young.exists());
}

#[test]
fn a_marker_rewritten_by_a_live_launch_is_not_swept() {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = marked(root.path(), "_MEIrewrit0", 11, 12);
    let marker_path = directory.join(OWNER_MARKER_NAME);
    let mut host = FakeHost::new();
    // The recorded pids are dead, but a new launch claims the directory
    // between the liveness checks and the delete.
    host.on_pid_check = Some(Box::new(move || {
        fs::write(&marker_path, marker(21, 22)).expect("rewrite");
    }));

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert_eq!(result.reclaimed_count, 0);
    assert!(directory.exists());
}

#[test]
fn unmarked_guard_dirs_are_only_counted_without_a_scan() {
    let root = tempfile::tempdir().expect("tempdir");
    let legacy = bundle(root.path(), "_MEIlegacy0");
    let other = extraction_dir(root.path(), "_MEIother00");
    fs::write(other.join("unrelated.bin"), [b'y'; 10]).expect("unrelated");
    let mut settings = aged(THREE_HOURS);
    settings.scan_open_paths = false;
    let mut host = FakeHost::new();

    let result = reclaim(root.path(), &settings, &mut host);

    assert_eq!(result.unmarked_count, 1);
    assert!(result.unmarked_bytes_estimate >= HTML.len() as u64);
    assert_eq!(result.unmarked_scan, "disabled");
    assert_eq!(result.reclaimed_count, 0);
    assert_eq!(host.scans, 0);
    assert!(legacy.exists() && other.exists());
}

#[test]
fn unmarked_byte_sampling_is_bounded() {
    let root = tempfile::tempdir().expect("tempdir");
    for index in 0..15 {
        let directory = bundle(root.path(), &format!("_MEIlegacy{index:02}"));
        if index >= UNMARKED_BYTES_SAMPLE_LIMIT {
            // Past the sample, so a walk of it would skew the estimate.
            fs::write(directory.join("huge.bin"), [0_u8; 4096]).expect("huge");
        }
    }
    let mut settings = aged(THREE_HOURS);
    settings.scan_open_paths = false;

    let result = reclaim(root.path(), &settings, &mut FakeHost::new());

    assert_eq!(result.unmarked_count, 15);
    assert_eq!(result.unmarked_bytes_estimate, HTML.len() as u64 * 15);
}

#[cfg(unix)]
#[test]
fn symlinked_extraction_dirs_are_ignored() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = marked(&root.path().join("real"), "_MEItarget0", 9, 10);
    let link = root.path().join("_MEIlink000");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut FakeHost::new());

    assert!(fs::symlink_metadata(&link)
        .expect("link")
        .file_type()
        .is_symlink());
    assert_eq!(result.reclaimed_count, 0);
    assert_eq!(result.unmarked_count, 0);
    assert!(target.exists());
}

#[test]
fn only_extraction_names_are_swept() {
    for name in ["_MEIabcd", "_MEI0123456789", "_MEIaB3x"] {
        assert!(is_extraction_name(name), "{name}");
    }
    for name in [
        "_MEIabc",
        "_MEI",
        "_MEIab-cd",
        "MEIabcd",
        "_meiabcd",
        "_MEIabcé",
    ] {
        assert!(!is_extraction_name(name), "{name}");
    }
}

#[test]
fn owner_markers_must_be_small_valid_records() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join(OWNER_MARKER_NAME);
    let read = |contents: &str| {
        fs::write(&path, contents).expect("marker");
        read_owner_marker(&path)
    };

    assert_eq!(
        read(&marker(7, 8)),
        Some(Owner {
            pid: 7,
            parent_pid: 8
        })
    );
    for contents in [
        r#"{"schema":"guard.onefile-extraction-owner.v0","pid":1,"parent_pid":2}"#,
        r#"{"schema":"guard.onefile-extraction-owner.v1","pid":"1","parent_pid":2}"#,
        r#"{"schema":"guard.onefile-extraction-owner.v1","pid":true,"parent_pid":2}"#,
        r#"{"schema":"guard.onefile-extraction-owner.v1","pid":1.5,"parent_pid":2}"#,
        r#"{"schema":"guard.onefile-extraction-owner.v1","pid":1}"#,
        r#"["guard.onefile-extraction-owner.v1",1,2]"#,
        "not json",
    ] {
        assert_eq!(read(contents), None, "{contents}");
    }
    let padded = format!(
        r#"{{"schema":"{OWNER_MARKER_SCHEMA}","pid":1,"parent_pid":2,"pad":"{}"}}"#,
        "x".repeat(OWNER_MARKER_MAX_BYTES as usize)
    );
    assert_eq!(read(&padded), None);

    fs::remove_file(&path).expect("remove marker");
    fs::create_dir(&path).expect("marker dir");
    assert_eq!(read_owner_marker(&path), None);
    assert_eq!(read_owner_marker(&root.path().join("missing")), None);
}

#[cfg(unix)]
#[test]
fn a_symlinked_owner_marker_is_not_read() {
    let root = tempfile::tempdir().expect("tempdir");
    let real = root.path().join("real.json");
    fs::write(&real, marker(1, 2)).expect("real marker");
    let link = root.path().join(OWNER_MARKER_NAME);
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert_eq!(read_owner_marker(&link), None);
}

#[test]
fn temp_root_errors_are_recorded() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("missing");
    let result = reclaim(&missing, &aged(THREE_HOURS), &mut FakeHost::new());
    assert_eq!(result.errors, ["temp_root_unavailable"]);

    let file = root.path().join("file");
    fs::write(&file, b"x").expect("file");
    let result = reclaim(&file, &aged(THREE_HOURS), &mut FakeHost::new());
    assert_eq!(result.errors, ["temp_root_listing_failed"]);
}

#[test]
fn a_failed_delete_is_recorded() {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = marked(root.path(), "_MEIdead000", 4242, 4241);
    let mut host = FakeHost::new();
    host.remove_error = Some(io::ErrorKind::PermissionDenied);

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert_eq!(result.reclaimed_count, 0);
    assert_eq!(result.errors, ["rmtree:PermissionError"]);
    assert!(directory.exists());
}

#[test]
fn the_error_list_is_bounded() {
    let mut result = ReclaimResult::new();
    for index in 0..MAX_RECORDED_ERRORS + 4 {
        result.remember_error(format!("error-{index}"));
    }
    assert_eq!(result.errors.len(), MAX_RECORDED_ERRORS);
    assert_eq!(result.errors[0], "error-0");
}

#[test]
fn unmarked_dirs_are_identified_by_guard_signatures() {
    let root = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        classify_unmarked(&bundle(root.path(), "_MEIbundle1")),
        Some(Unmarked::Bundle)
    );
    assert_eq!(
        classify_unmarked(&partial(root.path(), "_MEIpartial")),
        Some(Unmarked::Partial)
    );

    let mypyc = extraction_dir(root.path(), "_MEImypyc1");
    fs::create_dir(mypyc.join("Python.framework")).expect("framework");
    fs::write(mypyc.join("abc123__mypyc.cpython-312-darwin.so"), b"x").expect("mypyc");
    // Other onefile apps with mypyc-compiled dependencies share this layout.
    assert_eq!(classify_unmarked(&mypyc), None);

    let package_file = extraction_dir(root.path(), "_MEIpkgfile");
    fs::write(package_file.join(PACKAGE_DIR_NAME), b"x").expect("package file");
    assert_eq!(classify_unmarked(&package_file), None);
    assert_eq!(
        classify_unmarked(&extraction_dir(root.path(), "_MEIempty01")),
        None
    );
    assert_eq!(classify_unmarked(&root.path().join("missing")), None);
}

#[test]
fn unused_bundle_and_partial_dirs_are_reclaimed_after_one_scan() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let cut_short = partial(root.path(), "_MEIpartial");
    let mut host = FakeHost::new();

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert!(!full.exists() && !cut_short.exists());
    assert_eq!(result.unmarked_reclaimed_count, 2);
    assert_eq!(result.partial_reclaimed_count, 1);
    assert_eq!(result.reclaimed_count, 2);
    assert!(result.unmarked_reclaimed_bytes > 0);
    assert_eq!(result.unmarked_scan, "ok");
    assert_eq!(result.unmarked_count, 0);
    // One system-wide scan per sweep, not one per directory.
    assert_eq!(host.scans, 1);
}

#[test]
fn dirs_in_use_by_a_live_process_are_kept() {
    let root = tempfile::tempdir().expect("tempdir");
    let live = bundle(root.path(), "_MEIlive001");
    let dead = bundle(root.path(), "_MEIdead001");

    let result = reclaim(
        root.path(),
        &aged(THREE_HOURS),
        &mut FakeHost::in_use(&["_MEIlive001"]),
    );

    assert!(live.exists());
    assert!(!dead.exists());
    assert_eq!(result.unmarked_count, 1);
}

#[test]
fn a_failed_scan_skips_every_unmarked_dir() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let cut_short = partial(root.path(), "_MEIpartial");
    let mut host = FakeHost::new();
    host.in_use = None;

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert!(full.exists() && cut_short.exists());
    assert_eq!(result.unmarked_scan, "unavailable");
    assert!(result
        .errors
        .contains(&"open_path_scan_unavailable".to_owned()));
    assert_eq!(result.unmarked_count, 2);
    assert_eq!(host.scans, 1);
}

#[test]
fn no_scan_runs_without_an_unmarked_candidate() {
    let root = tempfile::tempdir().expect("tempdir");
    let young = bundle(root.path(), "_MEIyoung01");
    let current = bundle(root.path(), "_MEIcurrent");
    let unidentified = extraction_dir(root.path(), "_MEIunknown");
    fs::write(unidentified.join("data.bin"), b"x").expect("data");
    let mut settings = aged(THREE_HOURS);
    // Every directory is younger than the unmarked floor except the
    // current extraction and the one that is not provably Guard's.
    settings.unmarked_min_age_seconds = 4.0 * 3600.0;
    settings.current_meipass = Some(fs::canonicalize(&current).expect("current"));
    let mut host = FakeHost::new();

    let result = reclaim(root.path(), &settings, &mut host);

    assert!(young.exists() && current.exists() && unidentified.exists());
    assert_eq!(result.unmarked_reclaimed_count, 0);
    assert_eq!(result.unmarked_scan, "not_needed");
    assert_eq!(host.scans, 0);
}

#[test]
fn the_unmarked_floor_is_configurable() {
    let root = tempfile::tempdir().expect("tempdir");
    let middle = bundle(root.path(), "_MEImiddle1");
    let result = reclaim(root.path(), &aged(3600.0), &mut FakeHost::new());
    assert_eq!(result.unmarked_reclaimed_count, 0);
    assert!(middle.exists());

    let mut settings = aged(3600.0);
    settings.unmarked_min_age_seconds = 1800.0;
    let result = reclaim(root.path(), &settings, &mut FakeHost::new());
    assert_eq!(result.unmarked_reclaimed_count, 1);
    assert!(!middle.exists());
}

#[test]
fn a_sweep_is_bounded_by_count_and_time() {
    let root = tempfile::tempdir().expect("tempdir");
    for index in 0..5 {
        bundle(root.path(), &format!("_MEIbatch{index}"));
    }
    let mut settings = aged(THREE_HOURS);
    settings.max_unmarked_reclaims = 2;
    let result = reclaim(root.path(), &settings, &mut FakeHost::new());
    assert_eq!(result.unmarked_reclaimed_count, 2);
    assert!(result.unmarked_budget_exhausted);
    assert_eq!(result.unmarked_count, 3);

    let mut settings = aged(THREE_HOURS);
    settings.unmarked_time_budget = Some(Duration::from_secs(10));
    let mut host = FakeHost::new();
    host.elapsed = vec![Duration::ZERO, Duration::from_secs(1000)];
    let result = reclaim(root.path(), &settings, &mut host);
    assert_eq!(result.unmarked_reclaimed_count, 1);
    assert!(result.unmarked_budget_exhausted);
    assert_eq!(result.unmarked_count, 2);
}

#[test]
fn a_dry_run_counts_without_deleting() {
    let root = tempfile::tempdir().expect("tempdir");
    let dead = marked(root.path(), "_MEIdead000", 4242, 4241);
    let full = bundle(root.path(), "_MEIbundle1");
    let mut settings = aged(THREE_HOURS);
    settings.dry_run = true;

    let result = reclaim(root.path(), &settings, &mut FakeHost::new());

    assert_eq!(result.reclaimed_count, 2);
    assert_eq!(result.killed_launches, 1);
    assert_eq!(result.unmarked_reclaimed_count, 1);
    assert!(dead.exists() && full.exists());
}

#[test]
fn dirs_owned_by_other_users_are_skipped() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let mut host = FakeHost::new();
    host.owned = false;

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert!(full.exists());
    assert_eq!(result.unmarked_scan, "not_needed");
    assert_eq!(host.scans, 0);
}

#[test]
fn a_failed_unmarked_delete_is_recorded_and_the_dir_still_counted() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let mut host = FakeHost::new();
    host.remove_error = Some(io::ErrorKind::PermissionDenied);

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert!(full.exists());
    assert_eq!(result.errors, ["rmtree:PermissionError"]);
    assert_eq!(result.unmarked_count, 1);
}

/// Opening a directory to set its times needs write access on Windows.
#[cfg(unix)]
fn set_dir_mtime(directory: &Path, mtime: SystemTime) {
    fs::File::open(directory)
        .and_then(|handle| handle.set_modified(mtime))
        .expect("set mtime");
}

#[cfg(unix)]
#[test]
fn a_dir_touched_after_listing_is_kept() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let touched = full.clone();
    let mut host = FakeHost::new();
    host.on_scan = Some(Box::new(move || {
        set_dir_mtime(&touched, SystemTime::now() + Duration::from_secs(60));
    }));

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    assert!(full.exists());
    assert_eq!(result.unmarked_reclaimed_count, 0);
}

#[cfg(unix)]
#[test]
fn a_dir_that_gains_a_marker_is_kept() {
    let root = tempfile::tempdir().expect("tempdir");
    let full = bundle(root.path(), "_MEIbundle1");
    let listed_mtime = fs::metadata(&full)
        .and_then(|metadata| metadata.modified())
        .expect("mtime");
    let claimed = full.clone();
    let mut host = FakeHost::new();
    host.on_scan = Some(Box::new(move || {
        fs::write(claimed.join(OWNER_MARKER_NAME), "{}").expect("marker");
        set_dir_mtime(&claimed, listed_mtime);
    }));

    let result = reclaim(root.path(), &aged(THREE_HOURS), &mut host);

    // A marker file, even an invalid one, means the owner is not ours to
    // guess.
    assert!(full.exists());
    assert_eq!(result.unmarked_reclaimed_count, 0);
}

#[test]
fn liveness_fails_closed() {
    assert!(pid_alive(i64::from(std::process::id())));
    for pid in [0, -1, i64::MAX] {
        assert!(pid_alive(pid), "{pid}");
    }
}

#[test]
fn requests_are_validated() {
    let root = std::env::temp_dir();
    let request = |extra: serde_json::Value| {
        let mut request = serde_json::json!({
            "schema": SCHEMA,
            "temp_root": root,
            "current_meipass": null,
            "now": 1_700_000_000.0,
            "min_age_seconds": 600.0,
            "unmarked_min_age_seconds": 7200.0,
            "max_unmarked_reclaims": 250,
            "unmarked_time_budget_seconds": 120.0,
            "scan_open_paths": false,
            "dry_run": true,
        });
        let fields = request.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("extra") {
            fields.insert(key.clone(), value.clone());
        }
        serde_json::from_value::<Request>(request).map_err(|_| invalid())
    };

    let (_, parsed) = settings(request(serde_json::json!({})).expect("valid")).expect("settings");
    assert!(parsed.dry_run && !parsed.scan_open_paths);
    // An extraction directory that is already gone is simply not current.
    let (_, parsed) = settings(
        request(serde_json::json!({ "current_meipass": root.join("_MEIgone0000") }))
            .expect("valid"),
    )
    .expect("settings");
    assert_eq!(parsed.current_meipass, None);

    for extra in [
        serde_json::json!({ "schema": "onefile-extraction-reclaim.v0" }),
        serde_json::json!({ "temp_root": "relative/tmp" }),
        serde_json::json!({ "min_age_seconds": -1.0 }),
        serde_json::json!({ "unmarked_time_budget_seconds": -1.0 }),
    ] {
        let parsed = request(extra.clone()).and_then(settings);
        assert!(parsed.is_err(), "{extra}");
    }
    assert!(request(serde_json::json!({ "extra": 1 })).is_err());
    assert!(run_command(&b"{}"[..]).is_err());
}

#[cfg(unix)]
#[test]
fn an_exited_process_is_dead() {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .expect("spawn");
    let pid = i64::from(child.id());
    child.wait().expect("wait");

    assert!(!pid_alive(pid));
}
