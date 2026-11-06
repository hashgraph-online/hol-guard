use std::time::SystemTime;

use super::*;

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
