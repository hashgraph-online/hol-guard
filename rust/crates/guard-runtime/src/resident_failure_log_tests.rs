use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_scope(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-resident-failure-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&scope).expect("create failure-log test scope");
    scope
}

#[test]
fn a_run_without_evidence_creates_no_record() {
    let scope = temp_scope("quiet");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.append(b"");
    drop(log);

    assert!(!ResidentFailureLog::path(&scope).exists());

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn supervisor_notes_land_in_the_scope_record() {
    let scope = temp_scope("note");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.note("native_resident_managed_exit_failed exit_code=101 ran_for_ms=42");
    drop(log);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        "native_resident_managed_exit_failed exit_code=101 ran_for_ms=42\n"
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_later_run_replaces_the_previous_record() {
    let scope = temp_scope("replace");
    let mut first = ResidentFailureLog::for_scope(&scope);
    first.note("native_resident_first_failure");
    drop(first);
    let mut second = ResidentFailureLog::for_scope(&scope);
    second.note("native_resident_second_failure");
    drop(second);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(recorded, "native_resident_second_failure\n");

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_flooding_resident_cannot_grow_the_record_past_its_bound() {
    let scope = temp_scope("bounded");
    let mut log = ResidentFailureLog::for_scope(&scope);
    for _ in 0..64 {
        log.append(&[b'x'; 4096]);
    }
    log.append(b"dropped");
    drop(log);

    let recorded = fs::read(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(recorded.len(), MAX_RESIDENT_FAILURE_BYTES);
    assert!(recorded.iter().all(|byte| *byte == b'x'));

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[cfg(unix)]
#[test]
fn the_record_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let scope = temp_scope("private");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.note("native_resident_managed_exit_failed exit_code=1 ran_for_ms=1");
    drop(log);

    let metadata = fs::symlink_metadata(ResidentFailureLog::path(&scope)).expect("stat record");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[cfg(not(windows))]
#[test]
fn resident_stderr_is_collected_up_to_the_record_bound() {
    let flood = vec![b'x'; MAX_RESIDENT_FAILURE_BYTES + 8192];
    let collected = collect_resident_stderr(&flood[..]);
    assert_eq!(collected.len(), MAX_RESIDENT_FAILURE_BYTES);
    assert!(collected.iter().all(|byte| *byte == b'x'));
}

#[test]
fn a_published_run_keeps_its_stderr_and_its_exit_note() {
    let scope = temp_scope("published");
    write_run(
        &scope,
        b"thread 'main' panicked at resident.rs:1:1:\nnative_resident_startup_failed\n",
        Some("native_resident_managed_exit_failed exit_code=101 ran_for_ms=12"),
    );

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        concat!(
            "thread 'main' panicked at resident.rs:1:1:\n",
            "native_resident_startup_failed\n",
            "native_resident_managed_exit_failed exit_code=101 ran_for_ms=12\n",
        )
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_flooding_resident_cannot_push_the_exit_note_out_of_the_record() {
    let scope = temp_scope("reserved");
    let note = "native_resident_managed_exit_failed exit_code=101 ran_for_ms=12";
    write_run(&scope, &vec![b'x'; MAX_RESIDENT_FAILURE_BYTES], Some(note));

    let recorded = fs::read(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(recorded.len(), MAX_RESIDENT_FAILURE_BYTES);
    assert!(recorded.ends_with(format!("{note}\n").as_bytes()));

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn an_exit_note_is_recorded_when_no_stderr_arrived() {
    // A grandchild can hold the stderr pipe open past the supervisor's wait,
    // and the reason the run ended still has to reach the user.
    let scope = temp_scope("note-only");
    write_run(
        &scope,
        b"",
        Some("native_resident_managed_exit_premature exit_code=0 ran_for_ms=4"),
    );

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        "native_resident_managed_exit_premature exit_code=0 ran_for_ms=4\n"
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_healthy_run_leaves_the_previous_record_untouched() {
    // Only a run with something to report publishes, so the record of the
    // failure that denied a call survives the next successful cycle.
    let scope = temp_scope("healthy");
    write_run(
        &scope,
        b"",
        Some("native_resident_managed_exit_failed exit_code=1 ran_for_ms=3"),
    );
    write_run(&scope, b"", None);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        "native_resident_managed_exit_failed exit_code=1 ran_for_ms=3\n"
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn an_older_run_does_not_overwrite_a_newer_runs_record() {
    let scope = temp_scope("superseded");
    write_run(&scope, b"newer failure\n", None);
    let path = ResidentFailureLog::path(&scope);
    let recorded_at = fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .expect("record modification time");

    let older_start = recorded_at - std::time::Duration::from_secs(5);
    write_run_unless_superseded(&scope, b"older failure\n", None, older_start);
    assert_eq!(
        fs::read_to_string(&path).expect("read record"),
        "newer failure\n"
    );

    let later_start = recorded_at + std::time::Duration::from_secs(5);
    write_run_unless_superseded(&scope, b"later failure\n", None, later_start);
    assert_eq!(
        fs::read_to_string(&path).expect("read record"),
        "later failure\n"
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn an_older_run_that_writes_late_does_not_hide_a_newer_runs_failure() {
    // The older supervisor is still waiting out its stderr tail when the newer
    // run starts, so it writes after that start. Its record must still read as
    // the older one when the newer run fails.
    let scope = temp_scope("late-writer");
    let now = std::time::SystemTime::now();
    let older_start = now - std::time::Duration::from_secs(20);
    let newer_start = now - std::time::Duration::from_secs(10);
    write_run_unless_superseded(&scope, b"older failure\n", None, older_start);
    write_run_unless_superseded(&scope, b"newer failure\n", None, newer_start);
    let path = ResidentFailureLog::path(&scope);
    assert_eq!(
        fs::read_to_string(&path).expect("read record"),
        "newer failure\n"
    );
    // And the newer record now holds off the older run's late write.
    write_run_unless_superseded(&scope, b"older again\n", None, older_start);
    assert_eq!(
        fs::read_to_string(&path).expect("read record"),
        "newer failure\n"
    );
    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn an_empty_record_does_not_hold_off_an_earlier_runs_failure() {
    // Taking the record's lock opens it, which creates an empty file stamped
    // now. That file is no later run's record.
    let scope = temp_scope("empty-record");
    drop(open_record(&scope).expect("open record"));
    let started = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
    write_run_unless_superseded(&scope, b"failure\n", None, started);
    assert_eq!(
        fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record"),
        "failure\n"
    );
    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_record_held_by_another_writer_is_skipped_rather_than_waited_on() {
    let scope = temp_scope("held-record");
    let holder = open_record(&scope).expect("open record");
    fs2::FileExt::lock_exclusive(&holder).expect("hold record");
    let started = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
    write_run_unless_superseded(&scope, b"failure\n", None, started);
    drop(holder);
    assert_eq!(
        fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record"),
        ""
    );
    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}
