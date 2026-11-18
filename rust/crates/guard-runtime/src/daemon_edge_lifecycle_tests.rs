use super::*;

#[test]
fn records_a_ready_event_load_events_reads() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), "ready", None, Some("abc123"), Some(4781));
    let entries: Vec<_> = fs::read_dir(home.path().join(DIRECTORY))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    let value: Value = serde_json::from_slice(&fs::read(&entries[0]).unwrap()).unwrap();
    assert_eq!(value["event"], "ready");
    assert_eq!(value["version"], 1);
    assert_eq!(value["port"], 4781);
    assert_eq!(value["session_id"], "abc123");
}

#[test]
fn load_events_returns_newest_valid_oldest_first() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), "starting", None, None, None);
    record(home.path(), "ready", None, None, Some(4781));
    let directory = home.path().join(DIRECTORY);
    fs::write(directory.join("99999999999999999999-bad.json"), "{}").unwrap();
    let (events, status) = load_events(home.path(), 20, true);
    assert_eq!(status, "invalid_entries_omitted");
    let names: Vec<_> = events.iter().map(|event| event["event"].clone()).collect();
    assert_eq!(names, vec![Value::from("starting"), Value::from("ready")]);
    let (latest, _) = load_events(home.path(), 1, false);
    assert!(latest.is_empty());
    assert_eq!(
        load_events(&home.path().join("missing"), 5, true).1,
        "journal_unavailable"
    );
}

#[test]
fn refuses_unsafe_labels() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), "Ready", None, None, None);
    record(home.path(), "ready", Some("bad reason"), None, None);
    assert!(!home.path().join(DIRECTORY).exists());
}

fn files(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home.join(DIRECTORY))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn recovery_requests_keep_their_own_ring() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), "ready", None, None, Some(4781));
    for _ in 0..MAX_RECOVERY_ENTRIES + 5 {
        record(
            home.path(),
            "recovery_requested",
            Some("transport-failure"),
            None,
            None,
        );
    }
    let names = files(home.path());
    let recovery = names
        .iter()
        .filter(|name| name.ends_with(RECOVERY_SUFFIX))
        .count();
    assert_eq!(recovery, MAX_RECOVERY_ENTRIES);
    // The daemon's own record outlives every request for recovery.
    assert_eq!(names.len() - recovery, 1);
}

#[test]
fn legacy_records_count_toward_the_lifecycle_ring() {
    let home = tempfile::tempdir().unwrap();
    record(home.path(), "ready", None, None, None);
    let directory = home.path().join(DIRECTORY);
    let legacy = files(home.path()).remove(0);
    let body = fs::read(directory.join(&legacy)).unwrap();
    for index in 0..MAX_LIFECYCLE_ENTRIES {
        fs::write(
            directory.join(format!("{index:020}-0000000001-legacy.json")),
            &body,
        )
        .unwrap();
    }
    record(home.path(), "ready", None, None, None);
    let names = files(home.path());
    assert_eq!(names.len(), MAX_LIFECYCLE_ENTRIES);
    assert!(!names.contains(&format!("{:020}-0000000001-legacy.json", 0)));
}

#[test]
fn a_record_about_another_process_names_who_wrote_it() {
    let home = tempfile::tempdir().unwrap();
    let details = Details {
        reason: Some("requested_retire"),
        by_pid: Some(41),
        by_parent_pid: Some(40),
        ..Details::default()
    };
    record_details(home.path(), 42, "retirement_requested", &details);
    let (events, status) = load_events(home.path(), 5, true);
    assert_eq!(status, "ok");
    assert_eq!(events[0]["pid"], 42);
    assert_eq!(events[0]["by_pid"], 41);
    assert_eq!(events[0]["by_parent_pid"], 40);
    let log = fs::read_to_string(home.path().join("logs").join("daemon.log")).unwrap();
    assert!(log.contains("retirement_requested pid=42 reason=requested_retire by_pid=41"));
    let refused = Details {
        location: Some("/private/path.rs:1"),
        ..Details::default()
    };
    record_details(home.path(), 43, "exiting", &refused);
    assert_eq!(load_events(home.path(), 5, true).0.len(), 1);
}

#[cfg(unix)]
#[test]
fn a_starting_daemon_names_each_predecessor_that_vanished() {
    let home = tempfile::tempdir().unwrap();
    let mut gone = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let gone_pid = gone.id();
    gone.wait().unwrap();
    let mut explained = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let explained_pid = explained.id();
    explained.wait().unwrap();
    let mut running = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let running_pid = running.id();
    for pid in [gone_pid, explained_pid, running_pid] {
        record_details(home.path(), pid, "published", &Details::default());
        record_details(home.path(), pid, "ready", &Details::default());
    }
    let reason = Details {
        reason: Some("signal_term"),
        ..Details::default()
    };
    record_details(home.path(), explained_pid, "exiting", &reason);

    record_unclean_exits(home.path());
    record_unclean_exits(home.path());
    let _ = running.kill();
    let _ = running.wait();

    let (events, _) = load_events(home.path(), 50, false);
    let unclean: Vec<&Value> = events
        .iter()
        .filter(|event| event["event"] == "unclean_exit_detected")
        .collect();
    assert_eq!(unclean.len(), 1, "{events:?}");
    assert_eq!(unclean[0]["pid"], gone_pid);
    assert_eq!(unclean[0]["reason"], "no_exit_record");
    assert_eq!(unclean[0]["by_pid"], std::process::id());
}

#[cfg(unix)]
#[test]
fn an_exit_journaled_before_a_later_start_step_still_ends_the_run() {
    let home = tempfile::tempdir().unwrap();
    let mut stopped = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let stopped_pid = stopped.id();
    stopped.wait().unwrap();
    let mut reused = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let reused_pid = reused.id();
    reused.wait().unwrap();
    let reason = Details {
        reason: Some("signal_term"),
        ..Details::default()
    };
    // SIGTERM lands between the ready line and the `ready` record.
    record_details(home.path(), stopped_pid, "published", &Details::default());
    record_details(home.path(), stopped_pid, "exiting", &reason);
    record_details(home.path(), stopped_pid, "ready", &Details::default());
    // An earlier run's exit does not end a later run of the same pid.
    record_details(home.path(), reused_pid, "published", &Details::default());
    record_details(home.path(), reused_pid, "exiting", &reason);
    record_details(home.path(), reused_pid, "published", &Details::default());
    record_details(home.path(), reused_pid, "ready", &Details::default());

    record_unclean_exits(home.path());

    let (events, _) = load_events(home.path(), 50, false);
    let unclean: Vec<&Value> = events
        .iter()
        .filter(|event| event["event"] == "unclean_exit_detected")
        .collect();
    assert_eq!(unclean.len(), 1, "{events:?}");
    assert_eq!(unclean[0]["pid"], reused_pid);
}
