use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_scope(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-requested-stop-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&scope).unwrap();
    scope
}

fn notes(scope: &Path) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(scope)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| is_note(name))
        .collect();
    found.sort();
    found
}

#[test]
fn a_note_is_read_once_by_the_supervisor_of_the_child_that_left_it() {
    let scope = temp_scope("read-once");

    assert!(!take(&scope, 4_242));
    record(&scope, 4_242).unwrap();
    assert!(take(&scope, 4_242));
    // Reading the note consumes it, so the next run starts without one.
    assert!(!take(&scope, 4_242));
    assert!(notes(&scope).is_empty());

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_note_another_child_left_cannot_forgive_this_run() {
    // The note names the child that wrote it, so a supervisor reaping a
    // different child reads nothing and that run keeps its restart charge.
    let scope = temp_scope("foreign-note");
    record(&scope, 4_242).unwrap();

    assert!(!take(&scope, 4_243));

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn overlapping_runs_each_keep_their_own_note() {
    // A Unix supervisor can still be draining its child's stderr while the
    // next supervisor starts, stops and reaps its own child. Neither may take
    // or discard the other's note: the first one through used to remove the
    // single scope-wide note, leaving the other run charged for a stop it was
    // asked to make.
    let scope = temp_scope("overlapping");
    record(&scope, 4_242).unwrap();
    record(&scope, 4_243).unwrap();

    assert!(take(&scope, 4_243), "the later run lost its own note");
    assert!(take(&scope, 4_242), "the earlier run lost its note");
    assert!(notes(&scope).is_empty());

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_run_cannot_be_forgiven_twice_by_one_note() {
    let scope = temp_scope("single-use");
    record(&scope, 4_242).unwrap();
    assert!(take(&scope, 4_242));

    // Nothing left to read, so a crash on the next run is still a crash.
    assert!(!take(&scope, 4_242));

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn notes_no_supervisor_came_back_for_are_swept_down_to_the_newest() {
    // Supervisors killed before they reap leave their children's notes
    // behind. They cannot forgive anything -- no later run is named by them
    // unless the operating system reuses the id -- but they must not collect
    // either.
    let scope = temp_scope("sweep");
    let abandoned = MAX_STOP_NOTES as u32 + 4;
    for process_id in 1..=abandoned {
        record(&scope, process_id).unwrap();
    }
    assert_eq!(notes(&scope).len(), abandoned as usize);

    // Any reaping supervisor sweeps; this one's own child left no note.
    assert!(!take(&scope, 999_999));

    assert_eq!(notes(&scope).len(), MAX_STOP_NOTES);

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_note_that_cannot_be_read_is_no_note() {
    let scope = temp_scope("unreadable");
    std::fs::write(note_path(&scope, 4_242), b"{\"schema\":\"something-else\"}").unwrap();

    assert!(!take(&scope, 4_242));

    std::fs::remove_dir_all(scope).unwrap();
}
