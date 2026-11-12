use super::super::{exit_record, requested_stop, restart_budget};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Build a state base a resident scope can live under, owned by this test.
fn supervised_exit_fixture(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

/// Read the restart budget a supervisor left behind, or `None` before the
/// first spawn has charged one.
fn supervised_exit_budget(scope: &Path) -> Option<serde_json::Value> {
    let encoded = fs::read(scope.join("restart-budget.json")).ok()?;
    serde_json::from_slice(&encoded).ok()
}

/// Drive one managed run the way the two processes really do: the supervisor
/// claims the scope and charges the spawn, the serving child leaves a note
/// named after itself if it was asked to stop, and the supervisor closes the
/// run out against the child it reaped.
fn drive_supervised_run(
    state_base: &Path,
    digest: &str,
    scope: &Path,
    serving_child: u32,
    stop_requested: bool,
) {
    let supervised = exit_record::supervised_scope(state_base, digest).unwrap();
    restart_budget::consume(scope).unwrap();
    // Measure the run from the charge the supervisor gives back, so the
    // release lands in the window that charge opened rather than in one
    // before it.
    let serving = Instant::now();
    if stop_requested {
        requested_stop::record(scope, serving_child).unwrap();
    }
    // The serve loops return as soon as the `shutdown` operation lands, so a
    // stop reaches the supervisor as a clean run far shorter than the second
    // an unexplained success has to clear, and as nothing else.
    exit_record::record_supervised_exit(
        supervised,
        None,
        true,
        Some(0),
        serving.elapsed(),
        serving_child,
    );
}

/// Two builds installed against one guard home stop each other's resident to
/// take the home-wide owner lock. Every one of those stops is requested, and
/// none of them is a crash, so no number of them may open the restart
/// circuit: once it opens, no resident starts, no policy is published, and
/// every prompt is refused with `native_policy_not_ready`.
#[test]
fn requested_stops_driven_through_the_supervisor_never_open_the_circuit() {
    let root = supervised_exit_fixture("supervised-requested-stop");
    let digest = "a".repeat(64);
    let scope = crate::resident_state::state_scope(&root, &digest).unwrap();

    // Twice the free restarts a window allows, so a charged stop could not
    // survive the loop. Each run is a fresh child, as it is in a real loop of
    // two runtimes stopping each other.
    for serving_child in 1..=6 {
        drive_supervised_run(&root, &digest, &scope, serving_child, true);
    }
    let budget = supervised_exit_budget(&scope).unwrap();
    let spawn_after_the_stops = restart_budget::consume(&scope);

    fs::remove_dir_all(&root).unwrap();

    assert_eq!(budget["attempts"], 0, "requested stops kept a charge");
    assert_eq!(
        budget["circuit_until_ms"], 0,
        "requested stops paced a spawn"
    );
    assert_eq!(budget["backoff_steps"], 0);
    assert!(
        spawn_after_the_stops.is_ok(),
        "a resident could not start after repeated requested stops: {spawn_after_the_stops:?}"
    );
}

/// The same loop without the note is a crash loop, and it must still stop
/// one. Without this the test above would pass against a budget that never
/// charges anything.
#[test]
fn immediate_exits_nobody_asked_for_still_open_the_circuit() {
    let root = supervised_exit_fixture("supervised-premature-exit");
    let digest = "b".repeat(64);
    let scope = crate::resident_state::state_scope(&root, &digest).unwrap();

    let mut opened_after = None;
    for attempt in 1..=6 {
        if restart_budget::consume(&scope).is_err() {
            opened_after = Some(attempt);
            break;
        }
        let supervised = exit_record::supervised_scope(&root, &digest).unwrap();
        let serving = Instant::now();
        exit_record::record_supervised_exit(
            supervised,
            None,
            true,
            Some(0),
            serving.elapsed(),
            attempt,
        );
    }

    fs::remove_dir_all(&root).unwrap();

    assert_eq!(
        opened_after,
        Some(4),
        "an unrequested immediate exit stopped keeping its restart charge"
    );
}

/// The loop that broke prompts in the field ran between two runtimes, not
/// one: a desktop bundle and a package install ship different binaries at the
/// same version, so each retires the other's resident to take the home-wide
/// owner lock. Their scopes are keyed by runtime digest, so the note one
/// child leaves must stay in its own scope -- a supervisor reaping a child of
/// the other digest, even one that happens to carry the same process id,
/// reads nothing there -- and neither budget may open under the alternation.
#[test]
fn two_runtimes_retiring_each_other_keep_their_notes_and_their_budgets_apart() {
    let root = supervised_exit_fixture("supervised-two-digests");
    let desktop = "c".repeat(64);
    let package = "d".repeat(64);
    let desktop_scope = crate::resident_state::state_scope(&root, &desktop).unwrap();
    let package_scope = crate::resident_state::state_scope(&root, &package).unwrap();

    // Process ids are reused across the two runtimes on purpose: the scope,
    // not the id alone, has to keep the notes apart.
    for serving_child in 1..=6 {
        drive_supervised_run(&root, &desktop, &desktop_scope, serving_child, true);
        drive_supervised_run(&root, &package, &package_scope, serving_child, true);
    }

    let desktop_budget = supervised_exit_budget(&desktop_scope).unwrap();
    let package_budget = supervised_exit_budget(&package_scope).unwrap();
    let desktop_spawn = restart_budget::consume(&desktop_scope);
    let package_spawn = restart_budget::consume(&package_scope);
    // A note left under one digest is not there for the other's supervisor.
    requested_stop::record(&desktop_scope, 4_242).unwrap();
    let package_took_a_desktop_note = requested_stop::take(&package_scope, 4_242);
    let desktop_took_its_own_note = requested_stop::take(&desktop_scope, 4_242);

    fs::remove_dir_all(&root).unwrap();

    assert_eq!(desktop_budget["attempts"], 0, "desktop stops kept a charge");
    assert_eq!(package_budget["attempts"], 0, "package stops kept a charge");
    assert_eq!(desktop_budget["circuit_until_ms"], 0);
    assert_eq!(package_budget["circuit_until_ms"], 0);
    assert!(
        desktop_spawn.is_ok(),
        "the desktop runtime could not start after the alternation: {desktop_spawn:?}"
    );
    assert!(
        package_spawn.is_ok(),
        "the package runtime could not start after the alternation: {package_spawn:?}"
    );
    assert!(
        !package_took_a_desktop_note,
        "a supervisor read a note left under another runtime's digest"
    );
    assert!(desktop_took_its_own_note);
}
