//! The resident's CLI observer: which launches it queues, its recent-key
//! skip, its bounded queue, and that an offer never waits on the worker.
//! Ported from the daemon's `test_guard_native_cli_observer.py`.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use guard_contracts::GuardHookEnvelopeV2;
use serde_json::{json, Map, Value};

use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;

const WAIT: Duration = Duration::from_secs(10);

fn observation(command: &str, cwd: &str, path: Option<&str>) -> Observation {
    Observation {
        command: command.to_owned(),
        cwd: cwd.to_owned(),
        home_dir: "/home/dev".to_owned(),
        guard_home: "/home/dev/.hol-guard".to_owned(),
        path: path.map(str::to_owned),
        launch_env: None,
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// An observer whose worker reports each observation it takes, then waits
/// for a release before it takes the next one.
fn held_observer(capacity: usize) -> (Observer, Receiver<Observation>, Sender<()>) {
    let (taken_tx, taken_rx) = channel();
    let (release_tx, release_rx) = channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let observer = Observer::start(capacity, move |observation| {
        let _ = taken_tx.send(observation);
        let _ = release_rx.lock().unwrap().recv();
    });
    (observer, taken_rx, release_tx)
}

/// An observer whose worker reports each observation and never holds.
fn free_observer(capacity: usize) -> (Observer, Receiver<Observation>) {
    let (taken_tx, taken_rx) = channel();
    let taken_tx = Mutex::new(taken_tx);
    let observer = Observer::start(capacity, move |observation| {
        let _ = taken_tx.lock().unwrap().send(observation);
    });
    (observer, taken_rx)
}

#[test]
fn a_repeat_within_the_ttl_is_skipped_and_queued_again_after_it() {
    let (observer, taken) = free_observer(4);
    let start = Instant::now();
    let first = observation("npx wrangler whoami", "/work", None);
    assert!(observer.offer_at(first.clone(), start));
    assert_eq!(taken.recv_timeout(WAIT).unwrap(), first);
    assert!(!observer.offer_at(first.clone(), start + RECENT_TTL - Duration::from_secs(1)));
    assert!(observer.offer_at(first.clone(), start + RECENT_TTL));
    assert_eq!(taken.recv_timeout(WAIT).unwrap(), first);
}

#[test]
fn the_launch_directory_is_part_of_the_key() {
    let (observer, _taken) = free_observer(4);
    let now = Instant::now();
    assert!(observer.offer_at(observation("npx wrangler whoami", "/work", None), now));
    assert!(observer.offer_at(observation("npx wrangler whoami", "/other", None), now));
    assert!(!observer.offer_at(observation("npx wrangler whoami", "/work", None), now));
}

#[test]
fn a_different_path_is_observed_again() {
    let (observer, taken) = free_observer(4);
    let now = Instant::now();
    let local = observation(
        "npx wrangler whoami",
        "/work",
        Some("/home/dev/.local/bin:/usr/bin"),
    );
    let system = observation("npx wrangler whoami", "/work", Some("/usr/bin"));
    assert!(observer.offer_at(local.clone(), now));
    assert!(!observer.offer_at(local.clone(), now));
    assert!(observer.offer_at(system.clone(), now));
    let paths: Vec<Option<String>> = (0..2)
        .map(|_| taken.recv_timeout(WAIT).unwrap().path)
        .collect();
    assert_eq!(paths, vec![local.path, system.path]);
}

#[test]
fn the_recent_keys_are_bounded_oldest_first() {
    let (observer, _taken) = free_observer(MAX_RECENT + 8);
    let now = Instant::now();
    for index in 0..=MAX_RECENT {
        assert!(observer.offer_at(observation(&format!("tool-{index}"), "/work", None), now));
    }
    // The first key aged out of the recent set; the newest is still skipped.
    assert!(observer.offer_at(observation("tool-0", "/work", None), now));
    let newest = format!("tool-{MAX_RECENT}");
    assert!(!observer.offer_at(observation(&newest, "/work", None), now));
}

#[test]
fn a_dropped_observation_is_not_remembered() {
    let (observer, taken, release) = held_observer(1);
    let now = Instant::now();
    let held = observation("held", "/work", None);
    let queued = observation("queued", "/work", None);
    let dropped = observation("dropped", "/work", None);
    assert!(observer.offer_at(held.clone(), now));
    assert_eq!(taken.recv_timeout(WAIT).unwrap(), held);
    assert!(observer.offer_at(queued.clone(), now));
    // The queue is full: the entry is dropped and its key stays eligible.
    assert!(!observer.offer_at(dropped.clone(), now));
    release.send(()).unwrap();
    assert_eq!(taken.recv_timeout(WAIT).unwrap(), queued);
    assert!(observer.offer_at(dropped.clone(), now));
    assert!(!observer.offer_at(queued, now));
    release.send(()).unwrap();
    assert_eq!(taken.recv_timeout(WAIT).unwrap(), dropped);
    release.send(()).unwrap();
}

#[test]
fn an_offer_never_waits_for_a_stuck_worker() {
    let (observer, taken, release) = held_observer(MAX_PENDING);
    assert!(observer.offer(observation("first", "/work", None)));
    taken.recv_timeout(WAIT).unwrap();
    let started = Instant::now();
    let queued = (0..MAX_PENDING + 16)
        .filter(|index| observer.offer(observation(&format!("next-{index}"), "/work", None)))
        .count();
    // The worker is still holding the first entry; every offer returned on
    // its own, and the ones past the bound were dropped.
    assert_eq!(queued, MAX_PENDING);
    assert!(started.elapsed() < WAIT);
    assert!(taken.try_recv().is_err());
    drop(release);
}

#[test]
fn a_panicking_record_keeps_the_worker() {
    let (taken_tx, taken) = channel();
    let taken_tx = Mutex::new(taken_tx);
    let observer = Observer::start(4, move |observation: Observation| {
        if observation.command == "panics" {
            panic!("record failed");
        }
        let _ = taken_tx.lock().unwrap().send(observation);
    });
    assert!(observer.offer(observation("panics", "/work", None)));
    assert!(observer.offer(observation("after", "/work", None)));
    assert_eq!(taken.recv_timeout(WAIT).unwrap().command, "after");
}

#[test]
fn camel_case_harness_payload_is_a_candidate() {
    let home = temp_home("observer-camel");
    let workspace = home.to_string_lossy().into_owned();
    let payload = object(json!({
        "toolName": "run_terminal_command",
        "toolInput": {"command": "npx wrangler whoami"},
        "cwd": workspace,
    }));
    let found = candidate(&payload, Some(workspace.as_str()), "/home/dev", "/g", None).unwrap();
    assert_eq!(found.command, "npx wrangler whoami");
    let resolved = resolve(found).unwrap();
    assert_eq!(resolved.cwd, workspace);
}

#[test]
fn a_payload_without_a_command_or_launch_directory_is_not_observed() {
    let payload = object(json!({"tool_name": "Read", "tool_input": {"file_path": "/x"}}));
    assert!(candidate(&payload, Some("/work"), "/home/dev", "/g", None).is_none());
    let relative = object(json!({"tool_input": {"command": "ls"}, "cwd": "relative/dir"}));
    let found = candidate(&relative, Some("/work"), "/home/dev", "/g", None).unwrap();
    assert!(resolve(found).is_none());
    let no_workspace = object(json!({"tool_input": {"command": "ls"}}));
    let found = candidate(&no_workspace, None, "/home/dev", "/g", None).unwrap();
    assert!(resolve(found).is_none());
}

#[test]
fn only_a_usable_path_is_kept() {
    let payload = object(json!({"tool_input": {"command": "ls"}}));
    let path_of = |path| {
        candidate(&payload, Some("/work"), "/home/dev", "/g", path)
            .unwrap()
            .path
    };
    assert_eq!(path_of(Some("/usr/bin")), Some("/usr/bin".to_owned()));
    assert_eq!(path_of(Some("")), None);
    assert_eq!(path_of(Some("/usr/bin\0/x")), None);
    assert_eq!(path_of(None), None);
}

#[test]
fn a_direct_answer_reads_the_stamped_path() {
    let payload = object(json!({
        "tool_input": {"command": "ls"},
        "guard_execution_environment": {"path": "/opt/bin"},
    }));
    let found = direct_candidate(&payload, "/work", "/home/dev", "/g", None).unwrap();
    assert_eq!(found.path.as_deref(), Some("/opt/bin"));
    assert_eq!(found.launch_env, None);
    // The daemon's published home and environment go with the observation,
    // as the edge's do, so the resident never identifies the launch against
    // its own.
    let daemon = LaunchEnvironment {
        user_home: "/home/dev".to_owned(),
        env: [("PATH".to_owned(), "/usr/bin".to_owned())].into(),
    };
    let found =
        direct_candidate(&payload, "/work", "/home/dev", "/g", Some(daemon.clone())).unwrap();
    assert_eq!(found.launch_env, Some(daemon));
    let unstamped = object(json!({
        "tool_input": {"command": "ls"},
        "guard_execution_environment": null,
    }));
    let found = direct_candidate(&unstamped, "/work", "/home/dev", "/g", None).unwrap();
    assert_eq!(found.path, None);
}

fn envelope(event: &str, observe_local_cli: bool) -> GuardHookEnvelopeV2 {
    envelope_with(event, observe_local_cli, None)
}

fn envelope_with(
    event: &str,
    observe_local_cli: bool,
    rules: Option<Value>,
) -> GuardHookEnvelopeV2 {
    let mut envelope = json!({
        "schema": guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA,
        "harness": "codex",
        "event": event,
        "raw_payload": {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        "policy_generation": 1,
        "policy_snapshot": {},
        "source": {
            "cwd": "/work",
            "home_dir": "/home/dev",
            "guard_home": "/home/dev/.hol-guard",
            "execution_environment": {
                "path": "/opt/bin",
                "environment_names": [],
                "environment_digest": "sha256:0",
            },
        },
        "observe_local_cli": observe_local_cli,
    });
    if let Some(rules) = rules {
        envelope["local_cli_rules"] = rules;
    }
    serde_json::from_value(envelope).unwrap()
}

#[test]
fn an_edge_envelope_is_observed_only_when_asked_and_before_a_tool() {
    let found = edge_candidate(&envelope("PreToolUse", true)).unwrap();
    assert_eq!(found.command, "ls");
    assert_eq!(found.launch_dir, "/work");
    assert_eq!(found.path.as_deref(), Some("/opt/bin"));
    assert!(edge_candidate(&envelope("beforeShellExecution", true)).is_some());
    assert!(edge_candidate(&envelope("PreToolUse", false)).is_none());
    assert!(edge_candidate(&envelope("PostToolUse", true)).is_none());
}

#[test]
fn an_edge_launch_resolves_against_the_daemon_environment() {
    let rules = json!({
        "store_path": "/home/dev/.hol-guard/guard.db",
        "user_home": "/home/daemon",
        "env": {"PATH": "/usr/local/bin:/usr/bin", "LANG": "C"},
    });
    let found = edge_candidate(&envelope_with("PreToolUse", true, Some(rules))).unwrap();
    let observation = Observation {
        command: found.command,
        cwd: "/work".to_owned(),
        home_dir: found.home_dir,
        guard_home: found.guard_home,
        path: found.path,
        launch_env: found.launch_env,
    };
    let sent = request(&observation);
    assert_eq!(sent.user_home, "/home/daemon");
    assert_eq!(sent.env.get("LANG").map(String::as_str), Some("C"));
    // The agent's stamped PATH still wins over the daemon's.
    assert_eq!(sent.env.get("PATH").map(String::as_str), Some("/opt/bin"));
    let unstamped = request(&Observation {
        path: None,
        ..observation
    });
    assert_eq!(
        unstamped.env.get("PATH").map(String::as_str),
        Some("/usr/local/bin:/usr/bin")
    );
}

#[test]
fn a_service_without_home_variables_uses_the_hook_home() {
    let none = |_: &str| None;
    assert_eq!(account_home(none, "/home/dev"), "/home/dev");
    let empty_home = |name: &str| (name == "HOME").then(String::new);
    assert_eq!(account_home(empty_home, "/home/dev"), "/home/dev");
    let profile = |name: &str| (name == "USERPROFILE").then(|| "C:\\Users\\dev".to_owned());
    assert_eq!(account_home(profile, "/home/dev"), "C:\\Users\\dev");
    let home = |name: &str| Some(format!("/{name}"));
    assert_eq!(account_home(home, "/home/dev"), "/HOME");
}

#[test]
fn the_observation_flag_is_left_out_of_an_envelope_that_does_not_ask() {
    let encoded = serde_json::to_value(envelope("PreToolUse", false)).unwrap();
    assert!(encoded.get("observe_local_cli").is_none());
    let encoded = serde_json::to_value(envelope("PreToolUse", true)).unwrap();
    assert_eq!(encoded["observe_local_cli"], json!(true));
}

#[test]
fn a_home_without_a_store_records_nothing() {
    let home = temp_home("observer-no-store");
    let guard_home = home.to_string_lossy().into_owned();
    record(Observation {
        guard_home,
        ..observation("ls", "/work", None)
    });
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0);
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&EDGE_LOCAL_CLI_OBSERVATION_FEATURE));
}
