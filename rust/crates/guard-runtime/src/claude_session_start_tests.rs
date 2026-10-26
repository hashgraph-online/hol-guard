use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::*;
use crate::claude_hook_bridge_fixture::GuardHome;
use crate::claude_session_start_live::tests::{live_home, serve, Reply, CURRENT_HEALTH};

/// Written by the Python refresh; `claude_session_start_contract_tests`
/// holds the contract to its bytes.
const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/claude_session_start/settings-current.v1.json");
const CONTEXT: &str = "{\"hookSpecificOutput\":{\"hookEventName\":\"SessionStart\",\
\"additionalContext\":\"HOL Guard protection is active for this workspace.\"}}\n";
const FIXTURE_URL: &str = "http://127.0.0.1:43123";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn fixture_state_path() -> String {
    fixture()["bridge_config"]["state_path"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The installer config for a Claude home whose daemon state is `state_path`.
fn config_text(claude_home: &Path, state_path: &Path, build: &str) -> String {
    let fixture = fixture();
    let mut bridge_config = fixture["bridge_config"].clone();
    bridge_config["state_path"] = json!(state_path.to_str().unwrap());
    json!({
        "fallback_command": ["/bin/sh", "-c", "exit 7"],
        "home": claude_home.to_str().unwrap(),
        "home_dir": claude_home.to_str().unwrap(),
        "runtime_build": build,
        "daemon_hook_command": fixture["daemon_hook_command"],
        "bridge_config": bridge_config,
    })
    .to_string()
}

/// The fixture settings as the Python refresh writes them for this daemon.
fn write_settings(claude_home: &Path, state_path: &Path, url: &str) -> PathBuf {
    let text = serde_json::to_string_pretty(&fixture()["settings"])
        .unwrap()
        .replace(&fixture_state_path(), state_path.to_str().unwrap())
        .replace(FIXTURE_URL, url);
    let settings = claude_home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, text).unwrap();
    settings
}

fn environment(home: &Path) -> SessionEnvironment {
    SessionEnvironment {
        home: Some(home.to_path_buf()),
        cursor: false,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// The lane's output where no daemon start may run.
fn no_op_output(
    config_text: &str,
    environment: &SessionEnvironment,
    deadline: Instant,
) -> Result<String, String> {
    session_output(config_text, environment, deadline, |command| {
        panic!("the lane started the daemon with {command:?}")
    })
}

/// A Claude home beside `guard`'s home.
fn claude_home(guard: &GuardHome) -> PathBuf {
    let home = guard.scratch("claude home");
    fs::create_dir_all(&home).unwrap();
    home
}

#[test]
fn config_parses_and_its_fallback_survives_later_failures() {
    let text = config_text(Path::new("/h"), Path::new("/h/s.json"), "1+a");
    let config = parse_config(&text).unwrap();
    assert_eq!(config.fallback_command, ["/bin/sh", "-c", "exit 7"]);
    assert_eq!(config.home, "/h");
    assert_eq!(config.runtime_build, "1+a");
    assert_eq!(config.daemon_hook.command.len(), 3);

    let mut partial: Value = serde_json::from_str(&text).unwrap();
    partial.as_object_mut().unwrap().remove("bridge_config");
    assert_eq!(parse_config(&partial.to_string()), None);
    assert_eq!(
        fallback_command(&partial.to_string()).unwrap(),
        ["/bin/sh", "-c", "exit 7"]
    );
    for text in [
        "",
        "[]",
        r#"{"fallback_command":[]}"#,
        r#"{"fallback_command":["/bin/sh",1]}"#,
        r#"{"fallback_command":"/bin/sh"}"#,
    ] {
        assert_eq!(fallback_command(text), None, "{text}");
        assert_eq!(parse_config(text), None, "{text}");
    }
    for key in ["home", "home_dir", "runtime_build", "daemon_hook_command"] {
        let mut blank: Value = serde_json::from_str(&text).unwrap();
        blank[key] = json!("");
        assert_eq!(parse_config(&blank.to_string()), None, "{key}");
    }
}

#[test]
fn context_is_the_python_hook_output_byte_for_byte() {
    let contract = crate::claude_session_start_contract::contract().unwrap();
    assert_eq!(
        context_output(
            &contract.session_start_event,
            &contract.session_start_context
        ),
        CONTEXT
    );
}

#[test]
fn runtime_build_names_this_binary() {
    assert_eq!(
        runtime_build(),
        format!("{}+{}", crate::PACKAGE_VERSION, crate::BUILD_SHA)
    );
}

#[test]
fn fallback_process_runs_the_installed_python_command_verbatim() {
    let argv = ["/usr/bin/python3", "-c", "x", "guard", "hook"].map(str::to_owned);
    let process = fallback_process(&argv);
    assert_eq!(process.get_program(), "/usr/bin/python3");
    let args: Vec<_> = process.get_args().collect();
    assert_eq!(args, ["-c", "x", "guard", "hook"]);
    assert_eq!(process.get_envs().count(), 0);
    assert_eq!(process.get_current_dir(), None);
}

#[test]
fn run_without_a_fallback_fails_without_handing_off() {
    assert_eq!(run("{}"), 2);
    assert_eq!(run("not json"), 2);
}

#[test]
fn current_settings_and_live_daemon_print_only_the_context() {
    let (guard, listener, state) = live_home("ss-noop", |_| {});
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let home = claude_home(&guard);
    let settings = write_settings(&home, &guard.state_path, &url);
    let before = (
        fs::read(&settings).unwrap(),
        fs::metadata(&settings).unwrap().modified().unwrap(),
    );
    let daemon = serve(
        listener,
        state,
        vec![Reply::Challenge, Reply::Health(200, CURRENT_HEALTH, None)],
    );

    let output = no_op_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
    );

    assert_eq!(output.as_deref(), Ok(CONTEXT));
    assert_eq!(daemon.join().unwrap().len(), 2);
    let after = (
        fs::read(&settings).unwrap(),
        fs::metadata(&settings).unwrap().modified().unwrap(),
    );
    assert_eq!(before, after);
    let entries: Vec<_> = fs::read_dir(settings.parent().unwrap()).unwrap().collect();
    assert_eq!(entries.len(), 1, "the lane wrote beside the settings");
}

#[test]
fn gates_before_the_daemon_hand_off() {
    let guard = GuardHome::new("ss-gates");
    let home = claude_home(&guard);
    write_settings(&home, &guard.state_path, FIXTURE_URL);
    let config = config_text(&home, &guard.state_path, &runtime_build());
    let other = guard.scratch("other home");
    fs::create_dir_all(&other).unwrap();
    let cursor = SessionEnvironment {
        home: Some(home.clone()),
        cursor: true,
    };
    let cases: [(&str, String, SessionEnvironment); 6] = [
        ("bad config", "{}".to_owned(), environment(&home)),
        (
            "other build",
            config_text(&home, &guard.state_path, "0.0.0+other"),
            environment(&home),
        ),
        ("cursor", config.clone(), cursor),
        ("other home", config.clone(), environment(&other)),
        (
            "no home",
            config.clone(),
            SessionEnvironment {
                home: None,
                cursor: false,
            },
        ),
        // The daemon state does not exist, so the daemon is not live.
        ("no daemon", config, environment(&home)),
    ];
    for (label, config, environment) in cases {
        assert!(
            no_op_output(&config, &environment, deadline()).is_err(),
            "{label} did not hand off"
        );
    }
}

#[test]
fn missing_or_escaping_settings_hand_off() {
    let guard = GuardHome::new("ss-settings");
    let home = claude_home(&guard);
    let config = config_text(&home, &guard.state_path, &runtime_build());
    assert!(no_op_output(&config, &environment(&home), deadline()).is_err());

    let outside = write_settings(&guard.scratch("outside"), &guard.state_path, FIXTURE_URL);
    fs::create_dir_all(home.join(".claude")).unwrap();
    std::os::unix::fs::symlink(&outside, home.join(".claude").join("settings.json")).unwrap();
    assert!(read_settings(&home, ".claude/settings.json").is_err());
}

#[test]
fn drifted_settings_hand_off_even_with_a_live_daemon() {
    let (guard, listener, state) = live_home("ss-drift", |_| {});
    let home = claude_home(&guard);
    // Entries written for another daemon URL are stale.
    write_settings(&home, &guard.state_path, FIXTURE_URL);
    let daemon = serve(
        listener,
        state,
        vec![Reply::Challenge, Reply::Health(200, CURRENT_HEALTH, None)],
    );

    let output = no_op_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
    );

    assert!(output.is_err());
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn unverified_daemon_hands_off() {
    let (guard, listener, state) = live_home("ss-refused", |_| {});
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let home = claude_home(&guard);
    write_settings(&home, &guard.state_path, &url);
    let daemon = serve(listener, state, vec![Reply::Refuse(403)]);

    let output = no_op_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
    );

    assert!(output.is_err());
    assert_eq!(daemon.join().unwrap().len(), 1);
}

/// A Guard home whose signed state names a daemon of this package version
/// whose pid no longer runs, and the URL that daemon listened on.
fn stopped_home(label: &str, edit: impl FnOnce(&mut Map<String, Value>)) -> (GuardHome, String) {
    let (guard, listener, _state) = live_home(label, |state| {
        state.insert("pid".to_owned(), json!(i32::MAX));
        edit(state);
    });
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    (guard, url)
}

fn recovery_command() -> Vec<String> {
    serde_json::from_value(fixture()["bridge_config"]["recovery_command"].clone()).unwrap()
}

#[test]
fn stopped_daemon_with_current_settings_is_started_and_prints_the_context() {
    let (guard, url) = stopped_home("ss-stopped", |_| {});
    let home = claude_home(&guard);
    let settings = write_settings(&home, &guard.state_path, &url);
    let before = fs::read(&settings).unwrap();
    let mut started = Vec::new();

    let output = session_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
        |command| {
            started.push(command.to_vec());
            true
        },
    );

    assert_eq!(output.as_deref(), Ok(CONTEXT));
    assert_eq!(started, [recovery_command()]);
    assert_eq!(fs::read(&settings).unwrap(), before);
}

#[test]
fn stopped_daemon_whose_start_fails_hands_off() {
    let (guard, url) = stopped_home("ss-stopped-start-failed", |_| {});
    let home = claude_home(&guard);
    write_settings(&home, &guard.state_path, &url);
    let mut attempts = 0;

    let output = session_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
        |_| {
            attempts += 1;
            false
        },
    );

    assert!(output.is_err());
    assert_eq!(attempts, 1);
}

#[test]
fn stopped_daemon_with_drifted_settings_hands_off_without_a_start() {
    let (guard, _url) = stopped_home("ss-stopped-drift", |_| {});
    let home = claude_home(&guard);
    write_settings(&home, &guard.state_path, FIXTURE_URL);

    let output = no_op_output(
        &config_text(&home, &guard.state_path, &runtime_build()),
        &environment(&home),
        deadline(),
    );

    assert!(output.is_err());
}

#[test]
fn stopped_daemon_of_another_version_or_host_hands_off_without_a_start() {
    let edits: [fn(&mut Map<String, Value>); 3] = [
        |state| {
            state.insert("package_version".to_owned(), json!("0.0.0"));
        },
        |state| {
            state.insert("host".to_owned(), json!("0.0.0.0"));
        },
        |state| {
            state.insert("pid".to_owned(), json!(0));
        },
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let (guard, url) = stopped_home(&format!("ss-stopped-gate-{index}"), edit);
        let home = claude_home(&guard);
        write_settings(&home, &guard.state_path, &url);

        let output = no_op_output(
            &config_text(&home, &guard.state_path, &runtime_build()),
            &environment(&home),
            deadline(),
        );

        assert!(output.is_err(), "gate {index} did not hand off");
    }
}
