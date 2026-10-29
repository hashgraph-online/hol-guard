use super::command_prefix_split;

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_string()).collect()
}

fn split(command: &[&str], drop_data: bool) -> (Vec<String>, Vec<(String, String)>) {
    let command = words(command);
    let (index, assignments, _dropped) = command_prefix_split(&command, drop_data);
    (command[index..].to_vec(), assignments)
}

/// Whether the peel dropped a setting rather than carrying it.
fn dropped(command: &[&str], drop_data: bool) -> bool {
    let command = words(command);
    command_prefix_split(&command, drop_data).2
}

#[test]
fn an_inert_assignment_is_carried_off_the_front() {
    let (core, carried) = split(&["CI=1", "pytest", "-q"], false);

    assert_eq!(core, words(&["pytest", "-q"]));
    assert_eq!(carried, vec![("CI".to_string(), "1".to_string())]);
}

#[test]
fn a_localisation_setting_is_carried_by_its_prefix() {
    let (core, carried) = split(&["LC_ALL=C", "pytest"], false);

    assert_eq!(core, words(&["pytest"]));
    assert_eq!(carried, vec![("LC_ALL".to_string(), "C".to_string())]);
}

#[test]
fn a_transparent_prefix_hands_back_the_program_behind_it() {
    let (core, carried) = split(&["command", "bun", "run", "build"], false);

    assert_eq!(core, words(&["bun", "run", "build"]));
    assert!(carried.is_empty());
}

#[test]
fn an_env_prefix_carries_the_setting_it_spells() {
    let (core, carried) = split(&["/usr/bin/env", "CI=1", "pytest", "-q"], false);

    assert_eq!(core, words(&["pytest", "-q"]));
    assert_eq!(carried, vec![("CI".to_string(), "1".to_string())]);
}

#[test]
fn a_bare_env_keeps_its_own_spelling() {
    let (core, carried) = split(&["env", "pytest"], false);

    assert_eq!(core, words(&["env", "pytest"]));
    assert!(carried.is_empty());
}

#[test]
fn an_option_keeps_the_prefix_in_place() {
    let (core, _) = split(&["command", "-v", "pytest"], false);

    assert_eq!(core, words(&["command", "-v", "pytest"]));
}

#[test]
fn an_unfiltered_setting_leaves_the_prefix_in_place() {
    let (core, carried) = split(&["env", "LD_PRELOAD=/tmp/x.so", "pytest"], true);

    assert_eq!(core, words(&["env", "LD_PRELOAD=/tmp/x.so", "pytest"]));
    assert!(carried.is_empty());
}

#[test]
fn a_plain_data_setting_is_dropped_only_when_the_caller_asks() {
    assert_eq!(
        split(&["REPORT_DIR=/tmp/r", "pytest"], false).0,
        words(&["REPORT_DIR=/tmp/r", "pytest"])
    );
    assert_eq!(
        split(&["REPORT_DIR=/tmp/r", "pytest"], true).0,
        words(&["pytest"])
    );
}

#[test]
fn a_dropped_setting_is_never_carried_into_the_run() {
    let (core, carried) = split(&["REPORT_DIR=/tmp/r", "CI=1", "pytest"], true);

    assert_eq!(core, words(&["pytest"]));
    assert_eq!(carried, vec![("CI".to_string(), "1".to_string())]);
}

#[test]
fn a_setting_the_run_would_receive_anyway_is_never_dropped() {
    for name in [
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "NODE_PATH",
        "TMPDIR",
        "TMP",
        "TEMP",
    ] {
        let written = format!("{name}=/tmp/x");
        let (core, _) = split(&[written.as_str(), "pytest"], true);

        assert_eq!(
            core,
            words(&[written.as_str(), "pytest"]),
            "{name} moves the run"
        );
    }
}

#[test]
fn a_value_opening_with_a_dash_is_not_plain_data() {
    let (core, _) = split(&["REPORT=-rf", "pytest"], true);

    assert_eq!(core, words(&["REPORT=-rf", "pytest"]));
}

#[test]
fn a_value_longer_than_its_budget_is_not_plain_data() {
    let written = format!("REPORT={}", "a".repeat(513));
    let (core, _) = split(&[written.as_str(), "pytest"], true);

    assert_eq!(core, words(&[written.as_str(), "pytest"]));

    let inside = format!("REPORT={}", "a".repeat(512));
    assert_eq!(
        split(&[inside.as_str(), "pytest"], true).0,
        words(&["pytest"])
    );
}

#[test]
fn a_trailing_data_setting_is_kept_because_it_names_no_program() {
    let (core, _) = split(&["REPORT_DIR=/tmp/r"], true);

    assert_eq!(core, words(&["REPORT_DIR=/tmp/r"]));
}

#[test]
fn a_word_the_shell_would_not_read_as_an_assignment_is_not_one() {
    let (core, carried) = split(&["A-B=1", "pytest"], true);

    assert_eq!(core, words(&["A-B=1", "pytest"]));
    assert!(carried.is_empty());
}

#[test]
fn stacked_prefixes_peel_down_to_the_program() {
    let (core, carried) = split(
        &[
            "CI=1",
            "command",
            "env",
            "NO_COLOR=1",
            "bun",
            "run",
            "build",
        ],
        false,
    );

    assert_eq!(core, words(&["bun", "run", "build"]));
    assert_eq!(
        carried,
        vec![
            ("CI".to_string(), "1".to_string()),
            ("NO_COLOR".to_string(), "1".to_string())
        ]
    );
}

#[test]
fn a_later_write_of_one_name_is_the_value_the_run_receives() {
    let (_, carried) = split(&["CI=1", "CI=0", "pytest"], false);

    assert_eq!(carried.last(), Some(&("CI".to_string(), "0".to_string())));
}

#[test]
fn an_empty_command_peels_nothing() {
    let (core, carried) = split(&[], false);

    assert!(core.is_empty());
    assert!(carried.is_empty());
}

#[test]
fn a_command_peeled_as_issued_reports_no_drop() {
    assert!(!dropped(&["CI=1", "command", "pytest"], true));
    assert!(!dropped(&["REPORT_DIR=/tmp/r", "pytest"], false));
}

#[test]
fn a_dropped_setting_is_reported_wherever_it_stood() {
    assert!(dropped(&["REPORT_DIR=/tmp/r", "pytest"], true));
    assert!(dropped(&["env", "REPORT_DIR=/tmp/r", "pytest"], true));
}

#[test]
fn a_refused_prefix_reports_no_drop_it_did_not_make() {
    assert!(!dropped(
        &["env", "REPORT_DIR=/tmp/r", "LD_PRELOAD=/tmp/x.so", "pytest"],
        true
    ));
}

#[test]
fn a_timing_prefix_hands_back_the_program_behind_it() {
    assert_eq!(
        split(&["time", "command", "bun", "test"], false).0,
        words(&["bun", "test"])
    );
    assert_eq!(
        split(&["LC_ALL=C", "time", "bun"], false).1,
        vec![("LC_ALL".to_string(), "C".to_string())]
    );
}

#[test]
fn a_prefix_option_keeps_every_spelling_in_place() {
    for command in [
        ["command", "-p", "bun"].as_slice(),
        ["time", "-p", "bun"].as_slice(),
        ["env", "-i", "CI=1", "bun"].as_slice(),
    ] {
        let kept: Vec<&str> = command.to_vec();
        assert_eq!(split(command, false).0, words(&kept), "{command:?}");
    }
}

#[test]
fn a_prefix_naming_no_program_stays_the_program_itself() {
    assert_eq!(split(&["command"], false).0, words(&["command"]));
}

#[test]
fn a_setting_that_steers_a_run_is_no_inert_assignment() {
    let (core, carried) = split(&["NODE_OPTIONS=--require=x", "bun"], false);

    assert_eq!(core, words(&["NODE_OPTIONS=--require=x", "bun"]));
    assert!(carried.is_empty());
}

#[test]
fn the_peel_stops_at_the_first_setting_it_cannot_carry() {
    let (core, carried) = split(&["CI=1", "APP_FLAG=1", "bun"], false);

    assert_eq!(core, words(&["APP_FLAG=1", "bun"]));
    assert_eq!(carried, vec![("CI".to_string(), "1".to_string())]);
}

#[test]
fn a_lone_inert_assignment_leaves_no_program_behind_it() {
    let (core, carried) = split(&["CI=1"], false);

    assert!(core.is_empty());
    assert_eq!(carried, vec![("CI".to_string(), "1".to_string())]);
}
