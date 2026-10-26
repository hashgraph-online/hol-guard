//! A pre-tool request that says where the command runs, and in what shell.
//!
//! The hook lane hands the harness's working directory and home directory to
//! the edge, and every rule that reads a path needs them: without them
//! `rg -n pattern ../service-api` cannot be resolved to anything, so it is
//! reviewed. A caller that asks the pre-tool entry point the same question —
//! `guard inspect`, the dashboard's console, a hook that goes through the
//! command-line lane — used to get the context-free answer, which reported a
//! review for work the enforced lane allows.
//!
//! The directories alone are not the whole question. `rg` reads the config
//! that `RIPGREP_CONFIG_PATH` names, and that file's lines become arguments,
//! so a search is admitted only where no such variable is set in the shell
//! the command will run in. The runtime cannot read that shell: the resident
//! is started with its own sanitized environment. So the request carries the
//! stamp the hook took, and a request without one leaves the proof unproven.
use crate::pretool_home_layout_reads::layout;
use guard_command::pretool::{evaluate_pre_tool, evaluate_pre_tool_in};
use guard_command::CommandModelRequestV1;
use guard_contracts::GuardExecutionEnvironmentV1;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

/// A plain interactive shell: a HOME, a PATH, and none of the variables that
/// move what a tool reads.
fn shell(home: &str) -> GuardExecutionEnvironmentV1 {
    GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".to_owned(),
        environment_names: vec!["HOME".to_owned(), "PATH".to_owned(), "SHELL".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

#[test]
fn a_sibling_search_reads_the_same_way_the_hook_lane_reads_it() {
    let layout = layout("pretool-request-context");
    let cwd = layout.org.join("app-portal");
    let home = layout.home.to_str().expect("home path");
    let command = request("rg -n fixture ../service-api");

    let without = evaluate_pre_tool(&command).unwrap();
    assert_eq!(
        without.minimum_action, "review",
        "a command that resolves nowhere is reviewed"
    );

    let unstamped = evaluate_pre_tool_in(&command, Some(home), cwd.to_str(), None).unwrap();
    assert_eq!(
        unstamped.minimum_action, "review",
        "directories alone cannot say what the shell exports: {}",
        unstamped.reason_code
    );

    let stamped = shell(home);
    let with = evaluate_pre_tool_in(&command, Some(home), cwd.to_str(), Some(&stamped)).unwrap();
    assert_eq!(with.minimum_action, "allow", "{}", with.reason_code);
}

#[test]
fn a_search_config_the_shell_exports_keeps_the_review() {
    let layout = layout("pretool-request-context-config");
    let cwd = layout.org.join("app-portal");
    let home = layout.home.to_str().expect("home path");
    let command = request("rg -n fixture ../service-api");

    let mut stamped = shell(home);
    stamped
        .environment_names
        .push("RIPGREP_CONFIG_PATH".to_owned());
    let decision =
        evaluate_pre_tool_in(&command, Some(home), cwd.to_str(), Some(&stamped)).unwrap();
    assert_ne!(
        decision.minimum_action, "allow",
        "a config can hand the search a path of its own: {}",
        decision.reason_code
    );
}

#[test]
fn a_sensitive_read_keeps_its_review_once_the_directories_are_known() {
    let layout = layout("pretool-request-context-secret");
    let cwd = layout.org.join("app-portal");
    let home = layout.home.to_str().expect("home path");
    let stamped = shell(home);
    for command in [
        "cat ~/.ssh/id_rsa",
        "rg -n token ~/.ssh",
        "cat ../service-api/.env",
    ] {
        let command = request(command);
        let decision =
            evaluate_pre_tool_in(&command, Some(home), cwd.to_str(), Some(&stamped)).unwrap();
        assert_ne!(decision.minimum_action, "allow", "{}", command.command);
    }
}
