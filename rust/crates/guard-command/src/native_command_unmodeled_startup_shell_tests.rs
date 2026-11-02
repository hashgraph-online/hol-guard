//! A shell that reads a startup file before its script still names the
//! programs that script runs.
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// `bash -c 'npm test'` models exactly and runs. The login spelling beside it,
/// and every `zsh -c`, read a startup file this text does not hold, which left
/// the whole invocation blocked outright with no approval left to give it. The
/// script is still in the text, and its own words name the owners a review
/// floor collects.
#[test]
fn a_startup_shell_script_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "bash -lc 'npm test'",
        "bash -lc \"npm test\"",
        "bash -ilc 'npm test'",
        "bash -il -c 'cargo test'",
        "bash -lc 'npm run build'",
        "zsh -c 'npm test'",
        "zsh -lc 'cargo build'",
        "zsh -ic 'npm test'",
        "sh -lc 'npm test'",
        "/bin/zsh -lc 'pytest -q'",
        "/bin/bash -lc 'npm test'",
        "bash -lc 'cd dashboard && npm test'",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// The script has to be the words in this text. A shell told to read anything
/// else keeps the path it had, and so does a shell whose `-c` script is not
/// the whole of what it runs.
#[test]
fn a_shell_reading_more_than_its_script_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        // `-s` reads the script from standard input, which this text is not.
        "bash -lsc 'npm test'",
        // The long spelling is not an option letter, so the walk stops.
        "bash --login -c 'npm test'",
        // A shell with its own script grammar, whose words are not these.
        "fish -c 'npm test'",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
