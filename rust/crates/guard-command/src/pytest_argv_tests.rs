use serde_json::json;

use crate::pytest_argv::command_targets_pytest;

fn command(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn targets(words: &[&str]) -> bool {
    command_targets_pytest(&command(words))
}

#[test]
fn a_pytest_launcher_names_pytest_however_it_is_spelled() {
    for program in [
        "pytest",
        "py.test",
        "PyTest",
        "/opt/venv/bin/pytest",
        "C:\\venv\\Scripts\\pytest.exe",
        ".venv/bin/py.test",
    ] {
        assert!(targets(&[program, "-q"]), "{program} is a pytest launcher");
    }
}

#[test]
fn an_interpreter_names_pytest_only_when_its_module_is_pytest() {
    assert!(targets(&["python", "-m", "pytest", "-q"]));
    assert!(targets(&["python3.12", "-mpytest"]));
    assert!(targets(&["pythonw.exe", "-m", "pytest.__main__"]));
    assert!(!targets(&["python", "-m", "unittest"]));
    assert!(!targets(&["python", "-m", "pytestify"]));
    assert!(!targets(&["python", "evil.py", "-m", "pytest"]));
}

#[test]
fn a_clustered_module_option_reads_as_the_interpreter_runs_it() {
    // The Python copy this replaced looked for `-m` as a whole word, so it read
    // `-Im pytest` as something other than pytest and reported the
    // authorization failure in place of the planner's own refusal.
    assert!(targets(&["python", "-Im", "pytest", "-q"]));
    assert!(targets(&[
        "python",
        "-IWignore::DeprecationWarning",
        "-m",
        "pytest"
    ]));
    assert!(!targets(&["python", "-Ic", "import pytest"]));
}

#[test]
fn a_program_read_from_standard_input_does_not_name_pytest() {
    assert!(!targets(&["python", "-", "-m", "pytest"]));
    assert!(!targets(&["python", "--", "-m", "pytest"]));
    assert!(!targets(&["python", "-c", "import pytest"]));
    assert!(!targets(&["python", "--command=import pytest"]));
}

#[test]
fn a_command_that_is_not_a_pytest_run_does_not_name_pytest() {
    assert!(!targets(&[]));
    assert!(!targets(&["node", "-e", "require('pytest')"]));
    assert!(!targets(&["pytest-watch", "-q"]));
    assert!(!targets(&["python"]));
}

#[test]
fn the_containment_screen_answers_the_same_question() {
    let answer = |words: &[&str]| {
        crate::contained_argv::evaluate("pytest_command", &json!({ "command": command(words) }))
    };
    assert_eq!(answer(&["pytest", "-q"]), Some(json!({ "value": true })));
    assert_eq!(
        answer(&["python", "-Im", "pytest"]),
        Some(json!({ "value": true }))
    );
    assert_eq!(
        answer(&["node", "-e", "0"]),
        Some(json!({ "value": false }))
    );
}
