//! Every portable command-source fixture passes against the current evaluator.
//!
//! The authoring script checks these only in the nightly extension builder, so
//! an evaluator change could leave a fixture's expectation stale until then.

use guard_command::native_command_program::source::run_fixtures;
use std::path::PathBuf;

fn fixture_paths() -> Vec<PathBuf> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .expect("fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("command-source-") && name.ends_with(".v1.json")
                })
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_portable_command_source_fixture_passes() {
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "no portable command-source fixtures found"
    );
    let mut failures = Vec::new();
    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let result = match run_fixtures(&std::fs::read(path).unwrap()) {
            Ok(result) => result,
            Err(error) => {
                failures.push(format!("{name}: {error}"));
                continue;
            }
        };
        assert_eq!(result["target_commands_executed"], 0, "{name}");
        for case in result["cases"].as_array().into_iter().flatten() {
            if case["passed"] != true {
                failures.push(format!(
                    "{name}: {} expected {} {} got {} {}",
                    case["id"],
                    case["expected_action"],
                    case["expected_effective_segments"],
                    case["actual_action"],
                    case["actual_effective_segments"],
                ));
            }
        }
        if result["ok"] != true && !failures.iter().any(|line| line.starts_with(&name)) {
            failures.push(format!("{name}: not ok"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
