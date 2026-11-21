//! A runner closed with a line that says how it went: the report rides into
//! containment with the run it describes.
#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture};

/// An agent rarely runs a suite bare. It closes the command with a line of
/// its own — `; echo done`, `&& echo PASS`, `|| echo FAIL`, or both arms —
/// so the transcript says how the run went without scrolling the output.
/// Each of those steps reads nothing and writes only its own label, so the
/// run behind it keeps the containment it would have had alone. The sink
/// prints the arm the shell would have reached.
#[test]
fn a_trailing_report_rides_into_containment_with_the_run_it_describes() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("cd {project} && bunx vitest run x; echo done"),
            format!("cd {project} && bunx vitest run x && echo PASS"),
            format!("cd {project} && bunx vitest run x || echo FAIL"),
            format!("cd {project} && bunx vitest run x && echo PASS || echo FAIL"),
            format!("cd {project} && bunx vitest run x 2>&1 | tail -20 && echo PASS"),
            format!("cd {project} && bunx vitest run x 2>&1 | tail -20; echo done"),
            format!("cd {project} && bunx vitest run x 2>&1 | tail -20 || echo \"run failed\""),
            "bunx vitest run x && echo PASS".into(),
            "bunx vitest run x; echo done".into(),
            "bunx vitest run x && echo PASS || echo FAIL".into(),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    (result.minimum_action.as_str(), result.reason_code.as_str()),
                    (
                        "sandbox-required",
                        "native_vitest_readonly_containment_required"
                    ),
                    "{harness}: {command}"
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A report is one `echo` of one printable label and nothing else. A step
/// that reads a file, a second label behind the first, an empty `echo`, or a
/// status the shell would read off the echo rather than off the run are all
/// ordinary steps, and the command keeps its review.
#[test]
fn a_step_that_is_not_a_report_keeps_the_review() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            // `$?` after `&&` or `||` is the echo's own status, not the run's.
            format!("cd {project} && bunx vitest run x && echo \"exit=$?\""),
            format!("cd {project} && bunx vitest run x || echo \"exit=$?\""),
            // A second label behind the first is a list, not one report.
            format!("cd {project} && bunx vitest run x && echo PASS && echo AGAIN"),
            format!("cd {project} && bunx vitest run x; echo done; echo again"),
            // A step that reads something is work of its own.
            format!("cd {project} && bunx vitest run x && cat notes.txt"),
            format!("cd {project} && bunx vitest run x; tail -3 notes.txt"),
            // An `echo` with nothing to print says nothing about the run.
            format!("cd {project} && bunx vitest run x && echo"),
            // A label the sink cannot print back verbatim.
            format!("cd {project} && bunx vitest run x && echo 'it ran'"),
            format!("cd {project} && bunx vitest run x && echo $SHELL"),
            format!("cd {project} && bunx vitest run x && echo one two"),
            // `-n`, `-e` and `-E` are options the shell's own echo consumes
            // rather than prints, so the sink's label is not what the
            // command would have produced.
            format!("cd {project} && bunx vitest run x && echo -n"),
            format!("cd {project} && bunx vitest run x; echo -e done"),
            format!("cd {project} && bunx vitest run x || echo -E FAIL"),
            "bunx vitest run x && rm -rf build".into(),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.minimum_action, "review", "{harness}: {command}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
