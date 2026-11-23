//! A lookup that may print a shell definition keeps its review instead of
//! running in the sandbox, whose fresh shell would report the name as missing.
use crate::pretool::workspace_contained_tests::{host, reason, workspace, CONTAINED};

#[test]
fn a_definition_printing_lookup_keeps_its_review() {
    let ws = workspace("definition-lookups", true);
    for command in [
        "type probe_func",
        "type -a probe_func",
        "command -v probe_alias",
        "command -V probe_func",
        "which hol_probe_func",
        "whence hol_probe_alias",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_lookup_of_a_program_on_path_still_runs_contained() {
    let ws = workspace("definition-lookups-path", true);
    let control = "npm run build";
    if reason("omp", control, &ws, true) == CONTAINED {
        for command in ["which sh", "command -v sh", "type sh"] {
            let reason = reason("omp", command, &ws, true);
            assert_eq!(reason, CONTAINED, "{command}");
        }
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_command_that_runs_its_operand_still_runs_contained() {
    let ws = workspace("definition-lookups-runs", true);
    let control = "npm run build";
    let contained = reason("omp", control, &ws, true) == CONTAINED;
    assert_eq!(contained, host(), "{control}");
    if contained {
        assert_eq!(reason("omp", "command npm run build", &ws, true), CONTAINED);
    }
    let _ = std::fs::remove_dir_all(&ws);
}
