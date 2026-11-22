#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture};

/// Every text filter the sink can apply in process keeps the containment the
/// same command keeps with `| tail`.
#[test]
fn text_filters_after_a_contained_core_keep_the_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            format!("cd {project} && bunx vitest run x 2>&1 | wc -l"),
            format!("cd {project} && bunx vitest run x 2>&1 | grep -c FAIL | cat"),
            format!("cd {project} && bunx vitest run x 2>&1 | sort | uniq -c"),
            format!("cd {project} && bunx vitest run x 2>&1 | sed -n '1,5p'"),
            format!("cd {project} && bunx vitest run x 2>&1 | tr -d '\\r' | tail -5"),
            format!("cd {project} && bunx vitest run x 2>&1 | cut -c 1-80 | wc -w"),
        ] {
            let result = classify(&root, harness, &command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(
                    result.reason_code, "native_vitest_readonly_containment_required",
                    "{harness}: {command}"
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A stage that opens something of its own is not a filter, whatever its
/// program is called.
#[test]
fn a_text_filter_that_names_a_file_keeps_its_review() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for command in [
        format!("cd {project} && bunx vitest run x 2>&1 | wc -l report.txt"),
        format!("cd {project} && bunx vitest run x 2>&1 | sort -o out.txt"),
        format!("cd {project} && bunx vitest run x 2>&1 | sed 's/a/b/w out.txt'"),
        format!("cd {project} && bunx vitest run x 2>&1 | sed -n 'w out.txt'"),
        format!("cd {project} && bunx vitest run x 2>&1 | cat extra.log"),
        format!("cd {project} && bunx vitest run x 2>&1 | sed -i.bak 's/a/b/'"),
    ] {
        let result = classify(&root, "omp", &command);
        assert_ne!(
            result.reason_code, "native_vitest_readonly_containment_required",
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
