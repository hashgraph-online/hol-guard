//! A Vitest run narrowed by test title keeps its containment when the title
//! holds a credential word. The title selects among collected tests; it opens
//! no file, so it is not a sensitive read.
#![cfg(unix)]

use crate::pretool_contained_wrappers::{classify, fixture};

#[test]
fn a_title_filter_with_a_credential_word_rides_into_containment() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("cd {project} && bunx vitest run -t \"masks the secret field\""),
            format!("cd {project} && bunx vitest run x -t \"rejects a short password\""),
            format!("cd {project} && bunx vitest run --testNamePattern=secret"),
            "bunx vitest run -t \"keeps the secret hidden\"".into(),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(
                result.reason_code, "native_sensitive_access_review",
                "{harness}: {command}"
            );
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

/// Vitest reads `-t` as a regular expression, so a title filter often holds
/// `|` alternation. The run is still contained, never sent to a sensitive
/// review for a credential word in one of the alternatives.
#[test]
fn a_title_alternation_with_a_credential_word_stays_contained() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in [
            format!("cd {project} && bunx vitest run -t \"never|keeps the secret\""),
            format!("cd {project} && bunx vitest run x --silent -t \"keeps the order|keeps the secret\""),
            format!("cd {project} && bunx vitest run --testNamePattern='password|token'"),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(
                result.reason_code, "native_sensitive_access_review",
                "{harness}: {command}"
            );
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}: {}",
                    result.reason_code
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_title_filter_that_can_name_a_file_keeps_its_review() {
    let root = fixture();
    let project = root.join("project");
    let project = project.to_str().unwrap();
    for harness in ["omp", "codex"] {
        for command in [
            format!("cd {project} && bunx vitest run -t .env"),
            format!("cd {project} && bunx vitest run -t password .env"),
        ] {
            let result = classify(&root, harness, &command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
            assert_ne!(
                result.reason_code, "native_vitest_readonly_containment_required",
                "{harness}: {command}"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
