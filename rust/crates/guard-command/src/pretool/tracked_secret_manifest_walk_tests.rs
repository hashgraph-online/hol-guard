//! Recursive searches that reach a committed Kubernetes `Secret` manifest.

use super::{fixture, write, write_index};
use std::path::PathBuf;

/// A recursive search that reaches a committed `Secret` manifest proceeds
/// only when its pattern cannot occur in the manifest, as it would for an
/// `.env` file: the manifest's values are never printed either way.
#[test]
fn a_walk_passes_a_secret_manifest_its_pattern_cannot_match() {
    let (home, project) = fixture();
    let manifest = "deploy/app-secrets.yaml";
    write(&project.join("src/one.ts"), "export const one = 1;\n");
    write(
        &project.join(manifest),
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  mode: cHJvZA==\n",
    );
    write_index(&project.join(".git"), &["src/one.ts", manifest]);
    let blocker = |pattern: &str| {
        let clearance = crate::pretool::search_pattern_clearance::PatternClearance::new(pattern);
        crate::pretool::search_scope::content_search_blocker(
            project.to_str().unwrap(),
            home.to_str(),
            project.to_str(),
            clearance.as_ref(),
        )
    };
    assert_eq!(blocker("export"), None);
    // Words in the manifest, in any letter case, and a pattern the clearance
    // cannot read keep the manifest in the way.
    for pattern in ["secret", "Mode", "export|cHJv", "export.*"] {
        assert_eq!(blocker(pattern), Some(PathBuf::from(manifest)), "{pattern}");
    }
    // A store directory or a secret extension is never cleared by content.
    let stored = "secrets/app.yaml";
    write(
        &project.join(stored),
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\n",
    );
    write_index(&project.join(".git"), &["src/one.ts", stored]);
    std::fs::remove_file(project.join(manifest)).unwrap();
    assert_eq!(blocker("export"), Some(PathBuf::from(stored)));
}

/// Claude `Grep` prints matching lines and `Glob` prints names, so neither
/// shows a committed manifest's values unless the pattern can occur in it.
#[test]
fn claude_searches_pass_a_secret_manifest_they_cannot_print() {
    let (home, project) = fixture();
    let manifest = "deploy/app-secrets.yaml";
    write(&project.join("src/one.ts"), "export const one = 1;\n");
    write(
        &project.join(manifest),
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  mode: cHJvZA==\n",
    );
    write_index(&project.join(".git"), &["src/one.ts", manifest]);
    let grep = |pattern: &str| {
        crate::pretool::search_scope::claude_grep_directory_scope_proven(
            &serde_json::json!({
                "tool_name": "Grep",
                "tool_input": {"pattern": pattern, "path": project},
            }),
            home.to_str(),
            project.to_str(),
        )
    };
    let glob = |pattern: &str| {
        crate::pretool::search_scope::claude_glob_scope_proven(
            &serde_json::json!({
                "tool_name": "Glob",
                "tool_input": {"pattern": pattern, "path": project},
            }),
            home.to_str(),
            project.to_str(),
        )
    };
    assert!(grep("export"));
    assert!(glob("**/*.ts"));
    for pattern in ["secret", "Mode", "export|cHJv", "export.*"] {
        assert!(!grep(pattern), "{pattern}");
    }
    // Untracked, the manifest is held for its name, as before.
    write_index(&project.join(".git"), &["src/one.ts"]);
    assert!(!grep("export"));
    assert!(!glob("**/*.ts"));
    // Committed again, an `.env` beside it still holds the listing.
    write_index(&project.join(".git"), &["src/one.ts", manifest]);
    write(&project.join(".env"), "MODE=prod\n");
    assert!(!glob("**/*.ts"));
    assert!(!grep("mode"));
}
