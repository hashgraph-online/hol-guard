#![cfg(unix)]
//! Recursive `grep` over a user skill tree.
//!
//! Each skill document and script below `~/.agents/skills` is readable one
//! at a time, but the tree sits below a hidden home directory, so a search
//! over it asked even when every file it opened was one of those documents.
//! The search may run when each file it opens is a skill document or script;
//! a data file, a hidden entry or a link it would reach keeps the review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// The root stays below the target directory: `$TMPDIR` on macOS resolves
/// under `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-grep-skill-tree")
        .join(format!(
            "{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".agents/skills/release-check/references",
        ".agents/skills/release-check/scripts",
        ".agents/skills/release-check/agents",
        ".agents/skills/docs-only/references",
        ".agents/skills/docs-only/scripts",
        ".agents/skills/hidden-notes/.cache",
        ".agents/skills/linked-notes",
        ".agents/skills/data-notes",
        "work/project/.agents/skills/local-check",
        "work/project/.agents/skills/local-data",
        "work/outside-skill",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".agents/skills/release-check/SKILL.md", "# Release check\n"),
        (
            ".agents/skills/release-check/references/review.md",
            "Run the review before merging.\n",
        ),
        (".agents/skills/release-check/scripts/run.sh", "#!/bin/sh\n"),
        (
            ".agents/skills/release-check/agents/model.yaml",
            "model: x\n",
        ),
        (".agents/skills/release-check/.DS_Store", "finder\n"),
        (".agents/skills/docs-only/SKILL.md", "# Docs\n"),
        (".agents/skills/docs-only/references/usage.md", "Usage.\n"),
        (".agents/skills/docs-only/scripts/check.py", "print(1)\n"),
        (".agents/skills/hidden-notes/SKILL.md", "# Hidden\n"),
        (".agents/skills/hidden-notes/.cache/notes.md", "cached\n"),
        (".agents/skills/linked-notes/SKILL.md", "# Linked\n"),
        (".agents/skills/data-notes/SKILL.md", "# Data\n"),
        (".agents/skills/data-notes/settings.json", "{}\n"),
        ("work/outside.md", "outside\n"),
        (
            "work/project/.agents/skills/local-check/SKILL.md",
            "# Local check\n",
        ),
        (
            "work/project/.agents/skills/local-data/SKILL.md",
            "# Local data\n",
        ),
        (
            "work/project/.agents/skills/local-data/settings.json",
            "{}\n",
        ),
        ("work/outside-skill/SKILL.md", "# Outside\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::os::unix::fs::symlink(
        home.join("work/outside.md"),
        home.join(".agents/skills/linked-notes/outside.md"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        home.join("work/outside-skill"),
        home.join("work/project/.agents/skills/linked-skill"),
    )
    .unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let cwd = home.join("work/project");
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
    .to_string()
}

#[test]
fn a_search_that_opens_only_skill_documents_is_allowed() {
    let home = home();
    let skills = home.join(".agents/skills");
    let skills = skills.display();
    let local = home.join("work/project/.agents/skills");
    let local = local.display();
    for command in [
        format!(
            "grep -r -n -i -E \"approved form|without review\" {skills}/release-check {skills}/docs-only --include='*.md' | cut -c1-300 | head -30"
        ),
        // A skill tree of the project sits beside the user's own.
        format!(
            "grep -r -n -i -E \"approved form|without review\" {skills}/release-check {skills}/docs-only {local}/local-check --include='*.md' | cut -c1-300 | head -30"
        ),
        format!("grep -rn 'Run the review' {skills}/release-check --include='*.md'"),
        format!(
            "grep -rln Usage {skills}/docs-only {skills}/release-check --include='*.md' --include='*.sh'"
        ),
        // Without an include the search opens every file, and here every
        // file is a document or a script.
        format!("grep -rn Usage {skills}/docs-only"),
        "grep -rn x .agents/skills/local-check".to_owned(),
        "grep -rln x .agents/skills/local-data --include='*.md'".to_owned(),
    ] {
        for harness in ["omp", "zcode", "claude-code", "codex"] {
            assert_eq!(action(&home, harness, &command), "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn a_search_that_opens_anything_else_in_the_tree_keeps_its_review() {
    let home = home();
    let skills = home.join(".agents/skills");
    let skills = skills.display();
    for command in [
        // The finder file and the model settings are opened too.
        format!("grep -rn review {skills}/release-check"),
        // A document below a hidden folder is not one a direct read allows.
        format!("grep -rn cached {skills}/hidden-notes --include='*.md'"),
        // The link leads out of the tree.
        format!("grep -rn outside {skills}/linked-notes --include='*.md'"),
        // A data file is not a skill document.
        format!("grep -rn x {skills}/data-notes --include='*.json'"),
        format!("grep -rn x {skills}/data-notes"),
        // The project's own skill tree keeps the same screens.
        "grep -rn x .agents/skills/local-data".to_owned(),
        // A project skill linked out of the checkout is not the project's.
        "grep -rn Outside .agents/skills/linked-skill --include='*.md'".to_owned(),
    ] {
        for harness in ["omp", "zcode"] {
            assert_ne!(
                action(&home, harness, &command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}
